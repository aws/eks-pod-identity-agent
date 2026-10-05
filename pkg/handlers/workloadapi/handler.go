// Package workloadapi serves the SPIFFE Workload API on the workload identity
// socket, to applications whose SPIFFE library finds it through the
// SPIFFE_ENDPOINT_SOCKET variable the Pod Identity webhook injects. It composes the
// tiers and fetches nothing: it attests the caller, reads the tiers, translates onto
// the wire types, and re-reads on every notification to keep each stream current.
//
// The bundle-only RPCs and ValidateJWTSVID serve any attested caller whose session
// names a provider, whether or not it holds an SVID, and refuse one that is not
// enrolled, which matches SPIRE's default of denying unregistered callers.
package workloadapi

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"k8s.io/apimachinery/pkg/util/wait"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/handlers"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// Opts are the tiers the handler composes. Every field is required, and each is
// an interface so the tests drive the handler with pkg/workloadidentity/fake. No
// socket path, no AWS config and no session: nothing here signs a request.
type Opts struct {
	// Attestor resolves the process behind a connection. Every RPC attests,
	// since a Workload API request carries no identity.
	Attestor workloadidentity.Attestor
	// Certs yields the workload's X.509-SVIDs.
	Certs workloadidentity.CertSource
	// Tokens yields JWT-SVIDs for the audiences a caller asks for.
	Tokens workloadidentity.TokenSource
	// Bundles yields trust material for the workload's provider, and leases it
	// for as long as a stream is open.
	Bundles workloadidentity.BundleSource
	// X509SVIDSubscriber, X509BundlesSubscriber and JWTBundlesSubscriber are each
	// stream's own Subscriber, built with Hub.ForRPC and that RPC's constant, so
	// the subscription metrics spell the RPC as the RPC metrics do.
	X509SVIDSubscriber    workloadidentity.Subscriber
	X509BundlesSubscriber workloadidentity.Subscriber
	JWTBundlesSubscriber  workloadidentity.Subscriber
}

// Handler implements the SPIFFE Workload API.
//
// UnimplementedSpiffeWorkloadAPIServer is embedded by value because the generated
// code requires it, and it answers the two WIT methods the agent does not serve.
type Handler struct {
	workload.UnimplementedSpiffeWorkloadAPIServer

	opts Opts
	// backoff paces a stream's retries of its own steps, attesting, subscribing,
	// leasing and reading the tiers, after a retryable failure. A failed send to
	// the workload is not retried: the stream ends and the client reconnects. Each
	// stream starts from a copy, so one stream's failures never slow another.
	backoff wait.Backoff
}

// retryBackoff paces those retries from one second doubling to thirty, go-spiffe's
// own client backoff, so a blocked stream polls the tiers no harder than the
// library would poll the agent.
var retryBackoff = wait.Backoff{
	Duration: time.Second,
	Factor:   2,
	Jitter:   0.1,
	Steps:    1 << 30,
	Cap:      30 * time.Second,
}

// New returns a Handler over the given tiers.
func New(opts Opts) *Handler {
	return &Handler{opts: opts, backoff: retryBackoff}
}

// Register attaches the handler to a gRPC server. It is what the wiring site
// passes as grpcserver.Opts.Register.
func (h *Handler) Register(registrar grpc.ServiceRegistrar) {
	workload.RegisterSpiffeWorkloadAPIServer(registrar, h)
}

// FetchX509SVID streams the caller's X.509-SVIDs, each with its trust domain's
// bundle and the federated bundles beside them, so a workload gets its identity
// and the means to verify peers in one message. It is woken by its pod's
// credential changes and its provider's X.509 changes, and dedupes on everything
// but the private key.
func (h *Handler) FetchX509SVID(_ *workload.X509SVIDRequest, stream grpc.ServerStreamingServer[workload.X509SVIDResponse]) error {
	return serve(h, stream.Context(), streamSpec[*workload.X509SVIDResponse]{
		rpc:       workloadidentity.RPCFetchX509SVID,
		subscribe: h.opts.X509SVIDSubscriber.SubscribeToWorkloadMaterial,
		build:     h.buildX509SVIDResponse,
		view:      x509SVIDView,
		send:      stream.Send,
	})
}

// FetchX509Bundles streams the X.509 authorities only, for a caller that verifies
// peers without an identity of its own. Its request carries no fields, so the
// attested caller names the provider, and an SVID renewal never wakes it.
func (h *Handler) FetchX509Bundles(_ *workload.X509BundlesRequest, stream grpc.ServerStreamingServer[workload.X509BundlesResponse]) error {
	return serve(h, stream.Context(), streamSpec[*workload.X509BundlesResponse]{
		rpc:       workloadidentity.RPCFetchX509Bundles,
		subscribe: h.opts.X509BundlesSubscriber.SubscribeToCertBundles,
		build:     h.buildX509BundlesResponse,
		send:      stream.Send,
	})
}

// FetchJWTBundles streams the JWT authorities as JWK Sets keyed by trust domain.
// It is the only stream a JWT key roll reaches.
func (h *Handler) FetchJWTBundles(_ *workload.JWTBundlesRequest, stream grpc.ServerStreamingServer[workload.JWTBundlesResponse]) error {
	return serve(h, stream.Context(), streamSpec[*workload.JWTBundlesResponse]{
		rpc:       workloadidentity.RPCFetchJWTBundles,
		subscribe: h.opts.JWTBundlesSubscriber.SubscribeToJWTBundles,
		build:     h.buildJWTBundlesResponse,
		send:      stream.Send,
	})
}

// FetchJWTSVID returns the caller's JWT-SVIDs, each carrying every requested
// audience, keeping only those for the requested SPIFFE ID when the caller names
// one. It takes no lease and subscribes to nothing.
func (h *Handler) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	start := time.Now()
	resp, err := h.fetchJWTSVID(ctx, req)
	if err != nil {
		return nil, failUnary(ctx, workloadidentity.RPCFetchJWTSVID, start, err)
	}
	handlers.ObserveRPC(workloadidentity.RPCFetchJWTSVID, nil, time.Since(start))
	return resp, nil
}

func (h *Handler) fetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	audiences := req.GetAudience()
	if len(audiences) == 0 || slices.Contains(audiences, "") {
		return nil, wierrors.ErrInvalidAudience.Wrapf(nil, "at least one audience must be specified, and none may be empty")
	}
	var want spiffeid.ID
	if raw := req.GetSpiffeId(); raw != "" {
		id, err := spiffeid.FromString(raw)
		if err != nil {
			return nil, wierrors.ErrInvalidRequest.Wrapf(nil, "the requested SPIFFE ID is invalid: %v", err)
		}
		want = id
	}

	caller, err := h.attest(ctx)
	if err != nil {
		return nil, err
	}
	svids, err := h.opts.Tokens.JWTSVIDs(ctx, caller, audiences)
	if err != nil {
		return nil, err
	}

	resp := &workload.JWTSVIDResponse{}
	for _, svid := range svids {
		if svid == nil || (!want.IsZero() && svid.ID != want) {
			continue
		}
		resp.Svids = append(resp.Svids, &workload.JWTSVID{SpiffeId: svid.ID.String(), Svid: svid.Marshal(), Hint: svid.Hint})
	}
	if len(resp.Svids) == 0 {
		return nil, wierrors.ErrNoIdentity.Wrapf(nil, "no identity issued")
	}
	return resp, nil
}

// ValidateJWTSVID verifies a token the caller presents against its provider's JWT
// authorities and returns the token's SPIFFE ID and claims. It needs the bundle and
// not an SVID of the caller's own, and it sees only its own provider's trust
// domains, so a token from another provider fails even on a shared node.
func (h *Handler) ValidateJWTSVID(ctx context.Context, req *workload.ValidateJWTSVIDRequest) (*workload.ValidateJWTSVIDResponse, error) {
	start := time.Now()
	resp, err := h.validateJWTSVID(ctx, req)
	if err != nil {
		return nil, failUnary(ctx, workloadidentity.RPCValidateJWTSVID, start, err)
	}
	handlers.ObserveRPC(workloadidentity.RPCValidateJWTSVID, nil, time.Since(start))
	return resp, nil
}

func (h *Handler) validateJWTSVID(ctx context.Context, req *workload.ValidateJWTSVIDRequest) (*workload.ValidateJWTSVIDResponse, error) {
	if req.GetAudience() == "" {
		return nil, wierrors.ErrInvalidAudience.Wrapf(nil, "an audience must be specified")
	}
	if req.GetSvid() == "" {
		return nil, wierrors.ErrInvalidRequest.Wrapf(nil, "a JWT-SVID must be specified")
	}

	caller, err := h.attest(ctx)
	if err != nil {
		return nil, err
	}
	// Taken first and mapped like any tier error: ParseAndValidate turns a
	// source error into its own invalid token error, which would report an STS
	// outage as a bad token. The source is point-in-time and fetches nothing.
	source, err := h.opts.Bundles.JWTSource(ctx, caller)
	if err != nil {
		return nil, err
	}

	svid, err := jwtsvid.ParseAndValidate(req.GetSvid(), source, []string{req.GetAudience()})
	if err != nil {
		// In the message, since a caller sees no cause: go-spiffe's errors describe
		// the token's header and claims, never the token itself.
		return nil, wierrors.ErrInvalidToken.Wrapf(nil, "%v", err)
	}
	claims, err := claimsStruct(svid.Claims)
	if err != nil {
		return nil, err
	}
	return &workload.ValidateJWTSVIDResponse{SpiffeId: svid.ID.String(), Claims: claims}, nil
}

// claimsStruct converts the token's claims through JSON, as SPIRE does, so any
// value go-jose decoded, such as a json.Number, converts rather than failing.
func claimsStruct(claims map[string]any) (*structpb.Struct, error) {
	raw, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	out := &structpb.Struct{}
	if err := protojson.Unmarshal(raw, out); err != nil {
		return nil, err
	}
	return out, nil
}

// attest resolves the caller from the connection the server's transport
// credentials put in ctx, the only route to it. A missing connection is a wiring
// bug, and refusing is still the only safe answer.
func (h *Handler) attest(ctx context.Context) (*workloadidentity.Workload, error) {
	conn, ok := grpcserver.ConnFromContext(ctx)
	if !ok {
		return nil, wierrors.ErrUnattestable.Wrapf(nil, "the caller's connection is not available, so it cannot be attested")
	}
	caller, err := h.opts.Attestor.Attest(ctx, conn)
	if err != nil {
		return nil, err
	}
	if caller == nil {
		return nil, wierrors.ErrUnattestable.Wrapf(nil, "attestation named no workload")
	}
	return caller, nil
}

// failUnary ends a unary call that failed: it records the failure, logs it and
// maps the error onto a status. A call whose client left is not recorded: the
// agent gave it no answer, and the tier error would only say the wait was cut short.
func failUnary(ctx context.Context, rpc string, start time.Time, err error) error {
	if ctx.Err() != nil {
		return handlers.StatusErrorFromContext(ctx)
	}
	handlers.ObserveRPC(rpc, err, time.Since(start))
	logFailure(ctx, rpc, err)
	return handlers.StatusError(err)
}

// logFailure logs an error the handler answers with. One it maps to Internal is
// unexpected and logged as an error; the rest are refusals a caller can act on.
func logFailure(ctx context.Context, rpc string, err error) {
	log := logger.FromContext(ctx).WithField("rpc", rpc)
	if handlers.StatusCode(err) == codes.Internal {
		log.Errorf("Unexpected error serving the Workload API: %v", err)
		return
	}
	log.Infof("Refusing the Workload API call: %v", err)
}

var _ workload.SpiffeWorkloadAPIServer = (*Handler)(nil)
