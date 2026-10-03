package sds

import (
	"context"
	"fmt"
	"strconv"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	pkgerrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/handlers"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// Opts are the tiers the handler composes, mirroring workloadapi.Opts. Every
// field is required and each is an interface, so the tests drive the handler with
// pkg/workloadidentity/fake rather than a cluster.
type Opts struct {
	// Attestor resolves the process behind the stream's connection. An SDS
	// request carries no identity, so the caller is attested when the stream
	// opens.
	Attestor workloadidentity.Attestor

	// Sessions exchanges the attested workload for an AWS session. The session
	// names the provider, which is what SubscribeToWorkloadMaterial routes on.
	// There is no node-level fallback.
	Sessions workloadidentity.SessionProvider

	// Certs yields the workload's X.509-SVID, served as the "default" resource.
	Certs workloadidentity.CertSource

	// Bundles yields trust anchors, served as "ROOTCA" and as the
	// spiffe://<trust-domain> resources.
	Bundles workloadidentity.BundleSource

	// Subs is how an open stream learns its material changed. It should be the
	// per-RPC view, hub.ForRPC(workloadidentity.RPCStreamSecrets), so the
	// subscription metrics carry this RPC's label.
	Subs workloadidentity.Subscriber
}

// Handler implements the Envoy Secret Discovery Service.
//
// UnimplementedSecretDiscoveryServiceServer is embedded by value because the
// generated code requires it: the interface has an unexported method only that
// struct provides, and registration panics on a nil pointer embed. It also
// supplies the two RPCs this agent does not serve, which the methods below
// override only to make the refusal legible.
type Handler struct {
	secretv3.UnimplementedSecretDiscoveryServiceServer

	opts Opts
}

// New returns a Handler over the given tiers.
func New(opts Opts) *Handler {
	return &Handler{opts: opts}
}

// Register attaches the handler to a gRPC server. It is what the wiring site
// passes as grpcserver.Opts.Register, in place of the stub this replaces.
func (h *Handler) Register(registrar grpc.ServiceRegistrar) {
	secretv3.RegisterSecretDiscoveryServiceServer(registrar, h)
}

// DeltaSecrets is not served.
//
// Overridden rather than left to the embedded Unimplemented so the refusal names
// the fix. DELTA_GRPC is a valid thing for a customer to write in an sds_config,
// and a sidecar configured that way would otherwise sit without a certificate
// with nothing on either side saying why. State-of-the-world is what Istio
// generates and what this agent serves; incremental xDS buys a single-resource
// subscription almost nothing, so it is deliberately absent rather than pending.
func (h *Handler) DeltaSecrets(_ secretv3.SecretDiscoveryService_DeltaSecretsServer) error {
	return status.Error(codes.Unimplemented,
		"this agent serves state-of-the-world SDS only: set api_type to GRPC, not DELTA_GRPC, in the sidecar's sds_config")
}

// FetchSecrets is not served.
//
// There is no Envoy configuration that reaches it: Envoy's gRPC subscription
// machinery is stream-only, and the unary method exists to carry the REST binding
// (POST /v3/discovery:secrets), which is HTTP/JSON and never arrives on this gRPC
// socket. So this refuses hand-written tooling rather than any sidecar.
func (h *Handler) FetchSecrets(_ context.Context, _ *discoveryv3.DiscoveryRequest) (*discoveryv3.DiscoveryResponse, error) {
	return nil, status.Error(codes.Unimplemented,
		"this agent serves SDS over StreamSecrets only: set api_type to GRPC in the sidecar's sds_config")
}

// StreamSecrets serves an Envoy sidecar its certificate and its validation
// context, and pushes replacements on the same stream when either changes.
//
// The caller is attested and its session read once, when the stream opens, and
// the provider that session names is what every subsequent read and the lease are
// bound to. A session that returns ErrNotEnrolled refuses the stream with the
// same code the Workload API uses for it.
func (h *Handler) StreamSecrets(stream secretv3.SecretDiscoveryService_StreamSecretsServer) error {
	ctx := stream.Context()
	log := logger.FromContext(ctx)

	caller, session, err := h.caller(ctx)
	if err != nil {
		return err
	}

	// The lease is taken for the stream's life, not around each read. This
	// stream reads the validation context only when it is signalled, so a
	// provider whose bundles hold still would look unused to the bundle tier,
	// which stops refreshing a provider with no open lease and would then miss
	// the next rotation.
	releaseLease, err := h.opts.Bundles.Lease(ctx, caller)
	if err != nil {
		return handlers.StatusError(err)
	}
	defer releaseLease()

	// Subscribed on every stream, including one that asks only for a validation
	// context: Envoy can add a TlsCertificate to this same stream later, and a
	// subscription taken out for bundles alone would never hear that
	// certificate's renewals. The cost is that a context-only stream also wakes
	// on its pod's renewals, which the dedupe below absorbs.
	//
	// SubscribeToJWTBundles is never called from here. Envoy does not consume JWT
	// authorities, so a JWT key roll must not wake this stream at all.
	signals, releaseSub := h.opts.Subs.SubscribeToWorkloadMaterial(ctx, caller, session.ProviderArn)
	defer releaseSub()

	s := &streamState{
		handler: h,
		stream:  stream,
		caller:  caller,
	}

	requests := recvLoop(ctx, stream)

	for {
		select {
		case <-ctx.Done():
			// A client disconnect and a server shutdown both arrive here.
			return handlers.StatusErrorFromContext(ctx)

		case <-signals:
			// The channel arrives primed, so the first signal may land before
			// Envoy has named anything. Nothing is subscribed yet in that case
			// and this reads nothing, which is intended: the first request is
			// answered from a fresh read of what it names.
			//
			// Each pass sends the state it reads now rather than anything the
			// signal carried, so a slow stream is never handed a superseded
			// credential.
			if err := s.sendNamed(ctx); err != nil {
				return err
			}

		case received, ok := <-requests:
			if !ok {
				// The receive side closed without the context ending, which
				// means Envoy half-closed the stream. Nothing more is coming, so
				// wait for the context rather than spinning on a closed channel.
				requests = nil
				continue
			}
			if received.err != nil {
				// io.EOF is a clean half-close and anything else is a broken
				// stream; neither is this handler's failure to report, and the
				// context's own status is the right answer for both.
				return handlers.StatusErrorFromContext(ctx)
			}
			if err := s.handleRequest(ctx, log, received.req); err != nil {
				return err
			}
		}
	}
}

// caller attests the process on the other end of the stream and reads its AWS
// session. Identical to the Workload API handler's, deliberately: a workload
// refused on one interface and served on the other would be the customer's to
// reverse engineer.
func (h *Handler) caller(ctx context.Context) (*workloadidentity.Workload, *workloadidentity.WorkloadSession, error) {
	conn, ok := grpcserver.ConnFromContext(ctx)
	if !ok {
		// The server was built without the conn-carrying credentials, so nobody
		// on this socket can be attested. A wiring bug, but refusing is still
		// the only safe answer.
		return nil, nil, status.Error(codes.PermissionDenied, "the caller's connection is not available, so it cannot be attested")
	}

	caller, err := h.opts.Attestor.Attest(ctx, conn)
	if err != nil {
		return nil, nil, handlers.StatusError(err)
	}

	session, err := h.opts.Sessions.Session(ctx, caller)
	if err != nil {
		return nil, nil, handlers.StatusError(err)
	}

	return caller, session, nil
}

// received is one result from the receive side of the stream.
type received struct {
	req *discoveryv3.DiscoveryRequest
	err error
}

// recvLoop reads the stream on a goroutine of its own, because Recv blocks and
// this handler has to wait on notifications at the same time.
//
// The goroutine ends when Recv fails, which it does as soon as the stream's
// context is cancelled, and gRPC cancels that context when the handler returns.
// So a handler that returns for any reason, including an abrupt client
// disconnect, leaves nothing behind. The send selects on ctx.Done so the final
// result cannot block forever on a channel nobody is reading.
func recvLoop(ctx context.Context, stream secretv3.SecretDiscoveryService_StreamSecretsServer) <-chan received {
	out := make(chan received, 1)

	go func() {
		defer close(out)

		for {
			req, err := stream.Recv()

			select {
			case out <- received{req: req, err: err}:
			case <-ctx.Done():
				return
			}

			if err != nil {
				return
			}
		}
	}()

	return out
}

// streamState is everything one stream remembers. None of it is shared, so none
// of it is locked: the loop above is the only reader and writer.
type streamState struct {
	handler *Handler
	stream  secretv3.SecretDiscoveryService_StreamSecretsServer
	caller  *workloadidentity.Workload

	// named is what Envoy is currently subscribed to, in request order, rebuilt
	// from each request it sends. State-of-the-world means a request carries the
	// whole set of interests rather than a change to it.
	named []resource

	// lastSent is the secret last put on this stream per resource name, which is
	// what the dedupe compares against. The notification tier leaves dedupe to
	// its handlers and its signals may be spurious, and on an X.509 rotation this
	// handler wakes for every stream of the provider at once.
	lastSent map[string]*tlsv3.Secret

	// sent counts responses sent on this stream and supplies both the version and
	// the nonce.
	//
	// One counter is enough. The version has to be monotonic per stream and must
	// not be derived from the material, and the nonce has to be unique per
	// response; since a response is only ever sent when something changed, the
	// two increment together. Deriving both from one counter makes it impossible
	// for them to disagree.
	sent uint64

	// lastNonce is the nonce on the most recent response. A request echoing
	// anything else is answering a response that has since been superseded.
	lastNonce string
}

// handleRequest applies one DiscoveryRequest.
//
// The acknowledgement protocol is not optional politeness: getting it wrong
// produces a stream that appears to work and then stops updating.
func (s *streamState) handleRequest(ctx context.Context, log *logrus.Entry, req *discoveryv3.DiscoveryRequest) error {
	// A rejection arrives as a request carrying an error detail. Logged and the
	// stream continues: rolling back would re-send material Envoy just refused,
	// and retrying would send the same bytes again.
	if detail := req.GetErrorDetail(); detail != nil {
		log.Warnf("Envoy rejected SDS version %s for %v: %s",
			req.GetVersionInfo(), req.GetResourceNames(), detail.GetMessage())
		return nil
	}

	requested, err := parseRequestedResources(req.GetResourceNames())
	if err != nil {
		return status.Error(codes.NotFound, err.Error())
	}

	// A request whose nonce is not the one on the most recent response is
	// answering a superseded response. It is ignored rather than treated as a new
	// subscription, which is what keeps a late acknowledgement from re-sending
	// everything.
	//
	// Ignored only when the named set is unchanged, though. Envoy sends a request
	// when its interest changes as well as to acknowledge, and with one resource
	// per response there can be more than one response in flight, so an interest
	// change can legitimately carry an older nonce. Dropping that would leave a
	// resource Envoy asked for unserved forever, which is far worse than
	// answering a stale acknowledgement.
	stale := req.GetResponseNonce() != "" && req.GetResponseNonce() != s.lastNonce
	if stale && sameResources(s.named, requested) {
		return nil
	}

	s.named = requested

	return s.sendNamed(ctx)
}

// sendNamed re-reads and sends every resource Envoy has named, one response each.
//
// One resource per DiscoveryResponse. Envoy's SdsApi is a singleton subscription
// that reads only the first resource and rejects a name that is not the one it
// asked for, and Envoy's mux layer hands each watch only the resources matching
// its own name, calling onConfigUpdate only when it found one. So a response
// carrying a subset does not read as a deletion of the names it omits, which is
// what makes one-at-a-time safe rather than merely conservative.
func (s *streamState) sendNamed(ctx context.Context) error {
	for _, r := range s.named {
		secret, err := s.handler.buildSecret(ctx, s.caller, r)
		if err != nil {
			return err
		}

		if proto.Equal(secret, s.lastSent[r.name]) {
			// Sending an identical resource under a new version makes Envoy do
			// work for nothing. This is the overlap the provider-keyed routing
			// cannot remove: a stream woken by its own pod's renewal whose
			// validation context did not change, and one woken by a rotation
			// whose certificate did not.
			continue
		}

		if err := s.send(secret); err != nil {
			return err
		}
	}

	return nil
}

// send puts one secret on the stream under a fresh version and nonce.
func (s *streamState) send(secret *tlsv3.Secret) error {
	packed, err := anypb.New(secret)
	if err != nil {
		return handlers.StatusError(fmt.Errorf("packing the secret %q: %w", secret.GetName(), err))
	}

	s.sent++
	version := strconv.FormatUint(s.sent, 10)
	nonce := version

	if err := s.stream.Send(&discoveryv3.DiscoveryResponse{
		VersionInfo: version,
		Resources:   []*anypb.Any{packed},
		TypeUrl:     SecretTypeURL,
		Nonce:       nonce,
	}); err != nil {
		// A send failure is a broken or closed stream, which already carries its
		// own status. Returning it unwrapped keeps a disconnect reported as such.
		return err
	}

	if s.lastSent == nil {
		s.lastSent = make(map[string]*tlsv3.Secret, len(s.named))
	}
	s.lastSent[secret.GetName()] = secret
	s.lastNonce = nonce

	return nil
}

// buildSecret reads the tier behind one resource and translates it onto the wire.
func (h *Handler) buildSecret(ctx context.Context, caller *workloadidentity.Workload, r resource) (*tlsv3.Secret, error) {
	switch r.kind {
	case kindTLSCertificate:
		svids, err := h.opts.Certs.X509SVIDs(ctx, caller)
		if err != nil {
			return nil, handlers.StatusError(err)
		}
		if len(svids) == 0 {
			// The tier promises exactly one, so an empty slice is a tier defect
			// rather than a caller problem.
			return nil, handlers.StatusError(pkgerrors.ErrIssuanceFailed.Wrapf(nil,
				"the certificate source returned no X.509-SVID for %q", r.name))
		}
		secret, err := tlsCertificateSecret(r.name, svids[0])
		if err != nil {
			return nil, handlers.StatusError(err)
		}
		return secret, nil

	case kindValidationContext:
		anchors, err := h.validationAnchors(ctx, caller, r)
		if err != nil {
			return nil, err
		}
		secret, err := validationContextSecret(r.name, anchors)
		if err != nil {
			return nil, handlers.StatusError(err)
		}
		return secret, nil

	default:
		// Unreachable: parseResourceName returns one of the two kinds or an
		// error.
		return nil, status.Errorf(codes.Internal, "resource %q has no secret kind", r.name)
	}
}

// validationAnchors resolves the trust anchors for one validation context
// resource.
func (h *Handler) validationAnchors(ctx context.Context, caller *workloadidentity.Workload, r resource) ([][]byte, error) {
	bundles, err := h.opts.Bundles.X509Bundles(ctx, caller)
	if err != nil {
		return nil, handlers.StatusError(err)
	}

	domain := r.trustDomain

	if domain == "" {
		// The ROOTCA case: the caller's own domain, which only the bundle tier
		// knows.
		domain, err = h.opts.Bundles.OwnTrustDomain(ctx, caller)
		if err != nil {
			return nil, handlers.StatusError(err)
		}
		if domain == "" {
			// The tier answers the empty string until a bundle for the provider
			// has been fetched, and a lease does not wait for one. Unavailable
			// rather than blocking: Envoy retries on it, and a cold start is
			// over in one fetch.
			return nil, status.Errorf(codes.Unavailable,
				"the trust domain for %q is not known yet, because no trust bundle has been fetched for this workload's provider", r.name)
		}
	}

	anchors, ok := bundles[domain]
	if !ok || len(anchors) == 0 {
		// A name the customer wrote that this provider has no anchors for.
		// NotFound rather than Unavailable: no retry produces a trust domain the
		// provider does not federate with.
		return nil, status.Errorf(codes.NotFound,
			"no trust anchors for trust domain %q", domain)
	}

	return anchors, nil
}

// parseRequestedResources parses every name on a request, rejecting the whole
// request if any name is unserveable.
//
// Rejecting the whole request rather than the names it understood: Envoy's
// subscription is state-of-the-world, so a partial answer would leave it
// subscribed to a name nothing will ever answer, with no error to explain it.
//
// Duplicates are dropped. Envoy has been known to name the same resource twice
// on one request, and serving it twice would mean two responses and two nonces
// for one subscription.
func parseRequestedResources(names []string) ([]resource, error) {
	resources := make([]resource, 0, len(names))
	seen := make(map[string]struct{}, len(names))

	for _, name := range names {
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}

		r, err := parseResourceName(name)
		if err != nil {
			return nil, err
		}
		resources = append(resources, r)
	}

	return resources, nil
}

// sameResources reports whether two parsed resource sets name the same things in
// the same order. Order is part of it because the sets come from Envoy in request
// order and a reordering is not worth distinguishing from a change.
func sameResources(a, b []resource) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].name != b[i].name {
			return false
		}
	}
	return true
}

var _ secretv3.SecretDiscoveryServiceServer = (*Handler)(nil)
