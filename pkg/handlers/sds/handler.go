package sds

import (
	"context"
	"fmt"
	"strconv"
	"time"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"k8s.io/apimachinery/pkg/util/wait"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	pkgerrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
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

	// Certs yields the workload's X.509-SVID, served as the "default" resource.
	Certs workloadidentity.CertSource

	// Bundles yields trust anchors, served as "ROOTCA" and as the
	// spiffe://<trust-domain> resources.
	Bundles workloadidentity.BundleSource

	// StreamSecretsSubscriber is how an open StreamSecrets learns its material
	// changed. Build it with Hub.ForRPC and workloadidentity.RPCStreamSecrets, so
	// the subscription metrics spell the RPC as the RPC metrics do. FetchSecrets
	// has none: a unary call answers once and has no stream to wake.
	StreamSecretsSubscriber workloadidentity.Subscriber
}

// No SessionProvider here, matching workloadapi.Opts: nothing in this package
// signs a request, and the notification tier resolves the provider.

// Handler implements the Envoy Secret Discovery Service.
//
// UnimplementedSecretDiscoveryServiceServer is embedded by value because the
// generated code requires it: registration panics on a nil pointer embed.
type Handler struct {
	secretv3.UnimplementedSecretDiscoveryServiceServer

	opts Opts

	// backoff paces an RPC's retries. Each RPC starts from a copy, so one
	// stream's failures never slow another's.
	backoff wait.Backoff
}

// Steps is not a retry budget. Await retries until the context ends or the error
// turns non-retryable, and Steps only bounds how many times the delay doubles:
// once it reaches Cap, wait.delay zeroes Steps itself and every later call
// returns the ceiling. It only has to exceed the five doublings from Duration to
// Cap, since at zero the delay would never grow past a second.
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
// passes as grpcserver.Opts.Register, in place of the stub this replaces.
func (h *Handler) Register(registrar grpc.ServiceRegistrar) {
	secretv3.RegisterSecretDiscoveryServiceServer(registrar, h)
}

// DeltaSecrets is not served. Overridden so the refusal names the fix, since a
// sidecar configured for DELTA_GRPC would otherwise sit without a certificate.
func (h *Handler) DeltaSecrets(_ secretv3.SecretDiscoveryService_DeltaSecretsServer) error {
	return status.Error(codes.Unimplemented,
		"this agent serves state-of-the-world SDS only: set api_type to GRPC, not DELTA_GRPC, in the sidecar's sds_config")
}

// FetchSecrets serves the same secrets StreamSecrets does, once. No Envoy
// sidecar reaches it, since Envoy only subscribes over the stream. It signals no
// staleness, so polling it is not a substitute for StreamSecrets.
func (h *Handler) FetchSecrets(ctx context.Context, req *discoveryv3.DiscoveryRequest) (*discoveryv3.DiscoveryResponse, error) {
	state := handlers.NewRPCState(workloadidentity.RPCFetchSecrets, h.backoff)

	resp, err := h.fetchSecrets(ctx, req)
	if err != nil {
		return nil, state.Failed(ctx, err)
	}
	state.Answered()

	return resp, nil
}

// fetchSecrets is FetchSecrets without the metrics, returning the tiers' own
// errors for the caller above to record and map exactly once. It takes no retry,
// so nothing here maps on its own.
func (h *Handler) fetchSecrets(ctx context.Context, req *discoveryv3.DiscoveryRequest) (*discoveryv3.DiscoveryResponse, error) {
	log := logger.FromContext(ctx)

	// Nothing here retries, unlike the stream: a unary caller has its own
	// deadline to spend, so a transient tier failure is answered with a retryable
	// code and the caller decides.
	caller, err := handlers.Attest(ctx, h.opts.Attestor)
	if err != nil {
		return nil, err
	}

	// The lease carries the enrollment refusal, so a workload naming no provider
	// is turned away here with the code the stream gives it. It also starts the
	// fetch on a cold provider, without which this call would answer the same way
	// forever.
	releaseLease, err := h.opts.Bundles.Lease(ctx, caller)
	if err != nil {
		return nil, err
	}
	defer releaseLease()

	requested, err := requestedOrAll(req.GetResourceNames())
	if err != nil {
		// NotFound, the same as the stream, rather than the InvalidArgument
		// SPIRE answers: one bad name has to produce one status on both methods
		// or the socket has two contracts.
		return nil, status.Error(codes.NotFound, err.Error())
	}

	resources := make([]*anypb.Any, 0, len(requested))
	for _, r := range requested {
		secret, err := h.buildSecret(ctx, caller, r)
		if err != nil {
			return nil, err
		}

		packed, err := anypb.New(secret)
		if err != nil {
			return nil, fmt.Errorf("packing the secret %q: %w", secret.GetName(), err)
		}

		resources = append(resources, packed)
	}

	log.Debugf("FetchSecrets served %d resource(s) to pod %s", len(resources), caller.PodUID)

	// Every resource in one response: the stream's one-per-response rule is
	// Envoy's singleton watch, and a unary fetch has none. VersionInfo and Nonce
	// stay empty because acknowledgement needs a stream to acknowledge on.
	return &discoveryv3.DiscoveryResponse{
		TypeUrl:   SecretTypeURL,
		Resources: resources,
	}, nil
}

// StreamSecrets serves an Envoy sidecar its certificate and validation context,
// and pushes replacements on the same stream when either changes. The caller is
// attested once, when the stream opens, and the lease, the subscription and every
// read are bound to that workload.
func (h *Handler) StreamSecrets(stream secretv3.SecretDiscoveryService_StreamSecretsServer) error {
	ctx := stream.Context()
	state := handlers.NewRPCState(workloadidentity.RPCStreamSecrets, h.backoff)

	// The loop only ever exits with an error, already mapped: a disconnect, a
	// shutdown and a refusal all arrive as one.
	return h.streamSecrets(ctx, stream, state)
}

// streamSecrets is StreamSecrets' loop. Await records and maps whatever ends it.
func (h *Handler) streamSecrets(ctx context.Context, stream secretv3.SecretDiscoveryService_StreamSecretsServer, state *handlers.RPCState) error {
	log := logger.FromContext(ctx)

	// Each setup step is awaited, so a transient failure before the first
	// response blocks the stream rather than ending it. nil signals: the
	// subscription that would provide them is itself one of these steps.
	var caller *workloadidentity.Workload
	if err := state.Await(ctx, nil, func() (err error) {
		caller, err = handlers.Attest(ctx, h.opts.Attestor)
		return err
	}); err != nil {
		return err
	}

	// Held for the stream's life, not around each read: this stream reads the
	// validation context only when signalled, so a provider whose bundles hold
	// still would look unused and stop being refreshed, missing the next
	// rotation.
	var releaseLease func()
	if err := state.Await(ctx, nil, func() (err error) {
		releaseLease, err = h.opts.Bundles.Lease(ctx, caller)
		return err
	}); err != nil {
		return err
	}
	defer releaseLease()

	// Subscribed on every stream, since Envoy can add a TlsCertificate later and
	// a bundles-only subscription would miss its renewals. Never
	// SubscribeToJWTBundles: Envoy does not consume JWT authorities.
	var signals <-chan struct{}
	var releaseSub func()
	if err := state.Await(ctx, nil, func() (err error) {
		signals, releaseSub, err = h.opts.StreamSecretsSubscriber.SubscribeToWorkloadMaterial(ctx, caller)
		return err
	}); err != nil {
		return err
	}
	defer releaseSub()

	s := &streamState{
		handler: h,
		stream:  stream,
		caller:  caller,
		rpc:     state,
	}

	requests := recvLoop(ctx, stream)

	for {
		select {
		case <-ctx.Done():
			// A client disconnect and a server shutdown both arrive here.
			return state.Ended(ctx)

		case <-signals:
			// The channel arrives primed, so a signal can land before Envoy has
			// named anything. Each pass sends what it reads now, not what the
			// signal carried, so a slow stream never gets superseded material.
			if err := state.Await(ctx, signals, func() error { return s.sendNamed(ctx) }); err != nil {
				return err
			}

		case received, ok := <-requests:
			if !ok {
				// Envoy half-closed. Nothing more is coming, so wait for the
				// context rather than spin on a closed channel.
				requests = nil
				continue
			}
			if received.err != nil {
				// A clean half-close or a broken stream; neither is this
				// handler's failure, and the context's status answers both.
				return state.Ended(ctx)
			}
			// Applying and sending are separate so only the send is retried.
			// Re-applying after a partial send would re-run the stale-nonce rule
			// against a nonce that send already advanced, leaving the resources
			// it still wanted unserved until the next signal.
			send, err := s.applyRequest(log, received.req)
			if err != nil {
				return err
			}
			if !send {
				continue
			}
			if err := state.Await(ctx, signals, func() error { return s.sendNamed(ctx) }); err != nil {
				return err
			}
		}
	}
}

// received is one result from the receive side of the stream.
type received struct {
	req *discoveryv3.DiscoveryRequest
	err error
}

// recvLoop reads the stream on its own goroutine, because Recv blocks and this
// handler waits on notifications too. It ends when Recv fails, which gRPC causes
// by cancelling the context on return, so no handler exit leaks it.
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

	// rpc is the stream's metrics state, shared with the method that ends the
	// stream, which is what keeps one stream to one observation.
	rpc *handlers.RPCState

	// named is what Envoy is currently subscribed to, in request order, rebuilt
	// from each request: state-of-the-world means a request carries the whole set
	// of interests rather than a change to it.
	named []resource

	// lastSent is the secret last put on this stream per resource name, which the
	// dedupe compares against. Needed because the notification tier leaves dedupe
	// to its handlers, and an X.509 rotation wakes every stream of the provider.
	lastSent map[string]*tlsv3.Secret

	// sent counts responses and supplies both the version and the nonce. The
	// version must be monotonic per stream and the nonce unique per response, and
	// a response is only sent when something changed, so one counter cannot let
	// the two disagree.
	sent uint64

	// lastNonce is the nonce on the most recent response. A request echoing
	// anything else is answering a response that has since been superseded.
	lastNonce string
}

// applyRequest applies one DiscoveryRequest to the stream's state and reports
// whether anything should be sent for it. It reads no tier and sends nothing, so
// it is never retried; the send that follows it is. Getting the acknowledgement
// protocol wrong produces a stream that appears to work and then stops updating.
func (s *streamState) applyRequest(log *logrus.Entry, req *discoveryv3.DiscoveryRequest) (bool, error) {
	// A rejection arrives as a request carrying an error detail. Logged, and the
	// stream continues: rolling back or retrying would both re-send what Envoy
	// just refused.
	if detail := req.GetErrorDetail(); detail != nil {
		log.Warnf("Envoy rejected SDS version %s for %v: %s",
			req.GetVersionInfo(), req.GetResourceNames(), detail.GetMessage())
		return false, nil
	}

	requested, err := parseRequestedResources(req.GetResourceNames())
	if err != nil {
		return false, status.Error(codes.NotFound, err.Error())
	}

	// A request echoing anything but the latest nonce acknowledges a superseded
	// response. Only ignored when the named set is unchanged: with one resource
	// per response several can be in flight, so an interest change can carry an
	// older nonce, and dropping it would leave that resource unserved forever.
	stale := req.GetResponseNonce() != "" && req.GetResponseNonce() != s.lastNonce
	if stale && sameResources(s.named, requested) {
		return false, nil
	}

	s.named = requested

	return true, nil
}

// sendNamed re-reads and sends every resource Envoy has named, one per response:
// its SdsApi reads only the first resource and rejects a name it did not ask for,
// and a subset does not read as a deletion of the names it omits.
func (s *streamState) sendNamed(ctx context.Context) error {
	for _, r := range s.named {
		secret, err := s.handler.buildSecret(ctx, s.caller, r)
		if err != nil {
			return err
		}

		if proto.Equal(secret, s.lastSent[r.name]) {
			// Absorbs the wakes provider-keyed routing cannot: a pod renewal
			// that left the validation context alone, and the reverse.
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
		return fmt.Errorf("packing the secret %q: %w", secret.GetName(), err)
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
		// A broken or closed stream, which already carries its own status.
		// Marked as a send so the metrics leave it uncounted.
		return handlers.SendError{Err: err}
	}

	// Only the first answer counts, so a long-lived stream pushing rotations
	// stays one RPC.
	s.rpc.Answered()

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
			return nil, err
		}
		if len(svids) == 0 {
			// The tier promises exactly one, so empty is a tier defect.
			return nil, pkgerrors.ErrIssuanceFailed.Wrapf(nil,
				"the certificate source returned no X.509-SVID for %q", r.name)
		}
		// Always exactly one: WISE issues one SVID per workload, so there is
		// never a second to choose from. CertSource is plural only because
		// FetchX509SVID returns a repeated field.
		return tlsCertificateSecret(r.name, svids[0])

	case kindValidationContext:
		bundle, err := h.validationBundle(ctx, caller, r)
		if err != nil {
			return nil, err
		}
		return validationContextSecret(r.name, bundle)

	default:
		// Unreachable: parseResourceName returns one of the two kinds or an
		// error.
		return nil, status.Errorf(codes.Internal, "resource %q has no secret kind", r.name)
	}
}

// validationBundle resolves the trust anchors for one validation context
// resource.
func (h *Handler) validationBundle(ctx context.Context, caller *workloadidentity.Workload, r resource) (*x509bundle.Bundle, error) {
	bundles, err := h.opts.Bundles.X509Bundles(ctx, caller)
	if err != nil {
		return nil, err
	}
	if bundles == nil {
		// Neither a set nor an error, which the lookup below would panic on.
		// Read as empty so it falls to the NotFound at the end.
		bundles = x509bundle.NewSet()
	}

	domain := r.trustDomain

	if domain.IsZero() {
		// The ROOTCA case: the caller's own domain, which only the tier knows.
		domain, err = h.opts.Bundles.OwnTrustDomain(ctx, caller)
		if err != nil {
			return nil, err
		}
		if domain.IsZero() {
			// Zero until a bundle has been fetched, which a lease does not wait
			// for. ErrBundleUnavailable because a retry fixes it; a hand-built
			// Unavailable would read as permanent and end the stream.
			return nil, pkgerrors.ErrBundleUnavailable.Wrapf(nil,
				"the trust domain for %q is not known yet, because no trust bundle has been fetched for this workload's provider", r.name)
		}
	}

	bundle, ok := bundles.Get(domain)
	if !ok || len(bundle.X509Authorities()) == 0 {
		// NotFound rather than Unavailable: no retry produces a trust domain
		// the provider does not federate with.
		return nil, status.Errorf(codes.NotFound,
			"no trust anchors for trust domain %q", domain.Name())
	}

	return bundle, nil
}

// parseRequestedResources parses every name on a request, rejecting all of them
// if one is unserveable, since a partial answer leaves Envoy waiting. Duplicates
// are dropped: serving one twice would mean two nonces for one subscription.
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

// requestedOrAll parses the names on a unary request, treating one that names
// nothing as a request for everything, the xDS wildcard rule. Not shared with the
// stream, whose first request routinely names nothing: reading that as everything
// would push a private key at a sidecar that asked for neither.
func requestedOrAll(names []string) ([]resource, error) {
	named := make([]string, 0, len(names))
	for _, name := range names {
		if name != "" {
			named = append(named, name)
		}
	}

	if len(named) == 0 {
		return allResources(), nil
	}

	return parseRequestedResources(named)
}

// allResources is the wildcard set: everything this agent can serve without the
// caller naming a trust domain. The spiffe://<own domain> form is left out
// because it would repeat ROOTCA's bytes under a second name. Federated domains
// belong here when federation arrives.
func allResources() []resource {
	return []resource{
		{name: ResourceNameTLSCertificate, kind: kindTLSCertificate},
		{name: ResourceNameOwnValidationContext, kind: kindValidationContext},
	}
}

// sameResources reports whether two parsed resource sets name the same things in
// the same order. Order counts because a reordering is not worth distinguishing
// from a change.
// sameResources reports whether two parsed resource sets name the same things in
// the same order. Deliberately not sorted first: a reorder then reads as an
// interest change, and serving one costs a dedupe pass that sends nothing.
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
