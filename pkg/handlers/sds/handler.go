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
	// changed. It should be built with Hub.ForRPC and
	// workloadidentity.RPCStreamSecrets, so the subscription metrics spell the
	// RPC as the RPC metrics do.
	//
	// There is no subscriber for FetchSecrets: a unary call answers once and has
	// no stream to wake.
	StreamSecretsSubscriber workloadidentity.Subscriber
}

// No SessionProvider here, matching workloadapi.Opts: nothing in this package
// signs a request, and the provider a subscription routes on is resolved inside
// the notification tier from the attested workload. The enrollment refusal a
// session used to carry now arrives from whichever tier resolves that provider,
// which is what keeps it identical on both interfaces.

// Handler implements the Envoy Secret Discovery Service.
//
// UnimplementedSecretDiscoveryServiceServer is embedded by value because the
// generated code requires it: the interface has an unexported method only that
// struct provides, and registration panics on a nil pointer embed. Of the
// service's three RPCs it now supplies only DeltaSecrets, which the method below
// overrides to make the refusal legible.
type Handler struct {
	secretv3.UnimplementedSecretDiscoveryServiceServer

	opts Opts

	// backoff paces an RPC's retries of its own steps: attesting, leasing,
	// subscribing and reading the tiers. A failed send to the caller is not
	// retried, since the stream is already gone and Envoy will reconnect. Each
	// RPC starts from a copy, so one stream's failures never slow another's.
	backoff wait.Backoff
}

// retryBackoff is go-spiffe's own client backoff, one second doubling to thirty,
// which workloadapi also uses. Matched rather than chosen: a blocked stream
// should poll the tiers no harder than a client would poll the agent, and two
// interfaces retrying the same tier at different rates would make a tier outage
// read differently depending on which one a workload happened to use.
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

// FetchSecrets serves the same secrets StreamSecrets does, once, with nothing
// subscribed behind them.
//
// No Envoy sidecar reaches it. Envoy's gRPC subscription machinery is
// stream-only, and the unary method exists to carry the REST binding
// (POST /v3/discovery:secrets), which is HTTP/JSON and never arrives on this
// gRPC socket. It is served for the callers that are not Envoy: an operator
// asking what a pod would be handed, a readiness probe, a control plane library
// doing a one-shot read. Serving it also removes a trap, since a method
// answering Unimplemented while the stream beside it serves identical material
// reads as a defect to anyone writing tooling against the socket.
//
// A caller that needs rotation must use StreamSecrets. What this returns is
// correct when it is sent and carries nothing that says when it stops being
// correct, so polling it is not a substitute for the stream.
func (h *Handler) FetchSecrets(ctx context.Context, req *discoveryv3.DiscoveryRequest) (*discoveryv3.DiscoveryResponse, error) {
	state := newRPCState(workloadidentity.RPCFetchSecrets, h.backoff)

	resp, err := h.fetchSecrets(ctx, req)
	if err != nil {
		return nil, state.failed(ctx, err)
	}
	state.answered()

	return resp, nil
}

// fetchSecrets is FetchSecrets without the metrics, so every path out of it
// carries the error the tiers raised rather than a status built from it. The
// caller above records it and maps it exactly once.
func (h *Handler) fetchSecrets(ctx context.Context, req *discoveryv3.DiscoveryRequest) (*discoveryv3.DiscoveryResponse, error) {
	log := logger.FromContext(ctx)

	// Nothing here is wrapped in a retry, unlike the stream. A unary caller is
	// holding a call open and has its own deadline to spend, so a transient tier
	// failure is answered rather than waited out: the code says it is worth
	// retrying and the caller decides whether to. Blocking inside the call would
	// spend a deadline we did not set on a wait the caller cannot see.
	caller, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}

	// Taken for the call rather than skipped, and it carries the enrollment
	// refusal: the lease resolves the caller's provider, so a workload that names
	// none is turned away here with the code the stream gives it, rather than
	// being served a certificate the unary method found a way to reach.
	//
	// It also earns its keep on a cold provider. A one-shot read is still a read
	// of that provider's bundles, and the first interest in one is what starts it
	// being fetched and refreshed; without a lease, this call and every retry of
	// it would answer the same way forever.
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

	// Every resource in one response, unlike the stream. The one-per-response
	// rule there exists because Envoy's SdsApi is a singleton watch that reads
	// resources[0]; a unary fetch has no watch, and the whole named set is what
	// the method means.
	//
	// VersionInfo and Nonce are left empty deliberately. Both belong to the
	// acknowledgement protocol, which needs a stream to acknowledge on: there is
	// nothing here for a caller to ACK or NACK, and a nonce it echoed onto a
	// stream later would be one that stream never issued. Upstream SPIRE leaves
	// both unset on this path for the same reason.
	return &discoveryv3.DiscoveryResponse{
		TypeUrl:   SecretTypeURL,
		Resources: resources,
	}, nil
}

// StreamSecrets serves an Envoy sidecar its certificate and its validation
// context, and pushes replacements on the same stream when either changes.
//
// The caller is attested once, when the stream opens, and every subsequent read,
// the lease and the subscription are bound to that workload. A workload whose
// provider cannot be named is ErrNotEnrolled from the subscription, which refuses
// the stream with the code the Workload API uses for it.
func (h *Handler) StreamSecrets(stream secretv3.SecretDiscoveryService_StreamSecretsServer) error {
	ctx := stream.Context()
	state := newRPCState(workloadidentity.RPCStreamSecrets, h.backoff)

	// The loop only ever exits with an error: a client disconnect, a server
	// shutdown and a refusal all arrive as one, so there is no success return to
	// account for here.
	return state.failed(ctx, h.streamSecrets(ctx, stream, state))
}

// streamSecrets is StreamSecrets without the metrics, returning the tiers' own
// errors for the caller above to record and map once.
func (h *Handler) streamSecrets(ctx context.Context, stream secretv3.SecretDiscoveryService_StreamSecretsServer, state *rpcState) error {
	log := logger.FromContext(ctx)

	// Each setup step is awaited, so a transient failure before the first
	// response blocks the stream rather than ending it. There is no signal
	// channel to cut the wait short yet, which is why nil is passed: the
	// subscription that would provide one is itself one of these steps.
	var caller *workloadidentity.Workload
	if err := state.await(ctx, nil, func() (err error) {
		caller, err = h.caller(ctx)
		return err
	}); err != nil {
		return err
	}

	// The lease is taken for the stream's life, not around each read. This
	// stream reads the validation context only when it is signalled, so a
	// provider whose bundles hold still would look unused to the bundle tier,
	// which stops refreshing a provider with no open lease and would then miss
	// the next rotation.
	var releaseLease func()
	if err := state.await(ctx, nil, func() (err error) {
		releaseLease, err = h.opts.Bundles.Lease(ctx, caller)
		return err
	}); err != nil {
		return err
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
	var signals <-chan struct{}
	var releaseSub func()
	if err := state.await(ctx, nil, func() (err error) {
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
			//
			// Awaited, and safe to re-run: a retried pass re-reads every named
			// resource and the dedupe suppresses the ones an earlier attempt
			// already sent unchanged.
			if err := state.await(ctx, signals, func() error { return s.sendNamed(ctx) }); err != nil {
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
			// Applying the request and sending for it are separate steps so that
			// only the send is retried. Re-applying a request after a partial
			// send would re-run the stale-nonce rule against a nonce that send
			// had already advanced, and the request would read as stale: the
			// resources it still wanted would go unserved until the next signal.
			send, err := s.applyRequest(log, received.req)
			if err != nil {
				return err
			}
			if !send {
				continue
			}
			if err := state.await(ctx, signals, func() error { return s.sendNamed(ctx) }); err != nil {
				return err
			}
		}
	}
}

// caller attests the process on the other end of the connection. Shared with the
// Workload API handler as handlers.Attest, deliberately: a workload refused on
// one interface and served on the other would be the customer's to reverse
// engineer.
func (h *Handler) caller(ctx context.Context) (*workloadidentity.Workload, error) {
	return handlers.Attest(ctx, h.opts.Attestor)
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

	// rpc is the stream's metrics state, so the first response can be recorded
	// where it is sent. Shared with the method that will end the stream, which is
	// what keeps one stream to one observation.
	rpc *rpcState

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

// applyRequest applies one DiscoveryRequest to the stream's state and reports
// whether anything should be sent for it. It reads no tier and sends nothing, so
// it is never retried; the send that follows it is.
//
// The acknowledgement protocol is not optional politeness: getting it wrong
// produces a stream that appears to work and then stops updating.
func (s *streamState) applyRequest(log *logrus.Entry, req *discoveryv3.DiscoveryRequest) (bool, error) {
	// A rejection arrives as a request carrying an error detail. Logged and the
	// stream continues: rolling back would re-send material Envoy just refused,
	// and retrying would send the same bytes again.
	if detail := req.GetErrorDetail(); detail != nil {
		log.Warnf("Envoy rejected SDS version %s for %v: %s",
			req.GetVersionInfo(), req.GetResourceNames(), detail.GetMessage())
		return false, nil
	}

	requested, err := parseRequestedResources(req.GetResourceNames())
	if err != nil {
		return false, status.Error(codes.NotFound, err.Error())
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
		return false, nil
	}

	s.named = requested

	return true, nil
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
		// A send failure is a broken or closed stream, which already carries its
		// own status. Marked as a send so the metrics leave it uncounted and
		// return it unwrapped, which keeps a disconnect reported as such.
		return sendError{err: err}
	}

	// The stream has answered. Only the first one counts, so a long-lived stream
	// pushing rotations stays one RPC.
	s.rpc.answered()

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
			// The tier promises exactly one, so an empty slice is a tier defect
			// rather than a caller problem.
			return nil, pkgerrors.ErrIssuanceFailed.Wrapf(nil,
				"the certificate source returned no X.509-SVID for %q", r.name)
		}
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
		// A tier answering with neither a set nor an error, which the lookup
		// below would otherwise panic on. Read as an empty set, so it falls to
		// the NotFound at the end of this function.
		bundles = x509bundle.NewSet()
	}

	domain := r.trustDomain

	if domain.IsZero() {
		// The ROOTCA case: the caller's own domain, which only the bundle tier
		// knows.
		domain, err = h.opts.Bundles.OwnTrustDomain(ctx, caller)
		if err != nil {
			return nil, err
		}
		if domain.IsZero() {
			// The tier answers the zero trust domain until a bundle for the
			// provider has been fetched, and a lease does not wait for one.
			//
			// ErrBundleUnavailable rather than a status built here, because this
			// is the cold start and it is exactly what a retry fixes: the lease
			// taken above is what starts the fetch, so the stream blocks for one
			// backoff and then serves. A hand-built Unavailable would carry no
			// taxonomy member, so IsRetryable would read it as permanent and end
			// the stream, and the metric would label it none.
			return nil, pkgerrors.ErrBundleUnavailable.Wrapf(nil,
				"the trust domain for %q is not known yet, because no trust bundle has been fetched for this workload's provider", r.name)
		}
	}

	bundle, ok := bundles.Get(domain)
	if !ok || len(bundle.X509Authorities()) == 0 {
		// A name the customer wrote that this provider has no anchors for.
		// NotFound rather than Unavailable: no retry produces a trust domain the
		// provider does not federate with.
		return nil, status.Errorf(codes.NotFound,
			"no trust anchors for trust domain %q", domain.Name())
	}

	return bundle, nil
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

// requestedOrAll parses the names on a unary request, treating a request that
// names nothing as a request for everything.
//
// Empty meaning everything is the xDS wildcard rule, and upstream SPIRE applies
// it on this method. An empty string among the names is dropped before the count
// is taken, also for parity: SPIRE filters those out, so a caller sending a
// single empty name gets the wildcard rather than an error.
//
// The stream path deliberately does not share any of this. An Envoy stream opens
// before it knows what it wants and its first request routinely names nothing,
// so reading that as "send everything" there would push a certificate and a
// private key at a sidecar that asked for neither.
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

// allResources is the wildcard set: the workload's own certificate and its own
// trust anchors, which is everything this agent can serve without the caller
// naming a trust domain.
//
// The spiffe://<own domain> form is left out rather than included, because it
// would repeat ROOTCA's bytes under a second name. Federation is out of scope, so
// there is no other domain to enumerate; when it arrives, the federated domains
// belong in this set, which is what makes the wildcard worth having.
func allResources() []resource {
	return []resource{
		{name: ResourceNameTLSCertificate, kind: kindTLSCertificate},
		{name: ResourceNameOwnValidationContext, kind: kindValidationContext},
	}
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
