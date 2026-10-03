// Package workloadapi serves the SPIFFE Workload API on the workload identity
// socket. It is the launch interface for applications that use a SPIFFE library:
// the library finds the socket through the SPIFFE_ENDPOINT_SOCKET environment
// variable the Pod Identity webhook injects, opens a stream, and expects the
// agent to keep it current.
//
// This package composes the tiers and does not fetch: it attests the caller,
// reads what it was given, translates onto the wire types, and keeps each stream
// current by re-reading on every notification. It has to work with libraries
// nobody at AWS wrote, so the specified behaviour wins over anything more
// convenient.
//
// Skeleton. Every method has its final signature, and the three streaming RPCs
// carry their real subscription lifecycle and send loop, which is where the
// notification tier's contract shows up. Assembling the responses, the error
// mapping and the two unary RPCs are PLACEHOLDER(T10).
package workloadapi

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// Opts are the tiers the handler composes. Every field is required, and each is
// an interface so the handler's tests drive it with pkg/workloadidentity/fake
// rather than a cluster. No socket path and no AWS config: this package serves
// what it is given and builds no client.
type Opts struct {
	// Attestor resolves the process behind a connection. The handler attests on
	// every RPC, since a Workload API request carries no identity.
	Attestor workloadidentity.Attestor
	// Certs yields the workload's X.509-SVIDs, minting or renewing as needed.
	Certs workloadidentity.CertSource
	// Tokens yields JWT-SVIDs for the audiences a caller asks for.
	Tokens workloadidentity.TokenSource
	// Bundles yields trust material, which is per provider rather than per pod.
	Bundles workloadidentity.BundleSource
	// Subs is how a stream learns its material changed. Each streaming RPC
	// subscribes with the attested caller and releases on end. One Subscriber
	// serves all three streams, so they share one RPC metric label; a field per
	// RPC would be a wiring change only.
	Subs workloadidentity.Subscriber
}

// Handler implements the SPIFFE Workload API.
//
// UnimplementedSpiffeWorkloadAPIServer is embedded by value because the generated
// code requires it: the interface has an unexported method only that struct
// provides, and registration panics on a nil pointer embed. It also answers the
// two WIT methods the agent does not serve, which is why they are not declared
// below.
type Handler struct {
	workload.UnimplementedSpiffeWorkloadAPIServer

	opts Opts
}

// New returns a Handler over the given tiers.
func New(opts Opts) *Handler {
	return &Handler{opts: opts}
}

// Register attaches the handler to a gRPC server. It is what the wiring site
// passes as grpcserver.Opts.Register, in place of the stub this replaces.
func (h *Handler) Register(registrar grpc.ServiceRegistrar) {
	workload.RegisterSpiffeWorkloadAPIServer(registrar, h)
}

// FetchX509SVID streams the caller's X.509-SVIDs with its provider's trust
// bundle, and sends a fresh response whenever either changes. Embedding the
// bundle is not redundant: the workload gets its identity and the means to verify
// peers in one message, so it never correlates two streams.
//
// One subscription carries both reasons to wake. The stream is deliberately not
// deduplicated, matching SPIRE and left open in T10: a rotation re-sends the
// response even though the certificate did not change.
func (h *Handler) FetchX509SVID(_ *workload.X509SVIDRequest, stream grpc.ServerStreamingServer[workload.X509SVIDResponse]) error {
	ctx := stream.Context()

	caller, err := h.caller(ctx)
	if err != nil {
		return err
	}

	signals, release, err := h.opts.Subs.SubscribeToWorkloadMaterial(ctx, caller)
	if err != nil {
		return statusError(err)
	}
	defer release()

	// PLACEHOLDER(T10): take BundleSource.Lease(ctx, caller) and defer its
	// release beside this one, so T6 does not evict a provider whose only reader
	// is waiting on a signal.

	return serveStream(ctx, signals, func() error {
		response, err := h.buildX509SVIDResponse(ctx, caller)
		if err != nil {
			return err
		}
		return stream.Send(response)
	})
}

// FetchX509Bundles streams trust material only, for a caller that verifies peers
// without an identity of its own. Its request carries no fields, so the attested
// caller names the provider. It subscribes through SubscribeToCertBundles, so an
// SVID renewal never wakes it, and deduplicates as SPIRE's bundle streams do.
func (h *Handler) FetchX509Bundles(_ *workload.X509BundlesRequest, stream grpc.ServerStreamingServer[workload.X509BundlesResponse]) error {
	ctx := stream.Context()

	caller, err := h.caller(ctx)
	if err != nil {
		return err
	}

	signals, release, err := h.opts.Subs.SubscribeToCertBundles(ctx, caller)
	if err != nil {
		return statusError(err)
	}
	defer release()

	// PLACEHOLDER(T10): take the bundle lease, as in FetchX509SVID.

	var last *workload.X509BundlesResponse
	return serveStream(ctx, signals, func() error {
		response, err := h.buildX509BundlesResponse(ctx, caller)
		if err != nil {
			return err
		}
		if proto.Equal(response, last) {
			return nil
		}
		if err := stream.Send(response); err != nil {
			return err
		}
		last = response
		return nil
	})
}

// FetchJWTSVID returns one JWT-SVID per requested audience. It is unary, takes no
// bundle lease, and subscribes to nothing.
//
// PLACEHOLDER(T10): attest, then read TokenSource for the requested audiences.
func (h *Handler) FetchJWTSVID(_ context.Context, _ *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "FetchJWTSVID is not implemented yet")
}

// FetchJWTBundles streams the JWT authorities as JWK Set documents keyed by trust
// domain. Like FetchX509Bundles its request carries no fields.
//
// The only stream a JWT key roll reaches, which is why a roll does not wake every
// SVID stream on the node. Deduplicates as FetchX509Bundles does.
func (h *Handler) FetchJWTBundles(_ *workload.JWTBundlesRequest, stream grpc.ServerStreamingServer[workload.JWTBundlesResponse]) error {
	ctx := stream.Context()

	caller, err := h.caller(ctx)
	if err != nil {
		return err
	}

	signals, release, err := h.opts.Subs.SubscribeToJWTBundles(ctx, caller)
	if err != nil {
		return statusError(err)
	}
	defer release()

	// PLACEHOLDER(T10): take the bundle lease, as in FetchX509SVID.

	var last *workload.JWTBundlesResponse
	return serveStream(ctx, signals, func() error {
		response, err := h.buildJWTBundlesResponse(ctx, caller)
		if err != nil {
			return err
		}
		if proto.Equal(response, last) {
			return nil
		}
		if err := stream.Send(response); err != nil {
			return err
		}
		last = response
		return nil
	})
}

// ValidateJWTSVID verifies someone else's token and returns its SPIFFE ID and
// claims, so it needs the bundle and not an SVID of the caller's own.
// PLACEHOLDER(T10): get BundleSource.JWTSource(ctx, caller) before
// jwtsvid.ParseAndValidate, so a bundle outage is Unavailable, not a bad token.
func (h *Handler) ValidateJWTSVID(_ context.Context, _ *workload.ValidateJWTSVIDRequest) (*workload.ValidateJWTSVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ValidateJWTSVID is not implemented yet")
}

// serveStream is the wait-then-send loop every streaming RPC runs. One function
// rather than three copies, since only sendCurrent differs.
//
// No special case for the initial response: the channel arrives primed, so the
// first pass is the initial send and every pass after it is a change. Each pass
// sends the state it reads now, never what the signal carried, which is what
// stops a slow stream from being handed a superseded credential.
//
// sendCurrent decides whether to send at all, which is where deduplication
// belongs: only the handler knows what it last put on this stream.
//
// A client disconnect and a server shutdown both arrive as a done context.
// Returning its status code keeps a disconnect reported as Canceled, not Unknown.
func serveStream(ctx context.Context, signals <-chan struct{}, sendCurrent func() error) error {
	for {
		select {
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err()
		case <-signals:
		}

		if err := sendCurrent(); err != nil {
			return err
		}
	}
}

// caller attests the process on the other end of the stream. The connection
// comes from the server's transport credentials, the only route to it. Every
// tier the handler reads takes the attested workload; none of them needs more.
func (h *Handler) caller(ctx context.Context) (*workloadidentity.Workload, error) {
	conn, ok := grpcserver.ConnFromContext(ctx)
	if !ok {
		// The server was built without the conn-carrying credentials, so nobody
		// on this socket can be attested. A wiring bug, but refusing is still the
		// only safe answer.
		return nil, status.Error(codes.PermissionDenied, "the caller's connection is not available, so it cannot be attested")
	}

	caller, err := h.opts.Attestor.Attest(ctx, conn)
	if err != nil {
		return nil, statusError(err)
	}
	return caller, nil
}

// statusError maps a tier error onto a gRPC status.
//
// PLACEHOLDER(T10): the real mapping is total over the pkg/errors taxonomy.
// Everything is Internal for now, which is wrong for most of it.
func statusError(err error) error {
	return status.Error(codes.Internal, err.Error())
}

// buildX509SVIDResponse assembles the current X.509-SVID response for the caller.
//
// PLACEHOLDER(T10): read CertSource and BundleSource, translate onto the wire
// types.
func (h *Handler) buildX509SVIDResponse(_ context.Context, _ *workloadidentity.Workload) (*workload.X509SVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "building an X509SVIDResponse is not implemented yet")
}

// buildX509BundlesResponse assembles the current X.509 trust bundle response.
//
// PLACEHOLDER(T10): read BundleSource.X509Bundles with the caller.
func (h *Handler) buildX509BundlesResponse(_ context.Context, _ *workloadidentity.Workload) (*workload.X509BundlesResponse, error) {
	return nil, status.Error(codes.Unimplemented, "building an X509BundlesResponse is not implemented yet")
}

// buildJWTBundlesResponse assembles the current JWT trust bundle response.
//
// PLACEHOLDER(T10): read BundleSource.JWTBundles with the caller.
func (h *Handler) buildJWTBundlesResponse(_ context.Context, _ *workloadidentity.Workload) (*workload.JWTBundlesResponse, error) {
	return nil, status.Error(codes.Unimplemented, "building a JWTBundlesResponse is not implemented yet")
}

var _ workload.SpiffeWorkloadAPIServer = (*Handler)(nil)
