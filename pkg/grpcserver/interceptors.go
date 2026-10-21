package grpcserver

import (
	"context"
	"strings"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
)

const (
	// SpiffeSecurityHeader is the gRPC metadata key the SPIFFE Workload API
	// requires a caller to set. go-spiffe's client sets it on every call and its
	// own test server rejects a call without it, so a workload using a conformant
	// SPIFFE library already sends it.
	//
	// It is spelled in lower case because HTTP/2 lower cases header names on the
	// wire and metadata lookups lower case the key, so a caller that capitalises
	// it differently still matches.
	SpiffeSecurityHeader = "workload.spiffe.io"

	// SpiffeSecurityHeaderValue is the only accepted value of
	// SpiffeSecurityHeader.
	SpiffeSecurityHeaderValue = "true"
)

// interceptorPair is one rule in the chain, in both of the shapes gRPC needs. The
// two halves of a rule are declared together so a rule cannot be added to the unary
// chain and forgotten in the stream chain, which on this socket would mean a rule
// that does not apply to most of the traffic.
type interceptorPair struct {
	// Unary applies the rule to a unary call.
	Unary grpc.UnaryServerInterceptor
	// Stream applies the same rule to a stream.
	Stream grpc.StreamServerInterceptor
}

// unaryChain and streamChain project the chain onto the two options gRPC takes,
// preserving order.
func unaryChain(pairs []interceptorPair) []grpc.UnaryServerInterceptor {
	chain := make([]grpc.UnaryServerInterceptor, 0, len(pairs))
	for _, pair := range pairs {
		chain = append(chain, pair.Unary)
	}
	return chain
}

func streamChain(pairs []interceptorPair) []grpc.StreamServerInterceptor {
	chain := make([]grpc.StreamServerInterceptor, 0, len(pairs))
	for _, pair := range pairs {
		chain = append(chain, pair.Stream)
	}
	return chain
}

// loggerFields are the log fields for one RPC.
//
// client-addr is the field logger.InjectLogger sets on the HTTP path, kept here so
// a log query filtering on it also matches a gRPC line. It is honest and it
// identifies nobody: an unnamed Unix socket client reports the autobind address
// "@", and the caller's identity comes from attestation rather than from an
// address. rpc-method is the field that actually locates a call.
//
// bind-addr is repeated here even though cmd already puts it on the server's
// context, because gRPC roots every handler context at context.Background rather
// than at the context passed to Serve, so an RPC inherits nothing from the server.
func loggerFields(ctx context.Context, fullMethod string) []interface{} {
	var clientAddr, bindAddr string
	if p, ok := peer.FromContext(ctx); ok {
		if p.Addr != nil {
			clientAddr = p.Addr.String()
		}
		if p.LocalAddr != nil {
			bindAddr = p.LocalAddr.String()
		}
	}
	return []interface{}{
		"client-addr", clientAddr,
		"bind-addr", bindAddr,
		"rpc-method", fullMethod,
	}
}

// UnaryLoggerInterceptor puts a logger on the RPC's context so downstream code
// reaches it with logger.FromContext, which is what logger.InjectLogger does for
// an HTTP handler.
func UnaryLoggerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return handler(logger.ContextWithField(ctx, loggerFields(ctx, info.FullMethod)...), req)
	}
}

// StreamLoggerInterceptor is the streaming half of UnaryLoggerInterceptor.
//
// grpc.ServerStream exposes its context read-only and gRPC offers no way to
// replace it, so the stream is wrapped rather than mutated. Without the wrapper
// this interceptor would compile and do nothing for every streaming method, which
// is most of the traffic here.
func StreamLoggerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()
		return handler(srv, withContext(ss, logger.ContextWithField(ctx, loggerFields(ctx, info.FullMethod)...)))
	}
}

// workloadAPIMethodPrefix begins the full method name of every SPIFFE Workload API
// RPC, which are the only calls the metadata gate applies to.
var workloadAPIMethodPrefix = "/" + workload.SpiffeWorkloadAPI_ServiceDesc.ServiceName + "/"

// checkSpiffeHeader rejects a Workload API call that does not carry
// SpiffeSecurityHeader set to SpiffeSecurityHeaderValue, and passes any other method.
// Only the Workload API is gated, as in SPIRE: its specification requires the header,
// and Envoy sends none, since istiod's SDS config carries no initial_metadata. It is
// not an authorization boundary; attestation is.
func checkSpiffeHeader(ctx context.Context, method string) error {
	if !strings.HasPrefix(method, workloadAPIMethodPrefix) {
		return nil
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Errorf(codes.InvalidArgument, "request carries no metadata: %s has to be set to %q",
			SpiffeSecurityHeader, SpiffeSecurityHeaderValue)
	}
	for _, value := range md.Get(SpiffeSecurityHeader) {
		if value == SpiffeSecurityHeaderValue {
			return nil
		}
	}
	return status.Errorf(codes.InvalidArgument, "request metadata %s has to be set to %q",
		SpiffeSecurityHeader, SpiffeSecurityHeaderValue)
}

// A rejection is logged at debug rather than at warn. The caller is told what is
// wrong in the status error, and anything that can reach the socket without the
// header can otherwise drive the agent's log volume from outside the trust
// boundary. Turn the level up on a node while debugging a client, not on every
// node.

// UnaryMetadataGateInterceptor applies the header requirement to a unary call.
func UnaryMetadataGateInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := checkSpiffeHeader(ctx, info.FullMethod); err != nil {
			logger.FromContext(ctx).Debugf("Rejecting call: %v", err)
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamMetadataGateInterceptor applies the same requirement to a stream.
func StreamMetadataGateInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := checkSpiffeHeader(ss.Context(), info.FullMethod); err != nil {
			logger.FromContext(ss.Context()).Debugf("Rejecting stream: %v", err)
			return err
		}
		return handler(srv, ss)
	}
}

// UnaryRateLimitInterceptor spends one token per unary call.
func UnaryRateLimitInterceptor(limiter *rate.Limiter) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !limiter.Allow() {
			return nil, rateLimitErr(ctx, info.FullMethod)
		}
		return handler(ctx, req)
	}
}

// StreamRateLimitInterceptor spends one token per stream establishment, and none
// per message.
//
// That is the whole point of having a separate limiter here. A stream on this
// socket lives for as long as the calling pod does, and every message the agent
// sends down it is a renewal the agent itself decided to send, so a per-message
// limit would throttle renewals and leave abuse untouched. What is worth rationing
// is opening a stream, because that is what allocates a subscription, an
// attestation and an issuance behind it.
func StreamRateLimitInterceptor(limiter *rate.Limiter) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !limiter.Allow() {
			return rateLimitErr(ss.Context(), info.FullMethod)
		}
		return handler(srv, ss)
	}
}

// rateLimitErr builds the rejection.
//
// ResourceExhausted rather than Unavailable, because gRPC reserves it for a quota
// being spent and a SPIFFE client retries it with backoff, where it treats
// InvalidArgument as fatal and gives up. That difference is also why the gate
// returns InvalidArgument: a client that is not going to start sending the header
// should stop asking.
//
// The rejection is logged at debug for the same reason the gate's is. Being refused
// costs the caller nothing, so a line per rejection hands whoever can open the socket
// control of the agent's log volume, on a component every pod on the node depends on.
// The signal an operator wants here is a counted one, and the RPC metrics belong to
// the handlers rather than to this file.
func rateLimitErr(ctx context.Context, fullMethod string) error {
	logger.FromContext(ctx).Debugf("Rate limiting %s", fullMethod)
	return status.Error(codes.ResourceExhausted, "too many requests")
}

// serverStreamWithContext overrides the context a stream reports and forwards
// everything else to the stream it embeds.
type serverStreamWithContext struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the replaced context.
func (s serverStreamWithContext) Context() context.Context { return s.ctx }

// withContext returns ss with ctx as its context.
func withContext(ss grpc.ServerStream, ctx context.Context) grpc.ServerStream {
	return serverStreamWithContext{ServerStream: ss, ctx: ctx}
}
