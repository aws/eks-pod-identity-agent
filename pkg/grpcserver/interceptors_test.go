package grpcserver

import (
	"context"
	"testing"
	"time"

	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	. "github.com/onsi/gomega"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// TestInterceptors drives the server this package builds, rather than one assembled
// out of the same interceptors, so the order and the wiring are covered along with
// the rules. Every case runs against a unary and a streaming method, because the
// middleware is two implementations of one rule.
func TestInterceptors(t *testing.T) {
	testCases := []struct {
		name string
		// metadata the client sends, nil for a client that sends none at all
		metadata metadata.MD
		// limiter replaces the one built from configuration
		limiter *rate.Limiter
		// expected is the status code the call has to end with
		expected codes.Code
	}{
		{
			name:     "a call carrying the header is served",
			metadata: metadata.Pairs(SpiffeSecurityHeader, SpiffeSecurityHeaderValue),
			expected: codes.OK,
		},
		{
			name: "a call carrying no metadata at all is rejected",
			// this is the browser or the stray HTTP/2 client the gate exists for
			expected: codes.InvalidArgument,
		},
		{
			name:     "a call carrying other metadata but not the header is rejected",
			metadata: metadata.Pairs("some-header", "some-value"),
			expected: codes.InvalidArgument,
		},
		{
			name:     "a call carrying the header with another value is rejected",
			metadata: metadata.Pairs(SpiffeSecurityHeader, "false"),
			expected: codes.InvalidArgument,
		},
		{
			name: "a client that capitalises the header still matches",
			// metadata.Pairs lower cases the key on the way out and HTTP/2 lower
			// cases header names on the wire, so what reaches the gate is already
			// normalised. The case is here because a client that writes the header
			// the way the SPIFFE specification prints it has to work, and this is
			// what proves the path does not care.
			metadata: metadata.Pairs("Workload.SPIFFE.IO", SpiffeSecurityHeaderValue),
			expected: codes.OK,
		},
		{
			name:     "a call over the admission budget is rejected",
			metadata: metadata.Pairs(SpiffeSecurityHeader, SpiffeSecurityHeaderValue),
			limiter:  rate.NewLimiter(0, 0),
			expected: codes.ResourceExhausted,
		},
	}

	for _, tc := range testCases {
		for _, streaming := range []bool{false, true} {
			kind := "unary"
			if streaming {
				kind = "stream"
			}
			t.Run(tc.name+", "+kind, func(t *testing.T) {
				g := NewWithT(t)

				path := tempSocketPath(t)
				srv := newStubServer(t, &stubService{}, Opts{
					SocketPath:     path,
					RequestLimiter: tc.limiter,
				})
				serve(t, srv)

				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				conn := dial(t, path)
				if tc.metadata != nil {
					ctx = metadata.NewOutgoingContext(ctx, tc.metadata)
				}

				// grpc.NewClient is lazy, so the first call is also what connects.
				// An unreachable socket and a rejected call are both reported here,
				// which is why the poll waits for a code rather than for success.
				g.Eventually(func() codes.Code {
					if streaming {
						_, err := openStream(ctx, conn)
						return status.Code(err)
					}
					return status.Code(callUnary(ctx, conn))
				}).WithContext(ctx).Should(Equal(tc.expected))
			})
		}
	}
}

// TestLoggerInterceptor_PutsALoggerOnTheContext is the definition-of-done item for
// logging, asserted on a field the interceptor sets rather than on FromContext
// returning something: FromContext falls back to the package logger when the
// context carries nothing, so a broken interceptor would pass that check.
func TestLoggerInterceptor_PutsALoggerOnTheContext(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		kind := "unary"
		if streaming {
			kind = "stream"
		}
		t.Run(kind, func(t *testing.T) {
			g := NewWithT(t)

			logs := captureLog(t)
			logFromHandler := func(ctx context.Context) error {
				logger.FromContext(ctx).Info("handled by the stub")
				return nil
			}
			stub := &stubService{
				unary:  logFromHandler,
				stream: func(ss grpc.ServerStream) error { return logFromHandler(ss.Context()) },
			}

			path := tempSocketPath(t)
			srv := newStubServer(t, stub, Opts{SocketPath: path})
			serve(t, srv)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn := dial(t, path)
			method := stubUnaryMethod
			g.Eventually(func() error {
				if streaming {
					method = stubStreamMethod
					_, err := openStream(withHeader(ctx), conn)
					return err
				}
				return callUnary(withHeader(ctx), conn)
			}).WithContext(ctx).Should(Succeed())

			// the fields the HTTP middleware sets, so one log query matches both
			// server types, plus the one that actually locates a call on this socket
			g.Eventually(logs.String, 10*time.Second).Should(SatisfyAll(
				ContainSubstring(`"msg":"handled by the stub"`),
				ContainSubstring(`"client-addr":"@"`),
				ContainSubstring(`"bind-addr":"`+path+`"`),
				ContainSubstring(`"rpc-method":"`+method+`"`),
			))
		})
	}
}

// TestInterceptorOrder_IsLoggerThenGateThenLimiter pins the order the HTTP chain
// uses, for the same reason it matters there: everything after the logger logs with
// the call's fields, and a call the gate refuses is never charged to the admission
// budget.
func TestInterceptorOrder_IsLoggerThenGateThenLimiter(t *testing.T) {
	g := NewWithT(t)

	path := tempSocketPath(t)
	// one token, so the first call that reaches the limiter spends it
	limiter := rate.NewLimiter(rate.Limit(0.001), 1)
	srv := newStubServer(t, &stubService{}, Opts{SocketPath: path, RequestLimiter: limiter})
	serve(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := dial(t, path)

	// a gated call must not spend a token, however many times it is made
	for i := 0; i < 3; i++ {
		g.Eventually(func() codes.Code { return status.Code(callUnary(ctx, conn)) }).
			WithContext(ctx).Should(Equal(codes.InvalidArgument))
	}
	g.Expect(limiter.Tokens()).To(BeNumerically("~", 1, 0.1),
		"the gate runs before the limiter, so a rejected call cannot consume the budget")

	// the first call past the gate spends the token, and the next is refused
	g.Expect(callUnary(withHeader(ctx), conn)).To(Succeed())
	g.Expect(status.Code(callUnary(withHeader(ctx), conn))).To(Equal(codes.ResourceExhausted))
}

// TestRateLimit_ChargesAStreamOnceAtEstablishment is the decision the spec asks to
// be stated in code: a stream is charged when it is opened and never per message,
// because every message the agent sends down one of these streams is a renewal it
// decided to send, so a per-message limit would throttle renewals rather than abuse.
func TestRateLimit_ChargesAStreamOnceAtEstablishment(t *testing.T) {
	g := NewWithT(t)

	sent := make(chan struct{})
	stub := &stubService{stream: func(ss grpc.ServerStream) error {
		// several more messages on the established stream, as a renewal would be
		for i := 0; i < 5; i++ {
			if err := ss.SendMsg(&emptypb.Empty{}); err != nil {
				return err
			}
		}
		close(sent)
		return nil
	}}

	path := tempSocketPath(t)
	// one token: enough for exactly one stream establishment and nothing else
	limiter := rate.NewLimiter(rate.Limit(0.001), 1)
	srv := newStubServer(t, stub, Opts{SocketPath: path, RequestLimiter: limiter})
	serve(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := dial(t, path)

	var stream grpc.ClientStream
	g.Eventually(func() error {
		var err error
		stream, err = openStream(withHeader(ctx), conn)
		return err
	}).WithContext(ctx).Should(Succeed())

	g.Eventually(sent, 10*time.Second).Should(BeClosed())
	for i := 0; i < 5; i++ {
		g.Expect(stream.RecvMsg(new(emptypb.Empty))).To(Succeed())
	}
	g.Expect(limiter.Tokens()).To(BeNumerically("<", 1),
		"the establishment spent the only token")

	// and a second stream is refused, which is what the budget is for
	_, err := openStream(withHeader(ctx), conn)
	g.Expect(status.Code(err)).To(Equal(codes.ResourceExhausted))
}

// TestMetadataGate_AppliesToEveryService pins that there is no exemption: whatever is
// registered on this socket needs the header, including the Envoy SDS service, whose
// sidecar is given it as a static GrpcService.initial_metadata entry rather than as an
// exception here.
func TestMetadataGate_AppliesToEveryService(t *testing.T) {
	g := NewWithT(t)

	for _, method := range []string{
		"/" + workload.SpiffeWorkloadAPI_ServiceDesc.ServiceName + "/FetchX509SVID",
		"/" + secretv3.SecretDiscoveryService_ServiceDesc.ServiceName + "/StreamSecrets",
		"/grpc.health.v1.Health/Check",
		stubUnaryMethod,
	} {
		err := checkSpiffeHeader(context.Background())
		g.Expect(status.Code(err)).To(Equal(codes.InvalidArgument), "%s has to need the header", method)
	}

	withHeaderCtx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(SpiffeSecurityHeader, SpiffeSecurityHeaderValue))
	g.Expect(checkSpiffeHeader(withHeaderCtx)).To(Succeed())
}
