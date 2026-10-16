package grpcserver

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test" // initializes the package logger
)

// This file holds what the tests in this package share: a stub service with one
// unary and one streaming method, and the helpers that bind, dial and observe one.
//
// The stub is a hand-written grpc.ServiceDesc over emptypb.Empty rather than
// generated code, so the interceptor and lifecycle tests do not wait on the real
// handlers or on a protoc step. Everything the definition of done asks for needs
// both method shapes, because the middleware here is two implementations of the
// same rule and a test of one proves nothing about the other.

// The stub takes the Workload API's service name because the metadata gate applies to
// that service only, and the interceptor tests need a method behind it.
var (
	stubServiceName  = workload.SpiffeWorkloadAPI_ServiceDesc.ServiceName
	stubUnaryMethod  = "/" + stubServiceName + "/Unary"
	stubStreamMethod = "/" + stubServiceName + "/Stream"
)

// stubService implements the stub. Both handlers default to succeeding; a test
// replaces either to observe its own context.
type stubService struct {
	// unary runs inside the unary method, after the interceptor chain.
	unary func(ctx context.Context) error
	// stream runs inside the streaming method, after the interceptor chain, with
	// one message already sent so a client can tell the stream is established.
	stream func(ss grpc.ServerStream) error
}

// serviceDesc returns the descriptor to register.
//
// The unary handler invokes the interceptor itself, which is not optional: gRPC
// calls stream interceptors on a streaming method, but for a unary method it passes
// the chained interceptor into the method handler and leaves calling it to the
// generated code. A hand-written handler that ignores the argument runs no unary
// interceptor at all, and every unary test then passes for the wrong reason.
func (s *stubService) serviceDesc() *grpc.ServiceDesc {
	return &grpc.ServiceDesc{
		ServiceName: stubServiceName,
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{{
			MethodName: "Unary",
			Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
				in := new(emptypb.Empty)
				if err := dec(in); err != nil {
					return nil, err
				}
				handler := func(ctx context.Context, _ any) (any, error) {
					if s.unary != nil {
						if err := s.unary(ctx); err != nil {
							return nil, err
						}
					}
					return &emptypb.Empty{}, nil
				}
				if interceptor == nil {
					return handler(ctx, in)
				}
				return interceptor(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: stubUnaryMethod}, handler)
			},
		}},
		Streams: []grpc.StreamDesc{{
			StreamName: "Stream",
			Handler: func(_ any, ss grpc.ServerStream) error {
				if err := ss.RecvMsg(new(emptypb.Empty)); err != nil {
					return err
				}
				if err := ss.SendMsg(&emptypb.Empty{}); err != nil {
					return err
				}
				if s.stream != nil {
					return s.stream(ss)
				}
				return nil
			},
			ServerStreams: true,
		}},
		Metadata: "stub",
	}
}

// register returns the Opts.Register function that attaches the stub.
func (s *stubService) register() func(grpc.ServiceRegistrar) {
	return func(registrar grpc.ServiceRegistrar) {
		registrar.RegisterService(s.serviceDesc(), new(any))
	}
}

// tempSocketPath returns a socket path under a short temporary directory.
//
// t.TempDir is not used for this: it embeds the test and subtest names in the path,
// and a Unix socket path is limited to 107 bytes, so a descriptive test name is
// enough to turn a bind into "invalid argument".
func tempSocketPath(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "pia")
	if err != nil {
		t.Fatalf("unable to create temporary directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "agent.sock")
}

// newStubServer binds a server carrying the stub service and whatever else opts
// asks for. It fills in the socket path and the shutdown budget when they are
// unset, so a test states only what it is about.
func newStubServer(t *testing.T, stub *stubService, opts Opts) *Server {
	t.Helper()
	g := NewWithT(t)

	if opts.SocketPath == "" {
		opts.SocketPath = tempSocketPath(t)
	}
	if opts.ShutdownWait == 0 {
		opts.ShutdownWait = time.Second
	}
	if opts.Register == nil {
		opts.Register = stub.register()
	}

	srv, err := New(opts)
	g.Expect(err).ToNot(HaveOccurred())
	return srv
}

// serve drives srv in the background and returns a channel closed once it has
// finished shutting down, plus the cancel that starts the shutdown.
func serve(t *testing.T, srv *Server) (stopped chan struct{}, shutdown func()) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	stopped = make(chan struct{})
	go func() {
		defer close(stopped)
		srv.ListenUntilContextCancelled(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-stopped
	})
	return stopped, cancel
}

// dial returns a client connection to the socket at path. grpc.NewClient is lazy
// and reports nothing about a bad target, so the first call is what proves the
// socket is reachable, which is why every caller here follows it with an RPC.
//
// The target has to be "unix://" plus an absolute path. A relative path after the
// scheme is read as an authority and rejected at the first RPC instead of here.
func dial(t *testing.T, path string) *grpc.ClientConn {
	t.Helper()
	g := NewWithT(t)

	conn, err := grpc.NewClient("unix://"+path, grpc.WithTransportCredentials(insecure.NewCredentials()))
	g.Expect(err).ToNot(HaveOccurred())
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// withHeader returns ctx carrying the SPIFFE metadata the gate requires, which is
// what a conformant SPIFFE client sends on every call.
func withHeader(ctx context.Context) context.Context {
	return metadata.NewOutgoingContext(ctx, metadata.Pairs(SpiffeSecurityHeader, SpiffeSecurityHeaderValue))
}

// callUnary invokes the stub's unary method.
func callUnary(ctx context.Context, conn *grpc.ClientConn) error {
	return conn.Invoke(ctx, stubUnaryMethod, &emptypb.Empty{}, new(emptypb.Empty))
}

// openStream opens the stub's streaming method and waits for the one message the
// handler sends, so a caller that gets no error is holding an established stream.
func openStream(ctx context.Context, conn *grpc.ClientConn) (grpc.ClientStream, error) {
	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{StreamName: "Stream", ServerStreams: true}, stubStreamMethod)
	if err != nil {
		return nil, err
	}
	if err := stream.SendMsg(&emptypb.Empty{}); err != nil {
		return nil, err
	}
	if err := stream.CloseSend(); err != nil {
		return nil, err
	}
	if err := stream.RecvMsg(new(emptypb.Empty)); err != nil {
		return nil, err
	}
	return stream, nil
}

// syncBuffer is a bytes.Buffer safe to read while logrus writes to it from a
// server goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLog redirects the logger package's output into a buffer for the length of
// the test.
//
// The package-level logger is unexported, but FromContext hands back an entry whose
// Logger field is that global, which is enough to redirect it from here. It is
// already initialized, by the blank import of internal/test.
func captureLog(t *testing.T) *syncBuffer {
	t.Helper()

	buf := &syncBuffer{}
	global := logger.FromContext(context.Background()).Logger
	previous := global.Out
	global.SetOutput(buf)
	t.Cleanup(func() { global.SetOutput(previous) })
	return buf
}
