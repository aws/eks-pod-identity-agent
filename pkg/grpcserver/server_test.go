package grpcserver

import (
	"context"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// TestNew_ServesTheStubServicesOverTheSocket is the definition of done in one test:
// the server binds the socket, serves the stub services, and a client reaches them
// over the socket. cmd/workload_identity_test.go covers what cmd registers.
//
// Every method answers Unimplemented for now, which is the point: the request
// travels the whole path, through the credentials and the interceptor chain, and
// comes back with the status the registered handler produced. A method the agent does
// not serve yet is distinguishable from one it will never serve, and a Workload API
// call without the SPIFFE header is refused before it reaches a handler at all.
//
// The methods are named by string rather than through a generated client, so one pair
// of helpers drives every service with an empty message, which decodes as any request.
func TestNew_ServesTheStubServicesOverTheSocket(t *testing.T) {
	unaryMethod := "/" + workload.SpiffeWorkloadAPI_ServiceDesc.ServiceName + "/ValidateJWTSVID"
	streamMethod := "/" + workload.SpiffeWorkloadAPI_ServiceDesc.ServiceName + "/FetchX509SVID"
	sdsStreamMethod := "/" + secretv3.SecretDiscoveryService_ServiceDesc.ServiceName + "/StreamSecrets"

	g := NewWithT(t)

	path := tempSocketPath(t)
	srv, err := New(Opts{
		SocketPath:   path,
		ShutdownWait: time.Second,
		Register:     RegisterStubServices,
	})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(srv.Addr()).To(Equal(path))

	serve(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := dial(t, path)

	invoke := func(ctx context.Context, method string) codes.Code {
		return status.Code(conn.Invoke(ctx, method, &emptypb.Empty{}, new(emptypb.Empty)))
	}
	receive := func(ctx context.Context, method string) codes.Code {
		stream, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, method)
		if err != nil {
			return status.Code(err)
		}
		if err := stream.SendMsg(&emptypb.Empty{}); err != nil {
			return status.Code(err)
		}
		if err := stream.CloseSend(); err != nil {
			return status.Code(err)
		}
		return status.Code(stream.RecvMsg(new(emptypb.Empty)))
	}

	// grpc.NewClient is lazy, so the first call is also what connects
	g.Eventually(func() codes.Code { return invoke(withHeader(ctx), unaryMethod) }).
		WithContext(ctx).Should(Equal(codes.Unimplemented))
	g.Expect(receive(withHeader(ctx), streamMethod)).To(Equal(codes.Unimplemented))
	g.Expect(receive(withHeader(ctx), sdsStreamMethod)).To(Equal(codes.Unimplemented))

	// and the gate stands in front of the Workload API, but not of SDS, which Envoy
	// calls without the header
	g.Expect(invoke(ctx, unaryMethod)).To(Equal(codes.InvalidArgument))
	g.Expect(receive(ctx, streamMethod)).To(Equal(codes.InvalidArgument))
	g.Expect(receive(ctx, sdsStreamMethod)).To(Equal(codes.Unimplemented))

	// A service nothing registered is Unimplemented too, but it says so differently,
	// and that difference is what registering the real descriptors buys: a client
	// sees a method the agent knows about and has not implemented yet, rather than a
	// service the agent has never heard of.
	registered := conn.Invoke(withHeader(ctx), unaryMethod, &emptypb.Empty{}, new(emptypb.Empty))
	unknown := conn.Invoke(withHeader(ctx), "/some.Other.Service/Method", &emptypb.Empty{}, new(emptypb.Empty))
	g.Expect(status.Code(unknown)).To(Equal(codes.Unimplemented))
	g.Expect(status.Convert(unknown).Message()).To(ContainSubstring("unknown service"))
	g.Expect(status.Convert(registered).Message()).ToNot(ContainSubstring("unknown service"))
}

// TestNew_AStaleSocketIsRemovedAndTheBindSucceeds is the agent-never-restarts
// failure. A socket file outlives an agent that was killed, and net.Listen refuses
// to bind a path that already exists.
func TestNew_AStaleSocketIsRemovedAndTheBindSucceeds(t *testing.T) {
	g := NewWithT(t)

	path := tempSocketPath(t)
	stale, err := net.Listen("unix", path)
	g.Expect(err).ToNot(HaveOccurred())
	// SetUnlinkOnClose(false) is how a test reproduces a SIGKILL: the process goes
	// away without Go getting to unlink the socket it created.
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	g.Expect(stale.Close()).To(Succeed())
	g.Expect(path).To(BeAnExistingFile())

	// the failure being guarded against, asserted so the test explains itself
	_, err = net.Listen("unix", path)
	g.Expect(err).To(MatchError(ContainSubstring("address already in use")))

	srv, err := New(Opts{SocketPath: path, ShutdownWait: time.Second})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(srv.Addr()).To(Equal(path))
}

// TestNew_CreatesTheSocketDirectory covers a node where the CSI driver has not
// published the directory, and a test host where nothing has.
//
// The mode assertion is the substance of it. A directory created with MkdirAll alone
// comes out masked by the process umask, so the agent would leave a directory nothing
// can traverse under any umask stricter than the usual 0022, and this test would pass
// or fail depending on the shell that ran it. The subtest under a restrictive umask is
// what pins that.
func TestNew_CreatesTheSocketDirectory(t *testing.T) {
	assertCreated := func(t *testing.T) {
		g := NewWithT(t)

		path := filepath.Join(filepath.Dir(tempSocketPath(t)), "workloadidentity", "agent.sock")
		_, err := New(Opts{SocketPath: path, ShutdownWait: time.Second})
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(path).To(BeAnExistingFile())

		info, err := os.Stat(filepath.Dir(path))
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(info.Mode().Perm()).To(Equal(socketDirMode))
	}

	t.Run("under the ambient umask", assertCreated)

	t.Run("under a umask that would mask the mode away", func(t *testing.T) {
		// The umask is per process rather than per goroutine, so this cannot run
		// beside another test that creates a file. Nothing here runs in parallel.
		previous := syscall.Umask(0o077)
		t.Cleanup(func() { syscall.Umask(previous) })

		assertCreated(t)
	})
}

// TestNew_LeavesAPublishedSocketDirectoryAlone pins the other half of that decision.
// In production the CSI driver publishes this directory, and its mode is the driver's
// contract; the agent says so in the log rather than rewriting it.
func TestNew_LeavesAPublishedSocketDirectoryAlone(t *testing.T) {
	g := NewWithT(t)

	logs := captureLog(t)
	path := tempSocketPath(t)
	dir := filepath.Dir(path)
	g.Expect(os.Chmod(dir, 0o700)).To(Succeed())

	_, err := New(Opts{SocketPath: path, ShutdownWait: time.Second})
	g.Expect(err).ToNot(HaveOccurred())

	info, err := os.Stat(dir)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o700)), "the agent has to leave a published directory as it is")
	g.Expect(logs.String()).To(ContainSubstring("cannot reach the socket inside it"),
		"and has to say so, because the symptom otherwise surfaces only in the workload")
}

// TestNew_SetsTheSocketMode pins the decided mode. Without the chmod the mode is
// whatever the process umask leaves, which under the usual 0022 is 0755 and denies
// a workload running as another user the write bit connect(2) needs.
func TestNew_SetsTheSocketMode(t *testing.T) {
	g := NewWithT(t)

	path := tempSocketPath(t)
	_, err := New(Opts{SocketPath: path, ShutdownWait: time.Second})
	g.Expect(err).ToNot(HaveOccurred())

	info, err := os.Lstat(path)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(info.Mode().Type()).To(Equal(fs.ModeSocket))
	g.Expect(info.Mode().Perm()).To(Equal(SocketMode))
}

// TestNew_ANonSocketAtTheSocketPathIsRefused is one of the two cases an
// unconditional remove gets wrong. Whatever is at the path is a mount that went
// wrong or a collision, and deleting it hides the fault behind a working bind.
func TestNew_ANonSocketAtTheSocketPathIsRefused(t *testing.T) {
	g := NewWithT(t)

	path := tempSocketPath(t)
	g.Expect(os.WriteFile(path, []byte("not a socket"), 0o600)).To(Succeed())

	_, err := New(Opts{SocketPath: path, ShutdownWait: time.Second})
	g.Expect(err).To(MatchError(ContainSubstring("is not a socket")))
	g.Expect(path).To(BeAnExistingFile())
}

// TestNew_ALiveSocketAtTheSocketPathIsRefused is the other case. Taking a healthy
// agent's socket leaves it accepting on an inode nothing can dial, which is worse
// than refusing to start.
func TestNew_ALiveSocketAtTheSocketPathIsRefused(t *testing.T) {
	g := NewWithT(t)

	path := tempSocketPath(t)
	incumbent, err := net.Listen("unix", path)
	g.Expect(err).ToNot(HaveOccurred())
	defer func() { _ = incumbent.Close() }()
	go acceptAndClose(incumbent)

	_, err = New(Opts{SocketPath: path, ShutdownWait: time.Second})
	g.Expect(err).To(MatchError(ContainSubstring("a process is listening on it")))
	g.Expect(path).To(BeAnExistingFile())
}

// TestNew_ASocketThatNeitherAnswersNorRefusesIsRefused is the case the liveness probe
// gets wrong if it reads any dial error as "nothing is there". A live listener whose
// backlog has filled makes connect block, so a connect that neither completes nor is
// refused says nothing about whether anyone is listening, and removing the socket on
// the strength of it takes the socket away from exactly the agent this guard protects.
func TestNew_ASocketThatNeitherAnswersNorRefusesIsRefused(t *testing.T) {
	g := NewWithT(t)

	path := tempSocketPath(t)
	stale, err := net.Listen("unix", path)
	g.Expect(err).ToNot(HaveOccurred())
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	g.Expect(stale.Close()).To(Succeed())

	previous := dialSocket
	t.Cleanup(func() { dialSocket = previous })
	dialSocket = func(string, time.Duration) (net.Conn, error) {
		return nil, os.ErrDeadlineExceeded
	}

	_, err = New(Opts{SocketPath: path, ShutdownWait: time.Second})
	g.Expect(err).To(MatchError(ContainSubstring("cannot tell whether a process is listening")))
	g.Expect(path).To(BeAnExistingFile(), "an unanswered probe must not cost a socket its file")
}

// TestNew_AnEmptySocketPathIsRefused stops a misconfiguration from binding
// something surprising in the working directory.
func TestNew_AnEmptySocketPathIsRefused(t *testing.T) {
	g := NewWithT(t)

	_, err := New(Opts{ShutdownWait: time.Second})
	g.Expect(err).To(MatchError(ContainSubstring("no socket path")))
}

// TestListenUntilContextCancelled_StopsWithinTheBudgetWithAStreamOpen is the
// shutdown case that does not exist on the HTTP path. GracefulStop waits for every
// in-flight RPC, and a stream here is held for the life of the calling pod, so an
// unbounded drain would wait for the kubelet's SIGKILL instead of finishing.
func TestListenUntilContextCancelled_StopsWithinTheBudgetWithAStreamOpen(t *testing.T) {
	g := NewWithT(t)

	const budget = 300 * time.Millisecond
	// The handler holds the stream until its context is cancelled, which is what a
	// real push stream does between renewals.
	stub := &stubService{stream: func(ss grpc.ServerStream) error {
		<-ss.Context().Done()
		return ss.Context().Err()
	}}
	path := tempSocketPath(t)
	srv := newStubServer(t, stub, Opts{SocketPath: path, ShutdownWait: budget})
	stopped, shutdown := serve(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := dial(t, path)
	g.Eventually(func() error { return callUnary(withHeader(ctx), conn) }).WithContext(ctx).Should(Succeed())

	_, err := openStream(withHeader(ctx), conn)
	g.Expect(err).ToNot(HaveOccurred())

	start := time.Now()
	shutdown()

	g.Eventually(stopped, 10*time.Second).Should(BeClosed())
	g.Expect(time.Since(start)).To(BeNumerically("<", 5*time.Second),
		"shutdown has to be bounded by the budget, not by the client letting go of the stream")
	g.Expect(time.Since(start)).To(BeNumerically(">=", budget),
		"a held stream has to be given the budget before it is cancelled")
	g.Expect(path).ToNot(BeAnExistingFile(), "the socket file has to be gone once shutdown returns")
}

// TestListenUntilContextCancelled_StopsWhenAHandlerIgnoresCancellation is the
// shutdown ordering that no amount of escalation can rescue, and that shutdown
// therefore has to survive rather than wait out.
//
// gRPC holds one lock across both GracefulStop and Stop while it waits for handler
// goroutines to return, and its accept loop does not return until whichever call got
// there first has finished. So a handler that is wedged for a reason its client
// disconnecting cannot fix parks all three. If shutdown waited for the accept loop,
// that one handler would hold the socket file on disk and hold every other server in
// the agent behind the shared WaitGroup, until the kubelet's SIGKILL.
func TestListenUntilContextCancelled_StopsWhenAHandlerIgnoresCancellation(t *testing.T) {
	g := NewWithT(t)

	const budget = 300 * time.Millisecond
	// A handler that watches nothing, which is what a blocking call to another
	// service without a context looks like from here. Released at the end of the test
	// so the goroutine does not outlive it.
	wedged := make(chan struct{})
	t.Cleanup(func() { close(wedged) })
	entered := make(chan struct{})
	stub := &stubService{stream: func(grpc.ServerStream) error {
		close(entered)
		<-wedged
		return nil
	}}

	path := tempSocketPath(t)
	srv := newStubServer(t, stub, Opts{SocketPath: path, ShutdownWait: budget})
	stopped, shutdown := serve(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := dial(t, path)
	g.Eventually(func() error {
		_, err := openStream(withHeader(ctx), conn)
		return err
	}).WithContext(ctx).Should(Succeed())
	g.Eventually(entered, 10*time.Second).Should(BeClosed())

	// The client goes away before the shutdown starts, which is what leaves the
	// handler wedged with no transport left to close: gRPC gets past draining and
	// into the wait for handlers, holding the lock the escalation needs.
	g.Expect(conn.Close()).To(Succeed())

	start := time.Now()
	shutdown()

	g.Eventually(stopped, 30*time.Second).Should(BeClosed(),
		"shutdown has to give up on a wedged handler rather than wait for it")
	g.Expect(time.Since(start)).To(BeNumerically("<", budget+forcedStopWait+5*time.Second))
	g.Expect(path).ToNot(BeAnExistingFile(), "the socket file has to be gone even then")
}

// TestListenUntilContextCancelled_AnIdleServerStopsWithoutSpendingTheBudget proves
// the bound is a ceiling and not a sleep, which is what keeps a rolling restart
// quick.
func TestListenUntilContextCancelled_AnIdleServerStopsWithoutSpendingTheBudget(t *testing.T) {
	g := NewWithT(t)

	path := tempSocketPath(t)
	srv := newStubServer(t, &stubService{}, Opts{SocketPath: path, ShutdownWait: 30 * time.Second})
	stopped, shutdown := serve(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := dial(t, path)
	g.Eventually(func() error { return callUnary(withHeader(ctx), conn) }).WithContext(ctx).Should(Succeed())

	start := time.Now()
	shutdown()

	g.Eventually(stopped, 10*time.Second).Should(BeClosed())
	g.Expect(time.Since(start)).To(BeNumerically("<", 10*time.Second))
	g.Expect(path).ToNot(BeAnExistingFile())
}

// TestNew_TheDefaultShutdownBudgetFitsTheTerminationGracePeriod pins the number the
// agent actually ships with against the constraint that makes it correct. The drain on
// this socket cannot complete once streams are held open, so the budget is always spent
// in full, and everything after it — cancelling the RPCs, cleaning up the socket, the
// agent's own exit — has to happen before the kubelet's SIGKILL.
func TestNew_TheDefaultShutdownBudgetFitsTheTerminationGracePeriod(t *testing.T) {
	g := NewWithT(t)

	// charts/eks-pod-identity-agent/templates/daemonset.yaml sets this.
	const terminationGracePeriod = 30 * time.Second

	g.Expect(DefaultShutdownWait + forcedStopWait).To(BeNumerically("<", terminationGracePeriod))

	// cmd leaves Opts.ShutdownWait unset, so the zero value has to mean the default
	// rather than no drain at all.
	srv, err := New(Opts{SocketPath: tempSocketPath(t)})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(srv.shutdownWait).To(Equal(DefaultShutdownWait))
}

// fatalSocketEnvVar carries the socket path to the child process in
// TestRemoveSocket_RunsWhenTheProcessDiesFatally.
const fatalSocketEnvVar = "GRPCSERVER_TEST_FATAL_SOCKET"

// TestRemoveSocket_RunsWhenTheProcessDiesFatally is the crash path, and it needs a
// second process because the crash it reproduces ends one.
//
// Every server in the agent reports a failure it cannot serve through with
// log.Fatalf, and logrus turns that into os.Exit, which runs no deferred function
// anywhere in the process. So a crash in one of the HTTP servers would leave this
// socket on disk, and the next boot would meet a file it has to reason about. logrus
// runs its exit handlers before exiting, which is what the wiring site hooks
// RemoveSocket onto; this asserts the hook does what it claims.
func TestRemoveSocket_RunsWhenTheProcessDiesFatally(t *testing.T) {
	if socketPath := os.Getenv(fatalSocketEnvVar); socketPath != "" {
		// The child. It binds the socket, registers the cleanup the way cmd does, and
		// then dies the way a server that cannot listen dies.
		srv, err := New(Opts{SocketPath: socketPath})
		if err != nil {
			t.Fatalf("child could not bind %s: %v", socketPath, err)
		}
		logrus.RegisterExitHandler(srv.RemoveSocket)
		logger.FromContext(context.Background()).Fatalf("simulating a server that cannot listen")
		return
	}

	g := NewWithT(t)

	path := tempSocketPath(t)
	child := exec.Command(os.Args[0], "-test.run=^TestRemoveSocket_RunsWhenTheProcessDiesFatally$")
	child.Env = append(os.Environ(), fatalSocketEnvVar+"="+path)
	output, err := child.CombinedOutput()

	g.Expect(err).To(HaveOccurred(), "the child has to exit non-zero, as a fatal log does")
	g.Expect(string(output)).To(ContainSubstring("simulating a server that cannot listen"))
	g.Expect(path).ToNot(BeAnExistingFile(),
		"a fatal exit has to take the socket with it, since no deferred call runs")
}

// TestRemoveSocket_LeavesASuccessorsSocketAlone is the shutdown mirror of the
// startup guard. By the time the explicit removal runs the agent no longer owns the
// path, and on a restart a replacement may already have bound it.
func TestRemoveSocket_LeavesASuccessorsSocketAlone(t *testing.T) {
	g := NewWithT(t)

	path := tempSocketPath(t)
	srv := newStubServer(t, &stubService{}, Opts{SocketPath: path})

	// stand in for the successor: something else bound and accepting on the path
	g.Expect(srv.lis.Close()).To(Succeed())
	successor, err := net.Listen("unix", path)
	g.Expect(err).ToNot(HaveOccurred())
	defer func() { _ = successor.Close() }()
	go acceptAndClose(successor)

	srv.RemoveSocket()

	g.Expect(path).To(BeAnExistingFile(), "the successor's socket has to survive")
}

// TestServerOptions_CannotReplaceThePinningCredentials pins the one exception to
// ServerOptions winning: a grpc.Creds entry there can't replace the credentials
// that pin each caller, or every RPC would arrive with no Peer.
func TestServerOptions_CannotReplaceThePinningCredentials(t *testing.T) {
	g := NewWithT(t)
	stub := &stubService{unary: func(ctx context.Context) error {
		if _, ok := PeerFromContext(ctx); !ok {
			return status.Error(codes.Internal, "no peer")
		}
		return nil
	}}
	path := tempSocketPath(t)
	serve(t, newStubServer(t, stub, Opts{
		SocketPath:    path,
		ServerOptions: []grpc.ServerOption{grpc.Creds(insecure.NewCredentials())},
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := dial(t, path)
	g.Eventually(func() error { return callUnary(withHeader(ctx), conn) }).WithContext(ctx).Should(Succeed())
}

// TestServerOptions_TheCallerCanOverrideAnOption pins that Opts.ServerOptions wins,
// which is what lets a test drive a timeout the production values put minutes away.
func TestServerOptions_TheCallerCanOverrideAnOption(t *testing.T) {
	g := NewWithT(t)

	// A silent caller holds a connection open without ever sending metadata, which
	// is what grpc.ConnectionTimeout bounds: it deadlines the connection up to the
	// end of the HTTP/2 handshake and clears the deadline once it completes, so it
	// costs an established stream nothing.
	const handshakeBudget = 300 * time.Millisecond
	path := tempSocketPath(t)
	srv := newStubServer(t, &stubService{}, Opts{
		SocketPath:    path,
		ServerOptions: []grpc.ServerOption{grpc.ConnectionTimeout(handshakeBudget)},
	})
	serve(t, srv)

	conn, err := net.Dial("unix", path)
	g.Expect(err).ToNot(HaveOccurred())
	defer func() { _ = conn.Close() }()

	// gRPC writes its settings frame on accept, so read until the server gives up
	// and closes rather than expecting silence.
	g.Expect(conn.SetReadDeadline(time.Now().Add(10 * time.Second))).To(Succeed())
	start := time.Now()
	buf := make([]byte, 512)
	for {
		if _, err := conn.Read(buf); err != nil {
			break
		}
	}
	g.Expect(time.Since(start)).To(BeNumerically(">=", handshakeBudget))
	g.Expect(time.Since(start)).To(BeNumerically("<", 5*time.Second),
		"a connection that never completes the handshake has to be dropped")
}

// TestKeepalive_AnOpenStreamSurvivesTheIdleTimeout is the risk in setting
// MaxConnectionIdle at all: if the idle clock ran while a stream was open, every
// push stream would be torn down on a timer and every pod on the node would
// reconnect on the same one.
func TestKeepalive_AnOpenStreamSurvivesTheIdleTimeout(t *testing.T) {
	g := NewWithT(t)

	const idle = 300 * time.Millisecond
	release := make(chan struct{})
	stub := &stubService{stream: func(ss grpc.ServerStream) error {
		select {
		case <-release:
			return nil
		case <-ss.Context().Done():
			return ss.Context().Err()
		}
	}}
	path := tempSocketPath(t)
	srv := newStubServer(t, stub, Opts{
		SocketPath: path,
		ServerOptions: []grpc.ServerOption{grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: idle,
		})},
	})
	serve(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn := dial(t, path)
	var stream grpc.ClientStream
	g.Eventually(func() error {
		var err error
		stream, err = openStream(withHeader(ctx), conn)
		return err
	}).WithContext(ctx).Should(Succeed())

	// well past the idle timeout, which gRPC holds at zero while a stream is open
	time.Sleep(4 * idle)
	close(release)

	g.Expect(stream.RecvMsg(new(emptypb.Empty))).To(MatchError(io.EOF),
		"an open stream has to outlive MaxConnectionIdle")
}

// acceptAndClose stands in for a live process on a socket: it answers a connect and
// hangs up, which is all the stale-socket probe looks for.
func acceptAndClose(lis net.Listener) {
	for {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}
}
