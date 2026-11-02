// Package grpcserver serves the workload identity APIs over a Unix domain socket.
//
// It is the gRPC counterpart of pkg/server, which is HTTP throughout: that
// package's registration type hands back an http.HandlerFunc and its middleware is
// http.HandlerFunc shaped, so none of it ports. The two server types have exactly
// one thing in common, which is their lifecycle: both listen until a context is
// cancelled and both can name what they are bound to. That is the interface cmd
// drives them through.
//
// Two things here have no counterpart on the HTTP path and are the substance of
// the package. Socket housekeeping, because a socket file outlives the process that
// bound it. And a bounded graceful stop, because the streams this server hosts are
// open for the life of the calling pod by design, so an unbounded drain waits for
// the kubelet's SIGKILL rather than for the clients.
package grpcserver

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	ratelimiter "go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/rate_limiter"
)

const (
	// SocketMode is the mode the socket is left with after the bind.
	//
	// An enrolled workload runs as whatever UID its pod spec asks for and the
	// socket is owned by the agent, so the other bits are the only ones that can
	// grant it access. connect(2) on a Unix socket needs the write bit on the
	// socket inode and the search bit on every directory above it; the execute bit
	// on the socket itself grants nothing, which is why this is 0666 rather than
	// the 0777 SPIRE uses.
	//
	// It is set explicitly because the bind applies the process umask, so leaving
	// it alone means the mode is whatever the image happens to be built with:
	// 0755 under the usual 0022, which no workload running as another user can
	// connect to.
	//
	// The mode is the first gate and not the gate. What protects the socket is
	// attestation: every RPC resolves its caller through
	// workloadidentity.Attestor, and a caller that cannot be resolved to a pod on
	// this node gets nothing.
	SocketMode os.FileMode = 0o666

	// socketDirMode is the mode of the socket's parent directory when the agent
	// has to create it. 0755 gives the search bit reaching the socket needs, and
	// withholds the write bit deliberately: a workload-writable directory would
	// let a compromised workload unlink the agent's socket and bind its own,
	// which turns a denial of service into an impersonation of the agent.
	socketDirMode os.FileMode = 0o755

	// socketDirTraversalBits are the bits a caller outside the agent's own user and
	// group needs on the socket's parent directory to reach the socket at all.
	// Without them connect(2) fails with EACCES however the socket itself is
	// chmodded, which is why a directory the agent did not create is worth a look.
	socketDirTraversalBits os.FileMode = 0o001

	// DefaultShutdownWait is the graceful drain budget when Opts.ShutdownWait is
	// unset.
	//
	// It is deliberately not the HTTP servers' termination budget, which the task
	// asked for and which is 35 seconds. Two reasons, and the second is the one that
	// settles it.
	//
	// The drain here provably cannot complete. GracefulStop waits for every in-flight
	// RPC, and the streams on this socket are held open for the life of the calling
	// pod: a GOAWAY does not end an open stream, so once the real handlers land every
	// SIGTERM spends the whole budget and then escalates. The HTTP servers get away
	// with a long budget because their requests finish in milliseconds; this one does
	// not.
	//
	// And the budget has to fit inside the DaemonSet's terminationGracePeriodSeconds,
	// which is 30 seconds in the chart. Together with forcedStopWait, 35 would put
	// the escalation, the socket cleanup and the agent's own exit after the kubelet's
	// SIGKILL, so none of it would ever run on a node.
	//
	// What a drain actually buys on this socket is letting an in-flight unary call
	// finish, which takes milliseconds. Five seconds is generous for that and leaves
	// the rest of the grace period to the other servers. SPIRE's agent does not drain
	// this socket at all, and its server bounds the same pattern at ten seconds.
	DefaultShutdownWait = 5 * time.Second

	// forcedStopWait is how long shutdown waits for the accept loop to unwind after
	// in-flight RPCs have been cancelled. It is short because there is nothing left to
	// wait for by then: the listener is closed, the socket is unlinked, and the only
	// thing that can still hold it up is a handler goroutine no cancellation reaches,
	// which the process is about to exit out of anyway. It is deliberately not another
	// ShutdownWait, since the sum of the two has to stay inside the DaemonSet's
	// termination grace period.
	forcedStopWait = 2 * time.Second

	// staleSocketProbeTimeout bounds the connect that tells a stale socket from one a
	// live process is still accepting on. A local connect normally either completes or
	// is refused at once; this bounds the case where it does neither, which is a live
	// listener with a full backlog and is treated as "cannot tell" rather than as
	// stale.
	staleSocketProbeTimeout = 250 * time.Millisecond

	// handshakeTimeout bounds a connection from accept up to and including the
	// HTTP/2 handshake, which is the answer to a caller that connects to the
	// socket and then sends nothing at all. gRPC applies it as a deadline on the
	// raw conn and clears that deadline the instant the handshake completes, so it
	// bounds nothing afterwards and costs a long-lived stream nothing. A handshake
	// over a Unix socket is sub-millisecond.
	handshakeTimeout = 10 * time.Second

	// maxConnectionIdle bounds a connection that finished the handshake and has no
	// active RPC, which is the same caller one step further in. gRPC holds the
	// idle clock at zero while any stream is open and starts it from establishment
	// for a connection that never opened one, so this covers both the caller that
	// handshakes and stops and the one that finishes its last stream and lingers,
	// while a push stream is never affected however long it runs.
	maxConnectionIdle = 5 * time.Minute
)

// Server serves gRPC on a Unix domain socket for the life of a context.
type Server struct {
	// grpc holds the registered services and owns the shutdown.
	grpc *grpc.Server
	// lis is bound by New, before anything serves, so a socket that cannot be
	// bound is a boot failure rather than a goroutine's problem.
	lis net.Listener
	// socketPath is the path lis is bound to, kept separately so shutdown can
	// clean up after the listener has been closed.
	socketPath string
	// shutdownWait bounds the graceful stop. It is injected rather than read from
	// a package constant so a test can use a budget it is willing to wait out.
	shutdownWait time.Duration
	// pinMethod is how callers are pinned, logged at start.
	pinMethod pinMethod
}

// Opts configures the server. The socket path and the shutdown budget come from
// the wiring site, the way an HTTP server there is given its addr.
type Opts struct {
	// SocketPath is the Unix socket to bind, as a bare filesystem path. It is
	// configuration.WorkloadIdentitySocketPath in production.
	SocketPath string
	// ShutdownWait bounds the graceful stop. Zero or less means
	// DefaultShutdownWait, which is what production uses; a test passes a budget it
	// is willing to wait out. Whatever it is, it plus forcedStopWait has to stay
	// inside the terminationGracePeriodSeconds the DaemonSet asks for, because the
	// kubelet sends SIGKILL at the end of that and anything still draining is lost.
	ShutdownWait time.Duration
	// Register attaches services to the server. It runs inside New, before
	// anything is accepted, which is what grpc.Server requires of a registration.
	Register func(registrar grpc.ServiceRegistrar)
	// RequestLimiter, when set, replaces the limiter built from the values in
	// package configuration. It exists so a test can drive the admission path of
	// the server this package actually builds, rather than of one it assembles out
	// of the same interceptors and hopes matches.
	RequestLimiter *rate.Limiter
	// ServerOptions are appended to the options this package builds, so a test can
	// tighten a timeout the production values put minutes away. gRPC keeps the last
	// of a repeated option that sets a value, such as grpc.ConnectionTimeout or
	// grpc.KeepaliveParams. The interceptor chains append rather than replace, so an
	// option here can add to the chain and cannot take the gate or the limiter out of
	// it.
	ServerOptions []grpc.ServerOption
	// PeerPidfd lets callers be pinned by SO_PEERPIDFD where the kernel has it.
	// Off, every caller is pinned through its /proc handle.
	PeerPidfd bool
}

// New binds the socket and returns a server ready to be driven.
//
// The bind happens here rather than inside ListenUntilContextCancelled, unlike the
// HTTP path where http.Server.ListenAndServe binds late. A socket that cannot be
// bound is worth reporting where the process can still exit non-zero, and a caller
// holding a Server knows the socket already exists, so nothing has to poll for it.
func New(opts Opts) (*Server, error) {
	// The /proc handle unless PeerPidfd is set. cmd sets it by default
	// (--workload-identity-peer-pidfd).
	method := pinProcHandle
	if opts.PeerPidfd {
		method = probePinMethod()
	}
	lis, err := ListenUnix(opts.SocketPath, SocketMode)
	if err != nil {
		return nil, err
	}

	srv := grpc.NewServer(serverOptions(opts, peerCredentials{method: method})...)
	if opts.Register != nil {
		opts.Register(srv)
	}

	shutdownWait := opts.ShutdownWait
	if shutdownWait <= 0 {
		shutdownWait = DefaultShutdownWait
	}

	return &Server{
		grpc:         srv,
		lis:          lis,
		socketPath:   opts.SocketPath,
		shutdownWait: shutdownWait,
		pinMethod:    method,
	}, nil
}

// serverOptions builds the socket's gRPC options. The interceptors run in the
// order written (logger, gate, limiter, as in pkg/server), from one chain both the
// unary and stream options derive, so the two can't drift; don't mix in the
// singular grpc.UnaryInterceptor, which gRPC puts outermost. One limiter serves
// both, since unary calls and new streams spend the same admission budget.
func serverOptions(opts Opts, creds credentials.TransportCredentials) []grpc.ServerOption {
	limiter := opts.RequestLimiter
	if limiter == nil {
		limiter = ratelimiter.NewRateLimiter(configuration.WorkloadIdentityRequestRate)
	}

	chain := []interceptorPair{
		{Unary: UnaryLoggerInterceptor(), Stream: StreamLoggerInterceptor()},
		{Unary: UnaryMetadataGateInterceptor(), Stream: StreamMetadataGateInterceptor()},
		{Unary: UnaryRateLimitInterceptor(limiter), Stream: StreamRateLimitInterceptor(limiter)},
	}

	options := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(unaryChain(chain)...),
		grpc.ChainStreamInterceptor(streamChain(chain)...),

		grpc.ConnectionTimeout(handshakeTimeout),

		// MaxConnectionAge and MaxConnectionAgeGrace are deliberately left unset,
		// which gRPC reads as infinity. Setting either tears down the push streams
		// the handlers are built on: gRPC sends a GOAWAY at the configured age and
		// force closes after the grace period, a SPIFFE client treats that as a
		// watch error and reconnects after a backoff, and every pod on the node
		// does it on the same clock. Time and Timeout stay at gRPC's defaults; a
		// dead peer on a Unix socket closes its file descriptor and the transport
		// notices immediately, so server pings have nothing to detect here.
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: maxConnectionIdle,
		}),
	}

	options = append(options, opts.ServerOptions...)
	// Last, so no ServerOptions entry can replace the credentials that pin each
	// caller. They are the only route from a connection to its Peer.
	return append(options, grpc.Creds(creds))
}

// Addr is the socket path the server is bound to. It is the log field cmd tags
// every line from this server with, which is why it is the same method name the
// HTTP server uses for its host and port.
func (s *Server) Addr() string {
	return s.socketPath
}

// ListenUntilContextCancelled serves until ctx is cancelled, then shuts down and
// returns. It mirrors pkg/server.Server's method of the same name, which is what
// lets one loop in cmd drive both server types.
func (s *Server) ListenUntilContextCancelled(ctx context.Context) {
	log := logger.FromContext(ctx)

	// Deferred rather than done at the end, so the socket is cleaned up on every way
	// out of this function: the ordinary shutdown below, the fatal path when Serve
	// fails, and a panic unwinding this goroutine. RemoveSocket covers what a defer
	// cannot, which is a call to log.Fatal anywhere else in the process.
	defer s.RemoveSocket()

	served := make(chan error, 1)
	go func() {
		log.Infof("Pod Identity Agent version %v", configuration.AgentVersion)
		log.Infof("Starting workload identity gRPC server, pinning callers with the %s", s.pinMethod)
		served <- s.grpc.Serve(s.lis)
	}()

	select {
	case err := <-served:
		// Serve returned on its own. After a successful bind that means the accept
		// loop failed, which is fatal the same way pkg/server treats a failed
		// ListenAndServe.
		if err != nil {
			log.Fatalf("Unable to serve workload identity gRPC: %v", err)
		}
		return
	case <-ctx.Done():
	}

	log.Info("Shutting down workload identity gRPC server...")
	s.stop(log, served)

	log.Info("Workload identity gRPC server stopped")
}

// stop runs GracefulStop under a deadline, escalates to Stop, and returns once Serve
// has returned or the escalation has been given its own slice of time.
//
// The bound is not a nicety here the way it is on the HTTP path. GracefulStop takes
// no context and blocks until every in-flight RPC returns, and a workload holds
// FetchX509SVID open for as long as it runs, so an unbounded drain ends at the
// kubelet's SIGKILL with the other servers still waiting on this one.
//
// Neither wait may be unbounded, and that is the part worth knowing before editing
// this. gRPC runs GracefulStop and Stop through the same routine, which holds the
// server's lock while it waits for handler goroutines to return, and Serve does not
// return until whichever call got there first fires the done event. So a handler that
// is wedged for a reason its transport closing cannot fix parks GracefulStop with the
// lock held, parks Stop on that lock, and parks Serve behind both. Waiting on Serve
// unconditionally would hand that handler the whole shutdown: the socket would stay
// on disk and cmd's WaitGroup would never return, for every server.
//
// Abandoning it instead is safe. The listener is closed and unlinked before either
// call waits for anything, so what is left is a goroutine the process is about to
// exit out of.
func (s *Server) stop(log *logrus.Entry, served <-chan error) {
	stopped := make(chan struct{})
	go func() {
		s.grpc.GracefulStop()
		close(stopped)
	}()

	select {
	case <-stopped:
		// The drain finished, so the done event has fired and Serve is on its way
		// out.
		<-served
		return
	case <-time.After(s.shutdownWait):
		log.Warnf("Graceful stop did not finish within %s, cancelling in-flight RPCs", s.shutdownWait)
	}

	// In its own goroutine, because the GracefulStop still in flight may be holding
	// the lock Stop needs.
	go s.grpc.Stop()

	select {
	case <-served:
	case <-time.After(forcedStopWait):
		log.Warnf("Workload identity gRPC server did not stop within %s of cancelling its RPCs, abandoning it", forcedStopWait)
	}
}

// RemoveSocket unlinks the socket if it is still there.
//
// It is usually a no-op, because Go's Unix listener unlinks the socket it created
// when it is closed and closing the listener is the first thing the stop does. It
// is still worth doing: that unlink is skipped for a listener the agent did not
// create itself, and it is what the next boot would otherwise have to clean up.
//
// It is exported because a deferred call cannot cover every way this process ends.
// The agent's servers report a listen failure with log.Fatalf, which logrus turns
// into os.Exit, and os.Exit runs no deferred function anywhere, so a crash in one of
// the HTTP servers would otherwise leave this socket behind. The wiring site hands
// this method to logrus.RegisterExitHandler, which logrus runs on any fatal entry
// before it exits. It is safe to call more than once and from either path.
//
// What nothing can cover is SIGKILL, and a panic in a goroutine other than the one
// running the server, since neither runs any cleanup. The guarded unlink at the next
// bind is the backstop for both.
//
// The removal is guarded the same way the one at startup is. By the time this runs
// the agent no longer owns the path, and on a restart a replacement may already
// have bound it; removing that would leave the new agent accepting on a path
// nothing can dial.
func (s *Server) RemoveSocket() {
	// Close the listener first, and do not care whether it was already closed. Go
	// unlinks a Unix socket it created when its listener closes, so this is usually
	// what does the removal. It also has to come first: the kernel answers a connect
	// from a bound socket's backlog whether or not anything is accepting, so while our
	// own listener is open the liveness guard below would read our socket as somebody
	// else's live one and leave it behind. What that guard protects against is a
	// successor that has already rebound the path, not ourselves.
	if s.lis != nil {
		_ = s.lis.Close()
	}

	if err := UnlinkIfStale(s.socketPath); err != nil {
		logger.FromContext(context.Background()).Warnf("Leaving %s in place: %v", s.socketPath, err)
	}
}

// ListenUnix prepares the path, binds it and leaves the socket with mode. The directory
// and a stale socket are dealt with before the bind and the mode after, since the bind
// creates the inode. Shared by the agent's workload identity socket (SocketMode) and the
// CSI driver binary's kubelet-only sockets (0600).
func ListenUnix(path string, mode os.FileMode) (net.Listener, error) {
	if path == "" {
		return nil, errors.New("grpcserver: no socket path configured")
	}

	if err := prepareSocketDir(filepath.Dir(path)); err != nil {
		return nil, err
	}

	if err := UnlinkIfStale(path); err != nil {
		return nil, err
	}

	lis, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("unable to listen on %s: %w", path, err)
	}

	// The bind applies the umask and never chmods, and there is no inode to chmod until
	// it runs. For a mode more permissive than the umask the window is on the strict
	// side. For the CSI sockets' 0600 this chmod tightens what the bind created, so the
	// window is permissive for as long as these two lines take — and their only caller
	// is the kubelet.
	if err := os.Chmod(path, mode); err != nil {
		_ = lis.Close()
		return nil, fmt.Errorf("unable to set mode %04o on %s: %w", mode, path, err)
	}

	return lis, nil
}

// prepareSocketDir makes sure the socket's parent directory exists and that a caller
// can traverse it.
//
// A directory the agent creates is also chmodded, for the same reason the socket is:
// MkdirAll's mode argument is masked by the process umask, so under a stricter umask
// than the usual 0022 the directory comes out without the bits a workload needs and
// the socket's own carefully chosen mode stops mattering. connect(2) needs the search
// bit on every directory above the socket.
//
// A directory that already exists is left exactly as it is. In production the CSI
// driver publishes this path, and its mode is the driver's contract rather than the
// agent's to rewrite. It is worth a line in the log when it is unreachable, though,
// because the symptom otherwise appears in the workload as a socket it cannot dial
// and nothing here would have said why.
func prepareSocketDir(dir string) error {
	if info, err := os.Stat(dir); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("socket directory %s is not a directory: %s", dir, info.Mode())
		}
		if info.Mode().Perm()&socketDirTraversalBits != socketDirTraversalBits {
			logger.FromContext(context.Background()).Warnf(
				"Socket directory %s is mode %04o: a workload running as another user cannot reach the socket inside it",
				dir, info.Mode().Perm())
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("unable to stat socket directory %s: %w", dir, err)
	}

	// MkdirAll rather than Mkdir: a node without the CSI driver, or a test, can be
	// more than one level short of the path.
	if err := os.MkdirAll(dir, socketDirMode); err != nil {
		return fmt.Errorf("unable to create socket directory %s: %w", dir, err)
	}
	if err := os.Chmod(dir, socketDirMode); err != nil {
		return fmt.Errorf("unable to set mode %04o on socket directory %s: %w", socketDirMode, dir, err)
	}
	return nil
}

// dialSocket is the connect the stale-socket probe makes.
//
// It is a variable so a test can produce the one answer that matters and cannot be
// reproduced reliably against a real socket: a live listener whose backlog has filled
// makes connect block rather than answering or being refused, and how many queued
// connections that takes depends on the host's somaxconn and file descriptor limit.
var dialSocket = func(path string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", path, timeout)
}

// UnlinkIfStale removes the socket at path if it is a socket nothing is listening
// on, and reports why it did not otherwise.
//
// A socket file survives an ungraceful exit, and net.Listen on a path that exists
// fails with "address already in use" whether that path is a leftover socket or an
// ordinary file, so without this an agent that was SIGKILLed never starts again.
//
// Removing it unconditionally, which is what SPIRE does, is wrong in two ways that
// are cheap to rule out. It deletes whatever is at the path even when that is not
// a socket at all, hiding a mount that went wrong behind a fresh bind. And it
// deletes a live agent's socket, leaving that agent accepting on an inode nothing
// can reach, which is a worse outcome than refusing to start: two agents on a node
// is a deployment fault, and the one already running is still serving pods.
//
// The remaining race is two agents starting at once, both finding the socket dead,
// and the second unlinking the first's fresh socket. Closing it needs a lock file
// beside the socket, and it is not closed here: the agent is a DaemonSet with one
// pod per node and the kubelet does not run two.
//
// Exported for internal/csidriver, which unlinks its two sockets on the way out and
// needs the same guard.
func UnlinkIfStale(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		// The ordinary case, on a first boot and after a graceful stop.
		return nil
	}
	if err != nil {
		return fmt.Errorf("unable to stat %s: %w", path, err)
	}

	if info.Mode().Type() != fs.ModeSocket {
		return fmt.Errorf("refusing to remove %s: %s is not a socket", path, info.Mode())
	}

	// A socket a process is still accepting on answers a connect, and a leftover one
	// is refused immediately with ECONNREFUSED. Anything else is not an answer: a
	// live listener whose backlog is full makes connect block, so treating a timeout
	// as "nothing is listening" would remove the socket of exactly the agent this
	// check exists to protect.
	conn, err := dialSocket(path, staleSocketProbeTimeout)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("refusing to remove %s: a process is listening on it", path)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("refusing to remove %s: cannot tell whether a process is listening on it: %w", path, err)
	}

	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("unable to remove stale socket %s: %w", path, err)
	}
	return nil
}
