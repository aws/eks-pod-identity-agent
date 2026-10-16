package cmd

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
)

// fakeRunnable stands in for an HTTP server. It records that it was started and
// that it was stopped, which is everything the drive loop promises about either
// server kind, and it binds nothing: the real credential servers listen on the
// link-local addresses, which a test cannot have.
type fakeRunnable struct {
	addr    string
	started chan struct{}
	stopped chan struct{}
}

func newFakeRunnable(addr string) *fakeRunnable {
	return &fakeRunnable{
		addr:    addr,
		started: make(chan struct{}),
		stopped: make(chan struct{}),
	}
}

func (f *fakeRunnable) Addr() string { return f.addr }

func (f *fakeRunnable) ListenUntilContextCancelled(ctx context.Context) {
	close(f.started)
	<-ctx.Done()
	close(f.stopped)
}

// newWorkloadIdentityServer builds the real gRPC server on a socket under a short
// temporary directory. The path is kept short on purpose: a Unix socket path is
// limited to 107 bytes and t.TempDir embeds the test name.
func newWorkloadIdentityServer(t *testing.T) (*grpcserver.Server, string) {
	t.Helper()
	g := NewWithT(t)

	dir, err := os.MkdirTemp("", "pia")
	g.Expect(err).ToNot(HaveOccurred())
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path := filepath.Join(dir, "agent.sock")
	srv, err := grpcserver.New(grpcserver.Opts{
		SocketPath:   path,
		ShutdownWait: time.Second,
		Register:     grpcserver.RegisterStubServices,
	})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(srv.Addr()).To(Equal(path))
	return srv, path
}

// TestRunServersUntilShutdown_ASigtermStopsEveryServerKind is the shutdown path end
// to end, across both server types, through the one interface the loop knows about.
//
// Sending a real signal to the test binary is safe here: signal.NotifyContext has
// diverted SIGTERM by the time any server reports that it started, so the signal
// cancels the context rather than ending the process.
func TestRunServersUntilShutdown_ASigtermStopsEveryServerKind(t *testing.T) {
	g := NewWithT(t)

	credentialish := newFakeRunnable("169.254.170.23:80")
	probeish := newFakeRunnable("localhost:2703")
	workloadIdentity, socketPath := newWorkloadIdentityServer(t)

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		runServersUntilShutdown(context.Background(), []runnable{credentialish, probeish, workloadIdentity})
	}()

	// every server got its own goroutine
	g.Eventually(credentialish.started, 10*time.Second).Should(BeClosed())
	g.Eventually(probeish.started, 10*time.Second).Should(BeClosed())
	g.Expect(socketPath).To(BeAnExistingFile())

	g.Expect(syscall.Kill(os.Getpid(), syscall.SIGTERM)).To(Succeed())

	g.Eventually(returned, 30*time.Second).Should(BeClosed(),
		"the loop only returns once every server has finished shutting down")
	g.Expect(credentialish.stopped).To(BeClosed())
	g.Expect(probeish.stopped).To(BeClosed())
	g.Expect(socketPath).ToNot(BeAnExistingFile(), "the gRPC server cleans up its socket on the way out")
}

// TestRunServersUntilShutdown_ACancelledParentContextStopsEveryServer covers the
// path the signal.NotifyContext shape buys: the parent context is now a shutdown
// trigger, so a test does not have to signal the process to drive the loop. In
// production the parent is context.Background and only the signal fires.
func TestRunServersUntilShutdown_ACancelledParentContextStopsEveryServer(t *testing.T) {
	g := NewWithT(t)

	first := newFakeRunnable("first")
	second := newFakeRunnable("second")

	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		runServersUntilShutdown(ctx, []runnable{first, second})
	}()

	g.Eventually(first.started, 10*time.Second).Should(BeClosed())
	g.Eventually(second.started, 10*time.Second).Should(BeClosed())

	cancel()

	g.Eventually(returned, 10*time.Second).Should(BeClosed())
	g.Expect(first.stopped).To(BeClosed())
	g.Expect(second.stopped).To(BeClosed())
}
