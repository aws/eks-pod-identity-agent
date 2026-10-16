package csidriver

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
)

// The driver waits for the agent's socket to answer, so it returns once something listens.
func TestWaitForSocket_ListenerAppearsLater_Returns(t *testing.T) {
	g := NewWithT(t)

	path := filepath.Join(testOpts(t).SocketDir, "agent.sock")
	g.Expect(os.MkdirAll(filepath.Dir(path), 0o755)).To(Succeed())
	listening := make(chan net.Listener, 1)
	go func() {
		time.Sleep(1500 * time.Millisecond)
		lis, err := net.Listen("unix", path)
		if err != nil {
			close(listening)
			return
		}
		listening <- lis
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	g.Expect(WaitForSocket(ctx, logger.FromContext(ctx), path)).To(Succeed())

	lis, ok := <-listening
	g.Expect(ok).To(BeTrue(), "the listener could not be bound")
	_ = lis.Close()
}

// A socket file left by a killed agent is not an agent serving it.
func TestWaitForSocket_StaleSocketFile_KeepsWaitingUntilCancelled(t *testing.T) {
	g := NewWithT(t)

	path := filepath.Join(testOpts(t).SocketDir, "agent.sock")
	g.Expect(os.MkdirAll(filepath.Dir(path), 0o755)).To(Succeed())
	lis, err := net.Listen("unix", path)
	g.Expect(err).ToNot(HaveOccurred())
	lis.(*net.UnixListener).SetUnlinkOnClose(false)
	g.Expect(lis.Close()).To(Succeed())

	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	g.Expect(WaitForSocket(ctx, logger.FromContext(ctx), path)).To(MatchError(context.DeadlineExceeded))
}
