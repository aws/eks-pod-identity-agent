package grpcserver

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// TestPeerFromContext_ReachesTheHandler covers a unary and a streaming method,
// since a stream reaches the accessor through ServerStream.Context.
func TestPeerFromContext_ReachesTheHandler(t *testing.T) {
	g := NewWithT(t)

	peers := make(chan *Peer, 2)
	report := func(ctx context.Context) error {
		p, ok := PeerFromContext(ctx)
		if !ok {
			return status.Error(codes.Internal, "handler could not reach the caller's peer")
		}
		peers <- p
		return nil
	}
	stub := &stubService{
		unary:  report,
		stream: func(ss grpc.ServerStream) error { return report(ss.Context()) },
	}

	path := tempSocketPath(t)
	srv := newStubServer(t, stub, Opts{SocketPath: path})
	serve(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := dial(t, path)
	g.Eventually(func() error { return callUnary(withHeader(ctx), conn) }).WithContext(ctx).Should(Succeed())
	_, err := openStream(withHeader(ctx), conn)
	g.Expect(err).ToNot(HaveOccurred())

	var first, second *Peer
	g.Eventually(peers, 10*time.Second).Should(Receive(&first))
	g.Eventually(peers, 10*time.Second).Should(Receive(&second))
	g.Expect(first.PID()).To(Equal(os.Getpid()))
	g.Expect(first.Alive()).To(Succeed())
	g.Expect(second).To(BeIdenticalTo(first), "both RPCs on one connection share its pin")
}

func TestPeerFromContext_WithoutTheCredentials(t *testing.T) {
	g := NewWithT(t)
	_, present := PeerFromContext(context.Background())
	g.Expect(present).To(BeFalse())
}

// pinMethods is every tier this kernel offers; the /proc tier works everywhere.
func pinMethods() []pinMethod {
	if probePinMethod() == pinSocketPidfd {
		return []pinMethod{pinProcHandle, pinSocketPidfd}
	}
	return []pinMethod{pinProcHandle}
}

// tierName is a tier's label as a subtest name.
func tierName(m pinMethod) string { return strings.TrimPrefix(m.String(), "/") }

// TestServerHandshake_PinsSelf runs every tier the kernel offers.
func TestServerHandshake_PinsSelf(t *testing.T) {
	for _, method := range pinMethods() {
		t.Run(tierName(method), func(t *testing.T) {
			g := NewWithT(t)
			server, client := unixPair(t)
			defer client.Close()

			returned, info, err := peerCredentials{method: method}.ServerHandshake(server)
			g.Expect(err).ToNot(HaveOccurred())
			byValue, ok := info.(AuthInfo)
			g.Expect(ok).To(BeTrue())
			g.Expect(byValue.Peer.PID()).To(Equal(os.Getpid()))
			g.Expect(byValue.Peer.Alive()).To(Succeed())

			g.Expect(returned.Close()).To(Succeed())
			g.Expect(byValue.Peer.Alive()).To(MatchError(errPeerGone), "closing the conn releases the pin")
		})
	}
}

// TestServerHandshake_PeerExitedBeforeHandshake: the connector exits, and its PID is
// freed, before the handshake, so nothing is pinned.
func TestServerHandshake_PeerExitedBeforeHandshake(t *testing.T) {
	for _, method := range pinMethods() {
		t.Run(tierName(method), func(t *testing.T) {
			g := NewWithT(t)
			gone := promPeerPinTotal.WithLabelValues(workloadidentity.OutcomeFailure, workloadidentity.ReasonPeerGone)
			before := testutil.ToFloat64(gone)

			conn := acceptFromExitedChild(t)
			defer conn.Close()

			_, _, err := peerCredentials{method: method}.ServerHandshake(conn)
			g.Expect(err).To(MatchError(errPeerGone))
			g.Expect(testutil.ToFloat64(gone) - before).To(Equal(1.0))
		})
	}
}

// TestPeer_AliveFailureClosesTheConnection: a connection whose peer is gone can
// never attest again, so it is closed and the client reconnects.
func TestPeer_AliveFailureClosesTheConnection(t *testing.T) {
	g := NewWithT(t)
	server, client := unixPair(t)
	defer client.Close()

	p := &Peer{pid: os.Getpid(), conn: server} // no pin: as after release
	g.Expect(p.Alive()).To(MatchError(errPeerGone))
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := client.Read(make([]byte, 1))
	g.Expect(err).To(MatchError(io.EOF), "the agent's end has to be closed, not merely silent")
}

func TestServerHandshake_RefusesNonUnix(t *testing.T) {
	g := NewWithT(t)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_, _, err := peerCredentials{method: pinProcHandle}.ServerHandshake(left)
	g.Expect(err).To(MatchError(errNotUnixSocket))
}

func TestClientHandshake_Fails(t *testing.T) {
	g := NewWithT(t)
	left, right := net.Pipe()
	defer func() { _ = right.Close() }()
	_, _, err := peerCredentials{}.ClientHandshake(context.Background(), "agent", left)
	g.Expect(err).To(MatchError(errClientHandshake))
	_, err = left.Write([]byte("anything"))
	g.Expect(err).To(HaveOccurred())
}

func unixPair(t *testing.T) (server, client net.Conn) {
	t.Helper()
	ln, err := net.Listen("unix", filepath.Join(shortTempDir(t), "p.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); accepted <- c }()
	client, err = net.Dial("unix", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return <-accepted, client
}

func acceptFromExitedChild(t *testing.T) net.Conn {
	t.Helper()
	sock := filepath.Join(shortTempDir(t), "x.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); accepted <- c }()
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperConnectAndExit")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER=1", "PIN_HELPER_SOCK="+sock)
	if err := cmd.Run(); err != nil { // Run waits for the child to exit, which frees its PID
		t.Fatal(err)
	}
	return <-accepted
}

func TestHelperConnectAndExit(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER") != "1" {
		return
	}
	if _, err := net.Dial("unix", os.Getenv("PIN_HELPER_SOCK")); err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

func shortTempDir(t *testing.T) string {
	dir, err := os.MkdirTemp("", "pin")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// TestPeer_HeldConnectionOutlivesItsPeer: a connection pinned while its connector
// lived must stop attesting once it exits, PID reuse or not.
func TestPeer_HeldConnectionOutlivesItsPeer(t *testing.T) {
	for _, method := range pinMethods() {
		t.Run(tierName(method), func(t *testing.T) { heldConnectionOutlivesItsPeer(t, method) })
	}
}

func heldConnectionOutlivesItsPeer(t *testing.T, method pinMethod) {
	g := NewWithT(t)
	sock := filepath.Join(shortTempDir(t), "h.sock")
	ln, err := net.Listen("unix", sock)
	g.Expect(err).ToNot(HaveOccurred())
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); accepted <- c }()

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperConnectAndWait")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER=1", "PIN_HELPER_SOCK="+sock)
	stdin, err := cmd.StdinPipe()
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(cmd.Start()).To(Succeed())
	conn := <-accepted

	_, info, err := peerCredentials{method: method}.ServerHandshake(conn)
	g.Expect(err).ToNot(HaveOccurred())
	p := info.(AuthInfo).Peer
	g.Expect(p.PID()).To(Equal(cmd.Process.Pid))
	g.Expect(p.Alive()).To(Succeed())

	_ = stdin.Close() // the child exits
	_ = cmd.Wait()
	g.Expect(p.Alive()).To(MatchError(errPeerGone))
}

func TestHelperConnectAndWait(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER") != "1" {
		return
	}
	c, err := net.Dial("unix", os.Getenv("PIN_HELPER_SOCK"))
	if err != nil {
		os.Exit(2)
	}
	_, _ = os.Stdin.Read(make([]byte, 1))
	_ = c
	os.Exit(0)
}
