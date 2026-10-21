package grpcserver

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	. "github.com/onsi/gomega"
)

const nsLastPID = "/proc/sys/kernel/ns_last_pid"

// requirePIDSteering skips unless PIDREUSE_REQUIRED is set. Other forks race the
// steer, so these tests run only in the fresh PID namespace `make test-pidreuse`
// creates, and fail there if they can't steer. Runtime threads take PIDs too, so
// it drops to one P, which keeps the scheduler from starting threads mid-steer.
func requirePIDSteering(t *testing.T) {
	t.Helper()
	if os.Getenv("PIDREUSE_REQUIRED") == "" {
		t.Skip("steers PIDs in a fresh PID namespace; run make test-pidreuse")
	}
	// The capability is checked on write, so probe by writing the current value back.
	current, err := os.ReadFile(nsLastPID)
	if err == nil {
		err = os.WriteFile(nsLastPID, current, 0)
	}
	if err != nil {
		t.Fatalf("cannot steer PIDs: %v", err)
	}
	prev := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(prev) })
}

// startOnPID steers ns_last_pid so a new process with the test's uid gets pid,
// and kills it when the test ends.
func startOnPID(t *testing.T, g *WithT, pid int) *exec.Cmd {
	t.Helper()
	g.Expect(os.WriteFile(nsLastPID, []byte(strconv.Itoa(pid-1)), 0)).To(Succeed())
	victim := exec.Command("sleep", "30")
	g.Expect(victim.Start()).To(Succeed())
	t.Cleanup(func() { _ = victim.Process.Kill(); _, _ = victim.Process.Wait() })
	g.Expect(victim.Process.Pid).To(Equal(pid), "the victim must hold the connector's PID")
	return victim
}

// TestPeer_PIDReuse_Refused: a child connects and is pinned, then exits, and a new
// process with the same uid takes its PID. Every tier must refuse the held
// connection and close it, where per-RPC attestation would attest the new process.
func TestPeer_PIDReuse_Refused(t *testing.T) {
	requirePIDSteering(t)
	for _, method := range pinMethods() {
		t.Run(tierName(method), func(t *testing.T) {
			g := NewWithT(t)
			sock := filepath.Join(shortTempDir(t), "r.sock")
			ln, err := net.Listen("unix", sock)
			g.Expect(err).ToNot(HaveOccurred())
			defer ln.Close()
			accepted := make(chan net.Conn, 1)
			go func() { c, _ := ln.Accept(); accepted <- c }()

			// The connector dials and stays alive until its stdin closes.
			connector := exec.Command(os.Args[0], "-test.run=TestHelperConnectAndWait")
			connector.Env = append(os.Environ(), "GO_WANT_HELPER=1", "PIN_HELPER_SOCK="+sock)
			stdin, err := connector.StdinPipe()
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(connector.Start()).To(Succeed())
			conn := <-accepted
			defer conn.Close()

			// Pin it while it's alive.
			_, info, err := peerCredentials{method: method}.ServerHandshake(conn)
			g.Expect(err).ToNot(HaveOccurred())
			p := info.(AuthInfo).Peer
			g.Expect(p.Alive()).To(Succeed())

			// Let it exit and wait for it, which frees its PID. Then a same-uid process
			// takes that PID.
			_ = stdin.Close()
			_ = connector.Wait()
			startOnPID(t, g, p.PID())

			// The pin still names the exited connector, so the new process is refused.
			g.Expect(p.Alive()).To(MatchError(errPeerGone))
			// net.ErrClosed, not io.EOF: the agent closed it, not the peer.
			_, err = conn.Read(make([]byte, 1))
			g.Expect(err).To(MatchError(net.ErrClosed), "a held connection whose connector is gone is closed")
		})
	}
}

// TestPeer_PIDReuseBeforeHandshake is the gap the SO_PEERPIDFD tier closes. The
// connector exits before the handshake and a same-uid process takes its freed PID.
// The /proc tier sees only the PID's new owner and pins it, as SPIRE would;
// SO_PEERPIDFD refers to the connector itself and refuses.
func TestPeer_PIDReuseBeforeHandshake(t *testing.T) {
	requirePIDSteering(t)
	for _, method := range pinMethods() {
		t.Run(tierName(method), func(t *testing.T) {
			g := NewWithT(t)
			sock := filepath.Join(shortTempDir(t), "h.sock")
			ln, err := net.Listen("unix", sock)
			g.Expect(err).ToNot(HaveOccurred())
			defer ln.Close()
			accepted := make(chan net.Conn, 1)
			go func() { c, _ := ln.Accept(); accepted <- c }()

			// The connector dials and exits at once. Run also waits for it to exit,
			// which frees its PID. Its connection sits in the backlog, not yet handshaken.
			connector := exec.Command(os.Args[0], "-test.run=TestHelperConnectAndExit")
			connector.Env = append(os.Environ(), "GO_WANT_HELPER=1", "PIN_HELPER_SOCK="+sock)
			g.Expect(connector.Run()).To(Succeed())
			conn := <-accepted
			defer conn.Close()

			// A same-uid process takes the PID before the handshake runs.
			victim := startOnPID(t, g, connector.Process.Pid)

			// SO_PEERPIDFD names the exited connector, not its PID, so the handshake refuses.
			returned, info, err := peerCredentials{method: method}.ServerHandshake(conn)
			if method == pinSocketPidfd {
				g.Expect(err).To(MatchError(errPeerGone))
				return
			}
			// The /proc tier opens /proc/<pid> now and finds the new process.
			g.Expect(err).ToNot(HaveOccurred(), "the /proc tier can't tell the new owner from the connector")
			defer returned.Close()
			p := info.(AuthInfo).Peer
			g.Expect(p.PID()).To(Equal(victim.Process.Pid))
			g.Expect(p.Alive()).To(Succeed())
		})
	}
}
