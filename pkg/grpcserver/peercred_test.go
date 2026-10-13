package grpcserver

import (
	"net"
	"os"
	"testing"

	. "github.com/onsi/gomega"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// TestParseStartTime_HandlesCommWithSpacesAndParens proves field 22 (starttime)
// is located from the last ')' rather than by splitting the whole line, so a
// process whose comm contains spaces and parentheses is parsed correctly.
func TestParseStartTime_HandlesCommWithSpacesAndParens(t *testing.T) {
	g := NewWithT(t)

	// comm is "(my (weird) comm)"; the 20 fields after the last ')' end with
	// starttime = 987654.
	stat := "4242 (my (weird) comm) S 1 4242 4242 0 -1 4194304 100 0 0 0 5 2 0 0 20 0 1 0 987654 rest ignored"

	startTime, err := parseStartTime(stat)

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(startTime).To(Equal(uint64(987654)))
}

// TestParseStartTime_Malformed rejects lines with no comm field or too few
// fields, rather than returning a bogus zero.
func TestParseStartTime_Malformed(t *testing.T) {
	testCases := []struct {
		name string
		stat string
	}{
		{name: "no closing paren", stat: "4242 no-paren S 1 2 3"},
		{name: "too few fields after comm", stat: "4242 (comm) S 1 2 3"},
		{name: "empty", stat: ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			_, err := parseStartTime(tc.stat)
			g.Expect(err).To(HaveOccurred())
		})
	}
}

// TestPeerFromConn_NotUnixSocket proves a non-Unix connection is refused with the
// errNotUnixSocket sentinel rather than panicking on the type assertion.
func TestPeerFromConn_NotUnixSocket(t *testing.T) {
	g := NewWithT(t)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	_, err := peerFromConn(c1, pinProcHandle)

	g.Expect(err).To(MatchError(errNotUnixSocket))
}

// TestPeerFromConn_RealSocket_PinsSelf drives the real SO_PEERCRED path over a
// Unix socket the test process connects to itself, so the peer resolves to this
// process: the reported PID is our own, the handle pins a live process, and the
// recheck passes.
func TestPeerFromConn_RealSocket_PinsSelf(t *testing.T) {
	g := NewWithT(t)

	conn, client := unixPair(t)
	defer client.Close()

	peer, err := peerFromConn(conn, pinProcHandle)
	g.Expect(err).NotTo(HaveOccurred())
	defer peer.release()

	g.Expect(peer.PID()).To(Equal(os.Getpid()))
	g.Expect(peer.Alive()).To(Succeed(), "a live self-peer must pass the recheck")
}
