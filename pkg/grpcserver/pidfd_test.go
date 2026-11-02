package grpcserver

import (
	"os"
	"strconv"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// TestPidfdPin_RecheckFailsOnceTheChildExits covers the SO_PEERPIDFD tier's check
// on any kernel: pidfd_open (5.3+) gives the same kind of pidfd the socket does.
func TestPidfdPin_RecheckFailsOnceTheChildExits(t *testing.T) {
	g := NewWithT(t)
	child, err := os.StartProcess("/bin/sleep", []string{"sleep", "30"}, &os.ProcAttr{})
	if err != nil {
		t.Skipf("cannot start a child: %v", err)
	}
	fd, err := unix.PidfdOpen(child.Pid, 0)
	if err != nil {
		_ = child.Kill()
		_, _ = child.Wait()
		t.Skipf("no pidfd_open: %v", err)
	}
	pin := pidfdPin{pidfd: os.NewFile(uintptr(fd), "pidfd")}
	defer pin.close()
	g.Expect(pin.recheck()).To(Succeed())

	g.Expect(child.Kill()).To(Succeed())
	_, _ = child.Wait()

	g.Expect(pin.recheck()).To(MatchError(errLivenessRecheckFailed))
}

// TestProbePinMethod_PicksThePidfdTierOn65Plus: mainline has SO_PEERPIDFD from
// 6.5. Below that it skips rather than assert the /proc tier, since backports exist.
func TestProbePinMethod_PicksThePidfdTierOn65Plus(t *testing.T) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		t.Skipf("uname: %v", err)
	}
	parts := strings.SplitN(unix.ByteSliceToString(uts.Release[:]), ".", 3)
	if len(parts) < 2 {
		t.Skipf("unparseable kernel release")
	}
	major, errMajor := strconv.Atoi(parts[0])
	minor, errMinor := strconv.Atoi(parts[1])
	if errMajor != nil || errMinor != nil {
		t.Skipf("unparseable kernel release")
	}
	if major < 6 || major == 6 && minor < 5 {
		t.Skipf("kernel %d.%d predates SO_PEERPIDFD", major, minor)
	}

	NewWithT(t).Expect(probePinMethod()).To(Equal(pinSocketPidfd))
}

// TestPeerFromPidfd_AFailedGetsockoptLeavesFd0Open: GetsockoptInt returns 0 on
// failure, and 0 is a real fd. Wrapping it would close the agent's fd 0, and the
// number would then be reused by another connection's pin. Not parallel: it
// swaps fd 0.
func TestPeerFromPidfd_AFailedGetsockoptLeavesFd0Open(t *testing.T) {
	if probePinMethod() == pinSocketPidfd {
		t.Skip("SO_PEERPIDFD succeeds on a live peer here, so the failure path isn't reachable")
	}
	g := NewWithT(t)
	saved, err := unix.Dup(0)
	g.Expect(err).ToNot(HaveOccurred())
	devNull, err := os.Open(os.DevNull)
	g.Expect(err).ToNot(HaveOccurred())
	defer devNull.Close()
	g.Expect(unix.Dup2(int(devNull.Fd()), 0)).To(Succeed())
	t.Cleanup(func() { _ = unix.Dup2(saved, 0); _ = unix.Close(saved) })

	server, client := unixPair(t)
	defer client.Close()
	defer server.Close()

	_, err = peerFromConn(server, pinSocketPidfd)

	g.Expect(err).To(MatchError(errPeerCredFailed))
	var st unix.Stat_t
	g.Expect(unix.Fstat(0, &st)).To(Succeed(), "fd 0 must survive a refused handshake")
}
