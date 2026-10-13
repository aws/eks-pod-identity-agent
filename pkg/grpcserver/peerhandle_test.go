package grpcserver

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// selfUcred is SO_PEERCRED as this process would report itself.
func selfUcred() *unix.Ucred {
	return &unix.Ucred{Pid: int32(os.Getpid()), Uid: uint32(os.Getuid()), Gid: uint32(os.Getgid())}
}

// TestPeerHandle_Recheck_RefusesAChangedOwner is the guard on a reuse that beat
// the handshake: a holder whose owner differs from SO_PEERCRED's is not the caller.
func TestPeerHandle_Recheck_RefusesAChangedOwner(t *testing.T) {
	g := NewWithT(t)
	h, err := newPeerHandle(selfUcred())
	g.Expect(err).ToNot(HaveOccurred())
	defer h.close()

	h.uid++

	g.Expect(h.recheck()).To(MatchError(errLivenessRecheckFailed))
	g.Expect(h.recheck()).To(MatchError(ContainSubstring("owner changed")))
}

// TestPeerHandle_Recheck_RefusesAChangedStartTime: a different start time means
// the handle no longer names the process that connected.
func TestPeerHandle_Recheck_RefusesAChangedStartTime(t *testing.T) {
	g := NewWithT(t)
	h, err := newPeerHandle(selfUcred())
	g.Expect(err).ToNot(HaveOccurred())
	defer h.close()

	h.startTime++

	g.Expect(h.recheck()).To(MatchError(ContainSubstring("start time changed")))
}

// TestNewPeerHandle_RefusesAnOwnerMismatchAtPin: the owner is checked at the pin
// too, not only on the first RPC.
func TestNewPeerHandle_RefusesAnOwnerMismatchAtPin(t *testing.T) {
	ucred := selfUcred()
	ucred.Gid++

	_, err := newPeerHandle(ucred)

	NewWithT(t).Expect(err).To(MatchError(errLivenessRecheckFailed))
}

// TestNewPeerHandle_ClassifiesTheOpenFailure: only a missing process is
// peer_gone. An LSM or hidepid refusal is not evidence the peer exited.
func TestNewPeerHandle_ClassifiesTheOpenFailure(t *testing.T) {
	g := NewWithT(t)
	original := procRoot
	t.Cleanup(func() { procRoot = original })

	procRoot = t.TempDir()
	_, err := newPeerHandle(selfUcred())
	g.Expect(err).To(MatchError(errPeerGone), "no /proc/<pid>: the process is gone")

	g.Expect(procOpenErr("open", fs.ErrPermission)).To(MatchError(errPeerCredFailed))
	g.Expect(procOpenErr("open", unix.ESRCH)).To(MatchError(errPeerGone))
	g.Expect(procOpenErr("parse", fmt.Errorf("%w", strconv.ErrSyntax))).To(MatchError(errPeerCredFailed))
}

// TestPeerHandle_Recheck_FailsOnceTheProcessIsReaped is the property the tier
// rests on: the handle's reads fail after reap, where fstat alone still succeeds.
func TestPeerHandle_Recheck_FailsOnceTheProcessIsReaped(t *testing.T) {
	g := NewWithT(t)
	child, err := os.StartProcess("/bin/sleep", []string{"sleep", "30"}, &os.ProcAttr{})
	if err != nil {
		t.Skipf("cannot start a child: %v", err)
	}
	ucred := &unix.Ucred{Pid: int32(child.Pid), Uid: uint32(os.Getuid()), Gid: uint32(os.Getgid())}
	h, err := newPeerHandle(ucred)
	g.Expect(err).ToNot(HaveOccurred())
	defer h.close()
	g.Expect(h.recheck()).To(Succeed())

	g.Expect(child.Kill()).To(Succeed())
	_, _ = child.Wait()

	g.Expect(h.recheck()).To(MatchError(errLivenessRecheckFailed))
	var st unix.Stat_t
	g.Expect(unix.Fstat(int(h.procDir.Fd()), &st)).To(Succeed(), "fstat still succeeds after reap")
	_, statErr := os.Stat(filepath.Join(procRoot, strconv.Itoa(child.Pid)))
	g.Expect(statErr).To(HaveOccurred())
}
