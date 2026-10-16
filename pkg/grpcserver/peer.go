package grpcserver

// Pinning a connection's peer. The handshake pins the process that connected, and
// every RPC on the connection checks that the same process is still running, so a
// PID the kernel has since given to another process is never attested.
//
// There are two tiers, picked once at boot. Where the kernel has SO_PEERPIDFD
// (Linux 6.5+), the pin is a pidfd for the connector itself, taken from the
// socket. Everywhere else it is SPIRE's peertracker check (peercred.go): a
// /proc/<pid> handle opened at the handshake, with start time and owner read
// through it.

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// pinMethod is how this kernel lets a connection's peer be pinned.
type pinMethod int

const (
	// pinProcHandle is SPIRE's tier, on every kernel. A PID reused between the
	// client's connect and the handshake is caught only by the owner check.
	pinProcHandle pinMethod = iota
	// pinSocketPidfd takes the connector's pidfd from the socket (SO_PEERPIDFD,
	// Linux 6.5+). The kernel records the connecting task at connect, so the pin is
	// the connector even if its PID was reused before the handshake; pinProcHandle
	// would pin the new owner if its UID matched. The recheck is a single poll,
	// with no /proc read or start-time parse.
	pinSocketPidfd
)

func (m pinMethod) String() string {
	if m == pinSocketPidfd {
		return "SO_PEERPIDFD"
	}
	return "/proc handle"
}

// probePinMethod reports the strongest tier this kernel offers. It can't fail:
// the /proc tier needs nothing the agent doesn't already rely on.
func probePinMethod() pinMethod {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return pinProcHandle
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	fd, err := unix.GetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	if err != nil {
		return pinProcHandle
	}
	_ = unix.Close(fd)
	return pinSocketPidfd
}

// Peer is the process at the other end of one accepted connection, pinned at the
// handshake and shared by every RPC on the connection. PID is a hint: what is read
// about it belongs to the caller only if Alive returns nil afterwards. Once Alive
// fails it fails for good, and it closes the connection so the client reconnects
// and is pinned afresh.
type Peer struct {
	pid  int
	conn net.Conn

	mu  sync.RWMutex
	pin peerConn // nil once released
}

var _ workloadidentity.Peer = (*Peer)(nil)

// PID is the peer's process ID in the agent's PID namespace.
func (p *Peer) PID() int { return p.pid }

// Alive reports whether the pinned process is still running. On failure it closes
// the connection.
func (p *Peer) Alive() error {
	err := func() error {
		p.mu.RLock()
		defer p.mu.RUnlock()
		if p.pin == nil {
			return errors.New("pin released")
		}
		return p.pin.recheck()
	}()
	if err != nil {
		_ = p.conn.Close()
		return fmt.Errorf("%w: %w", errPeerGone, err)
	}
	return nil
}

// release drops the pin. Idempotent; Alive fails from then on.
func (p *Peer) release() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pin != nil {
		_ = p.pin.close()
		p.pin = nil
	}
}

// pidfdPin is the SO_PEERPIDFD tier. An *os.File, so a pin that is somehow never
// released is still closed by its finalizer.
type pidfdPin struct {
	pidfd *os.File
}

// recheck returns an error once the pinned process has exited. A pidfd is a file
// descriptor for one process that becomes readable when the process exits, so a
// poll with a zero timeout asks "has it exited?" without blocking. Sending signal
// 0 instead would need permission over the process, which another pod's user or
// SELinux label can deny.
func (p pidfdPin) recheck() error {
	fds := []unix.PollFd{{Fd: int32(p.pidfd.Fd()), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(fds, 0)
		// EINTR means a signal arrived while poll ran, not that anything happened
		// to the process. Go uses signals internally (for example to preempt
		// goroutines), so this happens even with a zero timeout. Poll again.
		if errors.Is(err, unix.EINTR) {
			continue
		}
		// With one valid fd, poll has no other error to return, so treat any error
		// as a failed check rather than a live process.
		if err != nil {
			return fmt.Errorf("%w: poll pidfd: %v", errLivenessRecheckFailed, err)
		}
		// Any event means the process has exited (POLLIN), has been cleaned up
		// (POLLHUP), or the fd is no longer valid (POLLNVAL). All fail the check.
		if n > 0 {
			return fmt.Errorf("%w: process exited", errLivenessRecheckFailed)
		}
		return nil
	}
}

func (p pidfdPin) close() error { return p.pidfd.Close() }

// peerFromPidfd pins the connector by the pidfd the kernel recorded at connect,
// so no PID reuse can come between the two. A reaped connector has no task left
// to take a pidfd of.
func peerFromPidfd(conn net.Conn, raw syscall.RawConn, pid int) (*Peer, error) {
	pidfd := -1
	var pidfdErr error
	if ctrlErr := raw.Control(func(fd uintptr) {
		// GetsockoptInt returns 0, a real fd, on failure: keep the -1 sentinel.
		if v, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD); err != nil {
			pidfdErr = err
		} else {
			pidfd = v
		}
	}); ctrlErr != nil {
		return nil, fmt.Errorf("%w: controlling raw conn: %v", errPeerCredFailed, ctrlErr)
	}
	if errors.Is(pidfdErr, unix.EINVAL) || errors.Is(pidfdErr, unix.ESRCH) {
		return nil, fmt.Errorf("%w: getsockopt SO_PEERPIDFD: %v", errPeerGone, pidfdErr)
	}
	if pidfdErr != nil {
		return nil, fmt.Errorf("%w: getsockopt SO_PEERPIDFD: %v", errPeerCredFailed, pidfdErr)
	}

	pin := pidfdPin{pidfd: os.NewFile(uintptr(pidfd), "pidfd")}
	// Linux 6.16+ hands out a pidfd even for a reaped connector; it is readable
	// at once, which means the peer was gone before the handshake.
	if err := pin.recheck(); err != nil {
		_ = pin.close()
		return nil, fmt.Errorf("%w: %w", errPeerGone, err)
	}
	return &Peer{pid: pid, conn: conn, pin: pin}, nil
}

// pinnedConn is what gRPC serves on: the raw conn, releasing its Peer's pin on
// Close. If NewServerTransport fails before its own Close defer (reachable only
// with an unbuffered writer), gRPC closes the raw conn and the pin's os.File
// finalizer frees it instead.
type pinnedConn struct {
	net.Conn
	peer *Peer
}

func (c *pinnedConn) Close() error {
	defer c.peer.release()
	return c.Conn.Close()
}
