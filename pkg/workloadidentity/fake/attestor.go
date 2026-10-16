package fake

import (
	"context"
	"slices"
	"sync"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// Attestor is a fake workloadidentity.Attestor. It returns a canned Workload or
// a canned error, counts calls, records the peers it was handed, and parks
// its calls while its Gate is closed.
//
// Attest ignores peer beyond recording it, so a test of a tier above attestation
// can pass nil and never build a socket. Only the transport's own tests need
// a Unix socket.
//
// Set the fields before the fake is used. Use the setters to change behaviour
// while the fake is live; the fields themselves are not safe to write once a
// call can be in flight.
type Attestor struct {
	Gate

	// Result is returned by Attest when Func and Err are nil.
	Result *workloadidentity.Workload
	// Err, when non-nil and Func is nil, is returned by Attest together with a
	// nil Workload.
	Err error
	// Func, when non-nil, wins over Result and Err: Attest returns whatever it
	// returns.
	Func func(ctx context.Context, peer workloadidentity.Peer) (*workloadidentity.Workload, error)

	mu    sync.Mutex
	calls int
	peers []workloadidentity.Peer
}

// Attest records peer and returns the canned Workload, the canned error, or
// whatever Func returns.
//
// It parks at the Gate first and returns the Gate's error unchanged. A call that
// arrives with a done ctx, or that is woken by ctx rather than by Release, is
// never counted and its peer is never recorded. A parked call is not counted
// while it is parked; it counts and records itself once Release wakes it and it
// is next scheduled, which can be after Release has returned. Use WaitForBlocked
// to observe a parked call, and observe the call's own return before asserting on
// Calls or Peers.
func (a *Attestor) Attest(ctx context.Context, peer workloadidentity.Peer) (*workloadidentity.Workload, error) {
	if err := a.enter(ctx); err != nil {
		return nil, err
	}

	a.mu.Lock()
	a.calls++
	a.peers = append(a.peers, peer)
	fn, result, err := a.Func, a.Result, a.Err
	a.mu.Unlock()

	if fn != nil {
		return fn(ctx, peer)
	}
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Calls reports how many times Attest has run past the Gate. A call woken by
// Release is counted when it is next scheduled, not when Release returns.
func (a *Attestor) Calls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

// Peers returns a copy of the peers Attest was called with, in call order,
// so it is safe to read while another goroutine is calling the fake.
func (a *Attestor) Peers() []workloadidentity.Peer {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.peers)
}

// SetResult replaces the canned Workload and error while the fake is live.
func (a *Attestor) SetResult(w *workloadidentity.Workload, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Result = w
	a.Err = err
}

var _ workloadidentity.Attestor = &Attestor{}
