package fake

import (
	"context"
	"slices"
	"sync"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// SessionProvider is a fake workloadidentity.SessionProvider. It returns a
// canned WorkloadSession or a canned error, counts calls to both methods,
// records the workloads it was asked about and the pod UIDs it was told to
// invalidate, and parks Session while its Gate is closed.
//
// The canned value is called Result rather than Session because Session is the
// interface method name.
//
// Set the fields before the fake is used. Use the setters to change behaviour
// while the fake is live; the fields themselves are not safe to write once a
// call can be in flight.
type SessionProvider struct {
	Gate

	// Result is returned by Session when Func and Err are nil. It is handed back
	// uncopied, so every call gets the same pointer.
	Result *workloadidentity.WorkloadSession
	// Err, when non-nil and Func is nil, is returned by Session together with a
	// nil WorkloadSession.
	Err error
	// Func, when non-nil, wins over Result and Err: Session returns whatever it
	// returns.
	Func func(ctx context.Context, w *workloadidentity.Workload) (*workloadidentity.WorkloadSession, error)

	mu              sync.Mutex
	calls           int
	workloads       []*workloadidentity.Workload
	invalidateCalls int
	invalidated     []string
}

// Session records w and returns the canned WorkloadSession, the canned error, or
// whatever Func returns.
//
// It parks at the Gate first and returns the Gate's error unchanged. A call that
// arrives with a done ctx, or that is woken by ctx rather than by Release, is
// never counted and its workload is never recorded. A parked call is not counted
// while it is parked; it counts and records itself once Release wakes it and it
// is next scheduled, which can be after Release has returned. Use WaitForBlocked
// to observe a parked call, and observe the call's own return before asserting on
// Calls or Workloads.
//
// The returned *WorkloadSession is the canned pointer itself, not a copy, so a
// caller that mutates it rewrites the answer every later call sees.
func (p *SessionProvider) Session(ctx context.Context, w *workloadidentity.Workload) (*workloadidentity.WorkloadSession, error) {
	if err := p.enter(ctx); err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.calls++
	p.workloads = append(p.workloads, w)
	fn, result, err := p.Func, p.Result, p.Err
	p.mu.Unlock()

	if fn != nil {
		return fn(ctx, w)
	}
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Invalidate records podUID. It takes no ctx and therefore cannot honour
// cancellation, so it does not go through the Gate and only counts.
func (p *SessionProvider) Invalidate(podUID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.invalidateCalls++
	p.invalidated = append(p.invalidated, podUID)
}

// Calls reports how many times Session has run past the Gate. A call woken by
// Release is counted when it is next scheduled, not when Release returns.
func (p *SessionProvider) Calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// Workloads returns a copy of the workloads Session was called with, in call
// order, so it is safe to read while another goroutine is calling the fake.
func (p *SessionProvider) Workloads() []*workloadidentity.Workload {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.workloads)
}

// InvalidateCalls reports how many times Invalidate has been called.
func (p *SessionProvider) InvalidateCalls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.invalidateCalls
}

// Invalidated returns a copy of the pod UIDs Invalidate was called with, in call
// order, so it is safe to read while another goroutine is calling the fake.
func (p *SessionProvider) Invalidated() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.invalidated)
}

// SetResult replaces the canned WorkloadSession and error while the fake is
// live.
func (p *SessionProvider) SetResult(s *workloadidentity.WorkloadSession, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Result = s
	p.Err = err
}

var _ workloadidentity.SessionProvider = &SessionProvider{}
