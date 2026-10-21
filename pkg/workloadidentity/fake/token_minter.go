package fake

import (
	"context"
	"slices"
	"sync"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// TokenMinter is a fake workloadidentity.TokenMinter. It returns a canned
// ProjectedToken or a canned error, counts calls, records the workloads it was
// asked about, and parks its calls while its Gate is closed.
//
// Set the fields before the fake is used. Use the setters to change behaviour
// while the fake is live; the fields themselves are not safe to write once a
// call can be in flight.
type TokenMinter struct {
	Gate

	// Result is returned by Mint when Func and Err are nil. It is handed back
	// uncopied, so every call gets the same pointer.
	Result *workloadidentity.ProjectedToken
	// Err, when non-nil and Func is nil, is returned by Mint together with a
	// nil ProjectedToken.
	Err error
	// Func, when non-nil, wins over Result and Err: Mint returns whatever it
	// returns.
	Func func(ctx context.Context, w *workloadidentity.Workload) (*workloadidentity.ProjectedToken, error)

	mu        sync.Mutex
	calls     int
	workloads []*workloadidentity.Workload
}

// Mint records w and returns the canned ProjectedToken, the canned error, or
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
// The returned *ProjectedToken is the canned pointer itself, not a copy, so a
// caller that mutates it rewrites the answer every later call sees.
func (m *TokenMinter) Mint(ctx context.Context, w *workloadidentity.Workload) (*workloadidentity.ProjectedToken, error) {
	if err := m.enter(ctx); err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.calls++
	m.workloads = append(m.workloads, w)
	fn, result, err := m.Func, m.Result, m.Err
	m.mu.Unlock()

	if fn != nil {
		return fn(ctx, w)
	}
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Calls reports how many times Mint has run past the Gate. A call woken by
// Release is counted when it is next scheduled, not when Release returns.
func (m *TokenMinter) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// Workloads returns a copy of the workloads Mint was called with, in call order,
// so it is safe to read while another goroutine is calling the fake.
func (m *TokenMinter) Workloads() []*workloadidentity.Workload {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.workloads)
}

// SetResult replaces the canned ProjectedToken and error while the fake is live.
func (m *TokenMinter) SetResult(t *workloadidentity.ProjectedToken, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Result = t
	m.Err = err
}

var _ workloadidentity.TokenMinter = &TokenMinter{}
