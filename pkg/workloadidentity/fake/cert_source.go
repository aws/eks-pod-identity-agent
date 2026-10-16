package fake

import (
	"context"
	"slices"
	"sync"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// CertSource is a fake workloadidentity.CertSource. It returns a canned set of
// X.509-SVIDs or a canned error, counts calls, records the workloads it was
// asked about, and parks its calls while its Gate is closed.
//
// Set the fields before the fake is used. Use the setters to change behaviour
// while the fake is live; the fields themselves are not safe to write once a
// call can be in flight.
type CertSource struct {
	Gate

	// Result is returned by X509SVIDs when Func and Err are nil. A copy of the
	// slice is returned, so a caller mutating what it got cannot corrupt the
	// canned value. The elements are shared.
	Result []*x509svid.SVID
	// Err, when non-nil and Func is nil, is returned by X509SVIDs together with
	// a nil slice.
	Err error
	// Func, when non-nil, wins over Result and Err: X509SVIDs returns whatever
	// it returns, uncopied.
	Func func(ctx context.Context, w *workloadidentity.Workload) ([]*x509svid.SVID, error)

	mu        sync.Mutex
	calls     int
	workloads []*workloadidentity.Workload
}

// X509SVIDs records w and returns a copy of the canned slice, the canned error,
// or whatever Func returns.
//
// It parks at the Gate first and returns the Gate's error unchanged. A call that
// arrives with a done ctx, or that is woken by ctx rather than by Release, is
// never counted and its workload is never recorded. A parked call is not counted
// while it is parked; it counts and records itself once Release wakes it and it
// is next scheduled, which can be after Release has returned. Use WaitForBlocked
// to observe a parked call, and observe the call's own return before asserting on
// Calls or Workloads.
func (s *CertSource) X509SVIDs(ctx context.Context, w *workloadidentity.Workload) ([]*x509svid.SVID, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.calls++
	s.workloads = append(s.workloads, w)
	fn, result, err := s.Func, s.Result, s.Err
	s.mu.Unlock()

	if fn != nil {
		return fn(ctx, w)
	}
	if err != nil {
		return nil, err
	}
	return slices.Clone(result), nil
}

// Calls reports how many times X509SVIDs has run past the Gate. A call woken by
// Release is counted when it is next scheduled, not when Release returns.
func (s *CertSource) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// Workloads returns a copy of the workloads X509SVIDs was called with, in call
// order, so it is safe to read while another goroutine is calling the fake.
func (s *CertSource) Workloads() []*workloadidentity.Workload {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.workloads)
}

// SetResult replaces the canned X.509-SVIDs and error while the fake is live.
func (s *CertSource) SetResult(svids []*x509svid.SVID, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Result = svids
	s.Err = err
}

var _ workloadidentity.CertSource = &CertSource{}
