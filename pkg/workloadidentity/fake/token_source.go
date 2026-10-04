package fake

import (
	"context"
	"slices"
	"sync"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// JWTSVIDRequest is one recorded call to TokenSource.JWTSVIDs.
type JWTSVIDRequest struct {
	// Workload is the workload the JWT-SVIDs were requested for.
	Workload *workloadidentity.Workload
	// Audiences is a copy of the audiences the caller asked for, so a caller
	// reusing its slice cannot rewrite what the fake recorded.
	Audiences []string
}

// TokenSource is a fake workloadidentity.TokenSource. It returns a canned set of
// JWT-SVIDs or a canned error, counts calls, records every request, and parks its
// calls while its Gate is closed.
//
// Set the fields before the fake is used. Use the setters to change behaviour
// while the fake is live; the fields themselves are not safe to write once a
// call can be in flight.
type TokenSource struct {
	Gate

	// Result is returned by JWTSVIDs when Func and Err are nil, regardless of
	// how many audiences were asked for. A copy of the slice is returned, so a
	// caller mutating what it got cannot corrupt the canned value. The elements
	// are shared. Use Func to vary the answer per audience.
	Result []*jwtsvid.SVID
	// Err, when non-nil and Func is nil, is returned by JWTSVIDs together with a
	// nil slice.
	Err error
	// Func, when non-nil, wins over Result and Err: JWTSVIDs returns whatever it
	// returns, uncopied.
	Func func(ctx context.Context, w *workloadidentity.Workload, audiences []string) ([]*jwtsvid.SVID, error)

	mu       sync.Mutex
	calls    int
	requests []JWTSVIDRequest
}

// JWTSVIDs records the request and returns a copy of the canned slice, the
// canned error, or whatever Func returns. Func is handed the caller's audiences,
// not the recorded copy.
//
// It parks at the Gate first and returns the Gate's error unchanged. A call that
// arrives with a done ctx, or that is woken by ctx rather than by Release, is
// never counted and its request is never recorded. A parked call is not counted
// while it is parked; it counts and records itself once Release wakes it and it
// is next scheduled, which can be after Release has returned. Use WaitForBlocked
// to observe a parked call, and observe the call's own return before asserting on
// Calls or Requests.
func (s *TokenSource) JWTSVIDs(ctx context.Context, w *workloadidentity.Workload, audiences []string) ([]*jwtsvid.SVID, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.calls++
	s.requests = append(s.requests, JWTSVIDRequest{Workload: w, Audiences: slices.Clone(audiences)})
	fn, result, err := s.Func, s.Result, s.Err
	s.mu.Unlock()

	if fn != nil {
		return fn(ctx, w, audiences)
	}
	if err != nil {
		return nil, err
	}
	return slices.Clone(result), nil
}

// Calls reports how many times JWTSVIDs has run past the Gate. A call woken by
// Release is counted when it is next scheduled, not when Release returns.
func (s *TokenSource) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// Requests returns a copy of the recorded requests, in call order, so it is safe
// to read while another goroutine is calling the fake. Each request's Audiences
// is copied on the way out as well as at call time, so a test that mutates an
// element of what it got cannot rewrite what a later Requests reports. A nil
// Audiences stays nil, so a call made with no audiences stays distinguishable
// from one made with an empty slice.
func (s *TokenSource) Requests() []JWTSVIDRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	requests := slices.Clone(s.requests)
	for i := range requests {
		requests[i].Audiences = slices.Clone(requests[i].Audiences)
	}
	return requests
}

// SetResult replaces the canned JWT-SVIDs and error while the fake is live.
func (s *TokenSource) SetResult(svids []*jwtsvid.SVID, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Result = svids
	s.Err = err
}

var _ workloadidentity.TokenSource = &TokenSource{}
