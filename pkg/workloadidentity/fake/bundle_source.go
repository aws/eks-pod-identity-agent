package fake

import (
	"context"
	"slices"
	"sync"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// BundleSource is a fake workloadidentity.BundleSource. OwnTrustDomain,
// X509Bundles, JWTBundles and JWTSource pass the Gate, then answer from a canned
// value or error, and all but OwnTrustDomain from a func first. Lease never
// parks and tracks the canned leases it hands out. Every counted call records
// its workload in WorkloadRequests. Canned answers treat every workload alike,
// nil included; a test needing per-workload answers sets a func. Set the fields
// before first use and change them later only through the setters. The funcs
// have no setter; to vary one, close over the test's state.
type BundleSource struct {
	Gate

	// TrustDomain is returned by OwnTrustDomain when OwnTrustDomainErr is nil.
	TrustDomain string
	// OwnTrustDomainErr, when non-nil, is returned by OwnTrustDomain together
	// with the empty domain.
	OwnTrustDomainErr error

	// X509 is returned by X509Bundles when X509Func and X509Err are nil, as a
	// copy the caller cannot use to mutate the fake.
	X509 map[string][][]byte
	// X509Err, when non-nil and X509Func is nil, is returned by X509Bundles
	// together with a nil map.
	X509Err error
	// X509Func, when non-nil, wins over X509 and X509Err: X509Bundles hands it
	// the call's ctx and workload and returns whatever it returns, uncopied.
	X509Func func(ctx context.Context, w *workloadidentity.Workload) (map[string][][]byte, error)

	// JWT is returned by JWTBundles when JWTFunc and JWTErr are nil, as a copy
	// the caller cannot use to mutate the fake.
	JWT map[string][]byte
	// JWTErr, when non-nil and JWTFunc is nil, is returned by JWTBundles
	// together with a nil map.
	JWTErr error
	// JWTFunc, when non-nil, wins over JWT and JWTErr: JWTBundles hands it the
	// call's ctx and workload and returns whatever it returns, uncopied.
	JWTFunc func(ctx context.Context, w *workloadidentity.Workload) (map[string][]byte, error)

	// JWTSourceResult is returned by JWTSource when JWTSourceFunc and
	// JWTSourceErr are nil; the method holds the shorter name. A *jwtbundle.Set
	// or *jwtbundle.Bundle comes back as a copy taken at call time, so it stays
	// point-in-time like the real one. Any other Source comes back as is.
	JWTSourceResult jwtbundle.Source
	// JWTSourceErr, when non-nil and JWTSourceFunc is nil, is returned by
	// JWTSource together with a nil source.
	JWTSourceErr error
	// JWTSourceFunc, when non-nil, wins over JWTSourceResult and JWTSourceErr:
	// JWTSource hands it the call's ctx and workload and returns whatever it
	// returns, uncopied.
	JWTSourceFunc func(ctx context.Context, w *workloadidentity.Workload) (jwtbundle.Source, error)

	// LeaseErr, when non-nil and LeaseFunc is nil, is returned by Lease
	// together with a nil release func. While it is nil, Lease hands out a
	// canned lease for any workload, nil included.
	LeaseErr error
	// LeaseFunc, when non-nil, wins over LeaseErr: Lease hands it the call's ctx
	// and workload and returns whatever it returns. The fake does not track the
	// leases it hands out, so LiveLeases, Released and ReleaseCalls skip them.
	LeaseFunc func(ctx context.Context, w *workloadidentity.Workload) (release func(), err error)

	mu                  sync.Mutex
	ownTrustDomainCalls int
	x509BundlesCalls    int
	jwtBundlesCalls     int
	jwtSourceCalls      int
	leaseCalls          int
	// leases holds the canned leases not yet released. A lease whose ctx has
	// ended stays here until its AfterFunc runs, but already counts as released.
	leases           map[*bundleLease]struct{}
	released         int
	releaseCalls     int
	workloadRequests []*workloadidentity.Workload
}

// bundleLease is one canned lease handed out by BundleSource.Lease. It is only
// touched under the BundleSource's mu.
type bundleLease struct {
	ctx  context.Context
	stop func() bool
}

// OwnTrustDomain passes the Gate, then returns OwnTrustDomainErr with the empty
// domain, or TrustDomain. A call its ctx turns away is not counted or recorded;
// a released one is counted when next scheduled, maybe after Release returns, so
// wait for it to return before reading OwnTrustDomainCalls or WorkloadRequests.
func (s *BundleSource) OwnTrustDomain(ctx context.Context, w *workloadidentity.Workload) (string, error) {
	if err := s.enter(ctx); err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.ownTrustDomainCalls++
	s.workloadRequests = append(s.workloadRequests, w)
	if s.OwnTrustDomainErr != nil {
		return "", s.OwnTrustDomainErr
	}
	return s.TrustDomain, nil
}

// X509Bundles passes the Gate, then returns X509Func's result, X509Err or a
// deep copy of X509. A call its ctx turns away is not counted or recorded; a
// released one is counted when next scheduled, maybe after Release returns, so
// wait for it to return before reading X509BundlesCalls or WorkloadRequests.
func (s *BundleSource) X509Bundles(ctx context.Context, w *workloadidentity.Workload) (map[string][][]byte, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}

	var (
		fn      func(context.Context, *workloadidentity.Workload) (map[string][][]byte, error)
		bundles map[string][][]byte
		err     error
	)
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.x509BundlesCalls++
		s.workloadRequests = append(s.workloadRequests, w)
		fn, bundles, err = s.X509Func, s.X509, s.X509Err
		if fn == nil && err == nil {
			bundles = copyX509Bundles(bundles)
		}
	}()

	if fn != nil {
		return fn(ctx, w)
	}
	if err != nil {
		return nil, err
	}
	return bundles, nil
}

// JWTBundles passes the Gate, then returns JWTFunc's result, JWTErr or a deep
// copy of JWT. A call its ctx turns away is not counted or recorded; a released
// one is counted when next scheduled, maybe after Release returns, so wait for
// it to return before reading JWTBundlesCalls or WorkloadRequests.
func (s *BundleSource) JWTBundles(ctx context.Context, w *workloadidentity.Workload) (map[string][]byte, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}

	var (
		fn      func(context.Context, *workloadidentity.Workload) (map[string][]byte, error)
		bundles map[string][]byte
		err     error
	)
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.jwtBundlesCalls++
		s.workloadRequests = append(s.workloadRequests, w)
		fn, bundles, err = s.JWTFunc, s.JWT, s.JWTErr
		if fn == nil && err == nil {
			bundles = copyJWTBundles(bundles)
		}
	}()

	if fn != nil {
		return fn(ctx, w)
	}
	if err != nil {
		return nil, err
	}
	return bundles, nil
}

// JWTSource passes the Gate, then returns JWTSourceFunc's result, JWTSourceErr
// or a copy of JWTSourceResult. A call its ctx turns away is not counted or
// recorded; a released one is counted when next scheduled, so wait for it to
// return before reading JWTSourceCalls or WorkloadRequests.
func (s *BundleSource) JWTSource(ctx context.Context, w *workloadidentity.Workload) (jwtbundle.Source, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}

	var (
		fn     func(context.Context, *workloadidentity.Workload) (jwtbundle.Source, error)
		source jwtbundle.Source
		err    error
	)
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.jwtSourceCalls++
		s.workloadRequests = append(s.workloadRequests, w)
		fn, source, err = s.JWTSourceFunc, s.JWTSourceResult, s.JWTSourceErr
		if fn == nil && err == nil {
			source = copyJWTSource(source)
		}
	}()

	if fn != nil {
		return fn(ctx, w)
	}
	if err != nil {
		return nil, err
	}
	return source, nil
}

// Lease counts the call and records w, then returns LeaseFunc's result, LeaseErr
// or a canned lease. It takes a ctx but never parks at the Gate. A canned lease
// is released once, by its release func or its ctx ending, whichever is first,
// so a lease taken under a done ctx is never live.
func (s *BundleSource) Lease(ctx context.Context, w *workloadidentity.Workload) (func(), error) {
	var (
		fn      func(context.Context, *workloadidentity.Workload) (func(), error)
		err     error
		release func()
	)
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.leaseCalls++
		s.workloadRequests = append(s.workloadRequests, w)
		fn, err = s.LeaseFunc, s.LeaseErr
		if fn == nil && err == nil {
			release = s.newLeaseLocked(ctx)
		}
	}()

	if fn != nil {
		return fn(ctx, w)
	}
	if err != nil {
		return nil, err
	}
	return release, nil
}

// newLeaseLocked records a live canned lease and returns its release func. The
// caller must hold s.mu. Registering the AfterFunc under it cannot deadlock,
// because AfterFunc always runs its func on a goroutine of its own.
func (s *BundleSource) newLeaseLocked(ctx context.Context) func() {
	l := &bundleLease{ctx: ctx}
	l.stop = context.AfterFunc(ctx, func() { s.endLease(l, false) })
	if s.leases == nil {
		s.leases = make(map[*bundleLease]struct{})
	}
	s.leases[l] = struct{}{}
	return func() { s.endLease(l, true) }
}

// endLease releases l unless it is already released. byFunc marks the call as
// the lease's release func, which is credited in ReleaseCalls only when l's ctx
// has not ended first, since then the ctx is what released it.
func (s *BundleSource) endLease(l *bundleLease, byFunc bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, live := s.leases[l]; !live {
		return
	}
	delete(s.leases, l)
	s.released++
	if byFunc && l.ctx.Err() == nil {
		s.releaseCalls++
	}
	l.stop()
}

// OwnTrustDomainCalls reports how many times OwnTrustDomain has run past the
// Gate. A call woken by Release is counted when it is next scheduled, not when
// Release returns.
func (s *BundleSource) OwnTrustDomainCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ownTrustDomainCalls
}

// X509BundlesCalls reports how many times X509Bundles has run past the Gate. A
// call woken by Release is counted when it is next scheduled, not when Release
// returns.
func (s *BundleSource) X509BundlesCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.x509BundlesCalls
}

// JWTBundlesCalls reports how many times JWTBundles has run past the Gate. A
// call woken by Release is counted when it is next scheduled, not when Release
// returns.
func (s *BundleSource) JWTBundlesCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jwtBundlesCalls
}

// JWTSourceCalls reports how many times JWTSource has run past the Gate. A call
// woken by Release is counted when it is next scheduled, not when Release
// returns.
func (s *BundleSource) JWTSourceCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jwtSourceCalls
}

// LeaseCalls reports how many times Lease has been called, whichever of
// LeaseFunc, LeaseErr or a canned lease answered. A call is counted before
// LeaseFunc runs, so LeaseFunc sees its own call counted.
func (s *BundleSource) LeaseCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.leaseCalls
}

// LiveLeases reports how many canned leases are not yet released. A lease stops
// counting the moment its ctx reports an error, without waiting for the
// AfterFunc, so it is exact straight after a test cancels that ctx.
func (s *BundleSource) LiveLeases() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	live, _ := s.leaseCountsLocked()
	return live
}

// Released reports how many canned leases have been released, by their release
// func or their ctx, counting each lease once however often either happens.
// Every canned lease is counted by exactly one of LiveLeases and Released.
func (s *BundleSource) Released() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, released := s.leaseCountsLocked()
	return released
}

// ReleaseCalls reports how many canned leases were released by their release
// func, counting each once. Calling the func of a lease whose ctx had already
// ended counts in Released only, because the ctx released it first.
func (s *BundleSource) ReleaseCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.releaseCalls
}

// leaseCountsLocked splits the canned leases handed out into live and released,
// treating one whose ctx has ended as released before its AfterFunc runs. The
// caller must hold s.mu.
func (s *BundleSource) leaseCountsLocked() (live, released int) {
	for l := range s.leases {
		if l.ctx.Err() == nil {
			live++
		}
	}
	return live, s.released + len(s.leases) - live
}

// WorkloadRequests returns a copy of the workload every counted call to any of
// the five methods was handed, pointers as passed, in the order counted. A call
// parked on the Gate is recorded when the Gate lets it through, so it can land
// behind calls made later.
func (s *BundleSource) WorkloadRequests() []*workloadidentity.Workload {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.workloadRequests)
}

// SetTrustDomain replaces the domain and error OwnTrustDomain returns while the
// fake is live.
func (s *BundleSource) SetTrustDomain(domain string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TrustDomain = domain
	s.OwnTrustDomainErr = err
}

// SetX509Bundles replaces the canned X.509 authorities and error while the fake
// is live. The map is not copied on the way in, so the caller must not keep
// mutating it.
func (s *BundleSource) SetX509Bundles(bundles map[string][][]byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.X509 = bundles
	s.X509Err = err
}

// SetJWTBundles replaces the canned JWK Set bytes and error while the fake is
// live. The map is not copied on the way in, so the caller must not keep mutating
// it.
func (s *BundleSource) SetJWTBundles(bundles map[string][]byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.JWT = bundles
	s.JWTErr = err
}

// SetJWTSource replaces the canned JWT source and error while the fake is live.
// The source is not copied on the way in, so a change made to it afterwards
// reaches later calls but not a copy JWTSource has already returned.
func (s *BundleSource) SetJWTSource(source jwtbundle.Source, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.JWTSourceResult = source
	s.JWTSourceErr = err
}

// SetLease replaces the canned Lease error while the fake is live. Leases
// already handed out are unaffected.
func (s *BundleSource) SetLease(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LeaseErr = err
}

// copyX509Bundles copies a trust domain keyed set of DER authorities down to the
// bytes. A nil map copies to a nil map, so an unset canned value stays
// distinguishable from an empty one.
func copyX509Bundles(in map[string][][]byte) map[string][][]byte {
	if in == nil {
		return nil
	}
	out := make(map[string][][]byte, len(in))
	for domain, authorities := range in {
		if authorities == nil {
			out[domain] = nil
			continue
		}
		copied := make([][]byte, len(authorities))
		for i, der := range authorities {
			copied[i] = slices.Clone(der)
		}
		out[domain] = copied
	}
	return out
}

// copyJWTBundles copies a trust domain keyed set of JWK Set documents down to the
// bytes. A nil map copies to a nil map, so an unset canned value stays
// distinguishable from an empty one.
func copyJWTBundles(in map[string][]byte) map[string][]byte {
	if in == nil {
		return nil
	}
	out := make(map[string][]byte, len(in))
	for domain, jwks := range in {
		out[domain] = slices.Clone(jwks)
	}
	return out
}

// copyJWTSource snapshots a *jwtbundle.Set or *jwtbundle.Bundle down to each
// bundle's authority map; the keys themselves are shared. Any other source, a
// nil or typed-nil one included, is returned as is, since there is no way to
// copy it.
func copyJWTSource(in jwtbundle.Source) jwtbundle.Source {
	switch in := in.(type) {
	case *jwtbundle.Set:
		if in == nil {
			return in
		}
		bundles := in.Bundles()
		for i, bundle := range bundles {
			bundles[i] = bundle.Clone()
		}
		return jwtbundle.NewSet(bundles...)
	case *jwtbundle.Bundle:
		if in == nil {
			return in
		}
		return in.Clone()
	default:
		return in
	}
}

var _ workloadidentity.BundleSource = &BundleSource{}
