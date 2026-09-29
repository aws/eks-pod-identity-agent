package fake

import (
	"context"
	"crypto"
	"errors"
	"slices"
	"sync"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// AuthorityKey identifies one JWT verification key, and is what
// BundleSource.JWTAuthority is keyed and recorded by.
type AuthorityKey struct {
	// TrustDomain is the trust domain the key belongs to.
	TrustDomain string
	// KeyID is the JWK key ID within that trust domain.
	KeyID string
}

// ErrAuthorityNotFound is returned by BundleSource.JWTAuthority when the
// requested key is not in Authorities and no canned error or func is set. It is
// the fake's own sentinel rather than a member of the taxonomy in pkg/errors, so
// a test can tell a lookup miss in the fake apart from an error a real
// implementation would return.
var ErrAuthorityNotFound = errors.New("fake: no JWT authority for trust domain and key id")

// BundleSource is a fake workloadidentity.BundleSource. X509Bundles, JWTBundles
// and JWTAuthority each have a canned value, error, func and call counter; Lease
// has an error, a func and lease counters; OwnTrustDomain has only TrustDomain
// and a counter. Canned answers treat every provider ARN alike, even the empty
// one a real implementation rejects; a test needing per-provider answers sets a
// func. Only X509Bundles and JWTBundles go through the Gate. Set the fields
// before first use and change them later only through the setters. The funcs
// have no setter; to vary one, close over the test's state.
type BundleSource struct {
	Gate

	// TrustDomain is returned by OwnTrustDomain.
	TrustDomain string

	// X509 is returned by X509Bundles when X509Func and X509Err are nil, as a
	// copy the caller cannot use to mutate the fake.
	X509 map[string][][]byte
	// X509Err, when non-nil and X509Func is nil, is returned by X509Bundles
	// together with a nil map.
	X509Err error
	// X509Func, when non-nil, wins over X509 and X509Err: X509Bundles hands it
	// the call's ctx and provider ARN and returns whatever it returns, uncopied.
	X509Func func(ctx context.Context, providerArn string) (map[string][][]byte, error)

	// JWT is returned by JWTBundles when JWTFunc and JWTErr are nil, as a copy
	// the caller cannot use to mutate the fake.
	JWT map[string][]byte
	// JWTErr, when non-nil and JWTFunc is nil, is returned by JWTBundles
	// together with a nil map.
	JWTErr error
	// JWTFunc, when non-nil, wins over JWT and JWTErr: JWTBundles hands it the
	// call's ctx and provider ARN and returns whatever it returns, uncopied.
	JWTFunc func(ctx context.Context, providerArn string) (map[string][]byte, error)

	// Authorities is the lookup table for JWTAuthority. It is keyed without the
	// provider, so every provider resolves the same keys.
	Authorities map[AuthorityKey]crypto.PublicKey
	// AuthorityErr, when non-nil and AuthorityFunc is nil, is returned by
	// JWTAuthority for every key, together with a nil public key.
	AuthorityErr error
	// AuthorityFunc, when non-nil, wins over Authorities and AuthorityErr:
	// JWTAuthority hands it all three arguments and returns whatever it
	// returns.
	AuthorityFunc func(providerArn, trustDomain, keyID string) (crypto.PublicKey, error)

	// LeaseErr, when non-nil and LeaseFunc is nil, is returned by Lease
	// together with a nil release func. While it is nil, Lease hands out a
	// canned lease for any provider ARN, the empty one included.
	LeaseErr error
	// LeaseFunc, when non-nil, wins over LeaseErr: Lease hands it the call's ctx
	// and provider ARN and returns whatever it returns. The fake does not track
	// the leases it hands out, so LiveLeases, Released and ReleaseCalls skip them.
	LeaseFunc func(ctx context.Context, providerArn string) (release func(), err error)

	mu                  sync.Mutex
	ownTrustDomainCalls int
	x509BundlesCalls    int
	jwtBundlesCalls     int
	jwtAuthorityCalls   int
	leaseCalls          int
	// leases holds the canned leases not yet released. A lease whose ctx has
	// ended stays here until its AfterFunc runs, but already counts as released.
	leases            map[*bundleLease]struct{}
	released          int
	releaseCalls      int
	authorityRequests []AuthorityKey
	providerRequests  []string
}

// bundleLease is one canned lease handed out by BundleSource.Lease. It is only
// touched under the BundleSource's mu.
type bundleLease struct {
	ctx  context.Context
	stop func() bool
}

// OwnTrustDomain records providerArn and returns TrustDomain, whichever provider
// was named. It takes no ctx, so it does not go through the Gate; it counts and
// records on every call.
func (s *BundleSource) OwnTrustDomain(providerArn string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ownTrustDomainCalls++
	s.providerRequests = append(s.providerRequests, providerArn)
	return s.TrustDomain
}

// X509Bundles passes the Gate, then returns X509Func's result, X509Err or a
// deep copy of X509. A call its ctx turns away is not counted or recorded; a
// released one is counted when next scheduled, maybe after Release returns, so
// wait for it to return before reading X509BundlesCalls or ProviderRequests.
func (s *BundleSource) X509Bundles(ctx context.Context, providerArn string) (map[string][][]byte, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.x509BundlesCalls++
	s.providerRequests = append(s.providerRequests, providerArn)
	fn, bundles, err := s.X509Func, s.X509, s.X509Err
	if fn == nil && err == nil {
		bundles = copyX509Bundles(bundles)
	}
	s.mu.Unlock()

	if fn != nil {
		return fn(ctx, providerArn)
	}
	if err != nil {
		return nil, err
	}
	return bundles, nil
}

// JWTBundles passes the Gate, then returns JWTFunc's result, JWTErr or a deep
// copy of JWT. A call its ctx turns away is not counted or recorded; a released
// one is counted when next scheduled, maybe after Release returns, so wait for
// it to return before reading JWTBundlesCalls or ProviderRequests.
func (s *BundleSource) JWTBundles(ctx context.Context, providerArn string) (map[string][]byte, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.jwtBundlesCalls++
	s.providerRequests = append(s.providerRequests, providerArn)
	fn, bundles, err := s.JWTFunc, s.JWT, s.JWTErr
	if fn == nil && err == nil {
		bundles = copyJWTBundles(bundles)
	}
	s.mu.Unlock()

	if fn != nil {
		return fn(ctx, providerArn)
	}
	if err != nil {
		return nil, err
	}
	return bundles, nil
}

// JWTAuthority counts the call and records its provider and key, misses
// included. It answers from AuthorityFunc, else AuthorityErr, else Authorities,
// and returns ErrAuthorityNotFound for a key Authorities lacks.
func (s *BundleSource) JWTAuthority(providerArn, trustDomain, keyID string) (crypto.PublicKey, error) {
	key := AuthorityKey{TrustDomain: trustDomain, KeyID: keyID}

	s.mu.Lock()
	s.jwtAuthorityCalls++
	s.authorityRequests = append(s.authorityRequests, key)
	s.providerRequests = append(s.providerRequests, providerArn)
	fn, err := s.AuthorityFunc, s.AuthorityErr
	authority, found := s.Authorities[key]
	s.mu.Unlock()

	if fn != nil {
		return fn(providerArn, trustDomain, keyID)
	}
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrAuthorityNotFound
	}
	return authority, nil
}

// Lease counts the call and records providerArn, then returns LeaseFunc's
// result, LeaseErr or a canned lease. It takes a ctx but never parks at the
// Gate. A canned lease is released once, by its release func or its ctx ending,
// whichever is first, so a lease taken under a done ctx is never live.
func (s *BundleSource) Lease(ctx context.Context, providerArn string) (func(), error) {
	s.mu.Lock()
	s.leaseCalls++
	s.providerRequests = append(s.providerRequests, providerArn)
	fn, err := s.LeaseFunc, s.LeaseErr
	var release func()
	if fn == nil && err == nil {
		release = s.newLeaseLocked(ctx)
	}
	s.mu.Unlock()

	if fn != nil {
		return fn(ctx, providerArn)
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

// OwnTrustDomainCalls reports how many times OwnTrustDomain has been called.
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

// JWTAuthorityCalls reports how many times JWTAuthority has been called.
func (s *BundleSource) JWTAuthorityCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jwtAuthorityCalls
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

// AuthorityRequests returns a copy of the keys JWTAuthority was asked for, in
// call order, so it is safe to read while another goroutine is calling the fake.
// The provider each lookup named is not part of the key; it is in
// ProviderRequests with every other method's.
func (s *BundleSource) AuthorityRequests() []AuthorityKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.authorityRequests)
}

// ProviderRequests returns a copy of the provider ARN of every counted call to
// any of the five methods, in the order counted. A call parked on the Gate is
// recorded when the Gate lets it through, so it can land behind calls made later.
func (s *BundleSource) ProviderRequests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.providerRequests)
}

// SetTrustDomain replaces the domain OwnTrustDomain returns while the fake is
// live.
func (s *BundleSource) SetTrustDomain(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TrustDomain = domain
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

// SetAuthorities replaces the JWTAuthority lookup table and canned error while
// the fake is live. The map is not copied on the way in, so the caller must not
// keep mutating it.
func (s *BundleSource) SetAuthorities(authorities map[AuthorityKey]crypto.PublicKey, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Authorities = authorities
	s.AuthorityErr = err
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

var _ workloadidentity.BundleSource = &BundleSource{}
