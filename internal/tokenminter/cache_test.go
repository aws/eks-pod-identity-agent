package tokenminter

import (
	"context"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity/fake"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// clockAt returns a clock whose value the test can advance.
func clockAt(t *time.Time) func() time.Time {
	return func() time.Time { return *t }
}

// newTestMinter builds a CachedMinter over a fake minter with the janitor
// disabled, so a test drives expiry through the injected clock and invokes
// onRefresh directly rather than racing the background sweep.
//
// The fake is pkg/workloadidentity/fake.TokenMinter, the same fake the other
// tiers use, rather than one written for this package: CachedMinter decorates a
// workloadidentity.TokenMinter, so the shared fake is exactly the seam.
func newTestMinter(raw workloadidentity.TokenMinter, now func() time.Time) *CachedMinter {
	return newCachedMinter(raw, CachedMinterOpts{
		MaxCacheSize:    10,
		CleanupInterval: -1,
		now:             now,
	})
}

// TestMint_Miss_MintsAndCaches proves the first mint for a pod calls the API and
// returns the token.
func TestMint_Miss_MintsAndCaches(t *testing.T) {
	g := NewWithT(t)

	clock := time.Now()
	raw := &fake.TokenMinter{Result: &workloadidentity.ProjectedToken{Token: "t1", ExpiresAt: clock.Add(time.Hour)}}
	m := newTestMinter(raw, clockAt(&clock))

	got, err := m.Mint(context.Background(), testWorkload())

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got.Token).To(Equal("t1"))
	g.Expect(raw.Calls()).To(Equal(1))
}

// TestMint_CachedAmpleLife_Reused proves a second lookup while the cached token
// has ample life is served from cache without a second API call.
func TestMint_CachedAmpleLife_Reused(t *testing.T) {
	g := NewWithT(t)

	clock := time.Now()
	raw := &fake.TokenMinter{Result: &workloadidentity.ProjectedToken{Token: "t1", ExpiresAt: clock.Add(time.Hour)}}
	m := newTestMinter(raw, clockAt(&clock))
	w := testWorkload()

	_, err := m.Mint(context.Background(), w)
	g.Expect(err).NotTo(HaveOccurred())

	// Advance a little, still well within the token's life.
	clock = clock.Add(time.Minute)

	got, err := m.Mint(context.Background(), w)

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got.Token).To(Equal("t1"))
	g.Expect(raw.Calls()).To(Equal(1), "cache hit must not mint again")
}

// TestMint_CachedNearExpiry_Reminted proves a cached token with less than the
// minimum remaining life is re-minted rather than served.
func TestMint_CachedNearExpiry_Reminted(t *testing.T) {
	g := NewWithT(t)

	clock := time.Now()
	raw := &fake.TokenMinter{Func: func(_ context.Context, _ *workloadidentity.Workload) (*workloadidentity.ProjectedToken, error) {
		return &workloadidentity.ProjectedToken{Token: "fresh", ExpiresAt: clock.Add(time.Hour)}, nil
	}}
	m := newTestMinter(raw, clockAt(&clock))
	w := testWorkload()

	_, err := m.Mint(context.Background(), w)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(raw.Calls()).To(Equal(1))

	// Advance to inside the minimum-remaining floor of the first token's expiry.
	clock = clock.Add(time.Hour - 5*time.Second)

	got, err := m.Mint(context.Background(), w)

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got.Token).To(Equal("fresh"))
	g.Expect(raw.Calls()).To(Equal(2), "near-expiry token must be re-minted")
}

// TestMint_TooShortLived_Rejected proves a freshly minted token with too little
// life is a failed mint and is not cached.
func TestMint_TooShortLived_Rejected(t *testing.T) {
	g := NewWithT(t)

	clock := time.Now()
	raw := &fake.TokenMinter{Result: &workloadidentity.ProjectedToken{Token: "brief", ExpiresAt: clock.Add(5 * time.Second)}}
	m := newTestMinter(raw, clockAt(&clock))
	w := testWorkload()

	_, err := m.Mint(context.Background(), w)
	g.Expect(err).To(MatchError(wierrors.ErrTokenMintFailed))

	_, ok := m.cache.Get(w.PodUID)
	g.Expect(ok).To(BeFalse(), "a too-short token must not be cached")
}

// TestMint_NilWorkload_Errors proves an empty workload is refused before any API
// call.
func TestMint_NilWorkload_Errors(t *testing.T) {
	g := NewWithT(t)

	clock := time.Now()
	raw := &fake.TokenMinter{}
	m := newTestMinter(raw, clockAt(&clock))

	_, err := m.Mint(context.Background(), &workloadidentity.Workload{})

	g.Expect(err).To(MatchError(wierrors.ErrTokenMintFailed))
	g.Expect(raw.Calls()).To(Equal(0))
}

// TestMint_Concurrent_SingleFlight proves concurrent lookups for one pod, such
// as an X.509 and a JWT stream opening at once, collapse onto a single mint.
//
// The fake's Gate is what makes this deterministic rather than timed: the one
// mint that reaches the fake parks there, so no token can be cached while the
// other callers arrive. Every caller therefore has to go through the shared
// singleflight call, and a second mint would be a real failure rather than a
// scheduling accident.
func TestMint_Concurrent_SingleFlight(t *testing.T) {
	g := NewWithT(t)

	clock := time.Now()
	raw := &fake.TokenMinter{Result: &workloadidentity.ProjectedToken{Token: "shared", ExpiresAt: clock.Add(time.Hour)}}
	raw.Block()
	m := newTestMinter(raw, clockAt(&clock))
	w := testWorkload()

	const n = 8
	results := make(chan *workloadidentity.ProjectedToken, n)
	errs := make(chan error, n)
	var started sync.WaitGroup
	started.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			started.Done()
			tok, err := m.Mint(context.Background(), w)
			results <- tok
			errs <- err
		}()
	}

	// Every caller has entered Mint, and the one mint that got through is parked
	// at the gate, so releasing it now cannot let an early finisher serve a
	// cached token to a late arrival.
	started.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	g.Expect(raw.WaitForBlocked(ctx, 1)).To(Succeed())
	raw.Release()

	for i := 0; i < n; i++ {
		g.Expect(<-errs).NotTo(HaveOccurred())
		g.Expect(<-results).To(Equal(raw.Result))
	}
	g.Expect(raw.Calls()).To(Equal(1), "concurrent lookups must share one mint")
}

// TestOnRefresh_Success_UpdatesCache proves a background refresh re-mints and
// replaces the cached token.
func TestOnRefresh_Success_UpdatesCache(t *testing.T) {
	g := NewWithT(t)

	clock := time.Now()
	current := "first"
	raw := &fake.TokenMinter{Func: func(_ context.Context, _ *workloadidentity.Workload) (*workloadidentity.ProjectedToken, error) {
		return &workloadidentity.ProjectedToken{Token: current, ExpiresAt: clock.Add(time.Hour)}, nil
	}}
	m := newTestMinter(raw, clockAt(&clock))
	w := testWorkload()

	_, err := m.Mint(context.Background(), w)
	g.Expect(err).NotTo(HaveOccurred())

	current = "second"
	entry, ok := m.cache.Get(w.PodUID)
	g.Expect(ok).To(BeTrue())
	m.onRefresh(w.PodUID, entry)

	refreshed, ok := m.cache.Get(w.PodUID)
	g.Expect(ok).To(BeTrue())
	g.Expect(refreshed.token.Token).To(Equal("second"))
	g.Expect(raw.Calls()).To(Equal(2))
}

// TestOnRefresh_Forbidden_DropsEntry proves a non-retryable refresh failure
// evicts the entry rather than keeping a token that can never be renewed.
func TestOnRefresh_Forbidden_DropsEntry(t *testing.T) {
	g := NewWithT(t)

	clock := time.Now()
	calls := 0
	raw := &fake.TokenMinter{Func: func(_ context.Context, _ *workloadidentity.Workload) (*workloadidentity.ProjectedToken, error) {
		calls++
		if calls == 1 {
			return &workloadidentity.ProjectedToken{Token: "first", ExpiresAt: clock.Add(time.Hour)}, nil
		}
		return nil, wierrors.ErrTokenMintForbidden
	}}
	m := newTestMinter(raw, clockAt(&clock))
	w := testWorkload()

	_, err := m.Mint(context.Background(), w)
	g.Expect(err).NotTo(HaveOccurred())

	entry, ok := m.cache.Get(w.PodUID)
	g.Expect(ok).To(BeTrue())
	m.onRefresh(w.PodUID, entry)

	_, ok = m.cache.Get(w.PodUID)
	g.Expect(ok).To(BeFalse(), "a forbidden renewal must drop the entry")
}

// TestOnRefresh_RetryableFailure_KeepsToken proves a transient refresh failure
// leaves the existing token in place rather than dropping a live credential.
func TestOnRefresh_RetryableFailure_KeepsToken(t *testing.T) {
	g := NewWithT(t)

	clock := time.Now()
	calls := 0
	raw := &fake.TokenMinter{Func: func(_ context.Context, _ *workloadidentity.Workload) (*workloadidentity.ProjectedToken, error) {
		calls++
		if calls == 1 {
			return &workloadidentity.ProjectedToken{Token: "first", ExpiresAt: clock.Add(time.Hour)}, nil
		}
		return nil, wierrors.ErrTokenMintFailed
	}}
	m := newTestMinter(raw, clockAt(&clock))
	w := testWorkload()

	_, err := m.Mint(context.Background(), w)
	g.Expect(err).NotTo(HaveOccurred())

	entry, ok := m.cache.Get(w.PodUID)
	g.Expect(ok).To(BeTrue())
	m.onRefresh(w.PodUID, entry)

	kept, ok := m.cache.Get(w.PodUID)
	g.Expect(ok).To(BeTrue(), "a transient renewal failure must keep the existing token")
	g.Expect(kept.token.Token).To(Equal("first"))
}
