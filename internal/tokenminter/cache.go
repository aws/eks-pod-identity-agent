package tokenminter

// Per-pod caching and renewal, reusing the existing refresh machinery:
// internal/cache/expiring (the LRU+janitor the AWS-creds cache uses) for storage
// and background refresh, and a rate.Limiter to bound refresh traffic. Entries
// are keyed by pod UID with lifetimes taken from the API-returned expiry, and
// are dropped when the node-scoped pod store reports the pod deleted.

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cache/expiring"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

const (
	// defaultMinRemaining is the least life a cached token must have to be
	// served; below it, it is re-minted.
	defaultMinRemaining = 1 * time.Minute
	// defaultRenewFraction is the fraction of a token's life after which the
	// janitor re-mints it, keeping it warm for the session tier.
	defaultRenewFraction = 0.8
	// defaultCleanupInterval is the janitor sweep period.
	defaultCleanupInterval = 1 * time.Minute
	// defaultRenewalTimeout bounds one background re-mint. It stays under the
	// janitor's sweep period so a stalled mint cannot consume a whole sweep.
	defaultRenewalTimeout = 30 * time.Second
	// defaultRefreshQPS is the rate and the burst of the background re-mint
	// limiter. The burst is what binds in practice: a sweep drops the entries it
	// has no token for rather than waiting for one.
	defaultRefreshQPS = 2
	// minRefreshInterval floors the refresh delay so a short-lived token cannot
	// spin the janitor.
	minRefreshInterval = 1 * time.Second
)

// cacheEntry is one pod's cached token plus what a background refresh needs to
// re-mint without a caller.
//
// No stored context. The AWS-creds cache keeps the originating request's logger
// to carry its association ID into renewal logs; there is no equivalent value
// here, so a renewal running hours later would inherit nothing but that first
// caller's stale request fields. onRefresh builds its logger from the workload.
type cacheEntry struct {
	workload *workloadidentity.Workload
	token    *workloadidentity.ProjectedToken
}

// CachedMinter is the workloadidentity.TokenMinter the agent uses: it serves a
// cached token with ample life, mints otherwise, renews in the background, and
// drops a pod's token when the pod is deleted.
type CachedMinter struct {
	// raw is the uncached minter this decorates, apiMinter in production.
	raw     workloadidentity.TokenMinter
	cache   *expiring.Cache[string, cacheEntry]
	group   singleflight.Group
	limiter *rate.Limiter
	// pods is the node-scoped pod store, nil only in tests that skip presence checks.
	pods workloadidentity.PodStore
	// mu orders storeIfPresent against Invalidate, so a mint that finishes after
	// the pod's deletion callback cannot store its token again.
	mu sync.Mutex

	minRemaining   time.Duration
	renewFraction  float64
	renewalTimeout time.Duration

	// now is the clock, injectable so tests drive expiry without sleeping.
	now func() time.Time
}

// CachedMinterOpts configures a CachedMinter; every field takes a documented
// default when zero.
type CachedMinterOpts struct {
	// MaxCacheSize bounds cached tokens, one per pod. It has no default: the
	// value is --max-cache-size, the same per-node entry budget the AWS
	// credentials cache is given, since both caches hold one entry per pod on
	// the node. NewMinter rejects a non-positive value rather than substituting
	// one, because expiring.NewLru reads zero as unlimited.
	MaxCacheSize  int
	MinRemaining  time.Duration
	RenewFraction float64
	// CleanupInterval defaults when zero; a negative value disables the janitor
	// (used by unit tests of the lookup path).
	CleanupInterval time.Duration
	RenewalTimeout  time.Duration
	RefreshQPS      int
	// PodStore is the node-scoped pod store. NewMinter requires it and registers
	// Invalidate for its deletions, and the minter refuses to mint or store a
	// token for a pod it no longer holds. Nil, left only by tests that call
	// newCachedMinter directly, turns the presence checks off.
	PodStore workloadidentity.PodStore
	// now is the clock; defaults to time.Now. Set only in tests.
	now func() time.Time
}

// newCachedMinter builds a CachedMinter over an uncached minter. Shared by the
// exported wiring and by tests, which pass a fake minter and a controlled clock.
func newCachedMinter(raw workloadidentity.TokenMinter, opts CachedMinterOpts) *CachedMinter {
	if opts.MinRemaining <= 0 {
		opts.MinRemaining = defaultMinRemaining
	}
	if opts.RenewFraction <= 0 || opts.RenewFraction >= 1 {
		opts.RenewFraction = defaultRenewFraction
	}
	if opts.CleanupInterval == 0 {
		opts.CleanupInterval = defaultCleanupInterval
	}
	if opts.RenewalTimeout <= 0 {
		opts.RenewalTimeout = defaultRenewalTimeout
	}
	if opts.RefreshQPS <= 0 {
		opts.RefreshQPS = defaultRefreshQPS
	}
	if opts.now == nil {
		opts.now = time.Now
	}

	m := &CachedMinter{
		raw:            raw,
		cache:          expiring.NewLru[string, cacheEntry](opts.MaxCacheSize, expiring.NoExpiration, opts.CleanupInterval),
		limiter:        rate.NewLimiter(rate.Limit(opts.RefreshQPS), opts.RefreshQPS),
		pods:           opts.PodStore,
		minRemaining:   opts.MinRemaining,
		renewFraction:  opts.RenewFraction,
		renewalTimeout: opts.RenewalTimeout,
		now:            opts.now,
	}
	m.cache.OnRefresh(m.onRefresh)
	m.cache.OnEvicted(m.onEvicted)
	return m
}

// Mint serves a cached token with ample life or mints a fresh one. Concurrent
// calls for the same pod share a single mint. A pod gone from the pod store is
// refused with ErrUnattestable and its token dropped.
func (m *CachedMinter) Mint(ctx context.Context, w *workloadidentity.Workload) (*workloadidentity.ProjectedToken, error) {
	if w == nil || w.PodUID == "" {
		return nil, wierrors.ErrTokenMintFailed.Wrapf(nil, "cannot mint a token for an empty workload")
	}
	if !m.present(w.PodUID) {
		m.Invalidate(w.PodUID)
		return nil, podGone(w)
	}

	if entry, ok := m.cache.Get(w.PodUID); ok {
		if m.now().Before(entry.token.ExpiresAt.Add(-m.minRemaining)) {
			observeCache(workloadidentity.CacheResultHit)
			return entry.token, nil
		}
		observeCache(workloadidentity.CacheResultExpired)
	} else {
		observeCache(workloadidentity.CacheResultMiss)
	}

	v, err, _ := m.group.Do(w.PodUID, func() (any, error) {
		return m.mintAndStore(ctx, w)
	})
	if err != nil {
		return nil, err
	}
	return v.(*workloadidentity.ProjectedToken), nil
}

// mintAndStore mints once, records metrics, rejects a token too short-lived to
// cache, and stores a usable one with a refresh scheduled ahead of expiry. A pod
// deleted while the mint was in flight gets ErrUnattestable and nothing stored.
func (m *CachedMinter) mintAndStore(ctx context.Context, w *workloadidentity.Workload) (*workloadidentity.ProjectedToken, error) {
	start := m.now()
	token, err := m.raw.Mint(ctx, w)
	if err == nil && !m.now().Before(token.ExpiresAt.Add(-m.minRemaining)) {
		err = wierrors.ErrTokenMintFailed.Wrapf(nil,
			"minted token for %s/%s expires within the %s floor", w.Namespace, w.PodName, m.minRemaining)
		token = nil
	}
	if err == nil {
		err = m.storeIfPresent(w, token)
	}
	observeMint(err, m.now().Sub(start).Seconds())
	if err != nil {
		return nil, err
	}
	return token, nil
}

// storeIfPresent stores the token only while the pod store still holds the pod.
// client-go removes a pod from the store before any deletion callback runs, so
// under mu either this store lands first and Invalidate removes it, or the
// check here already fails.
func (m *CachedMinter) storeIfPresent(w *workloadidentity.Workload, token *workloadidentity.ProjectedToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.present(w.PodUID) {
		return podGone(w)
	}
	m.store(w, token)
	return nil
}

// store writes an entry keyed by pod UID, refresh at a fraction of remaining
// life, eviction at full expiry.
func (m *CachedMinter) store(w *workloadidentity.Workload, token *workloadidentity.ProjectedToken) {
	lifetime := token.ExpiresAt.Sub(m.now())
	refresh := time.Duration(float64(lifetime) * m.renewFraction)
	if refresh < minRefreshInterval {
		refresh = minRefreshInterval
	}
	m.cache.SetWithRefreshExpire(w.PodUID, cacheEntry{workload: w, token: token}, refresh, lifetime)
}

// onRefresh re-mints a due entry, rate limited so a backlog cannot stampede the
// API server. A non-retryable failure drops the entry; a retryable one keeps
// the existing token until it truly expires.
//
// There is no caller, so the context is built here: the timeout is what bounds
// the background TokenRequest, and the log fields name the workload being
// renewed rather than whoever first asked for it.
func (m *CachedMinter) onRefresh(uid string, entry cacheEntry) {
	// The sweep can hand over a pod deleted since it collected the entry.
	if !m.present(uid) {
		m.Invalidate(uid)
		return
	}
	if !m.limiter.Allow() {
		return
	}

	ctx, cancel := context.WithTimeout(
		logger.ContextWithField(context.Background(),
			"from", "psat-renewal",
			"pod", entry.workload.Namespace+"/"+entry.workload.PodName),
		m.renewalTimeout)
	defer cancel()
	log := logger.FromContext(ctx)

	if _, err := m.mintAndStore(ctx, entry.workload); err != nil {
		if !wierrors.IsRetryable(err) {
			log.Infof("token renewal for pod %s failed unrecoverably, dropping: %v", uid, err)
			m.cache.Delete(uid)
			return
		}
		log.Infof("token renewal for pod %s failed, keeping existing token: %v", uid, err)
	}
}

// Invalidate drops a deleted pod's token. NewMinter registers it with the pod
// store; it holds mu so it cannot interleave with storeIfPresent.
func (m *CachedMinter) Invalidate(podUID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache.Delete(podUID)
}

// present reports whether the pod store still holds the pod. Without a pod
// store every pod is present.
func (m *CachedMinter) present(podUID string) bool {
	return m.pods == nil || m.pods.HasPod(podUID)
}

// podGone is the non-retryable refusal for a pod no longer on this node.
func podGone(w *workloadidentity.Workload) error {
	return wierrors.ErrUnattestable.Wrapf(nil,
		"pod %s/%s (%s) is no longer in the node-scoped store", w.Namespace, w.PodName, w.PodUID)
}

// onEvicted records an eviction on the cache metric.
func (m *CachedMinter) onEvicted(_ string, _ cacheEntry) {
	observeCache(workloadidentity.CacheResultEvicted)
}

var _ workloadidentity.TokenMinter = (*CachedMinter)(nil)
