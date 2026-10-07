// Package credcache keeps the agent's credentials, one entry per pod UID. It
// refreshes each entry before its credentials expire and evicts it after, by one
// algorithm for every entry. The caller that stores an entry decides who may read
// it, and gives the entry an Owner that renews it.
package credcache

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/time/rate"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cache/expiring"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
)

const (
	// DefaultMinCredentialTtl is how long credentials need to have left to be
	// stored or served, unless Opts.MinCredentialTtl says otherwise.
	DefaultMinCredentialTtl = 15 * time.Second

	defaultCleanupInterval = 1 * time.Minute
	defaultRefreshQPS      = 3
	defaultRetryInterval   = 1 * time.Minute
	defaultMaxRetryJitter  = 1 * time.Minute
	renewalTimeout         = 1 * time.Minute

	// A new set of credentials are placed in IMDS every ~30 minutes, so IMDS
	// creds should refresh as often.
	imdsRefreshInterval = 30 * time.Minute
)

var (
	promCacheError = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pod_identity_cache_errors",
		Help: "Removing credentials from cache, got non recoverable error",
	}, []string{"type", "code"},
	)

	promCacheState = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pod_identity_cache_state",
		Help: "The state of credential in cache",
	}, []string{"state"},
	)
)

// errNotCurrent is what a write returns when the cache no longer holds the entry
// it was asked to act on.
var errNotCurrent = errors.New("the entry was replaced or removed")

// Entry is one pod's credentials and what the cache needs to refresh them. The
// cache knows an entry by its Credentials pointer: Modify's copy keeps it and is
// the same entry, while Store and Replace put in a new one. Nothing that reads an
// entry modifies it.
type Entry struct {
	Credentials *credentials.EksCredentialsResponse
	Metadata    credentials.ResponseMetadata
	// Owner renews the entry and is told when it leaves the cache. The caller
	// that stores the entry sets it.
	Owner Owner
	// Request is the credentials request the HTTP retriever last fetched or
	// verified the entry for. The retriever serves the entry to a request with
	// the same token. Nil when the caller that stored the entry verifies no token.
	Request *credentials.EksCredentialsRequest
	// LogCtx carries the log fields naming the pod and association, for the
	// refresh and eviction logs.
	LogCtx context.Context
}

// source returns the credential source for this entry, defaulting to
// SourceAuthService.
func (e *Entry) source() credentials.CredentialSource {
	if e.Metadata == nil {
		return credentials.SourceAuthService
	}
	return e.Metadata.Source()
}

// logCtx returns LogCtx, or a context with no fields when it's unset.
func (e *Entry) logCtx() context.Context {
	if e.LogCtx == nil {
		return context.Background()
	}
	return e.LogCtx
}

// Owner renews entries for the caller that stored them. The cache asks it to
// renew an entry before its credentials expire, and tells it when the entry has
// gone, so every caller's entries refresh by the same algorithm.
type Owner interface {
	// Renew fetches the entry that replaces e. The cache stores it unless e has
	// since been replaced or removed.
	Renew(ctx context.Context, podUID string, e *Entry) (*Entry, error)
	// IsIrrecoverable reports whether err from Renew means dropping e rather
	// than keeping it until it expires, with a code for metrics.
	IsIrrecoverable(err error) (string, bool)
	// Evicted is called once e has left the cache. removed is whether a caller
	// deleted it, rather than the cache evicting it at its eviction time or for
	// capacity. It can run under the cache's lock, so it never calls the cache.
	Evicted(podUID string, e *Entry, removed bool)
}

// Opts configures a Cache.
type Opts struct {
	// RenewalTtl is the longest an entry goes before a refresh:
	// --max-credential-retention-before-renewal.
	RenewalTtl time.Duration
	// MaxSize bounds the cache, in pods: --max-cache-size.
	MaxSize int
	// RefreshQPS bounds background refreshes per second, 3 when zero.
	RefreshQPS int
	// CleanupInterval is how often the cache looks for entries to refresh or
	// evict. Zero means a minute; negative turns the sweep off, for tests.
	CleanupInterval time.Duration
	// MinCredentialTtl, RetryInterval, MaxRetryJitter and Now default when zero.
	// Only tests set them.
	MinCredentialTtl time.Duration
	RetryInterval    time.Duration
	MaxRetryJitter   time.Duration
	Now              func() time.Time
}

// Cache keeps credentials by pod UID. Its sweep refreshes an entry through the
// entry's Owner once its refresh time passes, and evicts it at its eviction
// time. Both times come from the credentials' source. Every write that acts on
// an entry another write may have replaced checks the cache still holds it.
type Cache struct {
	items *expiring.Cache[string, *Entry]
	// mu serializes every write, so a write's check that it still holds an entry
	// and the write itself are one step. Owner.Evicted can run under it.
	mu sync.Mutex
	// removing holds the credentials of the entry Delete is removing under mu, so
	// onEvicted can tell a removal from an eviction.
	removing atomic.Pointer[credentials.EksCredentialsResponse]

	maxSize          int
	renewalTtl       time.Duration
	minCredentialTtl time.Duration
	retryInterval    time.Duration
	maxRetryJitter   time.Duration
	now              func() time.Time
	// refreshLimiter slows down refreshes to avoid getting throttled in case
	// there is some sort of backlog of creds waiting to be refreshed.
	refreshLimiter *rate.Limiter
}

// New builds a Cache and starts its sweep. It panics when RefreshQPS is too low
// to refresh a full cache within RenewalTtl.
func New(opts Opts) *Cache {
	if opts.CleanupInterval == 0 {
		opts.CleanupInterval = defaultCleanupInterval
	}
	if opts.RefreshQPS <= 0 {
		opts.RefreshQPS = defaultRefreshQPS
	}
	if opts.RefreshQPS*int(opts.RenewalTtl.Seconds()) < opts.MaxSize/2 {
		panic(fmt.Sprintf(
			"Refresh QPS is too small (%d) or credentials renewal to small (%0.2fs) to keep up with cache's size (%d)",
			opts.RefreshQPS, opts.RenewalTtl.Seconds(), opts.MaxSize))
	}
	c := &Cache{
		items:            expiring.NewLru[string, *Entry](opts.MaxSize, opts.RenewalTtl, opts.CleanupInterval),
		maxSize:          opts.MaxSize,
		renewalTtl:       opts.RenewalTtl,
		minCredentialTtl: cmp.Or(opts.MinCredentialTtl, DefaultMinCredentialTtl),
		retryInterval:    cmp.Or(opts.RetryInterval, defaultRetryInterval),
		maxRetryJitter:   cmp.Or(opts.MaxRetryJitter, defaultMaxRetryJitter),
		now:              opts.Now,
		refreshLimiter:   rate.NewLimiter(rate.Limit(opts.RefreshQPS), opts.RefreshQPS),
	}
	if c.now == nil {
		c.now = time.Now
	}
	c.items.OnRefresh(c.onRefresh)
	c.items.OnEvicted(c.onEvicted)
	return c
}

// MaxSize is the most pods the cache holds entries for.
func (c *Cache) MaxSize() int { return c.maxSize }

// RecordMiss counts a request the cache had nothing to serve for.
func (c *Cache) RecordMiss() { promCacheState.WithLabelValues("miss").Inc() }

// Get returns the pod's entry, or false when it has none or the entry is past its
// eviction time. Usable says whether its credentials can still be served.
func (c *Cache) Get(podUID string) (*Entry, bool) {
	return c.items.Get(podUID)
}

// Usable reports whether e's credentials can be stored or served, and how long
// they have left. The policy is per source:
//   - IMDS: always usable (static stability), reporting the IMDS refresh interval.
//   - Auth Service: usable while more than the minimum TTL is left.
func (c *Cache) Usable(e *Entry) (time.Duration, bool) {
	if e.source() == credentials.SourceIMDS {
		// IMDS creds are always "valid": return the refresh interval as the
		// duration (not a real remaining TTL) so callers never treat them as expired.
		return imdsRefreshInterval, true
	}
	credsDuration := e.Credentials.Expiration.Time.Sub(c.now())
	return credsDuration, credsDuration > c.minCredentialTtl
}

// Store puts e in the cache for podUID, replacing whatever is there, and schedules
// its refresh and eviction by source. It refuses an entry with no Owner or with
// credentials that aren't usable.
func (c *Cache) Store(ctx context.Context, podUID string, e *Entry) error {
	refreshTtl, evictionTtl, err := c.schedule(ctx, podUID, e)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items.SetWithRefreshExpire(podUID, e, refreshTtl, evictionTtl)
	return nil
}

// Replace stores next in place of old, as Store does, only if the cache still
// holds old for podUID. It reports whether the cache now holds next, which it
// already does when next's owner stored it while renewing.
func (c *Cache) Replace(ctx context.Context, podUID string, old, next *Entry) (bool, error) {
	refreshTtl, evictionTtl, err := c.schedule(ctx, podUID, next)
	if err != nil {
		return false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.containsLocked(podUID, next); ok {
		return true, nil
	}
	if _, ok := c.containsLocked(podUID, old); !ok {
		return false, nil
	}
	c.items.SetWithRefreshExpire(podUID, next, refreshTtl, evictionTtl)
	return true, nil
}

// Modify replaces old with a copy that f has changed, keeping old's refresh and
// eviction times, only if the cache still holds old for podUID. f changes no
// credentials. It reports whether it replaced old.
func (c *Cache) Modify(podUID string, old *Entry, f func(*Entry)) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	modified := false
	c.items.Modify(podUID, func(current *Entry) *Entry {
		if current.Credentials != old.Credentials {
			return current
		}
		next := *current
		f(&next)
		modified = true
		return &next
	})
	return modified
}

// Delete removes old, only if the cache still holds it for podUID. It reports
// whether it did.
func (c *Cache) Delete(podUID string, old *Entry) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.containsLocked(podUID, old); !ok {
		return false
	}
	c.removing.Store(old.Credentials)
	defer c.removing.Store(nil)
	c.items.Delete(podUID)
	return true
}

// Contains reports whether the cache holds e for podUID, past its eviction
// time or not.
func (c *Cache) Contains(podUID string, e *Entry) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.containsLocked(podUID, e)
	return ok
}

// containsLocked returns what the cache holds for podUID, and whether that is e,
// past its eviction time or not. The caller holds mu.
func (c *Cache) containsLocked(podUID string, e *Entry) (*Entry, bool) {
	current, _, ok := c.items.GetStale(podUID)
	return current, ok && current.Credentials == e.Credentials
}

// schedule checks e can be stored and returns its refresh and eviction TTLs.
func (c *Cache) schedule(ctx context.Context, podUID string, e *Entry) (time.Duration, time.Duration, error) {
	if e == nil || e.Credentials == nil {
		return 0, 0, errors.New("no credentials to cache")
	}
	if e.Owner == nil {
		return 0, 0, errors.New("no owner to renew the cached credentials")
	}
	credsDuration, usable := c.Usable(e)
	if !usable {
		return 0, 0, fmt.Errorf("fetched credentials are expired or will expire within the next %0.2f seconds", credsDuration.Seconds())
	}
	refreshTtl, evictionTtl := c.ttls(e.source(), credsDuration)
	logger.FromContext(ctx).WithFields(map[string]interface{}{
		"refreshTtl":    refreshTtl,
		"evictionTtl":   evictionTtl,
		"credsDuration": credsDuration,
		"source":        e.source(),
		"podUID":        podUID,
	}).Infof("Storing creds in cache")
	return refreshTtl, evictionTtl, nil
}

// ttls returns per-source refresh and eviction TTLs.
func (c *Cache) ttls(source credentials.CredentialSource, credsDuration time.Duration) (refresh, eviction time.Duration) {
	// IMDS credentials have static-stability guarantees. Even if expired, static-stability may
	// be enabled, so the credentials should still be honored. Hence, they are treated as having
	// no expiration.
	if source == credentials.SourceIMDS {
		return imdsRefreshInterval, expiring.NoExpiration
	}
	return min(credsDuration, c.renewalTtl), credsDuration
}

// onRefresh is the sweep's refresh callback: renew e through its Owner, drop it
// on an irrecoverable failure, and otherwise keep it and retry later. It skips e
// once the cache no longer holds it, since the sweep picks every due entry first.
func (c *Cache) onRefresh(podUID string, e *Entry) {
	ctx, cancel := context.WithTimeout(
		logger.ContextWithField(e.logCtx(), "from", "renewal-thread"), renewalTimeout)
	defer cancel()
	log := logger.FromContext(ctx)
	if !c.Contains(podUID, e) {
		log.Infof("Credentials for pod %s were replaced or removed before their refresh, nothing to refresh", podUID)
		return
	}
	if c.refreshLimiter.Allow() {
		err := c.refreshLimiter.Wait(ctx)
		if err != nil {
			log.Errorf("Problem waiting, will schedule refresh to next sweep")
			return
		}
		err = c.renew(ctx, podUID, e)
		if err == nil {
			// if we retrieved the credentials successfully, exit we don't need to do anything else
			promCacheState.WithLabelValues("hit").Inc()
			return
		}
		if errors.Is(err, errNotCurrent) {
			log.Infof("Credentials for pod %s were replaced or removed while refreshing, not storing the refresh", podUID)
			return
		}

		errCode, isIrrecoverableError := e.Owner.IsIrrecoverable(err)
		if isIrrecoverableError {
			log.WithField("source", e.source()).Infof("Background refresh failed for pod %s: removing credentials from cache (irrecoverable): %v", podUID, err)
			promCacheError.WithLabelValues("NonRecoverable", errCode).Inc()
			c.Delete(podUID, e)
			return
		}
		promCacheError.WithLabelValues("Recoverable", errCode).Inc()
		log.WithField("source", e.source()).Infof("Background refresh failed for pod %s: keeping existing credentials in cache (recoverable): %v", podUID, err)
	} else {
		log.Infof("Background refresh rate limited for pod %s: keeping credentials locally", podUID)
	}
	c.keep(ctx, podUID, e)
}

// renew asks e's Owner for its replacement and stores it in e's place.
func (c *Cache) renew(ctx context.Context, podUID string, e *Entry) error {
	next, err := e.Owner.Renew(ctx, podUID, e)
	if err != nil {
		return err
	}
	replaced, err := c.Replace(ctx, podUID, e, next)
	if err != nil {
		return err
	}
	if !replaced {
		return errNotCurrent
	}
	return nil
}

// keep holds on to e after a refresh that didn't happen or didn't succeed, if
// its credentials are still usable, and retries after the retry interval plus
// jitter. It reschedules what the cache holds, which Modify may have changed, and
// does nothing once the cache no longer holds e.
func (c *Cache) keep(ctx context.Context, podUID string, e *Entry) {
	log := logger.FromContext(ctx)
	credsDuration, valid := c.Usable(e)
	if !valid {
		log.Infof("Evicting credentials since they are too old")
		return
	}
	calculatedRetryInterval := c.retryInterval + time.Duration(rand.Int63n(int64(c.maxRetryJitter)))

	var newRefreshTtl, newEvictionTtl time.Duration
	// IMDS creds never expire (static stability); Auth creds expire with
	// the credential.
	if e.source() == credentials.SourceIMDS {
		newRefreshTtl = calculatedRetryInterval
		newEvictionTtl = expiring.NoExpiration
	} else {
		newRefreshTtl = min(credsDuration, calculatedRetryInterval)
		newEvictionTtl = credsDuration
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	current, ok := c.containsLocked(podUID, e)
	if !ok {
		log.Infof("Credentials for pod %s were replaced or removed while refreshing, not keeping the old ones", podUID)
		return
	}
	log.WithFields(map[string]interface{}{
		"refreshTtl":    newRefreshTtl,
		"evictionTtl":   newEvictionTtl,
		"credsDuration": credsDuration,
		"source":        e.source(),
		"podUID":        podUID,
	}).Infof("Credentials still valid, keeping them — will try again after refresh ttl")
	c.items.SetWithRefreshExpire(podUID, current, newRefreshTtl, newEvictionTtl)
}

// onEvicted runs for every entry that leaves the cache: one a caller deleted, one
// past its eviction time, or one pushed out for capacity. It logs and counts the
// eviction, then tells the entry's Owner.
func (c *Cache) onEvicted(podUID string, e *Entry) {
	log := logger.FromContext(e.logCtx())
	log.WithField("source", e.source()).Infof("Credentials evicted from cache")
	promCacheState.WithLabelValues("evicted").Inc()
	e.Owner.Evicted(podUID, e, e.Credentials == c.removing.Load())
}
