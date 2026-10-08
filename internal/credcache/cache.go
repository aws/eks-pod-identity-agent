// Package credcache keeps the agent's credentials, one entry per pod UID. It
// refreshes each entry before its credentials expire and evicts it after, by one
// rule for every entry: present the entry's request to its source. The caller
// that stores an entry decides who may read it.
package credcache

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
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

	// tokenRenewalFloor is how long a stored token needs to have left for a
	// refresh to present it when Opts.RefreshWith gives the entry a TokenSource.
	// One closer to expiry is swapped for a current token first.
	tokenRenewalFloor = 5 * time.Minute

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

// Entry is one pod's credentials and what the cache needs to refresh them. The
// cache knows an entry by its Credentials pointer. Every fetch must allocate its
// own credentials and only Modify's copy shares them, so Store puts in a new
// entry while Modify keeps it the same one. Nothing that reads an entry modifies
// it.
type Entry struct {
	Credentials *credentials.EksCredentialsResponse
	Metadata    credentials.ResponseMetadata
	// Request is the credentials request the entry was last fetched or verified
	// for, and what a refresh presents. The HTTP retriever serves the entry to a
	// request with the same token. An entry without one can't be refreshed.
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

// TokenSource gives a refresh a current token when the stored one is close to
// expiry. An entry Opts.RefreshWith gives none presents its stored token as it
// is.
type TokenSource interface {
	// Token returns a current token for the pod and service account current's
	// token was issued for.
	Token(ctx context.Context, current *credentials.EksCredentialsRequest) (string, error)
	// IsIrrecoverable reports whether err from Token means dropping the entry
	// rather than keeping it until it expires, with a code for metrics.
	IsIrrecoverable(err error) (string, bool)
}

// classifier reports whether a failed refresh drops its entry, as
// credentials.CredentialRetriever and TokenSource do.
type classifier interface {
	IsIrrecoverable(err error) (string, bool)
}

// Opts configures a Cache.
type Opts struct {
	// Delegate is the source a refresh uses unless RefreshWith gives another: the
	// [IMDS, EKS Auth] chain, or EKS Auth alone. Required. Every source must return
	// credentials no entry already holds, since they name the renewed entry.
	Delegate credentials.CredentialRetriever
	// RefreshWith gives what refreshes e: the source its request goes to, and a
	// TokenSource that swaps a stored token close to expiry first. A nil source
	// means Delegate, a nil TokenSource means the stored token goes as it is, and
	// a nil RefreshWith means (Delegate, nil).
	RefreshWith func(e *Entry) (source credentials.CredentialRetriever, tokens TokenSource)
	// RenewalTtl is the longest an entry goes before a refresh:
	// --max-credential-retention-before-renewal.
	RenewalTtl time.Duration
	// MaxSize bounds the cache, in pods: --max-cache-size.
	MaxSize int
	// RefreshQPS bounds background refreshes per second, 3 when zero.
	RefreshQPS int
	// CleanupInterval is how often the cache looks for entries to refresh or
	// evict. Zero or negative means a minute.
	CleanupInterval time.Duration
	// MinCredentialTtl, RetryInterval, MaxRetryJitter and Now default when zero.
	// Only tests set them.
	MinCredentialTtl time.Duration
	RetryInterval    time.Duration
	MaxRetryJitter   time.Duration
	Now              func() time.Time
}

// Cache keeps credentials by pod UID. Its sweep refreshes an entry once its
// refresh time passes, presenting the entry's request to the entry's source, and
// evicts it at its eviction time. Both times come from the credentials' source.
// Writes go by pod UID, as upstream's do. A refresh skips an entry removed or
// replaced since the sweep picked it, and one that keeps the old credentials
// doesn't put them back over a newer entry or a removed one.
type Cache struct {
	items *expiring.Cache[string, *Entry]
	// mu serializes every write, so keep's check that the cache still holds its
	// entry and its write are one step.
	mu sync.Mutex

	delegate    credentials.CredentialRetriever
	refreshWith func(e *Entry) (credentials.CredentialRetriever, TokenSource)

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

// New builds a Cache and starts its sweep. It panics when Delegate is nil, or when
// RefreshQPS is too low to refresh a full cache within RenewalTtl.
func New(opts Opts) *Cache {
	if opts.Delegate == nil {
		panic("Delegate must be non-nil")
	}
	if opts.CleanupInterval <= 0 {
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
		delegate:         opts.Delegate,
		refreshWith:      opts.RefreshWith,
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
// eviction time. CredentialsWithinValidTtl says whether its credentials can still
// be served.
func (c *Cache) Get(podUID string) (*Entry, bool) {
	return c.items.Get(podUID)
}

// CredentialsWithinValidTtl reports whether e's credentials can be stored or
// served, and how long they have left. The policy is per source:
//   - IMDS: always valid (static stability), reporting the IMDS refresh interval.
//   - Auth Service: valid while more than the minimum TTL is left.
func (c *Cache) CredentialsWithinValidTtl(e *Entry) (time.Duration, bool) {
	if e.source() == credentials.SourceIMDS {
		// IMDS creds are always "valid": return the refresh interval as the
		// duration (not a real remaining TTL) so callers never treat them as expired.
		return imdsRefreshInterval, true
	}
	credsDuration := e.Credentials.Expiration.Time.Sub(c.now())
	return credsDuration, credsDuration > c.minCredentialTtl
}

// Store puts e in the cache for podUID, replacing whatever is there, and schedules
// its refresh and eviction by source. It refuses an entry whose credentials
// aren't within their valid TTL.
func (c *Cache) Store(ctx context.Context, podUID string, e *Entry) error {
	if e == nil || e.Credentials == nil {
		return errors.New("no credentials to cache")
	}
	credsDuration, valid := c.CredentialsWithinValidTtl(e)
	if !valid {
		return fmt.Errorf("fetched credentials are expired or will expire within the next %0.2f seconds", credsDuration.Seconds())
	}
	refreshTtl, evictionTtl := c.ttls(e.source(), credsDuration)
	func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.items.SetWithRefreshExpire(podUID, e, refreshTtl, evictionTtl)
	}()
	logger.FromContext(ctx).WithFields(map[string]interface{}{
		"refreshTtl":    refreshTtl,
		"evictionTtl":   evictionTtl,
		"credsDuration": credsDuration,
		"source":        e.source(),
		"podUID":        podUID,
	}).Infof("Storing creds in cache")
	return nil
}

// Modify replaces podUID's entry with a copy that f has changed, keeping the
// entry's refresh and eviction times. f changes no credentials. It reports
// whether podUID had an entry.
func (c *Cache) Modify(podUID string, f func(*Entry)) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	modified := false
	c.items.Modify(podUID, func(current *Entry) *Entry {
		next := *current
		f(&next)
		modified = true
		return &next
	})
	return modified
}

// Delete removes podUID's entry, if it has one.
func (c *Cache) Delete(podUID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items.Delete(podUID)
}

// contains reports whether the cache holds e for podUID, past its eviction time
// or not.
func (c *Cache) contains(podUID string, e *Entry) bool {
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

// onRefresh is the sweep's refresh callback: renew e, drop it on an irrecoverable
// failure, and otherwise keep it and retry later. It skips e once the cache no
// longer holds it, since the sweep picks every due entry first.
func (c *Cache) onRefresh(podUID string, e *Entry) {
	ctx, cancel := context.WithTimeout(
		logger.ContextWithField(e.logCtx(), "from", "renewal-thread"), renewalTimeout)
	defer cancel()
	log := logger.FromContext(ctx)
	if !c.contains(podUID, e) {
		log.Infof("Credentials for pod %s were replaced or removed before their refresh, nothing to refresh", podUID)
		return
	}
	if c.refreshLimiter.Allow() {
		err := c.refreshLimiter.Wait(ctx)
		if err != nil {
			log.Errorf("Problem waiting, will schedule refresh to next sweep")
			return
		}
		failedBy, err := c.renew(ctx, podUID, e)
		if err == nil {
			// if we retrieved the credentials successfully, exit we don't need to do anything else
			promCacheState.WithLabelValues("hit").Inc()
			return
		}

		errCode, isIrrecoverableError := noRequestErrCode, false
		if failedBy != nil {
			errCode, isIrrecoverableError = failedBy.IsIrrecoverable(err)
		}
		if isIrrecoverableError {
			log.WithField("source", e.source()).Infof("Background refresh failed for pod %s: removing credentials from cache (irrecoverable): %v", podUID, err)
			promCacheError.WithLabelValues("NonRecoverable", errCode).Inc()
			c.Delete(podUID)
			return
		}
		promCacheError.WithLabelValues("Recoverable", errCode).Inc()
		log.WithField("source", e.source()).Infof("Background refresh failed for pod %s: keeping existing credentials in cache (recoverable): %v", podUID, err)
	} else {
		log.Infof("Background refresh rate limited for pod %s: keeping credentials locally", podUID)
	}
	// if there was an error, try to keep the old credentials in the agent if they haven't expired
	c.keep(ctx, podUID, e)
}

// noRequestErrCode is the metrics code for a refresh of an entry without a
// request, which no source classifies.
const noRequestErrCode = "NoRequest"

// renew fetches e's replacement through what RefreshWith gives it and stores it
// for podUID, whatever the cache holds by then. On failure it also returns what
// classifies the error: the TokenSource for a token error, the source otherwise,
// and nil for an entry without a request.
func (c *Cache) renew(ctx context.Context, podUID string, e *Entry) (classifier, error) {
	if e.Request == nil {
		return nil, errors.New("cached credentials have no request to refresh them with")
	}
	source, tokens := c.refresher(e)
	req := *e.Request
	if tokens != nil && c.tokenExpiring(req.ServiceAccountToken) {
		token, err := tokens.Token(ctx, e.Request)
		if err != nil {
			return tokens, fmt.Errorf("error getting a current token to refresh with: %w", err)
		}
		req.ServiceAccountToken = token
	}
	creds, metadata, err := source.GetIamCredentials(ctx, &req)
	if err != nil {
		return source, fmt.Errorf("error getting credentials to cache: %w", err)
	}
	if creds == nil {
		return source, errors.New("delegate returned nil credentials")
	}
	// The renewal logs as the refresh does, from the renewal thread, and its
	// store log names its own association.
	next := &Entry{Credentials: creds, Metadata: metadata, Request: &req,
		LogCtx: logger.CloneToNewIfPresent(ctx, context.Background())}
	if metadata != nil {
		next.LogCtx = logger.ContextWithField(next.LogCtx, "association-id", metadata.AssociationId())
	}
	if err := c.Store(next.LogCtx, podUID, next); err != nil {
		return source, err
	}
	return nil, nil
}

// refresher returns what refreshes e: RefreshWith's source, or Delegate when
// RefreshWith is nil or gives none, and RefreshWith's TokenSource, if any.
func (c *Cache) refresher(e *Entry) (credentials.CredentialRetriever, TokenSource) {
	var source credentials.CredentialRetriever
	var tokens TokenSource
	if c.refreshWith != nil {
		source, tokens = c.refreshWith(e)
	}
	if source == nil {
		source = c.delegate
	}
	return source, tokens
}

// tokenExpiring reports whether token expires within tokenRenewalFloor. A token
// whose expiry can't be read counts as expiring.
func (c *Cache) tokenExpiring(token string) bool {
	exp, err := credentials.GetExpiryFromToken(token)
	return err != nil || exp.Sub(c.now()) <= tokenRenewalFloor
}

// keep holds on to e after a refresh that didn't happen or didn't succeed, if
// its credentials are still within their valid TTL, and retries after the retry
// interval plus jitter. It reschedules what the cache holds, which Modify may
// have changed, and does nothing once the cache no longer holds e.
func (c *Cache) keep(ctx context.Context, podUID string, e *Entry) {
	log := logger.FromContext(ctx)
	credsDuration, valid := c.CredentialsWithinValidTtl(e)
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
// eviction.
func (c *Cache) onEvicted(_ string, e *Entry) {
	log := logger.FromContext(e.logCtx())
	log.WithField("source", e.source()).Infof("Credentials evicted from cache")
	promCacheState.WithLabelValues("evicted").Inc()
}
