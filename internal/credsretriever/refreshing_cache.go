package credsretriever

import (
	"context"
	"fmt"
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cache/expiring"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/validation"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	"golang.org/x/time/rate"
)

// tokenValidator performs local JWT validation when available.
type tokenValidator interface {
	ValidateToken(ctx context.Context, req *credentials.EksCredentialsRequest) error
}

type cachedCredentialRetriever struct {
	// internalCache is where credentials are stored, it runs a janitor that evicts and refreshes
	// entries once they expire. Key in the cache is the pod UID, values
	// are of type cacheEntry.
	internalCache *expiring.Cache[string, cacheEntry]
	// internalActiveRequestCache tracks the active ongoing requests. Key in the cache is the service
	// token, values are errors returned from the active requests. When a service token is in the
	// internalActiveRequestCache, but not internalCache, it means an active request is ongoing,
	// other requests to the same service token should wait for this active request.
	internalActiveRequestCache *expiring.Cache[string, error]
	// delegate is who we are actually getting the credentials from
	delegate credentials.CredentialRetriever
	// tokenValidator performs local JWT validation when available
	tokenValidator atomic.Value // stores tokenValidator interface
	tvInitInFlight atomic.Bool
	// credentialsRenewalTtl the maximum amount of time that we can hold
	// credentials in the cache
	credentialsRenewalTtl time.Duration
	// minCredentialTtl minimum amount of time credentials need to have in order
	// to store them and consider them valid, default is 15s
	minCredentialTtl time.Duration
	// retryInterval is the least amount of time the cache will to wait to renew
	// credentials, default is 1m
	retryInterval time.Duration
	// maxRetryJitter is the maximum amount jitter time we can add when credentials
	// are scheduled for renewal
	maxRetryJitter time.Duration
	// now internal clock that is used to get time. Usefull for testing
	// purposes
	now internalClock
	// refreshRateLimiter slows down refreshes to avoid getting throttled by EKS Auth
	// in case there is some sort of backlog of creds waiting to be refreshed
	refreshRateLimiter *rate.Limiter
}

type cacheEntry struct {
	requestLogCtx      context.Context
	originatingRequest *credentials.EksCredentialsRequest
	credentials        *credentials.EksCredentialsResponse
	metadata           credentials.ResponseMetadata
}

// source returns the credential source for this cache entry, defaulting to
// SourceAuthService
func (e cacheEntry) source() credentials.CredentialSource {
	if e.metadata == nil {
		return credentials.SourceAuthService
	}
	return e.metadata.Source()
}

// internalClock is used to get the current time
type internalClock func() time.Time

// type assertion
var _ credentials.CredentialRetriever = &cachedCredentialRetriever{}

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

	promLocalValidation = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pod_identity_local_validation",
		Help: "Outcome of local token validation: success, failure, or skipped",
	}, []string{"result"},
	)
)

const (
	defaultActiveRequestRetries  = 9
	defaultActiveRequestWaitTime = 200 * time.Millisecond
	// defaultCleanupInterval sets how often we go over the cache to check if
	// there are expired credentials requiring renewal
	defaultCleanupInterval  = 1 * time.Minute
	defaultMinCredentialTtl = 15 * time.Second
	defaultRetryInterval    = 1 * time.Minute
	defaultMaxRetryJitter   = 1 * time.Minute
	renewalTimeout          = 1 * time.Minute

	// A new set of credentials are placed in IMDS every ~30 minutes, so IMDS
	// creds should refresh as often.
	imdsRefreshInterval = 30 * time.Minute
)

type CachedCredentialRetrieverOpts struct {
	Delegate              credentials.CredentialRetriever
	TokenValidator        tokenValidator
	CredentialsRenewalTtl time.Duration
	MaxCacheSize          int
	RefreshQPS            int
	CleanupInterval       time.Duration
}

// NewCachedCredentialRetriever creates a credential retriever that caches
// credentials up to min(credentialsRenewalTtl, fetchedCredentialExpiration)
// It renews credentials indefinitely until the association is removed and
// no longer needed
func NewCachedCredentialRetriever(opts CachedCredentialRetrieverOpts) credentials.CredentialRetriever {
	if opts.Delegate == nil {
		panic("Delegate is not allowed to be empty")
	}

	if opts.CleanupInterval <= 0 {
		opts.CleanupInterval = defaultCleanupInterval
	}
	if opts.RefreshQPS <= 0 {
		opts.RefreshQPS = 3
	}
	if opts.RefreshQPS*int(opts.CredentialsRenewalTtl.Seconds()) < opts.MaxCacheSize/2 {
		panic(fmt.Sprintf(
			"Refresh QPS is too small (%d) or credentials renewal to small (%0.2fs) to keep up with cache's size (%d)",
			opts.RefreshQPS, opts.CredentialsRenewalTtl.Seconds(), opts.MaxCacheSize))
	}
	return newCachedCredentialRetriever(opts)
}

func newCachedCredentialRetriever(opts CachedCredentialRetrieverOpts) *cachedCredentialRetriever {
	internalCache := expiring.NewLru[string, cacheEntry](opts.MaxCacheSize, opts.CredentialsRenewalTtl, opts.CleanupInterval)
	internalActiveRequestCache := expiring.NewLru[string, error](opts.MaxCacheSize, 0, 0)
	retriever := &cachedCredentialRetriever{
		delegate:                   opts.Delegate,
		internalCache:              internalCache,
		internalActiveRequestCache: internalActiveRequestCache,
		credentialsRenewalTtl:      opts.CredentialsRenewalTtl,
		minCredentialTtl:           defaultMinCredentialTtl,
		retryInterval:              defaultRetryInterval,
		maxRetryJitter:             defaultMaxRetryJitter,
		now:                        time.Now,
		refreshRateLimiter:         rate.NewLimiter(rate.Limit(opts.RefreshQPS), opts.RefreshQPS),
	}
	if opts.TokenValidator != nil {
		retriever.tokenValidator.Store(opts.TokenValidator)
	}
	internalCache.OnRefresh(retriever.onCredentialRenewal)
	internalCache.OnEvicted(retriever.onCredentialEviction)
	return retriever
}

func (r *cachedCredentialRetriever) String() string { return "cached-retriever" }

// IsIrrecoverable delegates error classification to the underlying delegate.
func (r *cachedCredentialRetriever) IsIrrecoverable(err error) (string, bool) {
	return r.delegate.IsIrrecoverable(err)
}

// GetIamCredentials fetches credentials from the cache if available
func (r *cachedCredentialRetriever) GetIamCredentials(ctx context.Context,
	request *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
	log := logger.FromContext(ctx)
	if request == nil {
		return nil, nil, fmt.Errorf("request to fetch credentials is empty, this is most likely a bug")
	}

	if request.ServiceAccountToken == "" {
		return nil, nil, fmt.Errorf("service account is empty, cannot fetch credentials without a valid one")
	}

	podUID, err := credentials.GetPodUIDFromToken(request.ServiceAccountToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get pod uid from service account token: %w", err)
	}

	// Bind podUID into the logger context
	ctx = logger.ContextWithField(ctx, "podUID", podUID)
	log = logger.FromContext(ctx)

	for i := 0; i <= defaultActiveRequestRetries; i++ {
		if resp, done := r.tryServingFromCache(ctx, podUID, request); done {
			return resp, nil, nil
		}

		if !r.waitForActiveRequest(ctx, request.ServiceAccountToken, i) {
			break
		}
	}

	if _, ok := r.internalActiveRequestCache.Get(request.ServiceAccountToken); ok {
		log.Warnf("Failed to complete active request in %v tries", defaultActiveRequestRetries)
	}

	r.internalActiveRequestCache.Add(request.ServiceAccountToken, nil)
	defer r.internalActiveRequestCache.Delete(request.ServiceAccountToken)

	log.WithField("cache-hit", 0).Tracef("Could not find entry in cache, requesting creds from delegate")
	promCacheState.WithLabelValues("miss").Inc()

	iamCredentials, metadata, err := r.callDelegateAndCache(ctx, request)
	if err != nil {
		return nil, nil, err
	}
	return iamCredentials.credentials, metadata, nil
}

// tryServingFromCache checks the internal cache for valid credentials matching the request.
// Returns the credentials and true if a cache hit was found, or nil and false otherwise.
func (r *cachedCredentialRetriever) tryServingFromCache(ctx context.Context,
	podUID string, request *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, bool) {
	log := logger.FromContext(ctx)

	val, ok := r.internalCache.Get(podUID)
	if !ok {
		return nil, false
	}

	if _, withinTtl := r.credentialsInEntryWithinValidTtl(val); !withinTtl {
		log.Info("Identified that entry in cache contains credentials with small ttl or invalid ttl, will be deleted")
		r.internalCache.Delete(podUID)
		return nil, false
	}

	// If the cached credentials' token matches the incoming requests' token, return the credentials
	if val.originatingRequest.ServiceAccountToken == request.ServiceAccountToken {
		log.WithField("cache-hit", 1).Tracef("Using cached credentials")
		return val.credentials, true
	}

	// Otherwise, attempt to validate the token locally
	tv, ok := r.tokenValidator.Load().(tokenValidator)
	if !ok {
		r.tryInitTokenValidator(context.Background())
		promLocalValidation.WithLabelValues("skipped").Inc()
		return nil, false
	}

	// Validate the token
	if err := tv.ValidateToken(ctx, request); err != nil {
		log.Infof("Local token validation failed: %v, falling back to delegate", err)
		promLocalValidation.WithLabelValues("failure").Inc()
		return nil, false
	}

	r.internalCache.Modify(podUID, func(e cacheEntry) cacheEntry {
		e.originatingRequest = request
		return e
	})
	log.WithField("cache-hit", 1).Tracef("Local validation succeeded, using cached credentials")
	promLocalValidation.WithLabelValues("success").Inc()
	return val.credentials, true
}

// tryInitTokenValidator kicks off a background token validator initialization
// if no other goroutine is already doing so. Uses an atomic CAS so that
// callers never block — they just skip if init is already in progress.
func (r *cachedCredentialRetriever) tryInitTokenValidator(ctx context.Context) {
	if !r.tvInitInFlight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer r.tvInitInFlight.Store(false)
		log := logger.FromContext(ctx)
		newTv, err := validation.NewTokenValidator(ctx)
		if err != nil {
			log.Infof("Token validator init failed: %v", err)
			return
		}
		r.tokenValidator.Store(newTv)
	}()
}

// waitForActiveRequest checks if there's an in-flight request for the same token.
// Returns true if the caller should continue waiting (i.e. keep looping), false to break out.
func (r *cachedCredentialRetriever) waitForActiveRequest(ctx context.Context,
	token string, attempt int) bool {
	log := logger.FromContext(ctx)

	if _, ok := r.internalActiveRequestCache.Get(token); !ok {
		return false
	}
	if attempt > 0 {
		log.Infof("Waiting for active request with %v tries", attempt)
	}
	if attempt < defaultActiveRequestRetries {
		time.Sleep(defaultActiveRequestWaitTime)
	}
	return true
}

func (r *cachedCredentialRetriever) callDelegateAndCache(ctx context.Context,
	request *credentials.EksCredentialsRequest) (cacheEntry, credentials.ResponseMetadata, error) {
	log := logger.FromContext(ctx)

	podUID, err := credentials.GetPodUIDFromToken(request.ServiceAccountToken)
	if err != nil {
		return cacheEntry{}, nil, fmt.Errorf("failed to get pod uid from service account token: %w", err)
	}

	newCacheEntry, err := r.fetchCredentialsFromDelegate(ctx, request)
	if err != nil {
		return cacheEntry{}, nil, fmt.Errorf("error getting credentials to cache: %w", err)
	}

	if newCacheEntry.credentials == nil {
		return cacheEntry{}, nil, fmt.Errorf("delegate returned nil credentials")
	}

	credsDuration, credentialsValid := r.credentialsInEntryWithinValidTtl(newCacheEntry)
	if !credentialsValid {
		return cacheEntry{}, nil, fmt.Errorf("fetched credentials are expired or will expire within the next %0.2f seconds", credsDuration.Seconds())
	}

	refreshTtl, evictionTtl := r.getCacheTtls(newCacheEntry.source(), credsDuration)
	log.WithFields(map[string]interface{}{
		"refreshTtl":    refreshTtl,
		"evictionTtl":   evictionTtl,
		"credsDuration": credsDuration,
		"source":        newCacheEntry.source(),
		"podUID":        podUID,
	}).Infof("Storing creds in cache")

	// Store credentials in cache if they are valid. It might be that
	// the credentials might have been either removed or inserted by another
	// thread, but it won't matter, we'll just upsert as the cache is thread safe
	r.internalCache.SetWithRefreshExpire(podUID, newCacheEntry, refreshTtl, evictionTtl)
	return newCacheEntry, newCacheEntry.metadata, nil
}

// credentialsInEntryWithinValidTtl reports whether the given cache entry's credentials
// are still usable, returning both the remaining credential duration and a
// validity boolean. The policy is source-specific and owned by the cache:
//   - IMDS: always valid (static-stability guarantee — never evict on expiry).
//     Duration returned is imdsRefreshInterval (actual expiry may be negative).
//   - Auth Service/Default: remaining TTL must exceed minCredentialTtl.
func (r *cachedCredentialRetriever) credentialsInEntryWithinValidTtl(entry cacheEntry) (time.Duration, bool) {
	if entry.source() == credentials.SourceIMDS {
		// IMDS creds are always "valid": return the refresh interval as the
		// duration (not a real remaining TTL) so callers never treat them as expired.
		return imdsRefreshInterval, true
	}
	// Default: Auth Service policy — credentials must have remaining TTL > minCredentialTtl.
	credsDuration := entry.credentials.Expiration.Time.Sub(r.now())
	return credsDuration, credsDuration > r.minCredentialTtl
}

// getCacheTtls returns per-source refresh and eviction TTLs.
func (r *cachedCredentialRetriever) getCacheTtls(source credentials.CredentialSource, credsDuration time.Duration) (refresh, eviction time.Duration) {
	// IMDS credentials have static-stability guarantees. Even if expired, static-stability may
	// be enabled, so the credentials should still be honored. Hence, they are treated as having
	// no expiration.
	if source == credentials.SourceIMDS {
		return imdsRefreshInterval, expiring.NoExpiration
	}
	return minDuration(credsDuration, r.credentialsRenewalTtl), credsDuration
}

func (r *cachedCredentialRetriever) fetchCredentialsFromDelegate(ctx context.Context,
	request *credentials.EksCredentialsRequest) (cacheEntry, error) {
	iamCredentials, metadata, err := r.delegate.GetIamCredentials(ctx, request)
	if err != nil {
		return cacheEntry{}, err
	}
	requestLogCtx := logger.ContextWithField(logger.CloneToNewIfPresent(ctx, context.Background()),
		"association-id", metadata.AssociationId())
	if podUID, uidErr := credentials.GetPodUIDFromToken(request.ServiceAccountToken); uidErr == nil {
		requestLogCtx = logger.ContextWithField(requestLogCtx, "podUID", podUID)
	}
	return cacheEntry{
		originatingRequest: request,
		requestLogCtx:      requestLogCtx,
		credentials:        iamCredentials,
		metadata:           metadata,
	}, nil
}

// onCredentialRenewal is called by the internalCache whenever it refreshed
// credentials from the cache.
func (r *cachedCredentialRetriever) onCredentialRenewal(key string, entry cacheEntry) {
	ctx, cancel := context.WithTimeout(
		logger.ContextWithField(entry.requestLogCtx, "from", "renewal-thread"), renewalTimeout)
	defer cancel()
	log := logger.FromContext(ctx)
	if r.refreshRateLimiter.Allow() {
		err := r.refreshRateLimiter.Wait(ctx)
		if err != nil {
			log.Errorf("Problem waiting, will schedule refresh to next sweep")
			return
		}
		_, _, err = r.callDelegateAndCache(ctx, entry.originatingRequest)
		if err == nil {
			// if we retrieved the credentials successfully, exit we don't need to do anything else
			promCacheState.WithLabelValues("hit").Inc()
			return
		}

		errCode, isIrrecoverableError := r.delegate.IsIrrecoverable(err)
		if isIrrecoverableError {
			log.WithField("source", entry.source()).Infof("Background refresh failed for pod %s: removing credentials from cache (irrecoverable): %v", key, err)
			promCacheError.WithLabelValues("NonRecoverable", errCode).Inc()
			podUID, err := credentials.GetPodUIDFromToken(entry.originatingRequest.ServiceAccountToken)
			if err != nil {
				log.Errorf("Could not parse podUID from service account token, will schedule refresh to next sweep")
				return
			}
			r.internalCache.Delete(podUID)
			return
		}
		promCacheError.WithLabelValues("Recoverable", errCode).Inc()
		log.WithField("source", entry.source()).Infof("Background refresh failed for pod %s: keeping existing credentials in cache (recoverable): %v", key, err)
	} else {
		log.Infof("Background refresh rate limited for pod %s: keeping credentials locally", key)
	}

	// if there was an error, try to keep the old credentials in the agent if they haven't expired
	credsDuration, valid := r.credentialsInEntryWithinValidTtl(entry)
	if valid {
		calculatedRetryInterval := r.retryInterval + time.Duration(rand.Int63n(int64(r.maxRetryJitter)))

		var newRefreshTtl, newEvictionTtl time.Duration
		// IMDS creds never expire (static stability); Auth creds expire with
		// the credential.
		if entry.source() == credentials.SourceIMDS {
			newRefreshTtl = calculatedRetryInterval
			newEvictionTtl = expiring.NoExpiration
		} else {
			newRefreshTtl = minDuration(credsDuration, calculatedRetryInterval)
			newEvictionTtl = credsDuration
		}

		log.WithFields(map[string]interface{}{
			"refreshTtl":    newRefreshTtl,
			"evictionTtl":   newEvictionTtl,
			"credsDuration": credsDuration,
			"source":        entry.source(),
			"podUID":        key,
		}).Infof("Credentials still valid, keeping them — will try again after refresh ttl")
		r.internalCache.SetWithRefreshExpire(key, entry, newRefreshTtl, newEvictionTtl)
	} else {
		log.Infof("Evicting credentials since they are too old")
	}
}

func (r *cachedCredentialRetriever) onCredentialEviction(key string, entry cacheEntry) {
	log := logger.FromContext(entry.requestLogCtx)
	log.WithField("source", entry.source()).Infof("Credentials evicted from cache")
	promCacheState.WithLabelValues("evicted").Inc()
}

func minDuration(a time.Duration, b time.Duration) time.Duration {
	if a > b {
		return b
	} else {
		return a
	}
}
