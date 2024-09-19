package credsretriever

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cache/expiring"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/eksauth"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	"golang.org/x/time/rate"
)

type cachedCredentialRetriever struct {
	// internalCache is where credentials are stored, it runs a janitor that evicts and refreshes
	// entries once they expire. Key in the cache is the service token, values
	// are of type cacheEntry.
	internalCache *expiring.Cache[string, cacheEntry]
	// delegate is who we are actually getting the credentials from
	delegate credentials.CredentialRetriever
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
}

// internalClock is used to get the current time
type internalClock func() time.Time

// type assertion
var _ credentials.CredentialRetriever = &cachedCredentialRetriever{}

var (
	promCacheError = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pod_identity_cache_errors",
		Help: "Removing credentials from cache, got non recoverable error",
	}, []string{"type"},
	)

	promCacheState = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pod_identity_cache_state",
		Help: "The state of credential in cache",
	}, []string{"state"},
	)
)

const (
	// defaultCleanupInterval sets how often we go over the cache to check if
	// there are expired credentials requiring renewal
	defaultCleanupInterval  = 1 * time.Minute
	defaultMinCredentialTtl = 15 * time.Second
	defaultRetryInterval    = 1 * time.Minute
	defaultMaxRetryJitter   = 1 * time.Minute
	renewalTimeout          = 1 * time.Minute
)

type CachedCredentialRetrieverOpts struct {
	Delegate              credentials.CredentialRetriever
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
	c := expiring.NewLru[string, cacheEntry](opts.MaxCacheSize, opts.CredentialsRenewalTtl, opts.CleanupInterval)
	retriever := &cachedCredentialRetriever{
		delegate:              opts.Delegate,
		internalCache:         c,
		credentialsRenewalTtl: opts.CredentialsRenewalTtl,
		minCredentialTtl:      defaultMinCredentialTtl,
		retryInterval:         defaultRetryInterval,
		maxRetryJitter:        defaultMaxRetryJitter,
		now:                   time.Now,
		refreshRateLimiter:    rate.NewLimiter(rate.Limit(opts.RefreshQPS), opts.RefreshQPS),
	}
	c.OnRefresh(retriever.onCredentialRenewal)
	c.OnEvicted(retriever.onCredentialEviction)
	return retriever
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

	// check if the request is in the cache, if it is, return it
	if val, ok := r.internalCache.Get(request.ServiceAccountToken); ok {
		if _, withinTtl := r.credentialsInEntryWithinValidTtl(val); withinTtl {
			log.WithField("cache-hit", 1).Tracef("Using cached credentials")
			return val.credentials, nil, nil
		}

		log.Info("Identified that entry in cache contains credentials with small ttl or invalid ttl, will be deleted")
		r.internalCache.Delete(request.ServiceAccountToken)
	}

	log.WithField("cache-hit", 0).Tracef("Could not find entry in cache, requesting creds from delegate")

	iamCredentials, metadata, err := r.callDelegateAndCache(ctx, request)
	if err != nil {
		return nil, nil, err
	}
	return iamCredentials.credentials, metadata, nil
}

func (r *cachedCredentialRetriever) callDelegateAndCache(ctx context.Context,
	request *credentials.EksCredentialsRequest) (cacheEntry, credentials.ResponseMetadata, error) {
	log := logger.FromContext(ctx)
	newCacheEntry, err := r.fetchCredentialsFromDelegate(ctx, request)
	if err != nil {
		return cacheEntry{}, nil, fmt.Errorf("error getting credentials to cache: %w", err)
	}

	credsDuration, credentialsValid := r.credentialsInEntryWithinValidTtl(newCacheEntry)
	if !credentialsValid {
		return cacheEntry{}, nil, fmt.Errorf("fetched credentials are expired or will expire within the next %0.2f seconds", credsDuration.Seconds())
	}

	refreshTtl := minDuration(credsDuration, r.credentialsRenewalTtl)
	log.WithField("refreshTtl", refreshTtl).Infof("Storing creds in cache")

	// Store credentials in cache if they are valid. It might be that
	// the credentials might have been either removed or inserted by another
	// thread, but it won't matter, we'll just upsert as the cache is thread safe
	r.internalCache.SetWithRefreshExpire(request.ServiceAccountToken, newCacheEntry, refreshTtl, credsDuration)
	return newCacheEntry, nil, nil
}

func (r *cachedCredentialRetriever) credentialsInEntryWithinValidTtl(newCacheEntry cacheEntry) (time.Duration, bool) {
	credsDuration := newCacheEntry.credentials.Expiration.Time.Sub(r.now())
	credentialsLessThanMinCredTtl := credsDuration > r.minCredentialTtl
	return credsDuration, credentialsLessThanMinCredTtl
}

func (r *cachedCredentialRetriever) fetchCredentialsFromDelegate(ctx context.Context,
	request *credentials.EksCredentialsRequest) (cacheEntry, error) {
	iamCredentials, metadata, err := r.delegate.GetIamCredentials(ctx, request)
	if err != nil {
		return cacheEntry{}, err
	}
	requestLogCtx := logger.ContextWithField(logger.CloneToNewIfPresent(ctx, context.Background()),
		"association-id", metadata.AssociationId())
	return cacheEntry{
		originatingRequest: request,
		requestLogCtx:      requestLogCtx,
		credentials:        iamCredentials,
	}, nil
}

// onCredentialRenewal is called by the internalCache whenever it evicted
// keys from the cache.
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

		if eksauth.IsIrrecoverableApiError(err) {
			log.Infof("Removing credentials from cache, got non recoverable error: %s", err.Error())
			promCacheError.WithLabelValues("NonRecoverable").Inc()
			r.internalCache.Delete(entry.originatingRequest.ServiceAccountToken)
			return
		}
		log.Infof("Could not renew, will try to keep existing creds. Error is recoverable: %s", err.Error())
	} else {
		log.Infof("Rate limited! Will try to keep creds locally")
	}

	// if there was an error, try to keep the old credentials in the agent if they haven't expired
	oldCreds := entry.credentials
	oldCredsDuration := oldCreds.Expiration.Time.Sub(r.now())
	if oldCredsDuration > r.minCredentialTtl {
		calculatedRetryInterval := r.retryInterval + time.Duration(rand.Int63n(int64(r.maxRetryJitter)))
		newRefreshTtl := minDuration(oldCredsDuration, calculatedRetryInterval)
		log.WithField("ttl", newRefreshTtl).
			Infof("Credentials still valid for at least %0.2fs, keeping them will try again after ttl expires", oldCredsDuration.Seconds())
		r.internalCache.SetWithRefreshExpire(key, entry, newRefreshTtl, oldCredsDuration)
	} else {
		promCacheState.WithLabelValues("evicted").Inc()
		log.Infof("Evicting credentials since they are too old")
	}
}

func (r *cachedCredentialRetriever) onCredentialEviction(key string, entry cacheEntry) {
	log := logger.FromContext(entry.requestLogCtx)
	log.Infof("Credentials evicted")
}

func minDuration(a time.Duration, b time.Duration) time.Duration {
	if a > b {
		return b
	} else {
		return a
	}
}
