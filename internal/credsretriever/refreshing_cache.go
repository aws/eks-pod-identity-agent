package credsretriever

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cache/expiring"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/credcache"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/validation"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
)

// tokenValidator performs local JWT validation when available.
type tokenValidator interface {
	ValidateToken(ctx context.Context, req *credentials.EksCredentialsRequest) error
}

type cachedCredentialRetriever struct {
	// cache is where credentials are stored. It refreshes and evicts them, and
	// is keyed by pod UID.
	cache *credcache.Cache
	// internalActiveRequestCache tracks the active ongoing requests. Key in the cache is the service
	// token, values are errors returned from the active requests. When a service token is in the
	// internalActiveRequestCache, but not cache, it means an active request is ongoing,
	// other requests to the same service token should wait for this active request.
	internalActiveRequestCache *expiring.Cache[string, error]
	// delegate is the credential source for trusted tokens
	delegate credentials.CredentialRetriever
	// authoritativeDelegate is the credential source that can validate untrusted tokens
	authoritativeDelegate credentials.CredentialRetriever
	// tokenValidator performs local JWT validation when available
	tokenValidator atomic.Value // stores tokenValidator interface
	tvInitInFlight atomic.Bool
}

// type assertion
var _ credentials.CredentialRetriever = &cachedCredentialRetriever{}

var (
	promLocalValidation = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pod_identity_local_validation",
		Help: "Outcome of local token validation: success, failure, or skipped",
	}, []string{"result"},
	)
)

const (
	defaultActiveRequestRetries  = 9
	defaultActiveRequestWaitTime = 200 * time.Millisecond
)

type CachedCredentialRetrieverOpts struct {
	// Cache is where the retriever stores and serves credentials.
	Cache                 *credcache.Cache
	Delegate              credentials.CredentialRetriever
	AuthoritativeDelegate credentials.CredentialRetriever
	TokenValidator        tokenValidator
}

// NewCachedCredentialRetriever creates a credential retriever that serves and
// stores credentials in opts.Cache, which refreshes them through Delegate until
// the association is removed and no longer needed.
func NewCachedCredentialRetriever(opts CachedCredentialRetrieverOpts) credentials.CredentialRetriever {
	if opts.Cache == nil || opts.Delegate == nil || opts.AuthoritativeDelegate == nil {
		panic("Cache, Delegate and AuthoritativeDelegate must be non-nil")
	}
	return newCachedCredentialRetriever(opts)
}

func newCachedCredentialRetriever(opts CachedCredentialRetrieverOpts) *cachedCredentialRetriever {
	retriever := &cachedCredentialRetriever{
		cache:                      opts.Cache,
		delegate:                   opts.Delegate,
		authoritativeDelegate:      opts.AuthoritativeDelegate,
		internalActiveRequestCache: expiring.NewLru[string, error](opts.Cache.MaxSize(), 0, 0),
	}
	if opts.TokenValidator != nil {
		retriever.tokenValidator.Store(opts.TokenValidator)
	}
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

	// Bind podUID into the logger context so all downstream logs for this
	// request are attributable to a specific pod.
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
	r.cache.RecordMiss()

	// The token is not trusted by the cache, so admit it via the authoritative
	// delegate (EKS Auth).
	entry, metadata, err := r.callDelegateAndCache(ctx, r.authoritativeDelegate, request)
	if err != nil {
		return nil, nil, err
	}
	return entry.Credentials, metadata, nil
}

// tryServingFromCache checks the cache for valid credentials matching the request.
// Returns the credentials and true if a cache hit was found, or nil and false otherwise.
func (r *cachedCredentialRetriever) tryServingFromCache(ctx context.Context,
	podUID string, request *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, bool) {
	log := logger.FromContext(ctx)

	val, ok := r.cache.Get(podUID)
	if !ok {
		return nil, false
	}

	if _, withinTtl := r.cache.Usable(val); !withinTtl {
		log.Info("Identified that entry in cache contains credentials with small ttl or invalid ttl, will be deleted")
		r.cache.Delete(podUID, val)
		return nil, false
	}

	// If the cached credentials' token matches the incoming requests' token, return the credentials
	if val.Request != nil && val.Request.ServiceAccountToken == request.ServiceAccountToken {
		log.WithField("cache-hit", 1).Tracef("Using cached credentials")
		return val.Credentials, true
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

	r.cache.Modify(podUID, val, func(e *credcache.Entry) {
		e.Request = request
	})
	log.WithField("cache-hit", 1).Tracef("Local validation succeeded, using cached credentials")
	promLocalValidation.WithLabelValues("success").Inc()
	return val.Credentials, true
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
	delegate credentials.CredentialRetriever,
	request *credentials.EksCredentialsRequest) (*credcache.Entry, credentials.ResponseMetadata, error) {
	podUID, err := credentials.GetPodUIDFromToken(request.ServiceAccountToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get pod uid from service account token: %w", err)
	}

	newCacheEntry, err := r.fetchCredentialsFromDelegate(ctx, delegate, request)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting credentials to cache: %w", err)
	}

	if newCacheEntry.Credentials == nil {
		return nil, nil, fmt.Errorf("delegate returned nil credentials")
	}

	// Store credentials in cache if they are valid. It might be that
	// the credentials might have been either removed or inserted by another
	// thread, but it won't matter, we'll just upsert as the cache is thread safe
	if err := r.cache.Store(ctx, podUID, newCacheEntry); err != nil {
		return nil, nil, err
	}
	return newCacheEntry, newCacheEntry.Metadata, nil
}

func (r *cachedCredentialRetriever) fetchCredentialsFromDelegate(ctx context.Context,
	delegate credentials.CredentialRetriever,
	request *credentials.EksCredentialsRequest) (*credcache.Entry, error) {
	iamCredentials, metadata, err := delegate.GetIamCredentials(ctx, request)
	if err != nil {
		return nil, err
	}
	requestLogCtx := logger.ContextWithField(logger.CloneToNewIfPresent(ctx, context.Background()),
		"association-id", metadata.AssociationId())
	if podUID, uidErr := credentials.GetPodUIDFromToken(request.ServiceAccountToken); uidErr == nil {
		requestLogCtx = logger.ContextWithField(requestLogCtx, "podUID", podUID)
	}
	return &credcache.Entry{
		Request:     request,
		LogCtx:      requestLogCtx,
		Credentials: iamCredentials,
		Metadata:    metadata,
		Owner:       delegateOwner{r},
	}, nil
}

// delegateOwner renews an entry this retriever stored by replaying the entry's
// request through the general delegate.
type delegateOwner struct {
	r *cachedCredentialRetriever
}

var _ credcache.Owner = delegateOwner{}

// Renew refreshes an already-cached entry via the general delegate.
func (o delegateOwner) Renew(ctx context.Context, _ string, e *credcache.Entry) (*credcache.Entry, error) {
	if e.Request == nil {
		return nil, fmt.Errorf("cached credentials have no request to refresh them with")
	}
	next, err := o.r.fetchCredentialsFromDelegate(ctx, o.r.delegate, e.Request)
	if err != nil {
		return nil, fmt.Errorf("error getting credentials to cache: %w", err)
	}
	if next.Credentials == nil {
		return nil, fmt.Errorf("delegate returned nil credentials")
	}
	return next, nil
}

// IsIrrecoverable classifies a failed refresh as the general delegate does.
func (o delegateOwner) IsIrrecoverable(err error) (string, bool) {
	return o.r.delegate.IsIrrecoverable(err)
}

// Evicted does nothing: the cache already logs and counts every eviction.
func (delegateOwner) Evicted(string, *credcache.Entry, bool) {}
