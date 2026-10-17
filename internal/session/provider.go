// Package session is the workload identity session tier. It shares the
// credential cache with the HTTP retriever, and either can serve an entry the
// other stored once its own check passes: token validation for HTTP, a
// decorated session here. Entries this tier stores are keyed by attested pod
// UID and keep the request they were exchanged with. The cache refreshes them by
// its one rule, with RefreshWith sending every decorated entry to EKS Auth and
// MinterTokens renewing its token close to expiry. Neither an exchange nor a
// refresh of a decorated entry goes to the IMDS chain, whose answers aren't
// decorated. A pod's deletion drops its entry, whichever caller stored it.
package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eksauth/types"
	"golang.org/x/sync/singleflight"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/credcache"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/podstore"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// renewalTimeout bounds one exchange and its store, as credcache bounds a
// refresh.
const renewalTimeout = 1 * time.Minute

// Opts configures New. Every field is required.
type Opts struct {
	// ClusterName is the EKS cluster the agent runs in.
	ClusterName string
	// Minter obtains the projected token each exchange presents. cmd passes the
	// minter MinterTokens wraps for the cache, so both share one token cache.
	Minter workloadidentity.TokenMinter
	// Cache is the credential cache the HTTP retriever serves from. The tier
	// stores its sessions there, and the cache refreshes them.
	Cache *credcache.Cache
	// EKSAuth is the EKS Auth client every exchange goes to.
	EKSAuth credentials.CredentialRetriever
	// PodStore reports the pod deletions the tier drops entries for.
	PodStore podstore.Interface
}

// Provider is the workloadidentity.SessionProvider the agent uses. It serves a
// decorated session from the shared cache while the cache says it's usable, and
// exchanges otherwise. When a pod is deleted it has the cache forget the pod, so
// neither an exchange nor a refresh in flight caches anything for it again.
type Provider struct {
	clusterName string
	minter      workloadidentity.TokenMinter
	cache       *credcache.Cache
	eksAuth     credentials.CredentialRetriever
	// group runs one exchange per pod at a time for Session callers, keyed by
	// pod UID. The cache's refreshes don't go through it.
	group   singleflight.Group
	metrics sessionMetrics
	// joined, when set, is called by every Session caller as it starts waiting
	// on an exchange. Only tests set it.
	joined func(podUID string)
}

var _ workloadidentity.SessionProvider = (*Provider)(nil)

// New builds a Provider over the shared credential cache. It returns an error
// rather than panicking, so startup can report a misconfigured workload
// identity socket.
func New(opts Opts) (*Provider, error) {
	switch {
	case opts.ClusterName == "":
		return nil, errors.New("session provider: cluster name is required")
	case opts.Minter == nil:
		return nil, errors.New("session provider: a token minter is required")
	case opts.Cache == nil:
		return nil, errors.New("session provider: workload identity needs the credential cache, which is off " +
			"while --max-credential-retention-before-renewal or --max-cache-size is zero")
	case opts.EKSAuth == nil:
		return nil, errors.New("session provider: an EKS Auth client is required")
	case opts.PodStore == nil:
		return nil, errors.New("session provider: the node-scoped pod store is required")
	}
	p := &Provider{
		clusterName: opts.ClusterName,
		minter:      opts.Minter,
		cache:       opts.Cache,
		eksAuth:     opts.EKSAuth,
		metrics:     defaultSessionMetrics(),
	}
	if err := opts.PodStore.OnPodDeleted(p.forget); err != nil {
		return nil, fmt.Errorf("session provider: registering the pod deletion callback: %w", err)
	}
	return p, nil
}

// Session returns a copy of the pod's decorated session: the cached one,
// whichever caller stored it, while the cache says it's usable, otherwise one
// from an exchange shared by every caller for the pod. An EKS Auth refusal is
// ErrSessionRefused; wierrors.IsRetryable decides for every error it returns.
func (p *Provider) Session(ctx context.Context, w *workloadidentity.Workload) (*workloadidentity.WorkloadSession, error) {
	if w == nil || w.PodUID == "" {
		return nil, wierrors.ErrSessionUnavailable.Wrapf(nil, "cannot exchange a session for an empty workload")
	}
	log := logger.FromContext(ctx)

	entry, ok := p.cache.Get(w.PodUID)
	switch {
	case !ok || !decorated(entry):
		log.WithField("cache-hit", 0).Tracef("Could not find a session in cache, exchanging a token with EKS Auth")
		p.metrics.observeCache(workloadidentity.CacheResultMiss)
	case p.usable(entry):
		log.WithField("cache-hit", 1).Tracef("Using cached session")
		p.metrics.observeCache(workloadidentity.CacheResultHit)
		return toWorkloadSession(entry), nil
	default:
		log.Info("Identified that the cached session expires within the floor, will exchange a new one")
		p.metrics.observeCache(workloadidentity.CacheResultExpired)
	}

	entry, err := p.fetch(ctx, w)
	if err == nil && !p.cached(w.PodUID, entry) {
		// The answer left the cache before it was handed out, possibly because
		// this caller invalidated it, so a second join reaches a later exchange.
		// Asking once more costs at most one exchange.
		log.Info("Session left the cache before it could be handed out, asking again")
		entry, err = p.fetch(ctx, w)
	}
	if err != nil {
		return nil, err
	}
	return toWorkloadSession(entry), nil
}

// Invalidate drops the pod's cached entry, whichever caller stored it, so the
// next caller exchanges again. A Session caller's exchange in flight still
// stores its answer, and callers that invalidate and ask again share it. A
// refresh in flight stores its renewal too, since the cache stores every
// renewal, but never puts the dropped session back.
func (p *Provider) Invalidate(podUID string) {
	if podUID == "" {
		return
	}
	entry, ok := p.cache.Get(podUID)
	if !ok {
		return
	}
	logCtx := entry.LogCtx
	if logCtx == nil {
		logCtx = context.Background()
	}
	logger.FromContext(logCtx).WithField("pod-uid", podUID).Info("Session invalidated, dropping its session")
	p.cache.Delete(podUID)
}

// forget is the pod deletion callback New registers with the pod store. It drops
// the pod's entry, whichever caller stored it, and has the cache refuse every
// later store for the pod, one for an exchange or refresh in flight included.
func (p *Provider) forget(podUID string) {
	if podUID == "" {
		return
	}
	if entry, ok := p.cache.Get(podUID); ok {
		logCtx := entry.LogCtx
		if logCtx == nil {
			logCtx = context.Background()
		}
		logger.FromContext(logCtx).WithField("pod-uid", podUID).Info("Pod deleted, dropping its cached credentials")
	}
	p.cache.Forget(podUID)
}

// cached reports whether the cache still serves e for podUID. The cache knows an
// entry by its credentials, so a Modify copy of e counts as e.
func (p *Provider) cached(podUID string, e *credcache.Entry) bool {
	current, ok := p.cache.Get(podUID)
	return ok && current.Credentials == e.Credentials
}

// fetch joins the pod's exchange in flight, or starts one, and waits for the
// entry it answers with. A caller already gone starts no exchange.
func (p *Provider) fetch(ctx context.Context, w *workloadidentity.Workload) (*credcache.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, wierrors.ErrSessionUnavailable.Wrapf(err, "gave up before exchanging a session for pod %s", w.PodUID)
	}
	return p.await(ctx, w.PodUID, p.joinForRequest(ctx, w))
}

// joinForRequest joins the pod's exchange in flight, or starts one that rechecks
// the cache first, for a caller that missed it just before another exchange
// stored. The exchange keeps ctx's values but not its cancellation, so a caller
// giving up never fails the others, and an abandoned exchange still stores.
func (p *Provider) joinForRequest(ctx context.Context, w *workloadidentity.Workload) <-chan singleflight.Result {
	// The exchange can outlive Session, so it mustn't read a struct the caller
	// can change.
	workload := *w
	detached := context.WithoutCancel(ctx)
	return p.group.DoChan(workload.PodUID, func() (any, error) {
		if entry, ok := p.cache.Get(workload.PodUID); ok && p.servable(entry) {
			return entry, nil
		}
		return p.exchangeAndStore(detached, &workload)
	})
}

// exchangeAndStore exchanges for w under renewalTimeout and stores the entry
// before returning it, so it's cached by the time group releases the pod. A pod
// deleted before the store is ErrUnattestable.
func (p *Provider) exchangeAndStore(ctx context.Context, w *workloadidentity.Workload) (*credcache.Entry, error) {
	ctx, cancel := context.WithTimeout(ctx, renewalTimeout)
	defer cancel()
	entry, err := p.exchange(ctx, w)
	if err != nil {
		return nil, err
	}
	storeCtx := logger.ContextWithField(ctx, "pod-uid", w.PodUID, "association-id", entry.Metadata.AssociationId())
	if err := p.cache.Store(storeCtx, w.PodUID, entry); err != nil {
		if errors.Is(err, credcache.ErrForgotten) {
			return nil, wierrors.ErrUnattestable.Wrapf(err, "pod %s was deleted while its session was exchanged", w.PodUID)
		}
		return nil, wierrors.ErrSessionUnavailable.Wrapf(err, "caching the session for pod %s", w.PodUID)
	}
	return entry, nil
}

// await waits on the caller's own ctx for the entry the exchange it joined
// answers with. A caller that gives up gets ErrSessionUnavailable wrapping its
// context's error. The exchange still stores, and DoChan's channel is buffered.
func (p *Provider) await(ctx context.Context, podUID string, results <-chan singleflight.Result) (*credcache.Entry, error) {
	if p.joined != nil {
		p.joined(podUID)
	}
	select {
	case result := <-results:
		if result.Err != nil {
			return nil, result.Err
		}
		return result.Val.(*credcache.Entry), nil
	case <-ctx.Done():
		return nil, wierrors.ErrSessionUnavailable.Wrapf(ctx.Err(),
			"gave up waiting for the session exchange for pod %s", podUID)
	}
}

// decorated reports whether e holds a session EKS Auth decorated for workload
// identity, with all three credential members. The HTTP retriever stores
// whatever EKS Auth or IMDS sent, so an entry it stored may be neither.
func decorated(e *credcache.Entry) bool {
	c := e.Credentials
	return c != nil && e.Metadata != nil && e.Metadata.ProviderArn() != "" &&
		c.AccessKeyId != "" && c.SecretAccessKey != "" && c.Token != ""
}

// usable reports whether the cache would still serve e's credentials.
func (p *Provider) usable(e *credcache.Entry) bool {
	_, ok := p.cache.CredentialsWithinValidTtl(e)
	return ok
}

// servable is the one condition under which this tier hands a cached entry out.
func (p *Provider) servable(e *credcache.Entry) bool {
	return decorated(e) && p.usable(e)
}

// exchange runs one exchange for Session callers and records it on the
// exchange metrics, once. The cache's refreshes aren't exchanges here. Latency is
// on the wall clock rather than the cache's clock, which tests freeze.
func (p *Provider) exchange(ctx context.Context, w *workloadidentity.Workload) (*credcache.Entry, error) {
	start := time.Now()
	entry, err := p.exchangeOnce(ctx, w)
	p.metrics.observeExchange(err, time.Since(start).Seconds())
	return entry, err
}

// exchangeOnce mints a token for w, exchanges it with EKS Auth, and checks the
// answer is a session this tier can serve. The entry it returns keeps the
// request it presented, for the cache's refreshes, and logs under a context
// naming the pod and association.
func (p *Provider) exchangeOnce(ctx context.Context, w *workloadidentity.Workload) (*credcache.Entry, error) {
	token, err := mint(ctx, p.minter, w)
	if err != nil {
		return nil, err
	}

	request := &credentials.EksCredentialsRequest{ClusterName: p.clusterName, ServiceAccountToken: token}
	response, metadata, err := p.eksAuth.GetIamCredentials(ctx, request)
	if err != nil {
		return nil, p.sessionError(err, w.PodUID)
	}
	if response == nil {
		return nil, wierrors.ErrSessionUnavailable.Wrapf(nil, "EKS Auth returned no session for pod %s", w.PodUID)
	}
	// EKS Auth sets the provider ARN only on a vend it decorated, so a session
	// without one is an ordinary Pod Identity session this tier can't use.
	if metadata == nil || metadata.ProviderArn() == "" {
		return nil, wierrors.ErrNotEnrolled.Wrapf(nil,
			"EKS Auth returned a session with no workload identity provider for pod %s: its association carries no "+
				"workload identity template, or the account is not allowlisted", w.PodUID)
	}
	if response.AccessKeyId == "" || response.SecretAccessKey == "" || response.Token == "" {
		return nil, wierrors.ErrSessionUnavailable.Wrapf(nil,
			"EKS Auth returned a session for pod %s without its credentials", w.PodUID)
	}

	entry := &credcache.Entry{
		Credentials: response,
		Metadata:    metadata,
		Request:     request,
		LogCtx: logger.ContextWithField(context.Background(),
			"pod-uid", w.PodUID, "association-id", metadata.AssociationId()),
	}
	if remaining, ok := p.cache.CredentialsWithinValidTtl(entry); !ok {
		return nil, wierrors.ErrSessionUnavailable.Wrapf(nil,
			"EKS Auth returned a session for pod %s that is expired or will expire within the next %0.2f seconds",
			w.PodUID, remaining.Seconds())
	}
	return entry, nil
}

// sessionError maps an EKS Auth error onto the taxonomy, keeping the cause so
// errors.As still reaches the SDK's error. EKS Auth also answers
// ResourceNotFound for a cluster it can't resolve, so that message names it.
func (p *Provider) sessionError(err error, podUID string) error {
	if _, ok := wierrors.AsWorkloadIdentityError(err); ok {
		return err
	}
	var notFound *types.ResourceNotFoundException
	if errors.As(err, &notFound) {
		return wierrors.ErrNotEnrolled.Wrapf(err, "EKS Auth found no pod identity association for pod %s in cluster %q",
			podUID, p.clusterName)
	}
	var denied *types.AccessDeniedException
	var invalidToken *types.InvalidTokenException
	if errors.As(err, &denied) || errors.As(err, &invalidToken) {
		return wierrors.ErrSessionRefused.Wrapf(err, "EKS Auth refused a session for pod %s", podUID)
	}
	return wierrors.ErrSessionUnavailable.Wrapf(err, "exchanging a token with EKS Auth for pod %s", podUID)
}

// toWorkloadSession returns a new session built from e, so no caller shares one
// with another caller or with the cache. e is decorated.
func toWorkloadSession(e *credcache.Entry) *workloadidentity.WorkloadSession {
	c := e.Credentials
	return &workloadidentity.WorkloadSession{
		Credentials: aws.Credentials{
			AccessKeyID:     c.AccessKeyId,
			SecretAccessKey: c.SecretAccessKey,
			SessionToken:    c.Token,
			AccountID:       c.AccountId,
			CanExpire:       true,
			Expires:         c.Expiration.Time,
		},
		ProviderArn: e.Metadata.ProviderArn(),
		ExpiresAt:   c.Expiration.Time,
	}
}
