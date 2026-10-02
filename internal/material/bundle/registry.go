// Package bundle is the trust bundle tier: it holds the node's current trust
// bundles, refreshes them from sts:GetTrustBundles, and signals when the
// authorities in them change. It implements workloadidentity.BundleSource.
//
// The tier keeps one cache per workload identity provider, not per pod, and
// learns each provider from the workload that reads it through Opts.Providers.
// Opts.Signer picks whose credentials sign the call, a workload session at
// launch. The agent serves exactly what GetTrustBundles returns, with no merge
// across trust domains.
package bundle

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

const (
	// softProviderCap is a rough guess at well above the handful of providers a
	// node is expected to see, not a calculated limit. Past it the node warns on
	// each new provider and still serves it, since leases and providerIdleTTL
	// already bound the count.
	softProviderCap = 64
	// providerIdleTTL is how long a provider with no lease stays cached after its
	// last read or its last lease ending.
	providerIdleTTL = time.Hour
	// tickInterval is how often Run checks for providers due a refresh.
	tickInterval = 30 * time.Second
	// sweepInterval is how often Run evicts idle providers, so one leaves between
	// providerIdleTTL and providerIdleTTL+sweepInterval after its last use.
	sweepInterval = 5 * time.Minute

	// defaultRefreshInterval applies when the document carries no usable hint.
	defaultRefreshInterval = 5 * time.Minute
	// minRefreshInterval floors the hint, so a pathological one cannot turn into a
	// hot loop against STS from every node.
	minRefreshInterval = time.Minute
	// maxRefreshInterval caps the hint. STS knows how long it publishes new
	// material before signing with it, so its hint is trusted up to here.
	maxRefreshInterval = time.Hour
	// refreshJitter is the most an interval is shortened by, so nodes that booted
	// together do not poll together. It never lengthens one.
	refreshJitter = 0.1

	// retryBaseDelay and retryMaxDelay bound the exponential backoff after a
	// failed fetch, so a long outage or a refusal that never clears costs each
	// node one call per provider every 10 minutes.
	retryBaseDelay = 10 * time.Second
	retryMaxDelay  = 10 * time.Minute

	// fetchTimeout bounds one GetTrustBundles call.
	fetchTimeout = 10 * time.Second
)

// Fetcher is the one STS call this tier makes. internal/cloud/sts satisfies it.
type Fetcher interface {
	GetTrustBundles(ctx context.Context, creds aws.Credentials, providerArn string) ([]sts.TrustBundle, error)
}

// Opts configures the tier. It carries no provider ARN and no credentials:
// Providers and Signer find both for each workload that reads the tier.
type Opts struct {
	// Fetcher makes the GetTrustBundles call. Required.
	Fetcher Fetcher
	// Notifier is told, per provider, of each real change in either authority
	// set. Required.
	Notifier workloadidentity.BundleNotifier
	// Providers names each reading workload's provider. Required.
	Providers workloadidentity.ProviderArnResolver
	// Signer chooses the credentials GetTrustBundles is signed with. Required.
	Signer Signer
}

// Registry is the trust bundle tier: one providerSource per workload identity
// provider, created the first time a read or a lease names it, and one refresher
// for all of them.
//
// A stream holds a lease for as long as it is open, which keeps its provider
// cached, and a refresh asks the Signer for credentials on behalf of the
// leaseholders and then the latest reader. A provider with no lease is evicted
// once providerIdleTTL has passed since its last read or its last lease ended.
type Registry struct {
	opts Opts

	mu      sync.Mutex
	entries map[string]*providerEntry

	// now, after and configure are the registry's clock, its ticker, and a hook
	// adjusting each providerSource as it is created, replaced in tests.
	now       func() time.Time
	after     func(time.Duration) <-chan time.Time
	configure func(*providerSource)
}

// providerEntry is one provider's source and the workloads that keep it alive.
type providerEntry struct {
	source *providerSource
	// holders counts the open leases of each workload, by pod UID.
	holders map[string]*leaseHolder
	// lastReader is the workload that most recently read or leased the provider.
	lastReader *workloadidentity.Workload
	// lastUsed is when the provider was last read or last had a lease end.
	lastUsed time.Time
}

// leaseHolder is a workload with open leases on a provider.
type leaseHolder struct {
	workload *workloadidentity.Workload
	leases   int
}

// New builds the tier. It fetches nothing and knows no provider yet; each
// provider arrives with the first workload that names it.
func New(opts Opts) (*Registry, error) {
	var missing []error
	if opts.Fetcher == nil {
		missing = append(missing, errors.New("a GetTrustBundles fetcher is required"))
	}
	if opts.Notifier == nil {
		missing = append(missing, errors.New("a bundle change notifier is required"))
	}
	if opts.Providers == nil {
		missing = append(missing, errors.New("a provider ARN resolver is required"))
	}
	if opts.Signer == nil {
		missing = append(missing, errors.New("a GetTrustBundles signer is required"))
	}
	if err := errors.Join(missing...); err != nil {
		return nil, err
	}
	return &Registry{
		opts:    opts,
		entries: map[string]*providerEntry{},
		now:     time.Now,
		after:   time.After,
	}, nil
}

// Run refreshes every provider that is due and evicts idle ones until ctx is
// done. Providers are refreshed one at a time, each bounded by fetchTimeout.
func (r *Registry) Run(ctx context.Context) {
	lastSweep := r.now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.after(tickInterval):
		}
		r.refreshDue(ctx)
		if now := r.now(); now.Sub(lastSweep) >= sweepInterval {
			r.sweep(ctx)
			lastSweep = now
		}
	}
}

// Lease keeps the workload's provider cached and refreshed until release is
// called or ctx ends, whichever comes first, learning the provider if it is new.
// Releasing the last lease restarts the provider's providerIdleTTL.
func (r *Registry) Lease(ctx context.Context, w *workloadidentity.Workload) (func(), error) {
	entry, _, err := r.resolve(ctx, w)
	if err != nil {
		return nil, err
	}
	holder := func() *leaseHolder {
		r.mu.Lock()
		defer r.mu.Unlock()
		holder, ok := entry.holders[w.PodUID]
		if !ok {
			holder = &leaseHolder{workload: w}
			entry.holders[w.PodUID] = holder
		}
		holder.leases++
		return holder
	}()

	var once sync.Once
	release := func() {
		once.Do(func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			if holder.leases--; holder.leases == 0 {
				delete(entry.holders, w.PodUID)
			}
			entry.lastUsed = r.now()
		})
	}
	stopWatching := context.AfterFunc(ctx, release)
	return func() {
		stopWatching()
		release()
	}, nil
}

// OwnTrustDomain returns the workload's provider's own trust domain.
func (r *Registry) OwnTrustDomain(ctx context.Context, w *workloadidentity.Workload) (string, error) {
	source, sign, err := r.read(ctx, w)
	if err != nil {
		return "", err
	}
	return source.OwnTrustDomain(ctx, sign)
}

// X509Bundles returns the workload's provider's X.509 authorities as DER, keyed by
// trust domain.
func (r *Registry) X509Bundles(ctx context.Context, w *workloadidentity.Workload) (map[string][][]byte, error) {
	source, sign, err := r.read(ctx, w)
	if err != nil {
		return nil, err
	}
	return source.X509Bundles(ctx, sign)
}

// JWTBundles returns the workload's provider's JWT authorities as standard JWK
// Sets, keyed by trust domain.
func (r *Registry) JWTBundles(ctx context.Context, w *workloadidentity.Workload) (map[string][]byte, error) {
	source, sign, err := r.read(ctx, w)
	if err != nil {
		return nil, err
	}
	return source.JWTBundles(ctx, sign)
}

// JWTSource returns the workload's provider's JWT authorities as a jwtbundle.Source
// for jwtsvid.ParseAndValidate.
func (r *Registry) JWTSource(ctx context.Context, w *workloadidentity.Workload) (jwtbundle.Source, error) {
	source, sign, err := r.read(ctx, w)
	if err != nil {
		return nil, err
	}
	return source.JWTSource(ctx, sign)
}

// read resolves the workload's provider as resolve does and returns its source,
// with how a fetch on the workload's behalf is signed.
func (r *Registry) read(ctx context.Context, w *workloadidentity.Workload) (*providerSource, signFunc, error) {
	entry, providerArn, err := r.resolve(ctx, w)
	if err != nil {
		return nil, nil, err
	}
	sign := func(ctx context.Context) (aws.Credentials, error) {
		return r.opts.Signer.Credentials(ctx, providerArn, []*workloadidentity.Workload{w})
	}
	return entry.source, sign, nil
}

// resolve names the workload's provider and returns its entry and ARN, learning
// the provider if it is new and counting the call as a read.
func (r *Registry) resolve(ctx context.Context, w *workloadidentity.Workload) (*providerEntry, string, error) {
	if w == nil {
		return nil, "", wierrors.ErrUnattestable.Wrapf(nil, "a trust bundle read names no workload")
	}
	providerArn, err := r.opts.Providers.ProviderArn(ctx, w)
	if err != nil {
		return nil, "", err
	}
	if providerArn == "" {
		return nil, "", wierrors.ErrNotEnrolled.Wrapf(nil, "the workload names no workload identity provider")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.entryLocked(providerArn)
	entry.lastReader = w
	entry.lastUsed = r.now()
	return entry, providerArn, nil
}

// entryLocked returns the provider's entry, creating it when the provider is new.
func (r *Registry) entryLocked(providerArn string) *providerEntry {
	if entry, ok := r.entries[providerArn]; ok {
		return entry
	}
	source := newProviderSource(providerArn, r.opts)
	if r.configure != nil {
		r.configure(source)
	}
	entry := &providerEntry{source: source, holders: map[string]*leaseHolder{}}
	r.entries[providerArn] = entry
	if len(r.entries) > softProviderCap {
		logger.FromContext(context.Background()).WithField("provider_arn", providerArn).
			Warnf("Tracking trust bundles for %d workload identity providers, more than the %d a node is expected to need",
				len(r.entries), softProviderCap)
	}
	return entry
}

// refreshDue refreshes each provider whose next refresh has come, signed with
// what the Signer picks for the workloads that keep it alive.
func (r *Registry) refreshDue(ctx context.Context) {
	now := r.now()
	type job struct {
		entry      *providerEntry
		due        time.Time
		candidates []*workloadidentity.Workload
	}
	work := func() []job {
		r.mu.Lock()
		defer r.mu.Unlock()
		var work []job
		for _, entry := range r.entries {
			due := entry.source.dueAt()
			if due.After(now) {
				continue
			}
			var candidates []*workloadidentity.Workload
			for _, holder := range entry.holders {
				candidates = append(candidates, holder.workload)
			}
			if reader := entry.lastReader; reader != nil && entry.holders[reader.PodUID] == nil {
				candidates = append(candidates, reader)
			}
			work = append(work, job{entry, due, candidates})
		}
		return work
	}()

	for _, item := range work {
		if ctx.Err() != nil {
			return
		}
		log := logger.FromContext(ctx).WithField("provider_arn", item.entry.source.providerArn)
		creds, err := r.opts.Signer.Credentials(ctx, item.entry.source.providerArn, item.candidates)
		if err != nil {
			item.entry.source.recordFailure(ctx, err, item.due)
			log.WithError(err).Warn("No credentials to refresh trust bundles with")
			continue
		}
		if err := item.entry.source.refresh(ctx, creds, item.due); err != nil && ctx.Err() == nil {
			log.WithError(err).Warn("Trust bundle refresh failed, serving the last good bundle")
		}
	}
}

// sweep evicts every provider with no lease whose providerIdleTTL has passed. A
// later read or lease learns the provider again.
func (r *Registry) sweep(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for providerArn, entry := range r.entries {
		if len(entry.holders) > 0 || now.Sub(entry.lastUsed) < providerIdleTTL {
			continue
		}
		delete(r.entries, providerArn)
		logger.FromContext(ctx).WithField("provider_arn", providerArn).
			Infof("Evicted trust bundles for a workload identity provider unused for %s", providerIdleTTL)
	}
}

var _ workloadidentity.BundleSource = &Registry{}
