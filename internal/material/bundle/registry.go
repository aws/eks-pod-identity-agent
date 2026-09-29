// Package bundle is the trust bundle tier: it holds the node's current trust
// bundles, refreshes them from sts:GetTrustBundles, and signals when the
// authorities in them change. It implements workloadidentity.BundleSource.
//
// The tier keeps one cache per workload identity provider, not per pod, learning
// each provider from the ARN in a workload's session. Fetches are signed with the
// node's own credentials, and the agent serves exactly what GetTrustBundles
// returns, with no merge across trust domains.
package bundle

import (
	"context"
	"crypto"
	"errors"
	"sync"
	"time"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

const (
	// softProviderCap is how many providers a node is expected to track. Past it
	// the node warns on each new provider and still serves it: leases and idleTTL
	// already bound the count, and refusing would break workloads for a local limit.
	softProviderCap = 64
	// idleTTL is how long a provider with no lease stays cached after its last read
	// or its last lease ending.
	idleTTL = time.Hour
	// sweepInterval is how often Run evicts idle providers, so one leaves between
	// idleTTL and idleTTL+sweepInterval after its last use.
	sweepInterval = 5 * time.Minute
)

// Registry is the trust bundle tier: one providerSource per workload identity
// provider, created the first time a read or a lease names it.
//
// A stream holds a lease on its provider for as long as it is open, which keeps
// the provider cached and refreshed, since a bundle-only stream otherwise reads
// only when signalled. A provider with no lease is evicted once idleTTL has passed
// since its last read or its last lease ended.
type Registry struct {
	opts Opts

	mu      sync.Mutex
	entries map[string]*providerEntry
	// runCtx is the context refresh loops run under, nil until Run starts.
	runCtx context.Context

	// now, after and configure are the registry's clock, its sweep timer, and a
	// hook adjusting each providerSource as it is created, replaced in tests.
	now       func() time.Time
	after     func(time.Duration) <-chan time.Time
	configure func(*providerSource)
}

// providerEntry is one provider's source and what decides when it is evicted.
type providerEntry struct {
	source *providerSource
	// leases counts the provider's open leases; a leased provider is never evicted.
	leases int
	// lastUsed is when the provider was last read or last had a lease end.
	lastUsed time.Time
	// stop ends the provider's refresh loop, nil until the loop starts.
	stop context.CancelFunc
}

// New builds the tier. It fetches nothing and knows no provider yet. It takes no
// session or provider ARN; each provider arrives with the call that names it.
func New(opts Opts) (*Registry, error) {
	var missing []error
	if opts.Fetcher == nil {
		missing = append(missing, errors.New("a GetTrustBundles fetcher is required"))
	}
	if opts.Notifier == nil {
		missing = append(missing, errors.New("a bundle change notifier is required"))
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

// Run keeps every known provider's bundles refreshed and evicts idle ones until
// ctx is done. Providers learned before Run get their refresh loops when it
// starts, and later ones at once. It returns when ctx is cancelled.
func (r *Registry) Run(ctx context.Context) {
	r.mu.Lock()
	r.runCtx = ctx
	for _, entry := range r.entries {
		r.startLocked(entry)
	}
	r.mu.Unlock()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.after(sweepInterval):
			r.sweep(ctx)
		}
	}
}

// Lease keeps the provider cached and refreshed until release is called or ctx
// ends, whichever comes first, learning the provider if it is new. Releasing the
// last lease restarts the provider's idleTTL. An empty ARN is ErrNotEnrolled.
func (r *Registry) Lease(ctx context.Context, providerArn string) (func(), error) {
	if providerArn == "" {
		return nil, errNoProvider()
	}
	r.mu.Lock()
	entry := r.entryLocked(providerArn, true)
	entry.leases++
	r.mu.Unlock()

	var once sync.Once
	release := func() {
		once.Do(func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			entry.leases--
			entry.lastUsed = r.now()
		})
	}
	stopWatching := context.AfterFunc(ctx, release)
	return func() {
		stopWatching()
		release()
	}, nil
}

// OwnTrustDomain returns the provider's own trust domain, or the empty string for
// a provider with no bundle fetched yet. It never learns a provider or fetches.
func (r *Registry) OwnTrustDomain(providerArn string) string {
	if source := r.known(providerArn); source != nil {
		return source.OwnTrustDomain()
	}
	return ""
}

// X509Bundles returns the provider's X.509 authorities as DER, keyed by trust
// domain, learning the provider if this is the first read to name it.
func (r *Registry) X509Bundles(ctx context.Context, providerArn string) (map[string][][]byte, error) {
	source, err := r.source(providerArn)
	if err != nil {
		return nil, err
	}
	return source.X509Bundles(ctx)
}

// JWTBundles returns the provider's JWT authorities as standard JWK Sets, keyed by
// trust domain, learning the provider if this is the first read to name it.
func (r *Registry) JWTBundles(ctx context.Context, providerArn string) (map[string][]byte, error) {
	source, err := r.source(providerArn)
	if err != nil {
		return nil, err
	}
	return source.JWTBundles(ctx)
}

// JWTAuthority resolves one JWT verification key from the provider's bundles. It
// never learns a provider or fetches, so for a provider with no bundle fetched yet
// it returns ErrBundleUnavailable.
func (r *Registry) JWTAuthority(providerArn, trustDomain, keyID string) (crypto.PublicKey, error) {
	if providerArn == "" {
		return nil, errNoProvider()
	}
	source := r.known(providerArn)
	if source == nil {
		return nil, wierrors.ErrBundleUnavailable.Wrapf(nil, "no trust bundle has been fetched for %s yet", providerArn)
	}
	return source.JWTAuthority(trustDomain, keyID)
}

// known returns the provider's source, or nil when nothing has named it, and
// counts the call as a read of the provider.
func (r *Registry) known(providerArn string) *providerSource {
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry := r.entryLocked(providerArn, false); entry != nil {
		return entry.source
	}
	return nil
}

// source returns the provider's source, learning the provider if it is new, and
// counts the call as a read of the provider.
func (r *Registry) source(providerArn string) (*providerSource, error) {
	if providerArn == "" {
		return nil, errNoProvider()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.entryLocked(providerArn, true).source, nil
}

// entryLocked returns the provider's entry with its idleTTL restarted, creating it
// and starting its refresh loop when create is set and the provider is new. It
// returns nil for an unknown provider when create is not set.
func (r *Registry) entryLocked(providerArn string, create bool) *providerEntry {
	entry, ok := r.entries[providerArn]
	if !ok {
		if !create {
			return nil
		}
		source := newProviderSource(providerArn, r.opts)
		if r.configure != nil {
			r.configure(source)
		}
		entry = &providerEntry{source: source}
		r.entries[providerArn] = entry
		r.startLocked(entry)
		if len(r.entries) > softProviderCap {
			logger.FromContext(context.Background()).WithField("provider_arn", providerArn).
				Warnf("Tracking trust bundles for %d workload identity providers, more than the %d a node is expected to need",
					len(r.entries), softProviderCap)
		}
	}
	entry.lastUsed = r.now()
	return entry
}

// startLocked starts the entry's refresh loop under Run's context, if Run is
// running.
func (r *Registry) startLocked(entry *providerEntry) {
	if r.runCtx == nil || r.runCtx.Err() != nil {
		return
	}
	loopCtx, stop := context.WithCancel(r.runCtx)
	entry.stop = stop
	go entry.source.Run(loopCtx)
}

// sweep evicts every provider with no lease whose idleTTL has passed, stopping
// its refresh loop. A later read or lease learns the provider again.
func (r *Registry) sweep(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for providerArn, entry := range r.entries {
		if entry.leases > 0 || now.Sub(entry.lastUsed) < idleTTL {
			continue
		}
		if entry.stop != nil {
			entry.stop()
		}
		delete(r.entries, providerArn)
		logger.FromContext(ctx).WithField("provider_arn", providerArn).
			Infof("Evicted trust bundles for a workload identity provider unused for %s", idleTTL)
	}
}

// errNoProvider is the error for a call naming no provider. The ARN comes from
// the workload's session, and a session without one is a workload whose
// association is not enrolled in workload identity.
func errNoProvider() error {
	return wierrors.ErrNotEnrolled.Wrapf(nil, "the workload's session names no workload identity provider")
}

var _ workloadidentity.BundleSource = &Registry{}
