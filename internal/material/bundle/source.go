package bundle

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sync/atomic"
	"time"

	"github.com/aws/smithy-go"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
)

// Refresh scheduling. The refresh hint, or the operator's override, sets the
// interval and these bound it. It has to stay short next to how long STS publishes
// new material before signing with it, or a node lacks a key STS already signs
// with. STS knows that window, so its hint is trusted up to maxRefreshInterval.
const (
	// defaultRefreshInterval applies when the document carries no usable hint
	// and no override is set.
	defaultRefreshInterval = 5 * time.Minute
	// minRefreshInterval floors both the hint and the override, so a
	// pathological value cannot turn into a hot loop against STS from every node
	// in the fleet.
	minRefreshInterval = time.Minute
	// maxRefreshInterval caps the hint. It does not cap the override: an
	// operator who sets a long interval has chosen it.
	maxRefreshInterval = 72 * time.Hour
	// refreshJitter is the fraction an interval is shortened by, at most, so
	// nodes that booted together do not poll together. It only ever shortens, so
	// the tier never polls later than the hint asks.
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
	GetTrustBundles(ctx context.Context, providerArn string) ([]sts.TrustBundle, error)
}

// ChangeNotifier is what the tier signals a changed authority set through.
// workloadidentity.Subscriber satisfies it; the tier needs nothing else from it.
type ChangeNotifier interface {
	BroadcastBundleChange()
}

// Opts configures the tier.
//
// There is no session provider and no provider ARN here, and that is the point:
// the tier is built from a fetcher signed with the node's credentials, and learns
// each provider from the workloads' sessions as the handlers name them.
type Opts struct {
	// Fetcher makes the GetTrustBundles call. It has to be built from the
	// agent's own AWS configuration, which is the node role, and never from a
	// workload session. Required.
	Fetcher Fetcher
	// Notifier is signalled once per real change in the authority set.
	// Required.
	Notifier ChangeNotifier
	// RefreshInterval overrides the document's refresh hint when positive. It
	// is still floored at minRefreshInterval.
	RefreshInterval time.Duration
}

// providerSource holds one provider's trust bundles. One fetch backs the four
// workloadidentity.BundleSource reads for that provider (Lease is the Registry's):
// each reads the same immutable snapshot, and only the refresh path and a first
// read with nothing cached call STS.
type providerSource struct {
	providerArn string
	fetcher     Fetcher
	notifier    ChangeNotifier
	override    time.Duration

	// current is the last good snapshot, nil until the first fetch succeeds. A
	// failed fetch never replaces it.
	current atomic.Pointer[snapshot]

	// fetching is a one-slot semaphore held across a fetch and its store, so a
	// slow fetch cannot land after a newer one and roll the bundle back, and
	// concurrent first reads share one call. It is a channel rather than a mutex
	// so a waiting reader can give up when its context does.
	fetching chan struct{}

	// failures, lastErr and retryAt record the latest fetch's outcome, from the
	// loop or a first read, as the one backoff both follow: a first read inside
	// it gets lastErr instead of calling STS, so retrying streams cannot storm
	// STS. They are only touched while holding fetching.
	failures int
	lastErr  error
	retryAt  time.Time

	// now, after and jitter are the tier's clock and randomness, replaced in
	// tests.
	now    func() time.Time
	after  func(time.Duration) <-chan time.Time
	jitter func() float64
}

// snapshot is one successful fetch, parsed. It is never modified after it is
// stored.
type snapshot struct {
	// own is the trust domain of the provider's own entry.
	own string
	// domains holds every entry the response carried, by trust domain.
	domains map[string]*domainBundle
	// refreshHint is the shortest usable hint across the entries, zero when none
	// carries one.
	refreshHint time.Duration
}

// newProviderSource builds one provider's source from options New has already
// checked. It does not fetch. The read that names the provider fetches first, and
// the refresh loop's first wake fetches only if nothing has been stored by then.
func newProviderSource(providerArn string, opts Opts) *providerSource {
	return &providerSource{
		providerArn: providerArn,
		fetcher:     opts.Fetcher,
		notifier:    opts.Notifier,
		override:    opts.RefreshInterval,
		fetching:    make(chan struct{}, 1),
		now:         time.Now,
		after:       time.After,
		jitter:      rand.Float64,
	}
}

// OwnTrustDomain returns the provider's own trust domain, or the empty string
// before the first fetch has succeeded. It cannot fetch, since it has no context
// and no error, so a caller that needs it populated reads X509Bundles or
// JWTBundles first.
func (s *providerSource) OwnTrustDomain() string {
	if snap := s.current.Load(); snap != nil {
		return snap.own
	}
	return ""
}

// X509Bundles returns every trust domain's X.509 authorities as DER. A domain
// whose document carried no x509-svid key is absent. The result is a copy.
func (s *providerSource) X509Bundles(ctx context.Context) (map[string][][]byte, error) {
	snap, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string][][]byte, len(snap.domains))
	for domain, parsed := range snap.domains {
		if len(parsed.x509) == 0 {
			continue
		}
		authorities := make([][]byte, len(parsed.x509))
		for i, der := range parsed.x509 {
			authorities[i] = slices.Clone(der)
		}
		out[domain] = authorities
	}
	return out, nil
}

// JWTBundles returns every trust domain's JWT authorities as a standard JWK Set.
// A domain whose document carried no jwt-svid key is absent. The result is a
// copy.
func (s *providerSource) JWTBundles(ctx context.Context) (map[string][]byte, error) {
	snap, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(snap.domains))
	for domain, parsed := range snap.domains {
		if parsed.jwt.Empty() {
			continue
		}
		out[domain] = slices.Clone(parsed.jwks)
	}
	return out, nil
}

// JWTAuthority resolves one JWT verification key. It has no context to bound a
// call with, so it never fetches, and returns ErrBundleUnavailable until the
// first fetch succeeds. After that, an unknown trust domain is
// ErrUnknownTrustDomain and a known domain without the key is ErrUnknownKeyID.
func (s *providerSource) JWTAuthority(trustDomain, keyID string) (crypto.PublicKey, error) {
	snap := s.current.Load()
	if snap == nil {
		return nil, wierrors.ErrBundleUnavailable.Wrapf(nil, "no trust bundle has been fetched yet")
	}
	// A domain with no jwt-svid authority is as unknown here as one with no
	// entry at all, which is also how JWTBundles presents it.
	parsed, ok := snap.domains[trustDomain]
	if !ok || parsed.jwt.Empty() {
		return nil, wierrors.ErrUnknownTrustDomain.Wrapf(nil, "no JWT trust bundle for trust domain %q", trustDomain)
	}
	key, ok := parsed.jwt.FindJWTAuthority(keyID)
	if !ok {
		return nil, wierrors.ErrUnknownKeyID.Wrapf(nil, "trust domain %q has no JWT authority with key ID %q", trustDomain, keyID)
	}
	return key, nil
}

// Run refreshes the bundles until ctx is done: waking at once and fetching only if
// nothing is stored yet, then on the refresh interval, and on a backoff after a
// failure. A failed refresh leaves the last good bundle serving.
func (s *providerSource) Run(ctx context.Context) {
	log := logger.FromContext(ctx).WithField("provider_arn", s.providerArn)
	var delay time.Duration
	first := true
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.after(delay):
		}

		// The loop usually starts because a read has just named the provider and is
		// fetching for itself, so its first wake only fetches if nothing has been
		// stored. Otherwise learning a provider would cost two calls back to back.
		wait, err := s.refreshUnlessStored(ctx, first)
		first = false
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.WithError(err).WithField("retry_in", wait).Warn("Trust bundle refresh failed, serving the last good bundle")
		}
		delay = wait
	}
}

// refresh fetches and stores one snapshot after any fetch already in flight, and
// returns how long to wait before the next one. Inside a failure's backoff, which
// a first read may have started while the loop slept, it does not fetch and
// returns that failure with what is left of the wait.
func (s *providerSource) refresh(ctx context.Context) (time.Duration, error) {
	return s.refreshUnlessStored(ctx, false)
}

// refreshUnlessStored is refresh, except that when skipIfStored is set and a
// snapshot is already stored it fetches nothing and returns the normal refresh
// delay. The check is made holding the semaphore, so a first read's fetch still in
// flight when the loop wakes counts as stored once the loop gets its turn.
func (s *providerSource) refreshUnlessStored(ctx context.Context, skipIfStored bool) (time.Duration, error) {
	if err := s.acquire(ctx); err != nil {
		return 0, err
	}
	defer s.release()
	if skipIfStored && s.current.Load() != nil {
		return s.refreshDelay(), nil
	}
	if s.lastErr != nil && s.now().Before(s.retryAt) {
		return s.retryAt.Sub(s.now()), s.lastErr
	}
	next, err := s.fetch(ctx)
	if err != nil && ctx.Err() != nil {
		// The loop is stopping. Its cancellation says nothing about STS, and
		// recording it would hand a context.Canceled to a first read whose own
		// context is live.
		return 0, err
	}
	if delay := s.recordOutcome(err); err != nil {
		return delay, err
	}
	s.store(ctx, next)
	return s.refreshDelay(), nil
}

// load returns the current snapshot, fetching one if nothing has been fetched
// yet. Concurrent first reads share one fetch: whoever holds the semaphore
// fetches, and the rest find its result when they get the semaphore in turn,
// whether that result was a snapshot or a failure still inside its backoff.
func (s *providerSource) load(ctx context.Context) (*snapshot, error) {
	if snap := s.current.Load(); snap != nil {
		return snap, nil
	}
	if err := s.acquire(ctx); err != nil {
		return nil, err
	}
	defer s.release()
	if snap := s.current.Load(); snap != nil {
		return snap, nil
	}
	if s.lastErr != nil && s.now().Before(s.retryAt) {
		return nil, s.lastErr
	}
	// The fetch is detached from this reader's cancellation, because its result
	// is for every reader queued behind it: one stream closing must not abort
	// the call the rest are waiting on and cost STS a second one. fetchTimeout
	// still bounds it.
	next, err := s.fetch(context.WithoutCancel(ctx))
	s.recordOutcome(err)
	if err != nil {
		return nil, err
	}
	s.store(ctx, next)
	return next, nil
}

// recordOutcome remembers a fetch's result for the fetches that follow it, and
// returns the backoff a failure starts. The caller holds the semaphore.
func (s *providerSource) recordOutcome(err error) time.Duration {
	if err == nil {
		s.failures, s.lastErr, s.retryAt = 0, nil, time.Time{}
		return 0
	}
	s.failures++
	s.lastErr = err
	delay := s.retryDelay(s.failures)
	s.retryAt = s.now().Add(delay)
	return delay
}

// acquire takes the semaphore, or gives up when ctx does. A caller whose context
// is already done never takes it, even when it is free: select chooses at random
// between ready cases, and a caller that has gone would otherwise start a fetch
// on nobody's behalf.
func (s *providerSource) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return wierrors.ErrBundleUnavailable.Wrapf(err, "gave up waiting for a trust bundle fetch")
	}
	select {
	case s.fetching <- struct{}{}:
		return nil
	case <-ctx.Done():
		return wierrors.ErrBundleUnavailable.Wrapf(ctx.Err(), "gave up waiting for a trust bundle fetch")
	}
}

func (s *providerSource) release() {
	<-s.fetching
}

// fetch makes one GetTrustBundles call and parses the response. An error is
// ErrBundleRefused when STS refused in a way a repeat cannot change, and
// ErrBundleUnavailable otherwise, including a response the tier will not serve,
// since that can clear up without the node changing.
func (s *providerSource) fetch(ctx context.Context) (*snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	start := time.Now()
	entries, err := s.fetcher.GetTrustBundles(ctx, s.providerArn)
	var next *snapshot
	if err == nil {
		next, err = parseResponse(entries)
		if err != nil {
			err = wierrors.ErrBundleUnavailable.Wrapf(err, "GetTrustBundles for %s returned trust material the agent will not serve", s.providerArn)
		}
	} else if refused(err) {
		err = wierrors.ErrBundleRefused.Wrapf(err, "GetTrustBundles for %s was refused", s.providerArn)
	} else {
		err = wierrors.ErrBundleUnavailable.Wrapf(err, "GetTrustBundles for %s failed", s.providerArn)
	}
	observeFetch(err, time.Since(start).Seconds())
	return next, err
}

// store makes next the current snapshot and signals a change when its authority
// set differs from the one it replaces. An unchanged set keeps the previous parse
// and takes only next's refresh hint, so reordered keys change nothing served.
// The first snapshot is not a change: nothing can hold a bundle it never received.
func (s *providerSource) store(ctx context.Context, next *snapshot) {
	prev := s.current.Load()
	if prev != nil && prev.sameAuthorities(next) {
		s.current.Store(&snapshot{own: prev.own, domains: prev.domains, refreshHint: next.refreshHint})
		return
	}
	s.current.Store(next)
	if prev == nil {
		return
	}
	observeChange()
	logger.FromContext(ctx).WithFields(logrus.Fields{
		"provider_arn":  s.providerArn,
		"trust_domains": len(next.domains),
	}).Info("Trust bundle authorities changed")
	s.notifier.BroadcastBundleChange()
}

// refreshInterval is the interval before jitter: the override when set,
// otherwise the hint, otherwise the default, bounded as the constants describe.
func (s *providerSource) refreshInterval() time.Duration {
	if s.override > 0 {
		return max(s.override, minRefreshInterval)
	}
	var hint time.Duration
	if snap := s.current.Load(); snap != nil {
		hint = snap.refreshHint
	}
	if hint <= 0 {
		return defaultRefreshInterval
	}
	return min(max(hint, minRefreshInterval), maxRefreshInterval)
}

// refreshDelay is the jittered wait before the next scheduled refresh.
func (s *providerSource) refreshDelay() time.Duration {
	return shorten(s.refreshInterval(), s.jitter())
}

// retryDelay is the jittered wait before retrying after the given number of
// consecutive failures.
func (s *providerSource) retryDelay(failures int) time.Duration {
	delay := retryMaxDelay
	if failures < 8 {
		delay = min(retryBaseDelay<<(failures-1), retryMaxDelay)
	}
	return shorten(delay, s.jitter())
}

// shorten takes up to refreshJitter off d, scaled by r in [0, 1).
func shorten(d time.Duration, r float64) time.Duration {
	return d - time.Duration(float64(d)*refreshJitter*r)
}

// refusedCodes are the STS error codes a repeat cannot change. ValidationError is
// what a malformed provider ARN gets. It is a list rather than every client fault
// because STS reports throttling and an expired or skewed signature as client
// faults too, and those clear up on their own.
var refusedCodes = map[string]bool{
	"ResourceNotFoundException": true,
	"AccessDenied":              true,
	"AccessDeniedException":     true,
	"ValidationError":           true,
	"InvalidAction":             true,
}

// refused reports whether err is an STS refusal a repeat cannot change.
func refused(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && refusedCodes[apiErr.ErrorCode()]
}

// parseResponse turns a GetTrustBundles response into a snapshot, or refuses it.
// Every entry is kept, by trust domain. The first is the provider's own: the API
// model has launch responses carry only that entry, with federation entries
// arriving additively, and nothing else in the response marks it.
func parseResponse(entries []sts.TrustBundle) (*snapshot, error) {
	if len(entries) == 0 {
		return nil, errors.New("the response holds no trust bundle")
	}
	next := &snapshot{domains: make(map[string]*domainBundle, len(entries))}
	for i, entry := range entries {
		trustDomain, err := spiffeid.TrustDomainFromString(entry.TrustDomain)
		if err != nil {
			return nil, fmt.Errorf("entry %d: trust domain %q: %w", i, entry.TrustDomain, err)
		}
		name := trustDomain.Name()
		if _, duplicate := next.domains[name]; duplicate {
			return nil, fmt.Errorf("entry %d repeats trust domain %q", i, name)
		}
		parsed, err := parseDocument(trustDomain, entry.Bundle)
		if err != nil {
			return nil, fmt.Errorf("trust domain %q: %w", name, err)
		}
		if i == 0 {
			next.own = name
		}
		next.domains[name] = parsed
		if parsed.refreshHint > 0 && (next.refreshHint == 0 || parsed.refreshHint < next.refreshHint) {
			next.refreshHint = parsed.refreshHint
		}
	}
	return next, nil
}

// sameAuthorities reports whether two snapshots would have every verifier on the
// node trust exactly the same keys, for exactly the same domains, with the same
// domain treated as the workload's own.
func (s *snapshot) sameAuthorities(other *snapshot) bool {
	if s.own != other.own || len(s.domains) != len(other.domains) {
		return false
	}
	for domain, parsed := range s.domains {
		otherParsed, ok := other.domains[domain]
		if !ok || !parsed.sameAuthorities(otherParsed) {
			return false
		}
	}
	return true
}
