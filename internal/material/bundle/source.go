package bundle

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// providerSource holds one provider's trust bundles. Every read serves the same
// immutable snapshot, and only a refresh, or a read with nothing cached, calls
// STS. The Registry decides when a refresh runs and whose credentials sign it.
type providerSource struct {
	providerArn string
	fetcher     Fetcher
	notifier    workloadidentity.BundleNotifier

	// current is the last good snapshot, nil until the first fetch succeeds. A
	// failed fetch never replaces it.
	current atomic.Pointer[snapshot]
	// due is when the next refresh should run, in Unix nanoseconds; zero means
	// now. It is set after every fetch, so the Registry can read it without the
	// semaphore.
	due atomic.Int64

	// fetching is a one-slot semaphore held across a fetch and its store, so a
	// slow fetch cannot land after a newer one and roll the bundle back, and
	// concurrent first reads share one call. It is a channel rather than a mutex
	// so a waiting reader can give up when its context does.
	fetching chan struct{}

	// failures, lastErr and retryAt record the latest fetch's outcome as the one
	// backoff the refresher and reads follow: a read inside it gets lastErr
	// instead of calling STS. They are only touched while holding fetching.
	failures int
	lastErr  error
	retryAt  time.Time

	// now and jitter are the source's clock and randomness, replaced in tests.
	now    func() time.Time
	jitter func() float64
}

// snapshot is one successful fetch, parsed. It is never modified after it is
// stored.
type snapshot struct {
	// ownDomain is the trust domain of the provider's own entry.
	ownDomain spiffeid.TrustDomain
	// domains holds every entry the response carried, by trust domain.
	domains map[string]*domainBundle
	// jwtSource is the JWT authorities in the form go-spiffe validates against.
	jwtSource jwtSource
	// refreshHint is the shortest usable hint across the entries, zero when none
	// carries one.
	refreshHint time.Duration
}

// signFunc returns the credentials a fetch on one reader's behalf is signed with.
// A read calls it only when it has to fetch.
type signFunc func(context.Context) (aws.Credentials, error)

// jwtSource is a snapshot's JWT authorities as a jwtbundle.Source. It hands out
// clones, so a caller cannot change what the tier serves.
type jwtSource map[spiffeid.TrustDomain]*jwtbundle.Bundle

// GetJWTBundleForTrustDomain implements jwtbundle.Source.
func (s jwtSource) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	bundle, ok := s[trustDomain]
	if !ok {
		return nil, fmt.Errorf("no JWT bundle for trust domain %q", trustDomain)
	}
	return bundle.Clone(), nil
}

// newProviderSource builds one provider's source from options New has already
// checked. It does not fetch, and it is due for a refresh at once.
func newProviderSource(providerArn string, opts Opts) *providerSource {
	return &providerSource{
		providerArn: providerArn,
		fetcher:     opts.Fetcher,
		notifier:    opts.Notifier,
		fetching:    make(chan struct{}, 1),
		now:         time.Now,
		jitter:      rand.Float64,
	}
}

// OwnTrustDomain returns the provider's own trust domain, fetching if nothing is
// cached yet.
func (s *providerSource) OwnTrustDomain(ctx context.Context, sign signFunc) (spiffeid.TrustDomain, error) {
	snap, err := s.load(ctx, sign)
	if err != nil {
		return spiffeid.TrustDomain{}, err
	}
	return snap.ownDomain, nil
}

// X509Bundles returns every trust domain's X.509 authorities as a set. A domain
// whose document carried no x509-svid key is absent. The set and its bundles are
// fresh clones; the certificates are the snapshot's.
func (s *providerSource) X509Bundles(ctx context.Context, sign signFunc) (*x509bundle.Set, error) {
	snap, err := s.load(ctx, sign)
	if err != nil {
		return nil, err
	}
	out := x509bundle.NewSet()
	for _, parsed := range snap.domains {
		if parsed.x509Authorities.Empty() {
			continue
		}
		out.Add(parsed.x509Authorities.Clone())
	}
	return out, nil
}

// JWTBundles returns every trust domain's JWT authorities as a standard JWK Set.
// A domain whose document carried no jwt-svid key is absent. The result is a copy.
func (s *providerSource) JWTBundles(ctx context.Context, sign signFunc) (map[string][]byte, error) {
	snap, err := s.load(ctx, sign)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(snap.domains))
	for domain, parsed := range snap.domains {
		if parsed.jwtAuthorities.Empty() {
			continue
		}
		out[domain] = slices.Clone(parsed.jwks)
	}
	return out, nil
}

// JWTSource returns the JWT authorities as a jwtbundle.Source. A domain with no
// jwt-svid key is unknown to it.
func (s *providerSource) JWTSource(ctx context.Context, sign signFunc) (jwtbundle.Source, error) {
	snap, err := s.load(ctx, sign)
	if err != nil {
		return nil, err
	}
	return snap.jwtSource, nil
}

// dueAt is when the next refresh should run. A source nothing has fetched for yet
// is due at once.
func (s *providerSource) dueAt() time.Time {
	return time.Unix(0, s.due.Load())
}

// refresh fetches and stores one snapshot with creds, after any fetch already in
// flight. It does nothing when the schedule has moved off due, the time the
// caller saw, since a fetch that ran meanwhile has done its work. Inside a
// failure's backoff it fetches nothing and returns that failure.
func (s *providerSource) refresh(ctx context.Context, creds aws.Credentials, due time.Time) error {
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer s.release()
	if !s.dueAt().Equal(due) {
		return nil
	}
	if s.lastErr != nil && s.now().Before(s.retryAt) {
		return s.lastErr
	}
	nextSnapshot, err := s.fetch(ctx, creds)
	if err != nil && ctx.Err() != nil {
		// The refresher is stopping. Its cancellation says nothing about STS, and
		// recording it would hand a context.Canceled to a reader whose context is live.
		return err
	}
	s.recordOutcome(err)
	if err != nil {
		return err
	}
	s.store(ctx, nextSnapshot)
	return nil
}

// recordFailure records a refresh that could not run as a failed fetch, so the
// next one waits out the backoff. Like refresh, it does nothing once the schedule
// has moved off due.
func (s *providerSource) recordFailure(ctx context.Context, err error, due time.Time) {
	if s.acquire(ctx) != nil {
		return
	}
	defer s.release()
	if s.dueAt().Equal(due) {
		s.recordOutcome(err)
	}
}

// load returns the current snapshot, fetching one signed by sign if nothing has
// been fetched yet. Concurrent first reads share one fetch: whoever holds the
// semaphore fetches, and the rest find its result, a snapshot or a failure still
// in its backoff, when they get the semaphore in turn.
func (s *providerSource) load(ctx context.Context, sign signFunc) (*snapshot, error) {
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
	// A reader that cannot sign gets its own error and starts no backoff, since
	// the next reader's credentials may be fine.
	creds, err := sign(ctx)
	if err != nil {
		return nil, err
	}
	// The fetch is detached from this reader's cancellation, because its result
	// is for every reader queued behind it. fetchTimeout still bounds it.
	nextSnapshot, err := s.fetch(context.WithoutCancel(ctx), creds)
	s.recordOutcome(err)
	if err != nil {
		return nil, err
	}
	s.store(ctx, nextSnapshot)
	return nextSnapshot, nil
}

// recordOutcome remembers a fetch's result for the fetches that follow it and
// schedules the next refresh: a failure's backoff, or the refresh interval. The
// caller holds the semaphore, and on success stores the snapshot right after.
func (s *providerSource) recordOutcome(err error) {
	if err == nil {
		s.failures, s.lastErr, s.retryAt = 0, nil, time.Time{}
		return
	}
	s.failures++
	s.lastErr = err
	s.retryAt = s.now().Add(s.retryDelay(s.failures))
	s.due.Store(s.retryAt.UnixNano())
}

// acquire takes the semaphore, or gives up when ctx does. A caller whose context
// is already done never takes it, even when it is free, so a caller that has gone
// cannot start a fetch on nobody's behalf.
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

// fetch makes one GetTrustBundles call signed with creds and parses the response.
// An error is ErrBundleRefused when STS refused in a way a repeat cannot change,
// and ErrBundleUnavailable otherwise, including a response the tier will not serve.
func (s *providerSource) fetch(ctx context.Context, creds aws.Credentials) (*snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	start := time.Now()
	entries, err := s.fetcher.GetTrustBundles(ctx, creds, s.providerArn)
	var nextSnapshot *snapshot
	if err == nil {
		nextSnapshot, err = parseResponse(entries)
		if err != nil {
			err = wierrors.ErrBundleUnavailable.Wrapf(err, "GetTrustBundles for %s returned trust material the agent will not serve", s.providerArn)
		}
	} else if refused(err) {
		err = wierrors.ErrBundleRefused.Wrapf(err, "GetTrustBundles for %s was refused", s.providerArn)
	} else {
		err = wierrors.ErrBundleUnavailable.Wrapf(err, "GetTrustBundles for %s failed", s.providerArn)
	}
	observeFetch(err, time.Since(start).Seconds())
	return nextSnapshot, err
}

// store makes nextSnapshot current, schedules the next refresh, then notifies each
// authority set that differs from the one it replaces. An unchanged snapshot keeps
// the previous parse and takes only the new refresh hint. The first snapshot is
// not a change: nothing can hold a bundle it never received.
func (s *providerSource) store(ctx context.Context, nextSnapshot *snapshot) {
	prev := s.current.Load()
	x509Changed := prev != nil && !prev.sameX509Authorities(nextSnapshot)
	jwtChanged := prev != nil && !prev.sameJWTAuthorities(nextSnapshot)
	if prev != nil && !x509Changed && !jwtChanged {
		kept := *prev
		kept.refreshHint = nextSnapshot.refreshHint
		s.current.Store(&kept)
	} else {
		s.current.Store(nextSnapshot)
	}
	s.due.Store(s.now().Add(s.refreshDelay()).UnixNano())
	if !x509Changed && !jwtChanged {
		return
	}
	observeChange()
	logger.FromContext(ctx).WithFields(logrus.Fields{
		"provider_arn":  s.providerArn,
		"trust_domains": len(nextSnapshot.domains),
		"x509_changed":  x509Changed,
		"jwt_changed":   jwtChanged,
	}).Info("Trust bundle authorities changed")
	if x509Changed {
		s.notifier.NotifyCertBundleChange(s.providerArn)
	}
	if jwtChanged {
		s.notifier.NotifyJWTBundleChange(s.providerArn)
	}
}

// refreshInterval is the interval before jitter: the hint bounded by
// minRefreshInterval and maxRefreshInterval, or the default without one.
func (s *providerSource) refreshInterval() time.Duration {
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
	nextSnapshot := &snapshot{
		domains:   make(map[string]*domainBundle, len(entries)),
		jwtSource: jwtSource{},
	}
	for i, entry := range entries {
		trustDomain, err := spiffeid.TrustDomainFromString(entry.TrustDomain)
		if err != nil {
			return nil, fmt.Errorf("entry %d: trust domain %q: %w", i, entry.TrustDomain, err)
		}
		name := trustDomain.Name()
		if _, duplicate := nextSnapshot.domains[name]; duplicate {
			return nil, fmt.Errorf("entry %d repeats trust domain %q", i, name)
		}
		parsed, err := parseDocument(trustDomain, entry.Bundle)
		if err != nil {
			return nil, fmt.Errorf("trust domain %q: %w", name, err)
		}
		if i == 0 {
			nextSnapshot.ownDomain = trustDomain
		}
		nextSnapshot.domains[name] = parsed
		if !parsed.jwtAuthorities.Empty() {
			nextSnapshot.jwtSource[trustDomain] = parsed.jwtAuthorities
		}
		if parsed.refreshHint > 0 && (nextSnapshot.refreshHint == 0 || parsed.refreshHint < nextSnapshot.refreshHint) {
			nextSnapshot.refreshHint = parsed.refreshHint
		}
	}
	return nextSnapshot, nil
}

// sameX509Authorities reports whether X.509 verifiers on the node would trust the
// same keys for the same domains, with the same domain as the workload's own.
func (s *snapshot) sameX509Authorities(other *snapshot) bool {
	return s.ownDomain == other.ownDomain && sameDomains(s, other, (*domainBundle).sameX509Authorities)
}

// sameJWTAuthorities reports whether JWT verifiers on the node would trust the
// same keys for the same domains.
func (s *snapshot) sameJWTAuthorities(other *snapshot) bool {
	return sameDomains(s, other, (*domainBundle).sameJWTAuthorities)
}

// sameDomains reports whether same holds for every domain in either snapshot. A
// domain one of them lacks compares as a nil domainBundle, which holds nothing.
func sameDomains(a, b *snapshot, same func(*domainBundle, *domainBundle) bool) bool {
	for domain, parsed := range a.domains {
		if !same(parsed, b.domains[domain]) {
			return false
		}
	}
	for domain, parsed := range b.domains {
		if _, ok := a.domains[domain]; !ok && !same(nil, parsed) {
			return false
		}
	}
	return true
}
