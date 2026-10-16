package jwt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
)

func TestRenewalPointUsesHalfOfIssuedLifetime(t *testing.T) {
	issuedAt := time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)
	expiresAt := issuedAt.Add(time.Hour)
	require.Equal(t, issuedAt.Add(30*time.Minute), renewalPoint(issuedAt, expiresAt, 0.5, 0, func() float64 {
		return 0.5
	}))
}

func TestRenewalPointSpreadsIdenticalTokenLifetimes(t *testing.T) {
	issuedAt := time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)
	expiresAt := issuedAt.Add(time.Hour)

	early := renewalPoint(issuedAt, expiresAt, 0.5, 0.1, func() float64 { return 0 })
	late := renewalPoint(issuedAt, expiresAt, 0.5, 0.1, func() float64 { return 1 })

	require.Equal(t, issuedAt.Add(27*time.Minute), early)
	require.Equal(t, issuedAt.Add(33*time.Minute), late)
}

func TestJWTSVIDUsesIssuedLifetimeAndConfiguredRenewal(t *testing.T) {
	for name, values := range map[string]struct {
		lifetime   time.Duration
		jitter     float64
		draw       float64
		renewAfter time.Duration
	}{
		"full hour midpoint at 30 minutes": {time.Hour, 0.1, 0.5, 30 * time.Minute},
		"early jitter at 27 minutes":       {time.Hour, 0.1, 0, 27 * time.Minute},
		"late jitter at 33 minutes":        {time.Hour, 0.1, 1, 33 * time.Minute},
		"jitter disabled at 30 minutes":    {time.Hour, 0, 1, 30 * time.Minute},
		"shorter grant renews earlier":     {10 * time.Minute, 0.1, 0.5, 5 * time.Minute},
	} {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second).Add(-values.renewAfter - time.Minute)
			issuer := successfulIssuer(t, &now, values.lifetime)
			source := newTestSource(t, issuer, &fakePodStore{}, &now, 10)
			source.renewalJitter = values.jitter
			source.draw = func() float64 { return values.draw }

			svids, err := source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"payments.example"})
			require.NoError(t, err)
			require.Len(t, svids, 1)
			require.Equal(t, testSpiffeID, svids[0].ID.String())
			require.Equal(t, now.Add(values.lifetime), svids[0].Expiry)
			require.Equal(t, time.Hour, issuer.allRequests()[0].req.Duration)

			cached, ok := source.cache.Get(makeCacheKey(testPodUID, []string{"payments.example"}))
			require.True(t, ok)
			require.True(t, cached.renewAt.Equal(now.Add(values.renewAfter)))

			now = now.Add(values.renewAfter - time.Second)
			beforeRenewal, err := source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"payments.example"})
			require.NoError(t, err)
			require.Equal(t, svids[0].Marshal(), beforeRenewal[0].Marshal())
			require.Equal(t, 1, issuer.calls())

			now = now.Add(time.Second)
			replacement, err := source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"payments.example"})
			require.NoError(t, err)
			require.Equal(t, 2, issuer.calls())
			require.NotEqual(t, svids[0].Marshal(), replacement[0].Marshal())
		})
	}
}

func TestFailedRenewalKeepsTokenUntilResponseExpiration(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second).Add(-6 * time.Minute)
	issuer := successfulIssuer(t, &now, 10*time.Minute)
	baseRespond := issuer.respond
	issuer.respond = func(attempt int, req sts.WebIdentityTokenRequest) (*sts.IssuedWebIdentityToken, error) {
		if attempt > 1 {
			return nil, errors.New("STS unavailable")
		}
		return baseRespond(attempt, req)
	}
	source := newTestSource(t, issuer, &fakePodStore{}, &now, 10)
	original, err := source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"payments.example"})
	require.NoError(t, err)

	now = now.Add(5*time.Minute + time.Second)
	stillValid, err := source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"payments.example"})
	require.NoError(t, err)
	require.Equal(t, original[0].Marshal(), stillValid[0].Marshal())

	now = original[0].Expiry.Add(time.Second)
	_, err = source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"payments.example"})
	require.Error(t, err)
	require.ErrorIs(t, err, wierrors.ErrIssuanceFailed)
}

func TestFailedRenewalFallsBackToCurrentCacheEntry(t *testing.T) {
	for _, tc := range []struct {
		name    string
		replace bool
		evict   bool
	}{
		{name: "original entry"},
		{name: "replacement entry", replace: true},
		{name: "evicted entry", evict: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second).Add(-6 * time.Minute)
			issuer := successfulIssuer(t, &now, 10*time.Minute)
			source := newTestSource(t, issuer, &fakePodStore{}, &now, 10)
			w := workload(testPodUID)
			audiences := []string{"ledger.example", "payments.example"}
			key := makeCacheKey(testPodUID, audiences)

			original, err := source.JWTSVIDs(context.Background(), w, audiences)
			require.NoError(t, err)
			now = now.Add(5*time.Minute + time.Second)

			expected := original[0]
			if tc.replace {
				expiresAt := now.Add(10 * time.Minute)
				expected, _, err = parseIssuedToken(&sts.IssuedWebIdentityToken{
					Token:      signedTokenForAudiences(t, audiences, now, expiresAt, "replacement"),
					Expiration: expiresAt,
				}, audiences)
				require.NoError(t, err)
			}
			upstream := errors.New("STS unavailable")
			issuer.respond = func(int, sts.WebIdentityTokenRequest) (*sts.IssuedWebIdentityToken, error) {
				if tc.replace {
					source.storeLocked(w, audiences, expected, now)
				}
				if tc.evict {
					source.cache.Delete(key)
				}
				return nil, upstream
			}

			actual, err := source.JWTSVIDs(context.Background(), w, audiences)
			require.Equal(t, 2, issuer.calls())
			if tc.evict {
				require.ErrorIs(t, err, upstream)
				require.Nil(t, actual)
			} else {
				require.NoError(t, err)
				require.Len(t, actual, 1)
				require.Same(t, expected, actual[0])
			}
		})
	}
}

func TestRenewalLogNeverContainsBearerToken(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuer := successfulIssuer(t, &now, 10*time.Minute)
	source := newTestSource(t, issuer, &fakePodStore{}, &now, 10)
	audiences := []string{"payments.example"}
	key := makeCacheKey(testPodUID, audiences)

	svids, err := source.JWTSVIDs(context.Background(), workload(testPodUID), audiences)
	require.NoError(t, err)
	cached, ok := source.cache.Get(key)
	require.True(t, ok)

	issuer.respond = func(int, sts.WebIdentityTokenRequest) (*sts.IssuedWebIdentityToken, error) {
		return nil, errors.New("STS unavailable")
	}
	var output bytes.Buffer
	global := logger.FromContext(context.Background()).Logger
	previous := global.Out
	global.SetOutput(&output)
	t.Cleanup(func() { global.SetOutput(previous) })

	source.onRefresh(key, cached)

	require.Contains(t, output.String(), "renewal failed")
	require.NotContains(t, output.String(), svids[0].Marshal())
}

func TestBackgroundRenewalContinuesOnlyWhilePodExists(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	watcher := &fakePodStore{}
	issuer := successfulIssuer(t, &now, 10*time.Minute)
	source := newTestSource(t, issuer, watcher, &now, 10)
	audiences := []string{"ledger.example", "payments.example"}
	key := makeCacheKey(testPodUID, audiences)

	_, err := source.JWTSVIDs(context.Background(), workload(testPodUID), audiences)
	require.NoError(t, err)
	original, ok := source.cache.Get(key)
	require.True(t, ok)

	source.onRefresh(key, original)
	require.Equal(t, 2, issuer.calls())
	require.Equal(t, audiences, issuer.allRequests()[0].req.Audiences)
	require.Equal(t, audiences, issuer.allRequests()[1].req.Audiences)
	replacement, ok := source.cache.Get(key)
	require.True(t, ok)
	require.Equal(t, audiences, replacement.svid.Audience)
	require.NotEqual(t, original.svid.Marshal(), replacement.svid.Marshal())

	watcher.delete(testPodUID)
	source.onRefresh(key, replacement)
	require.Equal(t, 2, issuer.calls(), "a deleted pod must not renew")
	require.Empty(t, source.cache.Items())
}

func TestBackgroundRenewalChecksPresenceBeforeDeletionCallback(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pods := &fakePodStore{}
	issuer := successfulIssuer(t, &now, time.Hour)
	source := newTestSource(t, issuer, pods, &now, 10)
	audiences := []string{"payments.example"}
	key := makeCacheKey(testPodUID, audiences)
	_, err := source.JWTSVIDs(context.Background(), workload(testPodUID), audiences)
	require.NoError(t, err)
	cached, ok := source.cache.Get(key)
	require.True(t, ok)

	pods.remove(testPodUID)
	source.onRefresh(key, cached)
	require.Equal(t, 1, issuer.calls())
	require.Empty(t, source.cache.Items())
	require.Empty(t, source.states)
}

func TestBackgroundRenewalPacesBacklogWithinOneSweep(t *testing.T) {
	const dueEntries = 25
	source, issuer, _ := newDueRenewalSource(t, dueEntries)
	source.limiter = rate.NewLimiter(20, 1)

	started := time.Now()
	source.cache.RefreshOrEvictExpired()

	require.Equal(t, 2*dueEntries, issuer.calls())
	require.GreaterOrEqual(t, time.Since(started), 1200*time.Millisecond-10*time.Millisecond)
	for _, item := range source.cache.Items() {
		require.Greater(t, item.Refresh, time.Now().UnixNano())
	}
	require.Empty(t, source.pending)
	require.Empty(t, source.states)
}

func TestBackgroundRenewalRechecksPodAfterWaitingForPermit(t *testing.T) {
	source, issuer, pods := newDueRenewalSource(t, 1)
	source.limiter = rate.NewLimiter(1, 1)
	require.True(t, source.limiter.Allow())
	key := makeCacheKey("pod-0", []string{"payments.example"})
	cached, ok := source.cache.Get(key)
	require.True(t, ok)

	done := make(chan struct{})
	go func() {
		source.onRefresh(key, cached)
		close(done)
	}()
	require.Eventually(t, func() bool {
		return source.limiter.Tokens() < 0
	}, 500*time.Millisecond, time.Millisecond)
	pods.delete(key.podUID)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("renewal did not finish after waiting for its permit")
	}
	require.Equal(t, 1, issuer.calls(), "a pod deleted while waiting must not reach STS")
	require.Empty(t, source.cache.Items())
	require.Empty(t, source.pending)
	require.Empty(t, source.states)
}

func TestBackgroundRenewalPermitDeadlineKeepsCachedToken(t *testing.T) {
	source, issuer, _ := newDueRenewalSource(t, 1)
	source.limiter = rate.NewLimiter(1, 1)
	require.True(t, source.limiter.Allow())
	source.renewalTimeout = 20 * time.Millisecond
	key := makeCacheKey("pod-0", []string{"payments.example"})
	cached, ok := source.cache.Get(key)
	require.True(t, ok)

	source.onRefresh(key, cached)

	require.Equal(t, 1, issuer.calls())
	current, ok := source.cache.Get(key)
	require.True(t, ok)
	require.Same(t, cached, current)
	require.True(t, source.servable(current.svid))
	require.Empty(t, source.pending)
	require.Empty(t, source.states)
}

func newDueRenewalSource(t *testing.T, podCount int) (*Source, *fakeIssuer, *fakePodStore) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second).Add(-31 * time.Minute)
	issuer := successfulIssuer(t, &now, time.Hour)
	pods := &fakePodStore{}
	source := newTestSource(t, issuer, pods, &now, 10)
	for i := range podCount {
		_, err := source.JWTSVIDs(context.Background(), workload(fmt.Sprintf("pod-%d", i)), []string{"payments.example"})
		require.NoError(t, err)
	}
	now = now.Add(31 * time.Minute)
	for key, item := range source.cache.Items() {
		source.cache.SetWithRefreshExpire(key, item.Object, time.Nanosecond, time.Hour)
	}
	return source, issuer, pods
}
