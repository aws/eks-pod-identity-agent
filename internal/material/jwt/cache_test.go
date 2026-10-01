package jwt

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/stretchr/testify/require"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
)

func TestPodDeletionEvictsEveryAudienceSetAndBlocksInflightStore(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	watcher := &fakePodStore{}
	issuer := successfulIssuer(t, &now, 10*time.Minute)
	source := newTestSource(t, issuer, watcher, &now, 10)
	_, err := source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"one.example", "two.example"})
	require.NoError(t, err)
	_, err = source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"one.example"})
	require.NoError(t, err)
	require.Len(t, source.cache.Items(), 2)

	watcher.delete(testPodUID)
	require.Empty(t, source.cache.Items())

	release := make(chan struct{})
	issuer.block = release
	result := make(chan error, 1)
	go func() {
		_, err := source.JWTSVIDs(context.Background(), workload("another-pod"), []string{"three.example"})
		result <- err
	}()
	require.Eventually(t, func() bool { return issuer.calls() == 3 }, time.Second, time.Millisecond)
	watcher.delete("another-pod")
	close(release)
	require.Error(t, <-result)
	require.Empty(t, source.cache.Items(), "a response arriving after deletion must not restore material")
}

func TestDeletedPodCannotIssueFromAnEarlierAttestation(t *testing.T) {
	for name, notify := range map[string]bool{"callback pending": false, "callback delivered": true} {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			pods := &fakePodStore{}
			issuer := successfulIssuer(t, &now, time.Hour)
			source := newTestSource(t, issuer, pods, &now, 10)
			provider := sessions(now.Add(time.Hour))
			source.sessionProvider = provider
			attestedBeforeDeletion := workload(testPodUID)

			if notify {
				pods.delete(testPodUID)
			} else {
				pods.remove(testPodUID)
			}
			svids, err := source.JWTSVIDs(context.Background(), attestedBeforeDeletion, []string{"payments.example"})
			require.ErrorIs(t, err, wierrors.ErrUnattestable)
			require.False(t, wierrors.IsRetryable(err))
			require.Nil(t, svids)
			require.Zero(t, provider.Calls())
			require.Zero(t, issuer.calls())
			require.Empty(t, source.cache.Items())
			require.Empty(t, source.pending)
			require.Empty(t, source.states)

			_, err = source.issueAndStore(context.Background(), attestedBeforeDeletion, []string{"payments.example"}, false)
			require.ErrorIs(t, err, wierrors.ErrUnattestable, "a shared issuance queued before deletion must also refuse")
			require.Zero(t, issuer.calls())
			require.Empty(t, source.states)
		})
	}
}

func TestPodAbsenceEvictsCachedTokensBeforeDeletionCallback(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pods := &fakePodStore{}
	issuer := successfulIssuer(t, &now, time.Hour)
	source := newTestSource(t, issuer, pods, &now, 10)
	w := workload(testPodUID)
	_, err := source.JWTSVIDs(context.Background(), w, []string{"one.example", "two.example"})
	require.NoError(t, err)
	_, err = source.JWTSVIDs(context.Background(), w, []string{"one.example"})
	require.NoError(t, err)
	require.Len(t, source.cache.Items(), 2)

	pods.remove(testPodUID)
	svids, err := source.JWTSVIDs(context.Background(), w, []string{"one.example"})
	require.ErrorIs(t, err, wierrors.ErrUnattestable)
	require.Nil(t, svids)
	require.Equal(t, 2, issuer.calls())
	require.Empty(t, source.cache.Items())
	require.Empty(t, source.states)
}

func TestPodAbsenceRejectsInflightResponseBeforeDeletionCallback(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pods := &fakePodStore{}
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	issuer := successfulIssuer(t, &now, time.Hour)
	issuer.block = release
	source := newTestSource(t, issuer, pods, &now, 10)
	result := make(chan error, 1)
	go func() {
		_, err := source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"payments.example"})
		result <- err
	}()
	require.Eventually(t, func() bool { return issuer.calls() == 1 }, time.Second, time.Millisecond)

	pods.remove(testPodUID)
	unblock()
	require.ErrorIs(t, <-result, wierrors.ErrUnattestable)
	require.Empty(t, source.cache.Items())
	require.Empty(t, source.pending)
	require.Empty(t, source.states)
}

func TestPodDeletedDuringSessionLookupSkipsSTS(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pods := &fakePodStore{}
	issuer := successfulIssuer(t, &now, time.Hour)
	source := newTestSource(t, issuer, pods, &now, 10)
	provider := sessions(now.Add(time.Hour))
	provider.Block()
	t.Cleanup(provider.Release)
	source.sessionProvider = provider
	result := make(chan error, 1)
	go func() {
		_, err := source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"payments.example"})
		result <- err
	}()
	waitCtx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	require.NoError(t, provider.WaitForBlocked(waitCtx, 1))

	pods.delete(testPodUID)
	provider.Release()
	require.ErrorIs(t, <-result, wierrors.ErrUnattestable)
	require.Equal(t, 1, provider.Calls())
	require.Zero(t, issuer.calls())
	require.Empty(t, source.cache.Items())
	require.Empty(t, source.pending)
	require.Empty(t, source.states)
}

func TestCallerCancellationCannotReleaseDeletionGuardBeforeIssuanceEnds(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	watcher := &fakePodStore{}
	release := make(chan struct{})
	issuer := successfulIssuer(t, &now, 10*time.Minute)
	issuer.block = release
	issuer.ignoreContext = true
	source := newTestSource(t, issuer, watcher, &now, 10)

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := source.JWTSVIDs(ctx, workload(testPodUID), []string{"payments.example"})
		result <- err
	}()
	require.Eventually(t, func() bool { return issuer.calls() == 1 }, time.Second, time.Millisecond)

	cancel()
	require.Error(t, <-result)
	watcher.delete(testPodUID)
	close(release)

	require.Eventually(t, func() bool {
		source.stateMu.Lock()
		defer source.stateMu.Unlock()
		return len(source.states) == 0
	}, time.Second, time.Millisecond)
	require.Empty(t, source.cache.Items(), "the late response must observe the pod deletion")
}

func TestAudienceSetLimitDoesNotEvictLiveTokens(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuer := successfulIssuer(t, &now, 10*time.Minute)
	source := newTestSource(t, issuer, &fakePodStore{}, &now, 2)
	_, err := source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"one.example", "two.example"})
	require.NoError(t, err)
	_, err = source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"one.example"})
	require.NoError(t, err)

	_, err = source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"two.example"})
	require.ErrorIs(t, err, wierrors.ErrInvalidAudience)
	require.Equal(t, 2, issuer.calls())
	require.Len(t, source.cache.Items(), 2)
	_, err = source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"two.example", "one.example", "one.example"})
	require.NoError(t, err)
	require.Equal(t, 2, issuer.calls())
	now = now.Add(5*time.Minute + time.Second)
	_, err = source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"two.example", "one.example"})
	require.NoError(t, err)
	require.Equal(t, 3, issuer.calls(), "an existing set can renew at the cap")
	require.Len(t, source.cache.Items(), 2)
}

func TestCacheSeparatesPodsWithTheSameAudience(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	watcher := &fakePodStore{}
	issuer := successfulIssuer(t, &now, time.Hour)
	source := newTestSource(t, issuer, watcher, &now, 1)
	audiences := []string{"payments.example"}

	first, err := source.JWTSVIDs(context.Background(), workload(testPodUID), audiences)
	require.NoError(t, err)
	second, err := source.JWTSVIDs(context.Background(), workload("another-pod"), audiences)
	require.NoError(t, err)
	require.NotEqual(t, first[0].Marshal(), second[0].Marshal())
	require.Equal(t, 2, issuer.calls())

	source.Invalidate("")
	require.Len(t, source.cache.Items(), 2)
	watcher.delete(testPodUID)
	require.Len(t, source.cache.Items(), 1)
	cached, err := source.JWTSVIDs(context.Background(), workload("another-pod"), audiences)
	require.NoError(t, err)
	require.Equal(t, second[0].Marshal(), cached[0].Marshal())
	require.Equal(t, 2, issuer.calls())
}

func TestAudienceSetLimitCountsInflightIssuanceAndReleasesFailedReservation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)

	issuer := successfulIssuer(t, &now, time.Hour)
	respond := issuer.respond
	upstream := errors.New("STS unavailable")
	issuer.respond = func(attempt int, req sts.WebIdentityTokenRequest) (*sts.IssuedWebIdentityToken, error) {
		if attempt == 1 {
			return nil, upstream
		}
		return respond(attempt, req)
	}
	issuer.block = release
	source := newTestSource(t, issuer, &fakePodStore{}, &now, 1)

	result := make(chan error, 1)
	go func() {
		_, err := source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"one.example"})
		result <- err
	}()
	require.Eventually(t, func() bool { return issuer.calls() == 1 }, time.Second, time.Millisecond)

	_, err := source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"two.example"})
	require.ErrorIs(t, err, wierrors.ErrInvalidAudience)
	require.Equal(t, 1, issuer.calls())

	unblock()
	require.ErrorIs(t, <-result, upstream)
	require.Empty(t, source.pending)
	_, err = source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"two.example"})
	require.NoError(t, err)
	require.Equal(t, 2, issuer.calls())
	require.Len(t, source.cache.Items(), 1)
}

func TestAudienceSetLimitDoesNotDoubleCountAStoredReservation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	source := newTestSource(t, successfulIssuer(t, &now, time.Hour), &fakePodStore{}, &now, 2)
	audiences := []string{"ledger.example", "payments.example"}
	key := makeCacheKey(testPodUID, audiences)
	require.NoError(t, source.reserveAudienceSet(key))
	defer source.releaseAudienceSet(key)
	source.store(workload(testPodUID), audiences, &jwtsvid.SVID{Expiry: now.Add(time.Hour)}, now)

	other := makeCacheKey(testPodUID, []string{"payments.example"})
	require.NoError(t, source.reserveAudienceSet(other))
	source.releaseAudienceSet(other)
}

func TestAudienceSetReservationSurvivesCacheExpiryDuringRenewal(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	source := newTestSource(t, successfulIssuer(t, &now, time.Hour), &fakePodStore{}, &now, 1)
	audiences := []string{"ledger.example", "payments.example"}
	key := makeCacheKey(testPodUID, audiences)
	source.store(workload(testPodUID), audiences, &jwtsvid.SVID{Expiry: now.Add(time.Hour)}, now)
	require.NoError(t, source.reserveAudienceSet(key))

	_, updated := source.cache.TouchWithExpire(key, time.Nanosecond)
	require.True(t, updated)
	require.Eventually(t, func() bool {
		_, expired, ok := source.cache.GetStale(key)
		return ok && expired
	}, time.Second, time.Millisecond)

	other := makeCacheKey(testPodUID, []string{"payments.example"})
	require.ErrorIs(t, source.reserveAudienceSet(other), wierrors.ErrInvalidAudience)
	source.releaseAudienceSet(key)
	require.NoError(t, source.reserveAudienceSet(other))
	source.releaseAudienceSet(other)
}

func TestExpiredAudienceSetCannotBypassTheCap(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	source := newTestSource(t, successfulIssuer(t, &now, time.Hour), &fakePodStore{}, &now, 1)
	w := workload(testPodUID)
	expired := makeCacheKey(testPodUID, []string{"ledger.example"})
	source.store(w, []string{"ledger.example"}, &jwtsvid.SVID{Expiry: now.Add(time.Hour)}, now)
	_, updated := source.cache.TouchWithExpire(expired, time.Nanosecond)
	require.True(t, updated)
	require.Eventually(t, func() bool {
		_, stale, ok := source.cache.GetStale(expired)
		return ok && stale
	}, time.Second, time.Millisecond)
	source.store(w, []string{"payments.example"}, &jwtsvid.SVID{Expiry: now.Add(time.Hour)}, now)

	require.ErrorIs(t, source.reserveAudienceSet(expired), wierrors.ErrInvalidAudience)
	require.Empty(t, source.pending)
}

func TestCacheStoresWorkloadAndAudienceSnapshots(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	source := newTestSource(t, successfulIssuer(t, &now, time.Hour), &fakePodStore{}, &now, 1)
	w := workload(testPodUID)
	audiences := []string{"ledger.example", "payments.example"}
	key := makeCacheKey(testPodUID, audiences)
	source.store(w, audiences, &jwtsvid.SVID{Expiry: now.Add(time.Hour)}, now)

	w.ServiceAccount = "changed"
	audiences[0] = "changed"
	cached, ok := source.cache.Get(key)
	require.True(t, ok)
	require.Equal(t, "payments", cached.workload.ServiceAccount)
	require.NotSame(t, w, cached.workload)
	require.Equal(t, []string{"ledger.example", "payments.example"}, cached.audiences)
}

func TestAudienceSetKeysDoNotCollide(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first []string
		other []string
	}{
		{"comma", []string{"a,b", "c"}, []string{"a", "b,c"}},
		{"NUL", []string{"a\x00b", "c"}, []string{"a", "b\x00c"}},
		{"length prefix", []string{"1:a", "b"}, []string{"1", "a", "b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first, err := normalizeAudiences(tc.first)
			require.NoError(t, err)
			other, err := normalizeAudiences(tc.other)
			require.NoError(t, err)
			firstKey := makeCacheKey(testPodUID, first)
			otherKey := makeCacheKey(testPodUID, other)
			require.NotEqual(t, firstKey, otherKey)
			require.NotEqual(t, keyString(firstKey), keyString(otherKey))
		})
	}
}

func TestCachedTokenIsNotServableAtExpiration(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	source := newTestSource(t, successfulIssuer(t, &now, time.Hour), &fakePodStore{}, &now, 1)
	for _, tc := range []struct {
		name string
		svid *jwtsvid.SVID
		want bool
	}{
		{"nil", nil, false},
		{"before expiration", &jwtsvid.SVID{Expiry: now.Add(time.Second)}, true},
		{"at expiration", &jwtsvid.SVID{Expiry: now}, false},
		{"after expiration", &jwtsvid.SVID{Expiry: now.Add(-time.Second)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, source.servable(tc.svid))
		})
	}
}
