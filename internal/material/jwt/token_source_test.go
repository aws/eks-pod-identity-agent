package jwt

import (
	"context"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/podstore/podstoretest"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
)

func TestNewDefaultsToPacedBackgroundRenewal(t *testing.T) {
	now := time.Now().UTC()
	source, err := New(Opts{
		Issuer:          successfulIssuer(t, &now, time.Hour),
		SessionProvider: sessions(now.Add(time.Hour)),
		PodStore:        &podstoretest.Store{},
		MaxCacheSize:    100,
		Duration:        time.Hour,
		CleanupInterval: -1,
	})
	require.NoError(t, err)
	require.EqualValues(t, 20, source.limiter.Limit())
	require.Equal(t, 1, source.limiter.Burst())
	require.Equal(t, 10*time.Second, source.renewalTimeout)
	require.Equal(t, 10*time.Second, source.issueTimeout)
}

func TestNewRejectsRenewalFractionsOutsideTheIssuedLifetime(t *testing.T) {
	now := time.Now().UTC()
	for name, fraction := range map[string]float64{
		"negative":     -0.1,
		"at expiry":    1,
		"after expiry": 1.1,
		"not a number": math.NaN(),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(Opts{
				Issuer:          successfulIssuer(t, &now, 10*time.Minute),
				SessionProvider: sessions(now.Add(time.Hour)),
				PodStore:        &podstoretest.Store{},
				MaxCacheSize:    100,
				Duration:        time.Hour,
				RenewalFraction: fraction,
			})
			require.Error(t, err)
		})
	}
}

func TestNewRequiresRequestedDuration(t *testing.T) {
	now := time.Now().UTC()
	_, err := New(Opts{
		Issuer:          successfulIssuer(t, &now, 10*time.Minute),
		SessionProvider: sessions(now.Add(time.Hour)),
		PodStore:        &podstoretest.Store{},
		MaxCacheSize:    100,
	})
	require.ErrorContains(t, err, "positive requested duration")
}

func TestNewRejectsRenewalBandsOutsideTheIssuedLifetime(t *testing.T) {
	now := time.Now().UTC()
	for name, values := range map[string]struct {
		fraction float64
		jitter   float64
	}{
		"negative jitter":       {fraction: 0.5, jitter: -0.1},
		"jitter above maximum":  {fraction: 0.5, jitter: 0.6},
		"jitter not a number":   {fraction: 0.5, jitter: math.NaN()},
		"band reaches issuance": {fraction: 0.1, jitter: 0.2},
		"band reaches expiry":   {fraction: 0.9, jitter: 0.2},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(Opts{
				Issuer:          successfulIssuer(t, &now, time.Hour),
				SessionProvider: sessions(now.Add(time.Hour)),
				PodStore:        &podstoretest.Store{},
				MaxCacheSize:    100,
				Duration:        time.Hour,
				RenewalFraction: values.fraction,
				RenewalJitter:   values.jitter,
			})
			require.Error(t, err)
		})
	}
}

func TestConcurrentRequestsShareOneIssuance(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	issuer := successfulIssuer(t, &now, 10*time.Minute)
	issuer.block = release
	source := newTestSource(t, issuer, &podstoretest.Store{}, &now, 1)

	const callers = 8
	audienceSets := [][]string{
		{"ledger.example", "payments.example"},
		{"payments.example", "ledger.example"},
		{"payments.example", "ledger.example", "payments.example"},
	}
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for i := range callers {
		requested := audienceSets[i%len(audienceSets)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := source.JWTSVIDs(context.Background(), workload(testPodUID), requested)
			errs <- err
		}()
	}
	require.Eventually(t, func() bool { return issuer.calls() == 1 }, time.Second, time.Millisecond)
	source.quotaMu.Lock()
	pending := len(source.pending)
	source.quotaMu.Unlock()
	require.Equal(t, 1, pending)
	unblock()
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.Equal(t, 1, issuer.calls())
	require.Equal(t, []string{"ledger.example", "payments.example"}, issuer.allRequests()[0].req.Audiences)
	require.Empty(t, source.pending)
	require.Len(t, source.cache.Items(), 1)
}

func TestEquivalentAudienceSetsShareTheCacheWithoutMutatingTheCaller(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuer := successfulIssuer(t, &now, time.Hour)
	source := newTestSource(t, issuer, &podstoretest.Store{}, &now, 10)
	requested := []string{"payments.example", "ledger.example", "payments.example"}

	first, err := source.JWTSVIDs(context.Background(), workload(testPodUID), requested)
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.Equal(t, []string{"ledger.example", "payments.example"}, first[0].Audience)
	require.Equal(t, []string{"payments.example", "ledger.example", "payments.example"}, requested)

	requested[0] = "changed.example"
	second, err := source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"ledger.example", "payments.example"})
	require.NoError(t, err)
	require.Len(t, second, 1)
	require.Same(t, first[0], second[0])
	require.Equal(t, 1, issuer.calls())
	require.Len(t, source.cache.Items(), 1)
}

func TestDifferentAudienceSetsDoNotShareTokens(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuer := successfulIssuer(t, &now, time.Hour)
	source := newTestSource(t, issuer, &podstoretest.Store{}, &now, 10)
	for _, audiences := range [][]string{
		{"ledger.example", "payments.example"},
		{"payments.example"},
		{"ledger.example"},
		{"payments.example", "other.example"},
	} {
		svids, err := source.JWTSVIDs(context.Background(), workload(testPodUID), audiences)
		require.NoError(t, err)
		require.Len(t, svids, 1)
		require.ElementsMatch(t, audiences, svids[0].Audience)
	}
	require.Equal(t, 4, issuer.calls())
	require.Len(t, source.cache.Items(), 4)
}

func TestInvalidAudienceSetsSkipSessionLookupAndSTS(t *testing.T) {
	for name, audiences := range map[string][]string{
		"missing":       nil,
		"empty member":  {"payments.example", ""},
		"blank member":  {"payments.example", " \t"},
		"too many":      strings.Fields(strings.Repeat("aud ", 11)),
		"too long":      {strings.Repeat("a", 1001)},
		"invalid UTF-8": {"\xff"},
	} {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			issuer := successfulIssuer(t, &now, time.Hour)
			provider := sessions(now.Add(time.Hour))
			source := newTestSource(t, issuer, &podstoretest.Store{}, &now, 10)
			source.sessionProvider = provider

			svids, err := source.JWTSVIDs(context.Background(), workload(testPodUID), audiences)
			require.ErrorIs(t, err, wierrors.ErrInvalidAudience)
			require.Nil(t, svids)
			require.Zero(t, provider.Calls())
			require.Zero(t, issuer.calls())
			require.Empty(t, source.cache.Items())
			require.Empty(t, source.pending)
			require.Empty(t, source.states)
		})
	}
}
