package jwt

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/podstore/podstoretest"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

func TestIssuanceRefreshesSessionOnlyWhenNeeded(t *testing.T) {
	for _, tc := range []struct {
		name           string
		remaining      time.Duration
		requested      time.Duration
		lookupDelay    time.Duration
		renewalTimeout time.Duration
		wantRefresh    bool
	}{
		{
			name:      "long session",
			remaining: 2 * time.Hour,
			requested: time.Hour,
		},
		{
			name:      "exact issuance budget",
			remaining: time.Hour + defaultRenewalTimeout,
			requested: time.Hour,
		},
		{
			name:        "nearly enough lifetime",
			remaining:   time.Hour + defaultRenewalTimeout - time.Second,
			requested:   time.Hour,
			wantRefresh: true,
		},
		{
			name:        "fractional remaining lifetime",
			remaining:   time.Hour + defaultRenewalTimeout - time.Nanosecond,
			requested:   time.Hour,
			wantRefresh: true,
		},
		{
			name:        "near session expiry",
			remaining:   2 * time.Minute,
			requested:   30 * time.Minute,
			wantRefresh: true,
		},
		{
			name:           "lifetime consumed during session lookup",
			remaining:      time.Hour + 22*time.Second,
			requested:      time.Hour,
			lookupDelay:    4 * time.Second,
			renewalTimeout: 20 * time.Second,
			wantRefresh:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			provider := sessions(now.Add(tc.remaining))
			old := provider.Result
			fresh := sessions(now.Add(2 * time.Hour)).Result
			fresh.Credentials.SessionToken = "refreshed-session"
			provider.Func = func(context.Context, *workloadidentity.Workload) (*workloadidentity.WorkloadSession, error) {
				now = now.Add(tc.lookupDelay)
				if provider.InvalidateCalls() == 0 {
					return old, nil
				}
				return fresh, nil
			}
			issuer := successfulIssuer(t, &now, tc.requested)
			source := newTestSource(t, issuer, &podstoretest.Store{}, &now, 1)
			source.duration = tc.requested
			source.sessionProvider = provider
			if tc.renewalTimeout != 0 {
				source.renewalTimeout = tc.renewalTimeout
			}

			svids, err := source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"payments.example"})
			require.NoError(t, err)
			require.Equal(t, now.Add(tc.requested), svids[0].Expiry)
			require.Equal(t, 1, issuer.calls())
			request := issuer.allRequests()[0]
			require.Equal(t, tc.requested, request.req.Duration)
			if !tc.wantRefresh {
				require.Empty(t, provider.Invalidated())
				require.Equal(t, 1, provider.Calls())
				require.Equal(t, old.Credentials, request.creds)
			} else {
				require.Equal(t, []string{testPodUID}, provider.Invalidated())
				require.Equal(t, 2, provider.Calls())
				require.Equal(t, fresh.Credentials, request.creds)
			}
		})
	}
}

func TestIssuanceDoesNotRetryWhenFreshSessionIsStillTooShort(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	provider := sessions(now.Add(2 * time.Minute))
	old := provider.Result
	fresh := sessions(now.Add(time.Hour - 2*time.Second)).Result
	provider.Func = func(context.Context, *workloadidentity.Workload) (*workloadidentity.WorkloadSession, error) {
		if provider.InvalidateCalls() == 0 {
			return old, nil
		}
		return fresh, nil
	}
	upstream := &smithy.GenericAPIError{Code: "SessionDurationEscalationException"}
	issuer := &fakeIssuer{respond: func(int, sts.WebIdentityTokenRequest) (*sts.IssuedWebIdentityToken, error) {
		return nil, upstream
	}}
	source := newTestSource(t, issuer, &podstoretest.Store{}, &now, 1)
	source.sessionProvider = provider

	_, err := source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"payments.example"})
	require.ErrorIs(t, err, wierrors.ErrIssuanceRefused)
	require.ErrorIs(t, err, upstream)
	require.False(t, wierrors.IsRetryable(err))
	require.Equal(t, 2, provider.Calls())
	require.Equal(t, 1, provider.InvalidateCalls())
	require.Equal(t, 1, issuer.calls())
	require.Equal(t, time.Hour, issuer.allRequests()[0].req.Duration)
	require.Empty(t, source.cache.Items())
	require.Empty(t, source.pending)
	require.Empty(t, source.states)
}

func TestSessionRefreshSkipsSTS(t *testing.T) {
	refreshErr := errors.New("EKS Auth unavailable")
	for _, tc := range []struct {
		name       string
		refreshErr error
		deletePod  bool
		wantErr    error
	}{
		{
			name:       "session refresh fails",
			refreshErr: refreshErr,
			wantErr:    refreshErr,
		},
		{
			name:      "pod deleted during refresh",
			deletePod: true,
			wantErr:   wierrors.ErrUnattestable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			pods := &podstoretest.Store{}
			provider := sessions(now.Add(2 * time.Minute))
			old := provider.Result
			fresh := sessions(now.Add(2 * time.Hour)).Result
			provider.Func = func(context.Context, *workloadidentity.Workload) (*workloadidentity.WorkloadSession, error) {
				if provider.InvalidateCalls() == 0 {
					return old, nil
				}
				if tc.refreshErr != nil {
					return nil, tc.refreshErr
				}
				if tc.deletePod {
					pods.Delete(testPodUID)
				}
				return fresh, nil
			}
			issuer := successfulIssuer(t, &now, time.Hour)
			source := newTestSource(t, issuer, pods, &now, 1)
			source.sessionProvider = provider

			_, err := source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"payments.example"})
			require.ErrorIs(t, err, tc.wantErr)
			require.Equal(t, 2, provider.Calls())
			require.Equal(t, []string{testPodUID}, provider.Invalidated())
			require.Zero(t, issuer.calls())
			require.Empty(t, source.cache.Items())
			require.Empty(t, source.pending)
			require.Empty(t, source.states)
		})
	}
}

func TestSessionRefreshKeepsOriginalDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
		provider := sessions(now.Add(2 * time.Minute))
		ctx, cancel := context.WithTimeout(context.Background(), defaultIssueTimeout)
		defer cancel()
		deadline, _ := ctx.Deadline()
		provider.Func = func(callCtx context.Context, _ *workloadidentity.Workload) (*workloadidentity.WorkloadSession, error) {
			require.Same(t, ctx, callCtx)
			callDeadline, ok := callCtx.Deadline()
			require.True(t, ok)
			require.Equal(t, deadline, callDeadline)
			if provider.InvalidateCalls() > 0 {
				<-callCtx.Done()
				return nil, callCtx.Err()
			}
			return provider.Result, nil
		}
		issuer := successfulIssuer(t, &now, time.Hour)
		source := newTestSource(t, issuer, &podstoretest.Store{}, &now, 1)
		source.sessionProvider = provider
		source.now = time.Now

		_, err := source.issueAndStore(ctx, workload(testPodUID), []string{"payments.example"}, false)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Equal(t, defaultIssueTimeout, time.Since(now))
		require.Equal(t, 2, provider.Calls())
		require.Equal(t, 1, provider.InvalidateCalls())
		require.Zero(t, issuer.calls())
		require.Empty(t, source.cache.Items())
		require.Empty(t, source.pending)
		require.Empty(t, source.states)
	})
}

func TestRenewalRemainsUsableAcrossSessionExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Second)
		session := sessions(now.Add(time.Hour - 2*time.Second)).Result
		provider := sessions(session.ExpiresAt)
		invalidations := 0
		provider.Func = func(context.Context, *workloadidentity.Workload) (*workloadidentity.WorkloadSession, error) {
			if provider.InvalidateCalls() != invalidations {
				invalidations = provider.InvalidateCalls()
				session = sessions(now.Add(time.Hour - 2*time.Second)).Result
			}
			return session, nil
		}
		issuer := &fakeIssuer{respond: func(attempt int, req sts.WebIdentityTokenRequest) (*sts.IssuedWebIdentityToken, error) {
			expiry := now.Add(req.Duration)
			if expiry.After(session.ExpiresAt) {
				return nil, &smithy.GenericAPIError{Code: "SessionDurationEscalationException"}
			}
			return &sts.IssuedWebIdentityToken{
				Token:      signedTokenForAudiences(t, req.Audiences, now, expiry, fmt.Sprint(attempt)),
				Expiration: expiry,
			}, nil
		}}
		source := newTestSource(t, issuer, &podstoretest.Store{}, &now, 1)
		source.duration = 30 * time.Minute
		source.sessionProvider = provider
		w := workload(testPodUID)
		audiences := []string{"payments.example"}
		_, err := source.JWTSVIDs(context.Background(), w, audiences)
		require.NoError(t, err)

		for range 75 {
			time.Sleep(defaultCleanupInterval)
			now = time.Now().UTC().Truncate(time.Second)
			source.cache.RefreshOrEvictExpired()
			cached, ok := source.cache.Get(makeCacheKey(testPodUID, audiences))
			require.True(t, ok, "no token at %s", now)
			require.True(t, source.servable(cached.svid), "expired token at %s", now)
			_, err := source.JWTSVIDs(context.Background(), w, audiences)
			require.NoError(t, err)
		}
		require.Greater(t, issuer.calls(), 3)
		require.Equal(t, 2, provider.InvalidateCalls())
	})
}
