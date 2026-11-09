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

// TestIssuanceAsksForASessionCoveringTheTokenAndItsBudget: the tier asks the
// session tier for a session with the token's lifetime plus the issuance budget
// left, never invalidates one, and signs STS with what it was given.
func TestIssuanceAsksForASessionCoveringTheTokenAndItsBudget(t *testing.T) {
	for _, tc := range []struct {
		name           string
		requested      time.Duration
		renewalTimeout time.Duration
	}{
		{name: "default budget", requested: time.Hour},
		{name: "short token", requested: 15 * time.Minute},
		{name: "custom budget", requested: time.Hour, renewalTimeout: 20 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			provider := sessions(now.Add(2 * time.Hour))
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
			require.Equal(t, []workloadidentity.SessionOptions{{MinRemaining: tc.requested + source.renewalTimeout}},
				provider.Options())
			require.Empty(t, provider.Invalidated())
			require.Equal(t, 1, issuer.calls())
			request := issuer.allRequests()[0]
			require.Equal(t, tc.requested, request.req.Duration)
			require.Equal(t, provider.Result.Credentials, request.creds)
		})
	}
}

// TestIssuanceDoesNotRetryWhenTheSessionIsStillTooShort: when the session tier
// can only hand out a session shorter than asked for, STS's refusal is returned
// after one session lookup and one STS call.
func TestIssuanceDoesNotRetryWhenTheSessionIsStillTooShort(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	provider := sessions(now.Add(time.Hour - 2*time.Second))
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
	require.Equal(t, 1, provider.Calls())
	require.Empty(t, provider.Invalidated())
	require.Equal(t, 1, issuer.calls())
	require.Equal(t, time.Hour, issuer.allRequests()[0].req.Duration)
	require.Empty(t, source.cache.Items())
	require.Empty(t, source.pending)
	require.Empty(t, source.states)
}

func TestSessionLookupFailureSkipsSTS(t *testing.T) {
	lookupErr := errors.New("EKS Auth unavailable")
	for _, tc := range []struct {
		name      string
		lookupErr error
		deletePod bool
		wantErr   error
	}{
		{
			name:      "session lookup fails",
			lookupErr: lookupErr,
			wantErr:   lookupErr,
		},
		{
			name:      "pod deleted during lookup",
			deletePod: true,
			wantErr:   wierrors.ErrUnattestable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			pods := &podstoretest.Store{}
			provider := sessions(now.Add(2 * time.Hour))
			fresh := provider.Result
			provider.Func = func(context.Context, *workloadidentity.Workload,
				workloadidentity.SessionOptions) (*workloadidentity.WorkloadSession, error) {
				if tc.lookupErr != nil {
					return nil, tc.lookupErr
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
			require.Equal(t, 1, provider.Calls())
			require.Empty(t, provider.Invalidated())
			require.Zero(t, issuer.calls())
			require.Empty(t, source.cache.Items())
			require.Empty(t, source.pending)
			require.Empty(t, source.states)
		})
	}
}

func TestSessionLookupKeepsTheIssuanceDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
		provider := sessions(now.Add(2 * time.Hour))
		ctx, cancel := context.WithTimeout(context.Background(), defaultIssueTimeout)
		defer cancel()
		provider.Func = func(callCtx context.Context, _ *workloadidentity.Workload,
			_ workloadidentity.SessionOptions) (*workloadidentity.WorkloadSession, error) {
			require.Same(t, ctx, callCtx)
			<-callCtx.Done()
			return nil, callCtx.Err()
		}
		issuer := successfulIssuer(t, &now, time.Hour)
		source := newTestSource(t, issuer, &podstoretest.Store{}, &now, 1)
		source.sessionProvider = provider
		source.now = time.Now

		_, err := source.issueAndStore(ctx, workload(testPodUID), []string{"payments.example"}, false)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Equal(t, defaultIssueTimeout, time.Since(now))
		require.Equal(t, 1, provider.Calls())
		require.Zero(t, issuer.calls())
		require.Empty(t, source.cache.Items())
		require.Empty(t, source.pending)
		require.Empty(t, source.states)
	})
}

// TestRenewalRemainsUsableAcrossSessionExpiry: with a session tier that exchanges
// whenever the cached session has less than asked for left, renewals keep a
// servable token through two session lifetimes.
func TestRenewalRemainsUsableAcrossSessionExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Second)
		session := sessions(now.Add(time.Hour - 2*time.Second)).Result
		provider := sessions(session.ExpiresAt)
		exchanges := 0
		provider.Func = func(_ context.Context, _ *workloadidentity.Workload,
			opts workloadidentity.SessionOptions) (*workloadidentity.WorkloadSession, error) {
			if session.ExpiresAt.Sub(now) < opts.MinRemaining {
				exchanges++
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
		require.Equal(t, 2, exchanges)
		require.Empty(t, provider.Invalidated())
	})
}
