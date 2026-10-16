package jwt

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/smithy-go"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity/fake"
)

func TestIssuanceCleansUpAfterRecoveredStorePanic(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuer := successfulIssuer(t, &now, time.Hour)
	source := newTestSource(t, issuer, &fake.PodStore{}, &now, 10)
	source.draw = func() float64 {
		panic("renewal point failed")
	}
	recovered := make(chan any, 1)
	go func() {
		defer func() { recovered <- recover() }()
		_, _ = source.issueAndStore(context.Background(), workload(testPodUID), []string{"payments.example"}, false)
	}()

	select {
	case value := <-recovered:
		require.Equal(t, "renewal point failed", value)
	case <-time.After(time.Second):
		t.Fatal("issuance cleanup blocked while unwinding a store panic")
	}

	require.Equal(t, 1, issuer.calls())
	require.Empty(t, source.pending)
	require.Empty(t, source.states)
	require.Empty(t, source.cache.Items())
}

func TestMultipleAudiencesUseOneTokenAndRenewTogether(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second).Add(-6 * time.Minute)
	issuer := successfulIssuer(t, &now, 10*time.Minute)
	source := newTestSource(t, issuer, &fake.PodStore{}, &now, 10)
	audiences := []string{"one.example", "two.example", "three.example"}

	svids, err := source.JWTSVIDs(context.Background(), workload(testPodUID), audiences)
	require.NoError(t, err)
	require.Len(t, svids, 1)
	require.ElementsMatch(t, audiences, svids[0].Audience)
	require.NotEmpty(t, svids[0].Marshal())
	require.Equal(t, 1, issuer.calls())
	request := issuer.allRequests()[0]
	require.Equal(t, []string{"one.example", "three.example", "two.example"}, request.req.Audiences)
	require.Equal(t, time.Hour, request.req.Duration)
	require.Equal(t, sts.TokenTypeJWTSVID, request.req.TokenType)
	require.Equal(t, "ASIAWORKLOAD", request.creds.AccessKeyID)

	now = now.Add(5*time.Minute + time.Second)
	renewed, err := source.JWTSVIDs(context.Background(), workload(testPodUID), audiences)
	require.NoError(t, err)
	require.Len(t, renewed, 1)
	require.ElementsMatch(t, audiences, renewed[0].Audience)
	require.NotEqual(t, svids[0].Marshal(), renewed[0].Marshal())
	require.Equal(t, 2, issuer.calls())
	require.Equal(t, request.req.Audiences, issuer.allRequests()[1].req.Audiences)
}

func TestIssuanceRejectsMissingOrExtraAudiencesWithoutCaching(t *testing.T) {
	for name, issuedAudiences := range map[string][]string{
		"missing": {"payments.example"},
		"extra":   {"ledger.example", "payments.example", "other.example"},
	} {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			expiresAt := now.Add(time.Hour)
			token := signedTokenForAudiences(t, issuedAudiences, now, expiresAt, name)
			issuer := &fakeIssuer{respond: func(int, sts.WebIdentityTokenRequest) (*sts.IssuedWebIdentityToken, error) {
				return &sts.IssuedWebIdentityToken{Token: token, Expiration: expiresAt}, nil
			}}
			source := newTestSource(t, issuer, &fake.PodStore{}, &now, 10)

			svids, err := source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"ledger.example", "payments.example"})
			require.ErrorIs(t, err, wierrors.ErrIssuanceFailed)
			require.ErrorContains(t, err, "do not match requested audiences")
			require.Nil(t, svids)
			require.Equal(t, 1, issuer.calls())
			require.Empty(t, source.cache.Items())
			require.Empty(t, source.pending)
		})
	}
}

func TestIssuanceClassifiesSTSFailuresAndInvalidatesOnlyStaleSessions(t *testing.T) {
	for _, tc := range []struct {
		code       string
		want       error
		invalidate bool
		retryable  bool
	}{
		{"Throttling", wierrors.ErrIssuanceThrottled, false, true},
		{"ThrottlingException", wierrors.ErrIssuanceThrottled, false, true},
		{"ThrottledException", wierrors.ErrIssuanceThrottled, false, true},
		{"RequestLimitExceeded", wierrors.ErrIssuanceThrottled, false, true},
		{"TooManyRequestsException", wierrors.ErrIssuanceThrottled, false, true},
		{"ValidationError", wierrors.ErrIssuanceFailed, false, true},
		{"ValidationException", wierrors.ErrIssuanceFailed, false, true},
		{"SessionDurationEscalationException", wierrors.ErrIssuanceRefused, false, false},
		{"OutboundWebIdentityFederationDisabledException", wierrors.ErrIssuanceRefused, false, false},
		{"JWTPayloadSizeExceededException", wierrors.ErrIssuanceRefused, false, false},
		{"SignerNotConfiguredException", wierrors.ErrIssuanceRefused, false, false},
		{"RegionalSignerUnavailableException", wierrors.ErrIssuanceRefused, false, false},
		{"AccessDenied", wierrors.ErrIssuanceFailed, true, true},
		{"AccessDeniedException", wierrors.ErrIssuanceFailed, true, true},
		{"InvalidClientTokenId", wierrors.ErrIssuanceFailed, true, true},
		{"ExpiredToken", wierrors.ErrIssuanceFailed, true, true},
		{"ExpiredTokenException", wierrors.ErrIssuanceFailed, true, true},
		{"InternalFailure", wierrors.ErrIssuanceFailed, false, true},
		{"UnknownFutureJWTException", wierrors.ErrIssuanceFailed, false, true},
		{"transport failure", wierrors.ErrIssuanceFailed, false, true},
	} {
		t.Run(tc.code, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			upstream := errors.New("connection reset")
			if tc.code != "transport failure" {
				upstream = fmt.Errorf("STS request: %w", &smithy.GenericAPIError{
					Code: tc.code, Message: "request failed",
				})
			}
			issuer := &fakeIssuer{respond: func(int, sts.WebIdentityTokenRequest) (*sts.IssuedWebIdentityToken, error) {
				return nil, upstream
			}}
			provider := sessions(now.Add(time.Hour))
			source := newTestSource(t, issuer, &fake.PodStore{}, &now, 1)
			source.sessionProvider = provider

			svids, err := source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"payments.example"})
			require.ErrorIs(t, err, tc.want)
			require.ErrorIs(t, err, upstream)
			require.Equal(t, tc.retryable, wierrors.IsRetryable(err))
			require.Nil(t, svids)
			require.Equal(t, 1, issuer.calls())
			require.Empty(t, source.cache.Items())
			require.Empty(t, source.pending)
			if tc.invalidate {
				require.Equal(t, []string{testPodUID}, provider.Invalidated())
			} else {
				require.Empty(t, provider.Invalidated())
			}
		})
	}
}

func TestClassificationPreservesUnknownClientFaultWithoutInferringItsCause(t *testing.T) {
	upstream := &smithy.GenericAPIError{
		Code: "UnknownFutureJWTException", Message: "request rejected", Fault: smithy.FaultClient,
	}
	err := classify(&smithy.OperationError{
		ServiceID: "STS", OperationName: "GetWebIdentityToken", Err: upstream,
	}, workload(testPodUID), []string{"payments.example"})
	require.ErrorIs(t, err, wierrors.ErrIssuanceFailed)
	require.ErrorIs(t, err, upstream)
	require.NotErrorIs(t, err, wierrors.ErrInvalidAudience)
	require.NotErrorIs(t, err, wierrors.ErrIssuanceRefused)
	var apiErr smithy.APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, upstream.Code, apiErr.ErrorCode())
	require.Equal(t, upstream.Message, apiErr.ErrorMessage())
	require.Equal(t, smithy.FaultClient, apiErr.ErrorFault())
}

func TestSessionFailureSkipsSTSAndReleasesAudienceSetReservation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuer := successfulIssuer(t, &now, time.Hour)
	provider := sessions(now.Add(time.Hour))
	validSession := provider.Result
	upstream := errors.New("session unavailable")
	provider.SetResult(nil, upstream)
	source := newTestSource(t, issuer, &fake.PodStore{}, &now, 1)
	source.sessionProvider = provider

	_, err := source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"one.example"})
	require.ErrorIs(t, err, upstream)
	require.Zero(t, issuer.calls())
	require.Empty(t, source.cache.Items())
	require.Empty(t, source.pending)
	require.Empty(t, provider.Invalidated())

	provider.SetResult(validSession, nil)
	_, err = source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"two.example"})
	require.NoError(t, err)
	require.Equal(t, 1, issuer.calls())
}

func TestIssuanceRejectsInvalidSTSResponses(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	expiresAt := now.Add(time.Hour)
	validClaims := jwtlib.RegisteredClaims{
		Subject:   testSpiffeID,
		Audience:  jwtlib.ClaimStrings{"payments.example"},
		IssuedAt:  jwtlib.NewNumericDate(now),
		ExpiresAt: jwtlib.NewNumericDate(expiresAt),
	}
	tokenWith := func(change func(*jwtlib.RegisteredClaims)) string {
		claims := validClaims
		change(&claims)
		return signedClaims(t, claims)
	}
	validToken := signedClaims(t, validClaims)

	for _, tc := range []struct {
		name     string
		response *sts.IssuedWebIdentityToken
		message  string
	}{
		{
			name:    "nil response",
			message: "no web identity token",
		},
		{
			name:     "empty token",
			response: &sts.IssuedWebIdentityToken{Expiration: expiresAt},
			message:  "no web identity token",
		},
		{
			name:     "missing response expiration",
			response: &sts.IssuedWebIdentityToken{Token: validToken},
			message:  "no web identity token expiration",
		},
		{
			name:     "malformed token",
			response: &sts.IssuedWebIdentityToken{Token: "not-a-jwt", Expiration: expiresAt},
			message:  "parsing the JWT-SVID",
		},
		{
			name: "missing subject",
			response: &sts.IssuedWebIdentityToken{
				Token: tokenWith(func(c *jwtlib.RegisteredClaims) {
					c.Subject = ""
				}),
				Expiration: expiresAt,
			},
			message: "missing subject",
		},
		{
			name: "invalid SPIFFE subject",
			response: &sts.IssuedWebIdentityToken{
				Token: tokenWith(func(c *jwtlib.RegisteredClaims) {
					c.Subject = "not-a-spiffe-id"
				}),
				Expiration: expiresAt,
			},
			message: "invalid subject",
		},
		{
			name: "wrong audience",
			response: &sts.IssuedWebIdentityToken{
				Token: tokenWith(func(c *jwtlib.RegisteredClaims) {
					c.Audience = jwtlib.ClaimStrings{"other.example"}
				}),
				Expiration: expiresAt,
			},
			message: "expected audience",
		},
		{
			name: "missing token expiration",
			response: &sts.IssuedWebIdentityToken{
				Token: tokenWith(func(c *jwtlib.RegisteredClaims) {
					c.ExpiresAt = nil
				}),
				Expiration: expiresAt,
			},
			message: "missing exp claim",
		},
		{
			name:     "response expiration later than token",
			response: &sts.IssuedWebIdentityToken{Token: validToken, Expiration: expiresAt.Add(2 * time.Second)},
			message:  "does not match JWT exp",
		},
		{
			name:     "response expiration earlier than token",
			response: &sts.IssuedWebIdentityToken{Token: validToken, Expiration: expiresAt.Add(-2 * time.Second)},
			message:  "does not match JWT exp",
		},
		{
			name: "expired token",
			response: &sts.IssuedWebIdentityToken{
				Token:      signedToken(t, "payments.example", now.Add(-time.Hour), now.Add(-time.Second), "expired"),
				Expiration: now.Add(-time.Second),
			},
			message: "expired JWT-SVID",
		},
		{
			name: "expiration equals now",
			response: &sts.IssuedWebIdentityToken{
				Token:      signedToken(t, "payments.example", now.Add(-time.Hour), now, "expired"),
				Expiration: now,
			},
			message: "expired JWT-SVID",
		},
		{
			name: "issuance equals expiration",
			response: &sts.IssuedWebIdentityToken{
				Token:      signedToken(t, "payments.example", expiresAt, expiresAt, "invalid-lifetime"),
				Expiration: expiresAt,
			},
			message: "issued in the future",
		},
		{
			name: "issuance after expiration",
			response: &sts.IssuedWebIdentityToken{
				Token:      signedToken(t, "payments.example", expiresAt.Add(time.Second), expiresAt, "invalid-lifetime"),
				Expiration: expiresAt,
			},
			message: "issued in the future",
		},
		{
			name: "future issuance",
			response: &sts.IssuedWebIdentityToken{
				Token: tokenWith(func(c *jwtlib.RegisteredClaims) {
					c.IssuedAt = jwtlib.NewNumericDate(now.Add(5 * time.Minute))
				}),
				Expiration: expiresAt,
			},
			message: "issued in the future",
		},
		{
			name: "not yet valid",
			response: &sts.IssuedWebIdentityToken{
				Token: tokenWith(func(c *jwtlib.RegisteredClaims) {
					c.NotBefore = jwtlib.NewNumericDate(now.Add(5 * time.Minute))
				}),
				Expiration: expiresAt,
			},
			message: "not valid yet",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuer := &fakeIssuer{respond: func(int, sts.WebIdentityTokenRequest) (*sts.IssuedWebIdentityToken, error) {
				return tc.response, nil
			}}
			provider := sessions(now.Add(time.Hour))
			source := newTestSource(t, issuer, &fake.PodStore{}, &now, 1)
			source.sessionProvider = provider

			svids, err := source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"payments.example"})
			require.ErrorIs(t, err, wierrors.ErrIssuanceFailed)
			require.ErrorContains(t, err, tc.message)
			require.Nil(t, svids)
			require.Empty(t, source.cache.Items())
			require.Empty(t, source.pending)
			require.Empty(t, provider.Invalidated())
		})
	}
}

func TestIssuanceUsesCallStartWhenTokenHasNoIssuedAt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	startedAt := now
	expiresAt := now.Add(time.Hour)
	token := signedClaims(t, jwtlib.RegisteredClaims{
		Subject:   testSpiffeID,
		Audience:  jwtlib.ClaimStrings{"payments.example"},
		ExpiresAt: jwtlib.NewNumericDate(expiresAt),
	})
	issuer := &fakeIssuer{respond: func(int, sts.WebIdentityTokenRequest) (*sts.IssuedWebIdentityToken, error) {
		now = now.Add(10 * time.Second)
		return &sts.IssuedWebIdentityToken{Token: token, Expiration: expiresAt}, nil
	}}
	source := newTestSource(t, issuer, &fake.PodStore{}, &now, 1)

	svids, err := source.JWTSVIDs(context.Background(), workload(testPodUID), []string{"payments.example"})
	require.NoError(t, err)
	require.Equal(t, expiresAt, svids[0].Expiry)
	cached, ok := source.cache.Get(makeCacheKey(testPodUID, []string{"payments.example"}))
	require.True(t, ok)
	require.Equal(t, startedAt.Add(30*time.Minute), cached.renewAt)
}
