package credsretriever

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/eksauth/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/imds"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
)

var (
	fixedNow    = time.Now()
	futureTime  = fixedNow.Add(6 * time.Hour)
	pastTime    = fixedNow.Add(-1 * time.Hour)
	testRequest = &credentials.EksCredentialsRequest{ServiceAccountToken: "tok", ClusterName: "cluster"}
)

func testContext() context.Context {
	return logger.ContextWithField(context.Background(), "test", "true")
}

func unexpiredCred(source credentials.CredentialSource) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata) {
	return &credentials.EksCredentialsResponse{
		AccessKeyId:     "AKIA-" + string(source),
		SecretAccessKey: "secret",
		Token:           "token",
		AccountId:       "123456789012",
		Expiration:      credentials.SdkCompliantExpirationTime{Time: futureTime},
	}, credentials.CredentialMetadata{CredSource: source}
}

func expiredCred(source credentials.CredentialSource) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata) {
	return &credentials.EksCredentialsResponse{
		AccessKeyId:     "AKIA-expired-" + string(source),
		SecretAccessKey: "secret",
		Token:           "token",
		AccountId:       "123456789012",
		Expiration:      credentials.SdkCompliantExpirationTime{Time: pastTime},
	}, credentials.CredentialMetadata{CredSource: source}
}

// credExpiringIn builds a credential whose expiration is now+offset, for testing
// the chain's expirationSkew boundary. keyID lets a test identify which credential
// was returned independent of source.
func credExpiringIn(keyID string, offset time.Duration) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata) {
	return &credentials.EksCredentialsResponse{
		AccessKeyId:     keyID,
		SecretAccessKey: "secret",
		Token:           "token",
		AccountId:       "123456789012",
		Expiration:      credentials.SdkCompliantExpirationTime{Time: time.Now().Add(offset)},
	}, credentials.CredentialMetadata{CredSource: credentials.SourceIMDS}
}

// stubRetriever is a simple test double for CredentialRetriever.
type stubRetriever struct {
	name          string
	cred          *credentials.EksCredentialsResponse
	meta          credentials.ResponseMetadata
	err           error
	called        bool
	irrecoverable bool
}

func (s *stubRetriever) String() string { return s.name }

func (s *stubRetriever) IsIrrecoverable(_ error) (string, bool) {
	return "TestCode", s.irrecoverable
}

func (s *stubRetriever) GetIamCredentials(_ context.Context, _ *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
	s.called = true
	return s.cred, s.meta, s.err
}

// Verifies the chain's credential-selection logic across the HLD decision matrix:
// unexpired-first-wins (and short-circuits later delegates), fall-through on
// expired/missing/errored delegates, expired-fallback when nothing is unexpired,
// nil-delegate skipping, and source metadata preserved through the chain.
func TestChained_SelectionMatrix(t *testing.T) {
	imdsCred, imdsMeta := unexpiredCred(credentials.SourceIMDS)
	imdsExpCred, imdsExpMeta := expiredCred(credentials.SourceIMDS)
	authCred, authMeta := unexpiredCred(credentials.SourceAuthService)
	irrecoverableErr := fmt.Errorf("wrapped: %w", &types.ResourceNotFoundException{})
	recoverableErr := fmt.Errorf("wrapped: %w", &types.InternalServerException{})

	tests := []struct {
		name       string
		imds       credentials.CredentialRetriever
		auth       credentials.CredentialRetriever
		wantKey    string // AccessKeyId of expected credential
		wantSource credentials.CredentialSource
		wantErr    bool
		authCalled bool
	}{
		{
			name:       "IMDS unexpired → return IMDS, Auth Service not called",
			imds:       &stubRetriever{name: "imds", cred: imdsCred, meta: imdsMeta},
			auth:       &stubRetriever{name: "auth", cred: authCred, meta: authMeta},
			wantKey:    imdsCred.AccessKeyId,
			wantSource: credentials.SourceIMDS,
			authCalled: false,
		},
		{
			name:       "IMDS expired + Auth Service unexpired → return Auth Service",
			imds:       &stubRetriever{name: "imds", cred: imdsExpCred, meta: imdsExpMeta},
			auth:       &stubRetriever{name: "auth", cred: authCred, meta: authMeta},
			wantKey:    authCred.AccessKeyId,
			wantSource: credentials.SourceAuthService,
			authCalled: true,
		},
		{
			name:       "IMDS expired + Auth Service irrecoverable error → return IMDS",
			imds:       &stubRetriever{name: "imds", cred: imdsExpCred, meta: imdsExpMeta},
			auth:       &stubRetriever{name: "auth", err: irrecoverableErr},
			wantKey:    imdsExpCred.AccessKeyId,
			wantSource: credentials.SourceIMDS,
			authCalled: true,
		},
		{
			name:       "IMDS expired + Auth Service recoverable error → return IMDS",
			imds:       &stubRetriever{name: "imds", cred: imdsExpCred, meta: imdsExpMeta},
			auth:       &stubRetriever{name: "auth", err: recoverableErr},
			wantKey:    imdsExpCred.AccessKeyId,
			wantSource: credentials.SourceIMDS,
			authCalled: true,
		},
		{
			name:       "IMDS missing + Auth Service unexpired → return Auth Service",
			imds:       &stubRetriever{name: "imds", err: imds.ErrPodNotInMapping},
			auth:       &stubRetriever{name: "auth", cred: authCred, meta: authMeta},
			wantKey:    authCred.AccessKeyId,
			wantSource: credentials.SourceAuthService,
			authCalled: true,
		},
		{
			name:       "IMDS network error → falls through to Auth Service",
			imds:       &stubRetriever{name: "imds", err: errors.New("IMDS rate limiter: context deadline exceeded")},
			auth:       &stubRetriever{name: "auth", cred: authCred, meta: authMeta},
			wantKey:    authCred.AccessKeyId,
			wantSource: credentials.SourceAuthService,
			authCalled: true,
		},
		{
			name:       "nil IMDS delegate → skipped, Auth Service returns credential",
			imds:       nil,
			auth:       &stubRetriever{name: "auth", cred: authCred, meta: authMeta},
			wantKey:    authCred.AccessKeyId,
			wantSource: credentials.SourceAuthService,
			authCalled: true,
		},
		{
			name:    "both delegates nil → return error",
			imds:    nil,
			auth:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := NewChainedRetriever(tt.imds, tt.auth)
			cred, meta, err := chain.GetIamCredentials(testContext(), testRequest)

			// Check if auth delegate was invoked
			authCalled := false
			if s, ok := tt.auth.(*stubRetriever); ok && s != nil {
				authCalled = s.called
			}
			assert.Equal(t, tt.authCalled, authCalled, "Auth Service called mismatch")

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, cred)
				assert.Equal(t, credentials.CredentialMetadata{}, meta)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cred)
			assert.Equal(t, tt.wantKey, cred.AccessKeyId)
			assert.Equal(t, tt.wantSource, meta.Source())
		})
	}
}

// Verifies a chain of one delegate returns that delegate's credential and source
// unchanged (the degenerate single-element chain).
func TestChained_SingleDelegate_Passthrough(t *testing.T) {
	cred, meta := unexpiredCred(credentials.SourceAuthService)
	auth := &stubRetriever{name: "auth", cred: cred, meta: meta}
	chain := NewChainedRetriever(auth)

	got, gotMeta, err := chain.GetIamCredentials(testContext(), testRequest)
	require.NoError(t, err)
	assert.Equal(t, cred.AccessKeyId, got.AccessKeyId)
	assert.Equal(t, credentials.SourceAuthService, gotMeta.Source())
}

// Verifies the expirationSkew boundary: a credential expiring beyond the skew is
// treated as unexpired and returned immediately, while one expiring within the
// skew is treated as expired and the chain falls through to the next delegate.
func TestChained_ExpirationSkewBoundary(t *testing.T) {
	// A comfortably-unexpired fallback so "fell through" is observable.
	authCred, authMeta := unexpiredCred(credentials.SourceAuthService)

	tests := []struct {
		name        string
		firstOffset time.Duration
		wantFirst   bool // true = first delegate's cred returned (treated unexpired)
	}{
		{"expires just beyond skew is accepted", expirationSkew + time.Minute, true},
		{"expires just within skew falls through", expirationSkew - time.Minute, false},
		{"expires exactly at skew falls through", expirationSkew, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			firstCred, firstMeta := credExpiringIn("AKIA-first", tt.firstOffset)
			first := &stubRetriever{name: "first", cred: firstCred, meta: firstMeta}
			second := &stubRetriever{name: "second", cred: authCred, meta: authMeta}
			chain := NewChainedRetriever(first, second)

			cred, _, err := chain.GetIamCredentials(testContext(), testRequest)
			require.NoError(t, err)
			if tt.wantFirst {
				assert.Equal(t, "AKIA-first", cred.AccessKeyId, "cred beyond skew should be returned as unexpired")
				assert.False(t, second.called, "second delegate should not be called when first is unexpired")
			} else {
				assert.Equal(t, authCred.AccessKeyId, cred.AccessKeyId, "cred within skew should fall through to the next delegate")
				assert.True(t, second.called, "second delegate should be called when first is within the skew")
			}
		})
	}
}

// Verifies that when every delegate returns only expired credentials, the chain
// falls back to the topmost (first) delegate's credential.
func TestChained_ExpiredFallback_PrefersTopmost(t *testing.T) {
	firstCred, firstMeta := credExpiringIn("AKIA-first-expired", -1*time.Hour)
	secondCred, secondMeta := credExpiringIn("AKIA-second-expired", -2*time.Hour)
	first := &stubRetriever{name: "first", cred: firstCred, meta: firstMeta}
	second := &stubRetriever{name: "second", cred: secondCred, meta: secondMeta}
	chain := NewChainedRetriever(first, second)

	cred, _, err := chain.GetIamCredentials(testContext(), testRequest)
	require.NoError(t, err)
	// The AccessKeyId check is what proves topmost-wins (a last-wins bug returns
	// the second cred). second.called just confirms the chain kept searching for
	// an unexpired cred rather than stopping at the first expired one.
	assert.Equal(t, "AKIA-first-expired", cred.AccessKeyId, "topmost expired credential should win")
	assert.True(t, second.called, "chain should consult all delegates when no unexpired cred exists")
}

// Verifies error aggregation when no delegate yields a credential: the chain
// wraps ErrAllDelegatesIrrecoverable only when every delegate's failure is
// irrecoverable, keeps individual errors unwrappable via errors.Is, and reports
// the same verdict through chain.IsIrrecoverable.
func TestChained_ErrorPropagation(t *testing.T) {
	t.Run("all delegates irrecoverable wraps sentinel", func(t *testing.T) {
		imdsDelegate := &stubRetriever{name: "imds", err: imds.ErrPodNotInMapping, irrecoverable: true}
		authDelegate := &stubRetriever{name: "auth", err: fmt.Errorf("wrapped: %w", &types.ResourceNotFoundException{}), irrecoverable: true}
		chain := NewChainedRetriever(imdsDelegate, authDelegate)

		_, _, err := chain.GetIamCredentials(testContext(), testRequest)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrAllDelegatesIrrecoverable), "should wrap ErrAllDelegatesIrrecoverable")
		// Individual delegate errors are unwrappable
		assert.True(t, errors.Is(err, imds.ErrPodNotInMapping), "should contain IMDS error")
	})

	t.Run("mixed recoverable does not wrap sentinel", func(t *testing.T) {
		imdsDelegate := &stubRetriever{name: "imds", err: imds.ErrPodNotInMapping, irrecoverable: true}
		authDelegate := &stubRetriever{name: "auth", err: errors.New("transient network error"), irrecoverable: false}
		chain := NewChainedRetriever(imdsDelegate, authDelegate)

		_, _, err := chain.GetIamCredentials(testContext(), testRequest)
		require.Error(t, err)
		assert.False(t, errors.Is(err, ErrAllDelegatesIrrecoverable), "should NOT wrap ErrAllDelegatesIrrecoverable")
		// Individual errors still present via Join
		assert.True(t, errors.Is(err, imds.ErrPodNotInMapping), "should contain IMDS error")
	})

	t.Run("chain.IsIrrecoverable agrees with sentinel", func(t *testing.T) {
		imdsDelegate := &stubRetriever{name: "imds", err: imds.ErrPodNotInMapping, irrecoverable: true}
		authDelegate := &stubRetriever{name: "auth", err: fmt.Errorf("wrapped: %w", &types.AccessDeniedException{}), irrecoverable: true}
		chain := NewChainedRetriever(imdsDelegate, authDelegate)

		_, _, err := chain.GetIamCredentials(testContext(), testRequest)
		require.Error(t, err)

		_, isIrrecoverable := chain.(credentials.CredentialRetriever).IsIrrecoverable(err)
		assert.True(t, isIrrecoverable, "chain.IsIrrecoverable should return true for ErrAllDelegatesIrrecoverable")

		// A recoverable error should return false
		_, isIrrecoverableRecoverable := chain.(credentials.CredentialRetriever).IsIrrecoverable(errors.New("some random error"))
		assert.False(t, isIrrecoverableRecoverable, "chain.IsIrrecoverable should return false for non-sentinel errors")
	})
}
