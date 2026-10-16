package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity/fake"
)

const (
	testPodUID   = "pod-uid-1"
	testSpiffeID = "spiffe://example.org/ns/default/sa/payments"
)

type issuanceRequest struct {
	creds aws.Credentials
	req   sts.WebIdentityTokenRequest
}

type fakeIssuer struct {
	mu            sync.Mutex
	requests      []issuanceRequest
	respond       func(int, sts.WebIdentityTokenRequest) (*sts.IssuedWebIdentityToken, error)
	block         <-chan struct{}
	ignoreContext bool
}

func (f *fakeIssuer) GetWebIdentityToken(
	ctx context.Context,
	creds aws.Credentials,
	req sts.WebIdentityTokenRequest,
) (*sts.IssuedWebIdentityToken, error) {
	f.mu.Lock()
	f.requests = append(f.requests, issuanceRequest{creds: creds, req: req})
	attempt := len(f.requests)
	respond, block := f.respond, f.block
	f.mu.Unlock()

	if block != nil {
		if f.ignoreContext {
			<-block
		} else {
			select {
			case <-block:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	return respond(attempt, req)
}

func (f *fakeIssuer) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *fakeIssuer) allRequests() []issuanceRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]issuanceRequest(nil), f.requests...)
}

func workload(podUID string) *workloadidentity.Workload {
	return &workloadidentity.Workload{
		PodUID:         podUID,
		PodName:        "payments",
		Namespace:      "default",
		ServiceAccount: "payments",
		NodeName:       "node-1",
	}
}

func sessions(expiresAt time.Time) *fake.SessionProvider {
	return &fake.SessionProvider{Result: &workloadidentity.WorkloadSession{
		Credentials: aws.Credentials{
			AccessKeyID:     "ASIAWORKLOAD",
			SecretAccessKey: "secret",
			SessionToken:    "session",
			CanExpire:       true,
			Expires:         expiresAt,
		},
		ProviderArn: "arn:aws:iam::111122223333:workload-identity-provider/example",
		ExpiresAt:   expiresAt,
	}}
}

func signedClaims(t *testing.T, claims jwtlib.RegisteredClaims) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	unsigned := jwtlib.NewWithClaims(jwtlib.SigningMethodES256, claims)
	unsigned.Header["kid"] = "test-key"
	token, err := unsigned.SignedString(key)
	require.NoError(t, err)
	return token
}

func signedToken(t *testing.T, audience string, issuedAt, expiresAt time.Time, id string) string {
	t.Helper()
	return signedTokenForAudiences(t, []string{audience}, issuedAt, expiresAt, id)
}

func signedTokenForAudiences(t *testing.T, audiences []string, issuedAt, expiresAt time.Time, id string) string {
	t.Helper()
	return signedClaims(t, jwtlib.RegisteredClaims{
		Subject:   testSpiffeID,
		Audience:  jwtlib.ClaimStrings(slices.Clone(audiences)),
		ExpiresAt: jwtlib.NewNumericDate(expiresAt),
		IssuedAt:  jwtlib.NewNumericDate(issuedAt),
		ID:        id,
	})
}

func successfulIssuer(t *testing.T, now *time.Time, lifetime time.Duration) *fakeIssuer {
	t.Helper()
	return &fakeIssuer{respond: func(attempt int, req sts.WebIdentityTokenRequest) (*sts.IssuedWebIdentityToken, error) {
		expiresAt := now.Add(lifetime)
		return &sts.IssuedWebIdentityToken{
			Token:      signedTokenForAudiences(t, req.Audiences, *now, expiresAt, string(rune('a'+attempt))),
			Expiration: expiresAt,
		}, nil
	}}
}

func newTestSource(
	t *testing.T,
	issuer Issuer,
	watcher *fake.PodStore,
	now *time.Time,
	maxAudienceSets int,
) *Source {
	t.Helper()
	source, err := New(Opts{
		Issuer:                issuer,
		SessionProvider:       sessions(now.Add(time.Hour)),
		PodStore:              watcher,
		MaxCacheSize:          100,
		MaxAudienceSetsPerPod: maxAudienceSets,
		Duration:              time.Hour,
		RenewalFraction:       0.5,
		RenewalJitter:         0.1,
		CleanupInterval:       -1,
		RefreshQPS:            100,
		now:                   func() time.Time { return *now },
		draw:                  func() float64 { return 0.5 },
	})
	require.NoError(t, err)
	require.Equal(t, 1, watcher.Registered())
	return source
}
