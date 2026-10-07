package session

import (
	"context"
	"errors"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/eksauth"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/eksauth/eksauthtest"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/credcache"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials/mockcreds"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity/fake"
)

// TestRefreshWith_GivesOnlyDecoratedEntriesEKSAuthAndTokens proves the fork
// rule: an entry with a provider ARN refreshes through EKS Auth with the token
// source, and one without, or without metadata, gets (nil, nil), which the cache
// reads as its Delegate with the stored token.
func TestRefreshWith_GivesOnlyDecoratedEntriesEKSAuthAndTokens(t *testing.T) {
	// No calls expected: the rule only picks a source and a token source.
	eksAuth := mockcreds.NewMockCredentialRetriever(gomock.NewController(t))
	tokens := MinterTokens(&fake.TokenMinter{})
	refreshWith := RefreshWith(eksAuth, tokens)

	for name, tc := range map[string]struct {
		metadata    credentials.ResponseMetadata
		wantEKSAuth bool
	}{
		"decorated": {
			metadata:    credentials.CredentialMetadata{CredSource: credentials.SourceAuthService, Provider: "arn:provider"},
			wantEKSAuth: true,
		},
		"undecorated": {metadata: credentials.CredentialMetadata{CredSource: credentials.SourceAuthService}},
		"from IMDS":   {metadata: credentials.CredentialMetadata{CredSource: credentials.SourceIMDS}},
		"no metadata": {},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			source, gotTokens := refreshWith(&credcache.Entry{Metadata: tc.metadata})
			if tc.wantEKSAuth {
				g.Expect(source).To(BeIdenticalTo(eksAuth))
				g.Expect(gotTokens).To(Equal(tokens))
				return
			}
			g.Expect(source).To(BeNil())
			g.Expect(gotTokens).To(BeNil())
		})
	}
}

// TestMinterTokens_MintsForTheWorkloadTheTokenNames proves Token derives the
// workload from the current token's kubernetes.io claims and returns what the
// minter mints for it.
func TestMinterTokens_MintsForTheWorkloadTheTokenNames(t *testing.T) {
	g := NewWithT(t)
	w := sessionTestWorkload(testSessionPodUID)
	current := mintedToken(1, w, time.Now().Add(time.Minute))
	minter := &fake.TokenMinter{Result: &workloadidentity.ProjectedToken{Token: "fresh-token"}}

	token, err := MinterTokens(minter).Token(t.Context(), &credentials.EksCredentialsRequest{
		ClusterName: testClusterName, ServiceAccountToken: current,
	})

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(token).To(Equal("fresh-token"))
	g.Expect(minter.Workloads()).To(HaveLen(1))
	g.Expect(*minter.Workloads()[0]).To(Equal(workloadidentity.Workload{
		PodUID: w.PodUID, PodName: w.PodName, Namespace: w.Namespace, ServiceAccount: w.ServiceAccount,
	}))
}

// TestMinterTokens_RefusesATokenWithoutTheClaims proves a token that doesn't
// name a pod, namespace and ServiceAccount is refused as ErrUnattestable, which
// drops the entry, and nothing is minted.
func TestMinterTokens_RefusesATokenWithoutTheClaims(t *testing.T) {
	w := sessionTestWorkload(testSessionPodUID)
	expires := time.Now().Add(time.Hour)
	without := func(change func(*workloadidentity.Workload)) string {
		copied := *w
		change(&copied)
		return mintedToken(1, &copied, expires)
	}
	for name, token := range map[string]string{
		"not a JWT":                      "not-a-jwt",
		"only a pod UID":                 test.CreateToken(t, test.TokenConfig{Expiry: expires, PodUID: w.PodUID}),
		"no pod UID":                     without(func(w *workloadidentity.Workload) { w.PodUID = "" }),
		"no pod name":                    without(func(w *workloadidentity.Workload) { w.PodName = "" }),
		"no namespace":                   without(func(w *workloadidentity.Workload) { w.Namespace = "" }),
		"no ServiceAccount":              without(func(w *workloadidentity.Workload) { w.ServiceAccount = "" }),
		"no kubernetes.io claims at all": test.CreateToken(t, test.TokenConfig{Expiry: expires}),
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			minter := &fake.TokenMinter{Result: &workloadidentity.ProjectedToken{Token: "fresh-token"}}
			tokens := MinterTokens(minter)

			got, err := tokens.Token(t.Context(), &credentials.EksCredentialsRequest{ServiceAccountToken: token})

			g.Expect(got).To(BeEmpty())
			g.Expect(err).To(MatchError(wierrors.ErrUnattestable))
			_, drop := tokens.IsIrrecoverable(err)
			g.Expect(drop).To(BeTrue(), "no retry can renew a token that names no pod")
			g.Expect(minter.Calls()).To(BeZero())
		})
	}
}

// TestMinterTokens_MapsMintFailuresOntoTheTaxonomy proves a mint failure
// reaches the cache as the exchange's would: a taxonomy error unchanged, any
// other error or an empty answer as ErrTokenMintFailed.
func TestMinterTokens_MapsMintFailuresOntoTheTaxonomy(t *testing.T) {
	forbidden := wierrors.ErrTokenMintForbidden.Wrapf(nil, "CSIDriver does not declare the audience")
	cause := errors.New("api server unreachable")
	current := mintedToken(1, sessionTestWorkload(testSessionPodUID), time.Now().Add(time.Minute))
	for name, tc := range map[string]struct {
		minter    *fake.TokenMinter
		wantKind  error
		wantCause error
	}{
		"a taxonomy error": {minter: &fake.TokenMinter{Err: forbidden}, wantKind: wierrors.ErrTokenMintForbidden},
		"any other error":  {minter: &fake.TokenMinter{Err: cause}, wantKind: wierrors.ErrTokenMintFailed, wantCause: cause},
		"no token":         {minter: &fake.TokenMinter{}, wantKind: wierrors.ErrTokenMintFailed},
		"an empty token":   {minter: &fake.TokenMinter{Result: &workloadidentity.ProjectedToken{}}, wantKind: wierrors.ErrTokenMintFailed},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := MinterTokens(tc.minter).Token(t.Context(), &credentials.EksCredentialsRequest{ServiceAccountToken: current})

			g.Expect(got).To(BeEmpty())
			g.Expect(err).To(MatchError(tc.wantKind))
			if tc.wantCause != nil {
				g.Expect(errors.Is(err, tc.wantCause)).To(BeTrue())
			}
		})
	}
}

// TestMinterTokens_IsIrrecoverable proves which token errors drop an entry: a
// non-retryable taxonomy error, and an error EKS Auth classifies as
// irrecoverable, with EKS Auth's code. A retryable one, or one EKS Auth calls
// recoverable, keeps it.
func TestMinterTokens_IsIrrecoverable(t *testing.T) {
	server := eksauthtest.New(t)
	client := eksauth.NewService(context.Background(), server.Config(), false)
	apiErr := func(apiErr *eksauthtest.APIError) error {
		server.SetError(apiErr)
		_, _, err := client.GetIamCredentials(t.Context(), &credentials.EksCredentialsRequest{
			ClusterName: testClusterName, ServiceAccountToken: "token",
		})
		return err
	}
	for name, tc := range map[string]struct {
		err      func() error
		wantCode string
		wantDrop bool
	}{
		"a refused mint": {
			err:      func() error { return wierrors.ErrTokenMintForbidden.Wrapf(nil, "refused") },
			wantCode: "Unknown", wantDrop: true,
		},
		"a failed mint": {
			err:      func() error { return wierrors.ErrTokenMintFailed.Wrapf(nil, "unreachable") },
			wantCode: "Unknown",
		},
		"an error outside the taxonomy": {err: func() error { return errors.New("boom") }, wantCode: "Unknown"},
		"EKS Auth's AccessDenied": {
			err:      func() error { return apiErr(eksauthtest.AccessDenied()) },
			wantCode: "AccessDeniedException", wantDrop: true,
		},
		"EKS Auth's Throttling": {
			err:      func() error { return apiErr(eksauthtest.Throttling()) },
			wantCode: "ThrottlingException",
		},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)

			code, drop := MinterTokens(&fake.TokenMinter{}).IsIrrecoverable(tc.err())

			g.Expect(code).To(Equal(tc.wantCode))
			g.Expect(drop).To(Equal(tc.wantDrop))
		})
	}
}
