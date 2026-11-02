package tokenminter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

func testWorkload() *workloadidentity.Workload {
	return &workloadidentity.Workload{
		PodUID:         "pod-uid-1",
		PodName:        "web-0",
		Namespace:      "team-a",
		ServiceAccount: "web",
		NodeName:       "ip-10-0-1-23",
	}
}

// tokenReactor installs a create reactor on serviceaccounts that captures the
// TokenRequest the minter sent and returns a canned status. The fake clientset's
// default reactor echoes the object back with an empty status, so a real token
// only appears when a reactor supplies one.
func tokenReactor(client *fake.Clientset, captured **authenticationv1.TokenRequest, token string, expiry time.Time) {
	client.PrependReactor("create", "serviceaccounts",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			create := action.(k8stesting.CreateAction)
			*captured = create.GetObject().(*authenticationv1.TokenRequest)
			return true, &authenticationv1.TokenRequest{
				Status: authenticationv1.TokenRequestStatus{
					Token:               token,
					ExpirationTimestamp: metav1.NewTime(expiry),
				},
			}, nil
		})
}

// TestMint_Success_ReturnsTokenBoundToPod proves a mint returns the API server's
// token and expiry, and that the TokenRequest carries the single EKS Auth
// audience and a pod-bound object reference to the attested pod.
func TestMint_Success_ReturnsTokenBoundToPod(t *testing.T) {
	g := NewWithT(t)

	client := fake.NewSimpleClientset()
	var sent *authenticationv1.TokenRequest
	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	tokenReactor(client, &sent, "signed-psat", expiry)

	m := newAPIMinter(client)
	w := testWorkload()

	got, err := m.Mint(context.Background(), w)

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got.Token).To(Equal("signed-psat"))
	g.Expect(got.ExpiresAt).To(Equal(expiry))

	g.Expect(sent.Spec.Audiences).To(Equal([]string{configuration.EksAuthAudience}))
	g.Expect(sent.Spec.ExpirationSeconds).NotTo(BeNil(),
		"the lifetime is requested rather than left to the API server's own default")
	g.Expect(*sent.Spec.ExpirationSeconds).To(Equal(tokenLifetimeSeconds))
	g.Expect(sent.Spec.BoundObjectRef).NotTo(BeNil())
	g.Expect(sent.Spec.BoundObjectRef.Kind).To(Equal("Pod"))
	g.Expect(sent.Spec.BoundObjectRef.Name).To(Equal(w.PodName))
	g.Expect(string(sent.Spec.BoundObjectRef.UID)).To(Equal(w.PodUID))
}

// TestMint_Forbidden_MapsToForbidden proves an API-server refusal for the EKS
// Auth audience is the not-retryable ErrTokenMintForbidden, which is the signal
// the CSIDriver tokenRequests declaration is missing.
func TestMint_Forbidden_MapsToForbidden(t *testing.T) {
	g := NewWithT(t)

	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "serviceaccounts",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(
				schema.GroupResource{Resource: "serviceaccounts"}, "web",
				errors.New("audience not declared"))
		})

	_, err := newAPIMinter(client).Mint(context.Background(), testWorkload())

	g.Expect(err).To(MatchError(wierrors.ErrTokenMintForbidden))
	g.Expect(wierrors.IsRetryable(err)).To(BeFalse())
}

// TestMint_ServerError_MapsToFailed proves any non-forbidden API failure is the
// retryable ErrTokenMintFailed.
func TestMint_ServerError_MapsToFailed(t *testing.T) {
	g := NewWithT(t)

	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "serviceaccounts",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewInternalError(errors.New("etcd down"))
		})

	_, err := newAPIMinter(client).Mint(context.Background(), testWorkload())

	g.Expect(err).To(MatchError(wierrors.ErrTokenMintFailed))
	g.Expect(wierrors.IsRetryable(err)).To(BeTrue())
}

// TestMint_EmptyToken_MapsToFailed proves a success response carrying no token
// is treated as a failed mint rather than handing back an empty credential.
func TestMint_EmptyToken_MapsToFailed(t *testing.T) {
	g := NewWithT(t)

	client := fake.NewSimpleClientset()
	var sent *authenticationv1.TokenRequest
	tokenReactor(client, &sent, "", time.Now().Add(time.Hour))

	_, err := newAPIMinter(client).Mint(context.Background(), testWorkload())

	g.Expect(err).To(MatchError(wierrors.ErrTokenMintFailed))
}

// throttlingTokenServer stands in for the API server over real HTTP, answering
// 429 for the first throttled attempts and then issuing token. It counts the
// attempts it saw.
//
// A real server is required rather than the fake clientset: the fake answers
// from its reactor chain and never builds a rest.Request, so client-go's retry
// path does not exist for it.
func throttlingTokenServer(t *testing.T, throttled int32, token string, expiry time.Time) (kubernetes.Interface, *int32) {
	t.Helper()

	attempts := new(int32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if atomic.AddInt32(attempts, 1) <= throttled {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(&metav1.Status{
				TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
				Status:   metav1.StatusFailure,
				Code:     http.StatusTooManyRequests,
				Reason:   metav1.StatusReasonTooManyRequests,
				Message:  "throttled by priority and fairness",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(&authenticationv1.TokenRequest{
			TypeMeta: metav1.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "TokenRequest"},
			Status: authenticationv1.TokenRequestStatus{
				Token:               token,
				ExpirationTimestamp: metav1.NewTime(expiry),
			},
		})
	}))
	t.Cleanup(srv.Close)

	client, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatalf("building a client against the test server: %v", err)
	}
	return client, attempts
}

// TestMint_Throttled_RetriedByClientGo pins the assumption the 429 handling
// rests on: the agent does not retry a throttled mint itself because client-go
// already does, honouring the Retry-After that API Priority and Fairness sets.
// Two 429s are absorbed and the mint succeeds on the third attempt.
func TestMint_Throttled_RetriedByClientGo(t *testing.T) {
	g := NewWithT(t)

	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	client, attempts := throttlingTokenServer(t, 2, "signed-psat", expiry)

	got, err := newAPIMinter(client).Mint(context.Background(), testWorkload())

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got.Token).To(Equal("signed-psat"))
	g.Expect(atomic.LoadInt32(attempts)).To(Equal(int32(3)),
		"client-go has to replay the TokenRequest, not surface the first 429")
}

// TestMint_ThrottledBeyondRetries_MapsToFailed proves a throttle that outlasts
// client-go's retries is the retryable ErrTokenMintFailed and not the terminal
// ErrTokenMintForbidden, so the cache keeps the pod's existing token and
// re-mints on a later sweep rather than dropping the entry.
func TestMint_ThrottledBeyondRetries_MapsToFailed(t *testing.T) {
	g := NewWithT(t)

	// More than the maxRetries client-go sets on every request, so every attempt
	// is refused and the error reaches the minter.
	client, attempts := throttlingTokenServer(t, 100, "unreachable", time.Now().Add(time.Hour))

	_, err := newAPIMinter(client).Mint(context.Background(), testWorkload())

	g.Expect(err).To(MatchError(wierrors.ErrTokenMintFailed))
	g.Expect(wierrors.IsRetryable(err)).To(BeTrue())
	g.Expect(err.Error()).To(ContainSubstring("throttled"))
	g.Expect(atomic.LoadInt32(attempts)).To(Equal(int32(11)),
		"one attempt plus the maxRetries client-go sets on every request")
}
