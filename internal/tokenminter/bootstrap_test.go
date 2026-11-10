package tokenminter

import (
	"context"
	"errors"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/podstore/podstoretest"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// TestNewMinter_Mints proves the wiring returns a minter that produces a token
// against the client it was given.
func TestNewMinter_Mints(t *testing.T) {
	g := NewWithT(t)
	client := fake.NewSimpleClientset(chartCSIDriver())
	noWrites(client)
	var sent *authenticationv1.TokenRequest
	tokenReactor(client, &sent, "psat", time.Now().Add(time.Hour))

	m, err := NewMinter(context.Background(), client, CachedMinterOpts{MaxCacheSize: 10, CleanupInterval: -1, PodStore: &podstoretest.Store{}})
	g.Expect(err).NotTo(HaveOccurred())

	got, err := m.Mint(context.Background(), testWorkload())
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got.Token).To(Equal("psat"))
}

// TestNewMinter_MakesNoAPICall proves the minter can be built while the API
// server is unreachable, which is what lets the agent serve before it answers:
// the CSIDriver pre-flight is the caller's, run once the API server does.
func TestNewMinter_MakesNoAPICall(t *testing.T) {
	g := NewWithT(t)
	client := fake.NewSimpleClientset()
	client.PrependReactor("*", "*",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewInternalError(errors.New("apiserver unavailable"))
		})

	m, err := NewMinter(context.Background(), client, CachedMinterOpts{MaxCacheSize: 10, CleanupInterval: -1, PodStore: &podstoretest.Store{}})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(m).NotTo(BeNil())
	g.Expect(client.Actions()).To(BeEmpty())
}

// TestMint_BeforeThePodStoreSyncs_IsRetryable proves a mint before the node's
// pods are listed fails retryably and asks nothing of the API server. The
// presence check would otherwise refuse every pod as deleted, which the
// credential cache reads as irrecoverable and drops the pod's credentials for.
func TestMint_BeforeThePodStoreSyncs_IsRetryable(t *testing.T) {
	g := NewWithT(t)
	client := fake.NewSimpleClientset(chartCSIDriver())
	var sent *authenticationv1.TokenRequest
	tokenReactor(client, &sent, "psat", time.Now().Add(time.Hour))
	pods := &podstoretest.Store{NotSynced: true}
	m, err := NewMinter(context.Background(), client, CachedMinterOpts{MaxCacheSize: 10, CleanupInterval: -1, PodStore: pods})
	g.Expect(err).NotTo(HaveOccurred())

	_, err = m.Mint(context.Background(), testWorkload())
	g.Expect(err).To(MatchError(wierrors.ErrTokenMintFailed))
	g.Expect(wierrors.IsRetryable(err)).To(BeTrue())
	g.Expect(sent).To(BeNil(), "no TokenRequest before the sync")

	pods.NotSynced = false
	got, err := m.Mint(context.Background(), testWorkload())
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got.Token).To(Equal("psat"))
}

// TestNewMinter_NilPodStore_Fails proves startup refuses a minter with no pod
// store, which could never drop a deleted pod's token, before reaching the API.
func TestNewMinter_NilPodStore_Fails(t *testing.T) {
	g := NewWithT(t)

	client := fake.NewSimpleClientset(chartCSIDriver())

	m, err := NewMinter(context.Background(), client, CachedMinterOpts{MaxCacheSize: 10, CleanupInterval: -1})

	g.Expect(err).To(MatchError(ContainSubstring("pod store")))
	g.Expect(m).To(BeNil())
	g.Expect(client.Actions()).To(BeEmpty())
}

// TestNewMinter_RegistrationError_Fails proves a pod store that cannot report
// deletions stops startup.
func TestNewMinter_RegistrationError_Fails(t *testing.T) {
	g := NewWithT(t)

	client := fake.NewSimpleClientset(chartCSIDriver())
	pods := &podstoretest.Store{RegisterErr: errors.New("no informer")}

	m, err := NewMinter(context.Background(), client, CachedMinterOpts{MaxCacheSize: 10, CleanupInterval: -1, PodStore: pods})

	g.Expect(err).To(MatchError(ContainSubstring("no informer")))
	g.Expect(m).To(BeNil())
}

// TestNewMinter_PodDeleted_DropsToken proves NewMinter registers for the pod
// store's deletions, so a deleted pod's cached token is dropped and the pod is
// refused afterwards.
func TestNewMinter_PodDeleted_DropsToken(t *testing.T) {
	g := NewWithT(t)

	client := fake.NewSimpleClientset(chartCSIDriver())
	noWrites(client)
	var sent *authenticationv1.TokenRequest
	tokenReactor(client, &sent, "psat", time.Now().Add(time.Hour))
	pods := &podstoretest.Store{}

	m, err := NewMinter(context.Background(), client, CachedMinterOpts{MaxCacheSize: 10, CleanupInterval: -1, PodStore: pods})
	g.Expect(err).NotTo(HaveOccurred())
	w := testWorkload()
	_, err = m.Mint(context.Background(), w)
	g.Expect(err).NotTo(HaveOccurred())

	pods.Delete(w.PodUID)

	_, ok := m.(*CachedMinter).cache.Get(w.PodUID)
	g.Expect(ok).To(BeFalse(), "the deletion callback must drop the pod's token")
	_, err = m.Mint(context.Background(), w)
	g.Expect(err).To(MatchError(wierrors.ErrUnattestable))
}
