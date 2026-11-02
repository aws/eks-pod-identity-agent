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

// TestNewMinter_ChecksDriverAndMints proves the wiring reads the chart-installed
// CSIDriver and returns a minter that produces a token against the same client.
func TestNewMinter_ChecksDriverAndMints(t *testing.T) {
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

// TestNewMinter_MissingDriver_StillStarts proves a cluster whose chart has not
// applied the CSIDriver yet still gets a minter: the check is a pre-flight, and
// the mint itself reports the refusal.
func TestNewMinter_MissingDriver_StillStarts(t *testing.T) {
	g := NewWithT(t)

	client := fake.NewSimpleClientset()
	noWrites(client)
	var sent *authenticationv1.TokenRequest
	tokenReactor(client, &sent, "psat", time.Now().Add(time.Hour))

	m, err := NewMinter(context.Background(), client, CachedMinterOpts{MaxCacheSize: 10, CleanupInterval: -1, PodStore: &podstoretest.Store{}})

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(m).NotTo(BeNil())
}

// TestNewMinter_HardCheckError_Fails proves an unexpected API failure reading the
// CSIDriver stops startup, rather than starting an agent that cannot reach the
// API server it mints against.
func TestNewMinter_HardCheckError_Fails(t *testing.T) {
	g := NewWithT(t)

	client := fake.NewSimpleClientset()
	client.PrependReactor("get", "csidrivers",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewInternalError(errors.New("apiserver unavailable"))
		})

	m, err := NewMinter(context.Background(), client, CachedMinterOpts{MaxCacheSize: 10, CleanupInterval: -1, PodStore: &podstoretest.Store{}})

	g.Expect(err).To(HaveOccurred())
	g.Expect(m).To(BeNil())
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
