package tokenminter

import (
	"context"
	"errors"
	"testing"

	. "github.com/onsi/gomega"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// chartCSIDriver is the object the agent's Helm chart installs, as a test
// fixture. The agent never builds this — it only reads it — so the shape lives
// here rather than in the package.
func chartCSIDriver() *storagev1.CSIDriver {
	attachNotRequired := false
	podInfo := true
	return &storagev1.CSIDriver{
		ObjectMeta: metav1.ObjectMeta{
			Name: configuration.WorkloadIdentityCSIDriver,
		},
		Spec: storagev1.CSIDriverSpec{
			AttachRequired:       &attachNotRequired,
			PodInfoOnMount:       &podInfo,
			VolumeLifecycleModes: []storagev1.VolumeLifecycleMode{storagev1.VolumeLifecycleEphemeral},
			TokenRequests: []storagev1.TokenRequest{
				{Audience: configuration.EksAuthAudience},
			},
		},
	}
}

// noWrites fails the test if the agent issues any write against csidrivers. The
// object is the chart's, and a node-local agent must never touch it.
func noWrites(client *fake.Clientset) {
	for _, verb := range []string{"create", "update", "patch", "delete"} {
		client.PrependReactor(verb, "csidrivers",
			func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New(action.GetVerb() + " must not be called: the CSIDriver belongs to the Helm chart")
			})
	}
}

// TestVerifyCSIDriverExists_PresentWithAudience_Passes proves the happy path: the
// chart-installed object declaring the audience is accepted, read-only.
func TestVerifyCSIDriverExists_PresentWithAudience_Passes(t *testing.T) {
	g := NewWithT(t)

	client := fake.NewSimpleClientset(chartCSIDriver())
	noWrites(client)

	err := VerifyCSIDriverExists(context.Background(), client)

	g.Expect(err).NotTo(HaveOccurred())
}

// TestVerifyCSIDriverExists_Absent_NonFatalAndNoCreate proves an absent CSIDriver does
// not fail startup and, above all, is not created by the agent: the chart owns
// the object. The condition surfaces per mint as ErrTokenMintForbidden.
func TestVerifyCSIDriverExists_Absent_NonFatalAndNoCreate(t *testing.T) {
	g := NewWithT(t)

	client := fake.NewSimpleClientset()
	noWrites(client)

	err := VerifyCSIDriverExists(context.Background(), client)

	g.Expect(err).NotTo(HaveOccurred())
	_, getErr := client.StorageV1().CSIDrivers().Get(context.Background(), configuration.WorkloadIdentityCSIDriver, metav1.GetOptions{})
	g.Expect(apierrors.IsNotFound(getErr)).To(BeTrue(), "the agent must not create the CSIDriver")
}

// TestVerifyCSIDriverExists_PresentWithoutAudience_NonFatalAndNoWrite proves an object
// missing the audience is warned about, never patched into shape.
func TestVerifyCSIDriverExists_PresentWithoutAudience_NonFatalAndNoWrite(t *testing.T) {
	g := NewWithT(t)

	stale := chartCSIDriver()
	stale.Spec.TokenRequests = nil
	client := fake.NewSimpleClientset(stale)
	noWrites(client)

	err := VerifyCSIDriverExists(context.Background(), client)

	g.Expect(err).NotTo(HaveOccurred())
	after, getErr := client.StorageV1().CSIDrivers().Get(context.Background(), configuration.WorkloadIdentityCSIDriver, metav1.GetOptions{})
	g.Expect(getErr).NotTo(HaveOccurred())
	g.Expect(after.Spec.TokenRequests).To(BeEmpty(), "the agent must not repair a chart-managed object")
}

// TestVerifyCSIDriverExists_ForbiddenGet_NonFatal proves the agent starts even where it
// has no read on storage.k8s.io: the pre-flight is skipped, not fatal.
func TestVerifyCSIDriverExists_ForbiddenGet_NonFatal(t *testing.T) {
	g := NewWithT(t)

	client := fake.NewSimpleClientset()
	client.PrependReactor("get", "csidrivers",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(
				schema.GroupResource{Group: "storage.k8s.io", Resource: "csidrivers"},
				configuration.WorkloadIdentityCSIDriver, errors.New("node identity may not read csidrivers"))
		})

	err := VerifyCSIDriverExists(context.Background(), client)

	g.Expect(err).NotTo(HaveOccurred())
}

// TestVerifyCSIDriverExists_Throttled_NonFatal proves a throttled read does not
// fail startup. client-go has already spent its Retry-After retries by the time
// the error arrives, and throttling peaks exactly when a DaemonSet rolls and
// every node runs this check at once — so failing here would crash-loop every
// agent into the throttle that rejected it.
func TestVerifyCSIDriverExists_Throttled_NonFatal(t *testing.T) {
	g := NewWithT(t)

	client := fake.NewSimpleClientset()
	noWrites(client)
	client.PrependReactor("get", "csidrivers",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewTooManyRequests("throttled by priority and fairness", 1)
		})

	err := VerifyCSIDriverExists(context.Background(), client)

	g.Expect(err).NotTo(HaveOccurred())
}

// TestVerifyCSIDriverExists_GetError_Returned proves an unexpected get failure (not a
// NotFound or Forbidden) is surfaced, so a broken API server is distinguishable
// from a cluster that is merely not set up yet.
func TestVerifyCSIDriverExists_GetError_Returned(t *testing.T) {
	g := NewWithT(t)

	client := fake.NewSimpleClientset()
	client.PrependReactor("get", "csidrivers",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewInternalError(errors.New("apiserver unavailable"))
		})

	err := VerifyCSIDriverExists(context.Background(), client)

	g.Expect(err).To(HaveOccurred())
}
