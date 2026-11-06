package podliveness

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	toolscache "k8s.io/client-go/tools/cache"

	// Initializes the package logger for tests (logger.FromContext falls back to
	// the package logger, which is nil until Initialize runs).
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

func pod(namespace, name, uid, nodeName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID(uid)},
		Spec:       corev1.PodSpec{NodeName: nodeName},
	}
}

// startSyncedChecker builds a podChecker over a fake clientset seeded with pods
// and waits for its cache to sync, so IsAlive answers from a populated store.
func startSyncedChecker(t *testing.T, nodeName string, pods ...*corev1.Pod) *podChecker {
	t.Helper()
	g := NewWithT(t)
	objs := make([]runtime.Object, 0, len(pods))
	for _, p := range pods {
		objs = append(objs, p)
	}
	clientset := fake.NewSimpleClientset(objs...)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pc := newCheckerForClient(ctx, clientset, nodeName)
	g.Eventually(pc.HasSynced, 5*time.Second, 10*time.Millisecond).Should(BeTrue())
	return pc
}

// TestChecker_RequestsOnlyThisNodesPods proves the informer scopes its list/watch
// to this node, so the agent never watches the whole cluster's pods.
func TestChecker_RequestsOnlyThisNodesPods(t *testing.T) {
	g := NewWithT(t)
	clientset := fake.NewSimpleClientset()
	var listedSelector string
	clientset.PrependReactor("list", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
		listedSelector = action.(clienttesting.ListAction).GetListRestrictions().Fields.String()
		return false, nil, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pc := newCheckerForClient(ctx, clientset, "node-a")
	g.Eventually(pc.HasSynced, 5*time.Second, 10*time.Millisecond).Should(BeTrue())

	g.Expect(listedSelector).To(Equal("spec.nodeName=node-a"))
}

// TestChecker_IsAlive covers the liveness answers once the cache has synced: a
// present pod is alive, an absent one is not, a name reused by a pod with a
// different UID counts the original as gone, and an empty UID on either side is
// not treated as a mismatch.
func TestChecker_IsAlive(t *testing.T) {
	pc := startSyncedChecker(t, "node-a",
		pod("team-a", "worker-7", "uid-123", "node-a"),
		pod("team-b", "no-uid", "", "node-a"),
	)
	g := NewWithT(t)

	g.Expect(pc.IsAlive("team-a", "worker-7", "uid-123")).To(BeTrue(), "a present pod is alive")
	g.Expect(pc.IsAlive("team-a", "missing", "uid-x")).To(BeFalse(), "an absent pod is not alive")
	g.Expect(pc.IsAlive("team-a", "worker-7", "uid-999")).To(BeFalse(), "a reused name with a different UID is a new pod, the original is gone")
	g.Expect(pc.IsAlive("team-a", "worker-7", "")).To(BeTrue(), "an empty requested UID is not a mismatch")
	g.Expect(pc.IsAlive("team-b", "no-uid", "uid-y")).To(BeTrue(), "an empty stored UID is not a mismatch")
}

// TestChecker_FailsOpenBeforeSync proves IsAlive reports alive until the cache
// has synced, so a renewal is never skipped on an unpopulated cache.
func TestChecker_FailsOpenBeforeSync(t *testing.T) {
	g := NewWithT(t)
	pc := &podChecker{informer: notSyncedInformer{}}
	g.Expect(pc.HasSynced()).To(BeFalse())
	g.Expect(pc.IsAlive("team-a", "worker-7", "uid-123")).To(BeTrue())
}

// TestNoopChecker_AlwaysAlive proves the fallback checker reports every pod alive
// and always synced, preserving pre-feature behavior.
func TestNoopChecker_AlwaysAlive(t *testing.T) {
	g := NewWithT(t)
	c := NewNoopChecker()
	g.Expect(c.HasSynced()).To(BeTrue())
	g.Expect(c.IsAlive("ns", "name", "uid")).To(BeTrue())
	g.Expect(c.IsAlive("", "", "")).To(BeTrue())
}

// notSyncedInformer is a SharedIndexInformer whose HasSynced is always false, for
// exercising the fail-open-before-sync path without starting a real informer.
type notSyncedInformer struct {
	toolscache.SharedIndexInformer
}

func (notSyncedInformer) HasSynced() bool { return false }
