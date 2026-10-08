package attestation

import (
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// indexerWithPods builds a real UID-indexed cache holding pods, so the store's
// lookup and projection are exercised without an informer or a cluster.
func indexerWithPods(t *testing.T, pods ...*corev1.Pod) cache.Indexer {
	t.Helper()
	g := NewWithT(t)

	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{podByUIDIndex: podUIDIndexFunc})
	for _, p := range pods {
		g.Expect(indexer.Add(p)).To(Succeed())
	}
	return indexer
}

func pod(uid, name, ns, sa, node string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			UID:       types.UID(uid),
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: sa,
			NodeName:           node,
		},
	}
}

// TestPodByUID_FoundAndProjected proves a present pod comes back projected onto
// PodInfo with every field mapped.
func TestPodByUID_FoundAndProjected(t *testing.T) {
	g := NewWithT(t)

	store := newPodStoreFromIndexer(indexerWithPods(t,
		pod(testPodUID, "web-0", "team-a", "web", testNode)))

	got, ok := store.PodByUID(testPodUID)

	g.Expect(ok).To(BeTrue())
	g.Expect(got).To(Equal(&PodInfo{
		UID:            testPodUID,
		Name:           "web-0",
		Namespace:      "team-a",
		ServiceAccount: "web",
		NodeName:       testNode,
	}))
}

// TestPodByUID_Missing proves an absent UID is a clean miss, not an error, so
// the attestor treats it as an unresolvable caller.
func TestPodByUID_Missing(t *testing.T) {
	g := NewWithT(t)

	store := newPodStoreFromIndexer(indexerWithPods(t))

	got, ok := store.PodByUID(testPodUID)

	g.Expect(ok).To(BeFalse())
	g.Expect(got).To(BeNil())
}

// TestNewPodStore_RequiresNodeName proves the store refuses to build without a
// node name, since an empty selector would scope the watch to the whole cluster.
func TestNewPodStore_RequiresNodeName(t *testing.T) {
	g := NewWithT(t)

	_, err := NewPodStore(t.Context(), nil, "")

	g.Expect(err).To(HaveOccurred())
}

// TestStripDownPod_KeepsNeededFieldsDropsRest proves the informer transform
// retains exactly the fields attestation reads and zeroes the memory-heavy
// fields (containers, volumes, status, managedFields, labels, annotations) that
// the cache would otherwise hold for every pod on the node.
func TestStripDownPod_KeepsNeededFieldsDropsRest(t *testing.T) {
	g := NewWithT(t)

	full := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			UID:             types.UID(testPodUID),
			Name:            "web-0",
			Namespace:       "team-a",
			ResourceVersion: "12345",
			Labels:          map[string]string{"app": "web"},
			Annotations:     map[string]string{"k": "v"},
			ManagedFields:   []metav1.ManagedFieldsEntry{{Manager: "kubelet"}},
		},
		Spec: corev1.PodSpec{
			NodeName:           testNode,
			ServiceAccountName: "web",
			Containers:         []corev1.Container{{Name: "app", Image: "nginx"}},
			Volumes:            []corev1.Volume{{Name: "data"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.5"},
	}

	out, err := stripDownPod(full)
	g.Expect(err).NotTo(HaveOccurred())

	trimmed, ok := out.(*corev1.Pod)
	g.Expect(ok).To(BeTrue(), "the transform must return a *corev1.Pod so the indexer keeps its type assertion")

	// Fields attestation reads are preserved.
	g.Expect(string(trimmed.UID)).To(Equal(testPodUID))
	g.Expect(trimmed.Name).To(Equal("web-0"))
	g.Expect(trimmed.Namespace).To(Equal("team-a"))
	g.Expect(trimmed.ResourceVersion).To(Equal("12345"))
	g.Expect(trimmed.Spec.NodeName).To(Equal(testNode))
	g.Expect(trimmed.Spec.ServiceAccountName).To(Equal("web"))

	// Memory-heavy fields are dropped.
	g.Expect(trimmed.Labels).To(BeNil())
	g.Expect(trimmed.Annotations).To(BeNil())
	g.Expect(trimmed.ManagedFields).To(BeNil())
	g.Expect(trimmed.Spec.Containers).To(BeNil())
	g.Expect(trimmed.Spec.Volumes).To(BeNil())
	g.Expect(trimmed.Status).To(Equal(corev1.PodStatus{}))

	// A trimmed pod still indexes by UID and projects to the same PodInfo, so
	// the rest of the store is unaffected by the transform.
	store := newPodStoreFromIndexer(indexerWithPods(t, trimmed))
	got, found := store.PodByUID(testPodUID)
	g.Expect(found).To(BeTrue())
	g.Expect(got).To(Equal(&PodInfo{
		UID: testPodUID, Name: "web-0", Namespace: "team-a", ServiceAccount: "web", NodeName: testNode,
	}))
}

// TestStripDownPod_Tombstone proves a missed-delete tombstone is unwrapped and
// its inner pod trimmed, so the store never retains a full pod even on a delete
// that arrives after a watch relist.
func TestStripDownPod_Tombstone(t *testing.T) {
	g := NewWithT(t)

	full := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: types.UID(testPodUID), Name: "web-0", Namespace: "team-a"},
		Spec:       corev1.PodSpec{NodeName: testNode, Containers: []corev1.Container{{Name: "app"}}},
	}
	tombstone := cache.DeletedFinalStateUnknown{Key: "team-a/web-0", Obj: full}

	out, err := stripDownPod(tombstone)
	g.Expect(err).NotTo(HaveOccurred())

	gotTombstone, ok := out.(cache.DeletedFinalStateUnknown)
	g.Expect(ok).To(BeTrue(), "a tombstone must stay a tombstone so delete handling still works")
	inner, ok := gotTombstone.Obj.(*corev1.Pod)
	g.Expect(ok).To(BeTrue())
	g.Expect(inner.Spec.Containers).To(BeNil(), "the wrapped pod must be trimmed too")
	g.Expect(string(inner.UID)).To(Equal(testPodUID))
}

// TestStripDownPod_PassesThroughUnknownType proves the transform leaves an
// unexpected object untouched rather than erroring, matching the reference
// pattern's robustness.
func TestStripDownPod_PassesThroughUnknownType(t *testing.T) {
	g := NewWithT(t)

	in := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}}
	out, err := stripDownPod(in)

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(out).To(BeIdenticalTo(in))
}

// watchPodsWithSignal makes the fake clientset close the returned channel once
// the informer's pod watch is registered with the tracker. The fake doesn't
// replay events to a watch that starts late, and the informer reports synced
// after its list, before its watch necessarily exists, so a test that deletes a
// pod straight after NewPodStore could otherwise lose the event.
func watchPodsWithSignal(clientset *fake.Clientset) <-chan struct{} {
	started := make(chan struct{})
	var once sync.Once
	clientset.PrependWatchReactor("pods", func(action k8stesting.Action) (bool, watch.Interface, error) {
		var opts metav1.ListOptions
		if watchAction, ok := action.(k8stesting.WatchActionImpl); ok {
			opts = watchAction.ListOptions
		}
		w, err := clientset.Tracker().Watch(action.GetResource(), action.GetNamespace(), opts)
		if err != nil {
			return false, nil, err
		}
		once.Do(func() { close(started) })
		return true, w, nil
	})
	return started
}

// podWatchCount reports how many pod watches the fake clientset has served.
func podWatchCount(clientset *fake.Clientset) int {
	count := 0
	for _, action := range clientset.Actions() {
		if action.GetVerb() == "watch" && action.GetResource().Resource == "pods" {
			count++
		}
	}
	return count
}

// TestOnPodDeleted_DeliversDeletedPodUID proves a pod deleted from the API
// server reaches a registered callback with its UID, through the store's own
// informer: the store still holds exactly one pod watch afterwards, so
// registering didn't open a second one.
func TestOnPodDeleted_DeliversDeletedPodUID(t *testing.T) {
	g := NewWithT(t)
	ctx := t.Context()

	clientset := fake.NewSimpleClientset()
	watching := watchPodsWithSignal(clientset)
	store, err := NewPodStore(ctx, clientset, testNode)
	g.Expect(err).NotTo(HaveOccurred())
	g.Eventually(watching).WithTimeout(5 * time.Second).Should(BeClosed())

	_, err = clientset.CoreV1().Pods("team-a").Create(ctx,
		pod(testPodUID, "web-0", "team-a", "web", testNode), metav1.CreateOptions{})
	g.Expect(err).NotTo(HaveOccurred())
	g.Eventually(func() bool {
		_, ok := store.PodByUID(testPodUID)
		return ok
	}).WithTimeout(5 * time.Second).WithPolling(5 * time.Millisecond).Should(BeTrue())

	deleted := make(chan string, 4)
	g.Expect(store.OnPodDeleted(func(uid string) { deleted <- uid })).To(Succeed())

	g.Expect(clientset.CoreV1().Pods("team-a").Delete(ctx, "web-0", metav1.DeleteOptions{})).To(Succeed())

	g.Eventually(deleted).WithTimeout(5 * time.Second).Should(Receive(Equal(testPodUID)))
	g.Consistently(deleted).WithTimeout(50*time.Millisecond).ShouldNot(Receive(),
		"one delete must be reported once, and the replayed add for the cached pod not at all")
	g.Expect(podWatchCount(clientset)).To(Equal(1), "OnPodDeleted must reuse the store's watch, not open another")
}

// TestOnPodDeleted_TombstoneDeliversUID proves a missed delete, which arrives as
// a DeletedFinalStateUnknown tombstone around the stripped-down pod, still
// reports the pod's UID, and that an event naming no pod is dropped.
func TestOnPodDeleted_TombstoneDeliversUID(t *testing.T) {
	g := NewWithT(t)

	var got []string
	handler := podDeletedHandler(func(uid string) { got = append(got, uid) })

	stripped, err := stripDownPod(cache.DeletedFinalStateUnknown{
		Key: "team-a/web-0",
		Obj: &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{UID: types.UID(testPodUID), Name: "web-0", Namespace: "team-a"},
			Spec:       corev1.PodSpec{NodeName: testNode, Containers: []corev1.Container{{Name: "app"}}},
		},
	})
	g.Expect(err).NotTo(HaveOccurred())

	handler(stripped)
	handler(pod(testPodUID, "web-0", "team-a", "web", testNode))
	handler(cache.DeletedFinalStateUnknown{Key: "team-a", Obj: &corev1.Namespace{}})
	handler(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}})
	handler(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "no-uid", Namespace: "team-a"}})
	handler((*corev1.Pod)(nil))

	g.Expect(got).To(Equal([]string{testPodUID, testPodUID}))
}

// TestOnPodDeleted_NoInformerErrors proves a store with no informer behind it
// refuses a registration it could never honour, rather than accepting a
// callback that would silently never fire.
func TestOnPodDeleted_NoInformerErrors(t *testing.T) {
	g := NewWithT(t)

	store := newPodStoreFromIndexer(indexerWithPods(t))

	g.Expect(store.OnPodDeleted(func(string) {})).To(MatchError(ContainSubstring("no informer")))
}

// TestOnPodDeleted_RefusesANilCallback proves a store that could register a
// callback refuses a nil one. Registered, it would be called on the informer's
// delivery goroutine at the first pod deletion, and the panic from calling it
// would take the agent down.
func TestOnPodDeleted_RefusesANilCallback(t *testing.T) {
	g := NewWithT(t)

	store, err := NewPodStore(t.Context(), fake.NewSimpleClientset(), testNode)
	g.Expect(err).NotTo(HaveOccurred())

	g.Expect(store.OnPodDeleted(nil)).To(MatchError(ContainSubstring("callback is required")))
}
