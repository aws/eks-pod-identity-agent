package podstore

import (
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

func TestPodDeletionHandlesObjectsAndMissedDeleteTombstones(t *testing.T) {
	p := pod(testPodUID, "web-0", "team-a", "web", testNode)
	for name, obj := range map[string]interface{}{
		"pod": p, "tombstone": cache.DeletedFinalStateUnknown{Obj: p},
	} {
		t.Run(name, func(t *testing.T) {
			var deleted []string
			podDeletedHandler(func(uid string) { deleted = append(deleted, uid) })(obj)
			require.Equal(t, []string{testPodUID}, deleted)
		})
	}
	for name, obj := range map[string]interface{}{
		"nil": nil, "typed nil": (*corev1.Pod)(nil), "wrong object": &corev1.Namespace{},
		"empty UID": &corev1.Pod{}, "invalid tombstone": cache.DeletedFinalStateUnknown{Obj: nil},
	} {
		t.Run(name, func(t *testing.T) {
			podDeletedHandler(func(string) { t.Fatal("unexpected deletion callback") })(obj)
		})
	}
}

func TestPodReplacementReportsTheOldUIDOnlyWhenTheUIDChanges(t *testing.T) {
	old := pod(testPodUID, "web-0", "team-a", "web", testNode)
	replacement := pod("replacement-uid", "web-0", "team-a", "web", testNode)
	var replaced []string
	podReplacedHandler(func(uid string) { replaced = append(replaced, uid) })(old, replacement)
	require.Equal(t, []string{testPodUID}, replaced)

	updated := old.DeepCopy()
	updated.ResourceVersion = "2"
	for name, objs := range map[string][2]interface{}{
		"resync": {old, old}, "same UID": {old, updated}, "wrong objects": {&corev1.Namespace{}, &corev1.Namespace{}},
		"wrong new object": {old, &corev1.Namespace{}}, "nil": {nil, nil}, "typed nil": {(*corev1.Pod)(nil), replacement},
		"empty old UID": {&corev1.Pod{}, replacement},
	} {
		t.Run(name, func(t *testing.T) {
			podReplacedHandler(func(string) { t.Fatal("unexpected deletion callback") })(objs[0], objs[1])
		})
	}
}

// TestPodReplacementSeenOnlyByARelistIsReported deletes web-0 and recreates it
// with a new UID while the watch is down. The relist finds key team-a/web-0 in
// both the cache and the list, so it delivers an update rather than a delete, and
// the old UID must still be reported.
func TestPodReplacementSeenOnlyByARelistIsReported(t *testing.T) {
	client := fake.NewSimpleClientset(pod(testPodUID, "web-0", "team-a", "web", testNode))
	// The first watch misses the replacement; its expiry forces the relist.
	missed := watch.NewFakeWithChanSize(1, false)
	var watches atomic.Int32
	client.PrependWatchReactor("pods", func(k8stesting.Action) (bool, watch.Interface, error) {
		if watches.Add(1) == 1 {
			return true, missed, nil
		}
		return false, nil, nil
	})
	store, err := New(t.Context(), client, testNode)
	require.NoError(t, err)
	replaced := make(chan string, 1)
	require.NoError(t, store.OnPodDeleted(func(uid string) { replaced <- uid }))

	pods := client.CoreV1().Pods("team-a")
	require.NoError(t, pods.Delete(t.Context(), "web-0", metav1.DeleteOptions{}))
	_, err = pods.Create(t.Context(), pod("replacement-uid", "web-0", "team-a", "web", testNode), metav1.CreateOptions{})
	require.NoError(t, err)
	missed.Error(&metav1.Status{Status: metav1.StatusFailure, Code: http.StatusGone, Reason: metav1.StatusReasonExpired})
	select {
	case uid := <-replaced:
		require.Equal(t, testPodUID, uid)
		require.False(t, store.HasPod(testPodUID))
		require.True(t, store.HasPod("replacement-uid"))
	case <-time.After(10 * time.Second):
		t.Fatal("the relist did not report the replaced pod")
	}
}

func TestPodDeletionRegistrationRequiresInformerAndCallback(t *testing.T) {
	var absent *Store
	require.Error(t, absent.OnPodDeleted(func(string) {}))
	require.Error(t, (&Store{}).OnPodDeleted(func(string) {}))
	require.Error(t, (&Store{}).OnPodDeleted(nil))
}

func TestPodDeletionCallbackUsesExistingInformer(t *testing.T) {
	client := fake.NewSimpleClientset(pod(testPodUID, "web-0", "team-a", "web", testNode))
	store, err := New(t.Context(), client, testNode)
	require.NoError(t, err)
	require.True(t, store.HasPod(testPodUID))
	deleted := make(chan string, 1)
	require.NoError(t, store.OnPodDeleted(func(uid string) { deleted <- uid }))
	require.NoError(t, client.CoreV1().Pods("team-a").Delete(t.Context(), "web-0", metav1.DeleteOptions{}))
	select {
	case uid := <-deleted:
		require.Equal(t, testPodUID, uid)
		require.False(t, store.HasPod(testPodUID))
	case <-time.After(5 * time.Second):
		t.Fatal("the node informer did not deliver the deletion")
	}
}

func TestHasPodUsesNodeCacheAndPodUID(t *testing.T) {
	var absent *Store
	require.False(t, absent.HasPod(testPodUID))
	require.False(t, (&Store{}).HasPod(testPodUID))
	p := pod(testPodUID, "web-0", "team-a", "web", testNode)
	indexer := indexerWithPods(t, p)
	store := newStoreFromIndexer(indexer)
	require.True(t, store.HasPod(testPodUID))
	require.False(t, store.HasPod(""))
	require.False(t, store.HasPod("missing"))
	require.NoError(t, indexer.Delete(p))
	require.False(t, store.HasPod(testPodUID))
	require.NoError(t, indexer.Add(pod("replacement-uid", "web-0", "team-a", "web", testNode)))
	require.False(t, store.HasPod(testPodUID), "a replacement with the same name has a different UID")
	require.True(t, store.HasPod("replacement-uid"))
}
