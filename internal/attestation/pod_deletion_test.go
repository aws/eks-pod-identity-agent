package attestation

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
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

func TestPodDeletionRegistrationRequiresInformerAndCallback(t *testing.T) {
	var absent *PodStore
	require.Error(t, absent.OnPodDeleted(func(string) {}))
	require.Error(t, (&PodStore{}).OnPodDeleted(func(string) {}))
	require.Error(t, (&PodStore{}).OnPodDeleted(nil))
}

func TestPodDeletionCallbackUsesExistingInformer(t *testing.T) {
	client := fake.NewSimpleClientset(pod(testPodUID, "web-0", "team-a", "web", testNode))
	store, err := NewPodStore(t.Context(), client, testNode)
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
	var absent *PodStore
	require.False(t, absent.HasPod(testPodUID))
	require.False(t, (&PodStore{}).HasPod(testPodUID))
	p := pod(testPodUID, "web-0", "team-a", "web", testNode)
	indexer := indexerWithPods(t, p)
	store := newPodStoreFromIndexer(indexer)
	require.True(t, store.HasPod(testPodUID))
	require.False(t, store.HasPod(""))
	require.False(t, store.HasPod("missing"))
	require.NoError(t, indexer.Delete(p))
	require.False(t, store.HasPod(testPodUID))
	require.NoError(t, indexer.Add(pod("replacement-uid", "web-0", "team-a", "web", testNode)))
	require.False(t, store.HasPod(testPodUID), "a replacement with the same name has a different UID")
	require.True(t, store.HasPod("replacement-uid"))
}
