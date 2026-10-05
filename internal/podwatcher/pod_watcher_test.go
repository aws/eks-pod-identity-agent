package podwatcher

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func newPod(name, namespace, uid, nodeName string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			UID:       types.UID(uid),
		},
		Spec: v1.PodSpec{NodeName: nodeName},
	}
}

func TestPodWatcher_New_MissingNodeName(t *testing.T) {
	g := NewWithT(t)
	t.Setenv(nodeNameEnvVar, "")
	_, err := New(context.Background())
	g.Expect(err).To(HaveOccurred())
}

func TestPodWatcher_IsPresent_TracksPods(t *testing.T) {
	g := NewWithT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pod := newPod("p1", "ns", "uid-1", "node-a")
	client := fake.NewSimpleClientset(pod)

	w, err := newWithClient(ctx, client, "node-a")
	g.Expect(err).ToNot(HaveOccurred())

	g.Eventually(w.HasSynced, 2*time.Second, 10*time.Millisecond).Should(BeTrue())

	present, known := w.IsPresent("uid-1")
	g.Expect(known).To(BeTrue())
	g.Expect(present).To(BeTrue())

	present, known = w.IsPresent("uid-unknown")
	g.Expect(known).To(BeTrue())
	g.Expect(present).To(BeFalse())
}

func TestPodWatcher_Delete_EvictsAndNotifies(t *testing.T) {
	g := NewWithT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pod := newPod("p1", "ns", "uid-1", "node-a")
	client := fake.NewSimpleClientset(pod)

	w, err := newWithClient(ctx, client, "node-a")
	g.Expect(err).ToNot(HaveOccurred())
	g.Eventually(w.HasSynced, 2*time.Second, 10*time.Millisecond).Should(BeTrue())

	deleted := make(chan string, 1)
	w.SetOnPodDeleted(func(uid string) { deleted <- uid })

	err = client.CoreV1().Pods("ns").Delete(ctx, "p1", metav1.DeleteOptions{})
	g.Expect(err).ToNot(HaveOccurred())

	// The delete callback fires with the pod UID.
	g.Eventually(deleted, 2*time.Second, 10*time.Millisecond).Should(Receive(Equal("uid-1")))

	// And the pod is no longer reported present.
	g.Eventually(func() bool {
		present, _ := w.IsPresent("uid-1")
		return present
	}, 2*time.Second, 10*time.Millisecond).Should(BeFalse())
}
