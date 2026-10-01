// Package podwatcher maintains the set of pods currently present on the local
// node using a node-scoped Kubernetes informer. The credential retriever uses
// it to avoid renewing (and to promptly evict) credentials for pods that no
// longer exist on the node.
package podwatcher

import (
	"context"
	"fmt"
	"os"
	"sync"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// nodeNameEnvVar is the environment variable, injected via the downward API,
// that holds the name of the node the agent runs on.
const nodeNameEnvVar = "NODE_NAME"

// apiserverQPS bounds the client's request rate to the API server.
const apiserverQPS = 5

// PodWatcher tracks the pod UIDs present on the local node via a node-scoped pod
// informer. It implements the pod-presence check used by the credential
// retriever and can notify a listener when a pod is deleted.
type PodWatcher struct {
	informer cache.SharedIndexInformer

	mu   sync.RWMutex
	uids map[types.UID]struct{}

	onDeleteMu   sync.RWMutex
	onPodDeleted func(podUID string)
}

// New builds and starts a node-scoped pod watcher. The node name is read from
// the NODE_NAME environment variable (injected via the downward API) and the
// in-cluster config is used to reach the API server. It returns an error when
// the node name is missing or a client cannot be built; callers should treat
// that as "pod liveness checking unavailable" and proceed without it (fail
// open), so credential renewal keeps working exactly as before.
func New(ctx context.Context) (*PodWatcher, error) {
	nodeName := os.Getenv(nodeNameEnvVar)
	if nodeName == "" {
		return nil, fmt.Errorf("%s environment variable is not set", nodeNameEnvVar)
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to build in-cluster config: %w", err)
	}
	config.QPS = apiserverQPS
	config.Burst = apiserverQPS

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return newWithClient(ctx, clientset, nodeName)
}

// newWithClient builds and starts a watcher against the given client. It is used
// by New and by tests with a fake client.
func newWithClient(ctx context.Context, clientset kubernetes.Interface, nodeName string) (*PodWatcher, error) {
	// Scope the informer to pods on this node across all namespaces. The field
	// selector is applied server-side, so the agent only lists and watches its
	// own node's pods.
	factory := informers.NewSharedInformerFactoryWithOptions(
		clientset,
		0, // no periodic resync; the watcher is event-driven
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", nodeName).String()
		}),
	)
	informer := factory.Core().V1().Pods().Informer()

	// Keep only the metadata the watcher needs, to bound per-node memory: the
	// informer store would otherwise hold full pod specs and statuses.
	if err := informer.SetTransform(trimPod); err != nil {
		return nil, fmt.Errorf("failed to set informer transform: %w", err)
	}

	w := &PodWatcher{
		informer: informer,
		uids:     make(map[types.UID]struct{}),
	}

	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    w.handleAdd,
		UpdateFunc: w.handleUpdate,
		DeleteFunc: w.handleDelete,
	}); err != nil {
		return nil, fmt.Errorf("failed to register informer event handler: %w", err)
	}

	factory.Start(ctx.Done())
	return w, nil
}

// IsPresent reports whether a pod with the given UID is present on this node.
// The second return value, known, is false until the informer has synced; while
// it is false callers MUST assume the pod is present (fail open), so credentials
// for live pods are never evicted because the local view is incomplete.
func (w *PodWatcher) IsPresent(podUID string) (present bool, known bool) {
	if !w.informer.HasSynced() {
		return false, false
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	_, ok := w.uids[types.UID(podUID)]
	return ok, true
}

// SetOnPodDeleted registers a callback invoked with the pod UID whenever a pod
// on this node is deleted. It is used to evict cached credentials immediately
// instead of waiting for the next scheduled renewal.
func (w *PodWatcher) SetOnPodDeleted(fn func(podUID string)) {
	w.onDeleteMu.Lock()
	w.onPodDeleted = fn
	w.onDeleteMu.Unlock()
}

// HasSynced reports whether the underlying informer has completed its initial
// list. Exposed for callers that want to wait for readiness.
func (w *PodWatcher) HasSynced() bool {
	return w.informer.HasSynced()
}

func (w *PodWatcher) handleAdd(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		return
	}
	w.mu.Lock()
	w.uids[pod.UID] = struct{}{}
	w.mu.Unlock()
}

func (w *PodWatcher) handleUpdate(_, newObj interface{}) {
	pod, ok := newObj.(*v1.Pod)
	if !ok {
		return
	}
	// A pod's UID never changes, so this simply keeps the entry present.
	w.mu.Lock()
	w.uids[pod.UID] = struct{}{}
	w.mu.Unlock()
}

func (w *PodWatcher) handleDelete(obj interface{}) {
	pod := podFromDeleteObj(obj)
	if pod == nil {
		return
	}
	w.mu.Lock()
	delete(w.uids, pod.UID)
	w.mu.Unlock()

	w.onDeleteMu.RLock()
	cb := w.onPodDeleted
	w.onDeleteMu.RUnlock()
	if cb != nil {
		cb(string(pod.UID))
	}
}

// podFromDeleteObj extracts the pod from a delete event, handling the tombstone
// wrapper the informer may deliver when the final state was missed.
func podFromDeleteObj(obj interface{}) *v1.Pod {
	if pod, ok := obj.(*v1.Pod); ok {
		return pod
	}
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		if pod, ok := tombstone.Obj.(*v1.Pod); ok {
			return pod
		}
	}
	return nil
}

// trimPod reduces a pod to the metadata the watcher needs before it is stored,
// keeping per-node memory low.
func trimPod(obj interface{}) (interface{}, error) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		// Pass through tombstones and anything unexpected unchanged.
		return obj, nil
	}
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			UID:       pod.UID,
			Name:      pod.Name,
			Namespace: pod.Namespace,
		},
	}, nil
}
