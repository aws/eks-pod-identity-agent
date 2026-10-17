// Package podstore is the agent's node-scoped view of pods. Attestation resolves
// a caller's pod UID through it, and the per-pod tiers drop a pod's material when
// it reports the pod gone.
//
// The store is backed by an informer whose list and watch carry a
// spec.nodeName field selector equal to the agent's node. The selector is not an
// optimisation. Under the Node authorizer the agent's node credential can only
// read pods bound to its own node, so the selector is the read authority made
// explicit, and it is what keeps a local caller from ever resolving to a pod on
// another node. The redundant node recheck in the attestor turns a selector
// regression from a security hole into a refused request.
package podstore

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
)

// podByUIDIndex is the informer index that keys pods by their UID, which is the
// identifier the cgroup path yields. The default informer index is by
// namespace/name, which attestation never has.
const podByUIDIndex = "byPodUID"

// PodInfo is the subset of a pod the attestor needs. It is a flat value rather
// than a *corev1.Pod so the store owns the projection and callers cannot reach
// into pod fields the attested identity does not depend on.
type PodInfo struct {
	// UID is the pod's Kubernetes UID.
	UID string
	// Name is the pod's name.
	Name string
	// Namespace is the pod's namespace.
	Namespace string
	// ServiceAccount is the pod's ServiceAccount name.
	ServiceAccount string
	// NodeName is the node the pod is scheduled on.
	NodeName string
}

// Interface is what the per-pod tiers need from the store. A pod is gone from
// HasPod before OnPodDeleted's callbacks run for it, so a tier that checks HasPod
// under the lock its callback takes never caches for a deleted pod. Store
// implements it.
type Interface interface {
	// HasPod reports whether the pod is on this node.
	HasPod(podUID string) bool
	// OnPodDeleted has fn called with the UID of each pod that leaves this node.
	// Callbacks must return promptly.
	OnPodDeleted(fn func(podUID string)) error
}

// Store is a node-scoped view of pods backed by a shared informer.
type Store struct {
	indexer  cache.Indexer
	informer cache.SharedIndexInformer
}

var _ Interface = (*Store)(nil)

// podUIDIndexFunc keys a pod object by its UID for the byPodUID index.
func podUIDIndexFunc(obj interface{}) ([]string, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("expected *corev1.Pod, got %T", obj)
	}
	return []string{string(pod.UID)}, nil
}

// stripDownPod is the informer TransformFunc that trims each pod down to only
// the fields attestation reads — UID, Name, Namespace, ResourceVersion, the node
// it is bound to, and its ServiceAccount — before it enters the cache.
// Everything else (containers, volumes, status, managedFields, labels,
// annotations) is dropped, which is where the memory goes on a node running many
// pods. The output is always a fresh *corev1.Pod, so the UID indexer, the event
// logger and PodByUID keep their existing type assertion.
//
// One edge case needs handling here. Normally the informer hands this function a
// plain *corev1.Pod. But if the informer's watch connection breaks (API server
// restart, network blip, or a resourceVersion that has aged out) a pod can be
// deleted while the informer isn't watching. On reconnect the informer relists,
// sees the pod is gone from the cluster but still in its cache, and synthesizes
// the delete it never observed — a "missed delete". Because the real object is
// already gone, client-go delivers it as a cache.DeletedFinalStateUnknown
// tombstone wrapping the last-known copy of the pod rather than the pod itself.
// We unwrap that tombstone, trim the pod inside it, and rewrap it, so a missed
// delete never causes the store to retain a full, untrimmed pod. Any other type
// is passed through unchanged.
//
// NOTE: if attestation ever needs another pod field, it must be added here, or
// it will be absent from the cache.
func stripDownPod(obj interface{}) (interface{}, error) {
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		trimmed, err := stripDownPod(tombstone.Obj)
		if err != nil {
			return nil, err
		}
		tombstone.Obj = trimmed
		return tombstone, nil
	}
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return obj, nil
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			UID:             pod.UID,
			Name:            pod.Name,
			Namespace:       pod.Namespace,
			ResourceVersion: pod.ResourceVersion,
		},
		Spec: corev1.PodSpec{
			NodeName:           pod.Spec.NodeName,
			ServiceAccountName: pod.Spec.ServiceAccountName,
		},
	}, nil
}

// New builds a pod store scoped to nodeName, starts its informer, and
// blocks until the cache has synced or ctx is done. The field selector is what
// scopes the list and watch to this node; it is applied through the informer
// factory so both the initial list and the ongoing watch carry it.
func New(ctx context.Context, clientset kubernetes.Interface, nodeName string) (*Store, error) {
	if nodeName == "" {
		return nil, fmt.Errorf("node name is required to scope the pod store")
	}

	nodeSelector := fields.OneTermEqualSelector("spec.nodeName", nodeName).String()
	// No resync. A resync never asks the API server: it replays each cached pod
	// to the handlers as an update from the pod to itself. podReplacedHandler
	// ignores that, since the UID is the same, and a resync never produces a
	// delete. Missed events come back through the reflector, which resumes the
	// watch and relists on 410.
	factory := informers.NewSharedInformerFactoryWithOptions(
		clientset,
		0,
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = nodeSelector
		}),
	)

	podInformer := factory.Core().V1().Pods().Informer()

	// Trim each pod to only the fields attestation reads before it is stored.
	// On a node running many pods the informer cache would otherwise retain every
	// pod's containers, volumes, status and managedFields; dropping them is a
	// large memory saving for a store whose only reader is PodByUID.
	if err := podInformer.SetTransform(stripDownPod); err != nil {
		return nil, fmt.Errorf("setting pod store transform: %w", err)
	}

	if err := podInformer.AddIndexers(cache.Indexers{podByUIDIndex: podUIDIndexFunc}); err != nil {
		return nil, fmt.Errorf("adding pod UID indexer: %w", err)
	}

	// Observability for the watch itself. The node-scoped list/watch is the
	// authority attestation reads, so surfacing each add/update/delete (at debug,
	// to stay quiet in production) makes it possible to confirm on a real node
	// that the informer is receiving events as pods come and go. The sync summary
	// below is logged at info because "the cache is ready and holds N pods" is the
	// one line an operator wants at startup.
	log := logger.FromContext(ctx)
	if _, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { logPodEvent(log, "add", obj) },
		UpdateFunc: func(_, obj interface{}) { logPodEvent(log, "update", obj) },
		DeleteFunc: func(obj interface{}) { logPodEvent(log, "delete", obj) },
	}); err != nil {
		return nil, fmt.Errorf("adding pod event handler: %w", err)
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced) {
		return nil, fmt.Errorf("pod informer cache failed to sync for node %q", nodeName)
	}

	indexer := podInformer.GetIndexer()
	log.WithFields(logrus.Fields{
		"node": nodeName,
		"pods": len(indexer.ListKeys()),
	}).Info("podstore: node-scoped pod informer synced")

	return &Store{indexer: indexer, informer: podInformer}, nil
}

// OnPodDeleted calls fn with the UID of each pod that leaves this node's store:
// deleted, or replaced by a same-named pod with a new UID, which a relist
// delivers as an update with no delete. It reuses this node's watch. Callbacks
// must return promptly.
func (s *Store) OnPodDeleted(fn func(podUID string)) error {
	if fn == nil {
		return fmt.Errorf("pod deletion callback is required")
	}
	if s == nil || s.informer == nil {
		return fmt.Errorf("pod store has no informer to report pod deletions from")
	}
	_, err := s.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		// Not for UID changes, which can't happen: for two pods sharing a name,
		// whose delete and create a relist folds into one update.
		UpdateFunc: podReplacedHandler(fn),
		DeleteFunc: podDeletedHandler(fn),
	})
	if err != nil {
		return fmt.Errorf("adding pod deletion handler: %w", err)
	}
	return nil
}

func podDeletedHandler(fn func(string)) func(interface{}) {
	return func(obj interface{}) {
		if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
			obj = tombstone.Obj
		}
		pod, ok := obj.(*corev1.Pod)
		if ok && pod != nil && pod.UID != "" {
			fn(string(pod.UID))
		}
	}
}

// podReplacedHandler reports the old UID when an update carries a different pod.
// A pod's UID never changes, but the informer keys pods by namespace/name: a pod
// deleted and recreated under the same name while the watch is down, such as a
// StatefulSet pod, reaches the relist as one update from old pod to new and no
// delete (client-go's SharedInformer doc). A resync keeps the UID and reports nothing.
func podReplacedHandler(fn func(string)) func(interface{}, interface{}) {
	return func(oldObj, newObj interface{}) {
		oldPod, oldOK := oldObj.(*corev1.Pod)
		newPod, newOK := newObj.(*corev1.Pod)
		if oldOK && newOK && oldPod != nil && newPod != nil && oldPod.UID != "" && oldPod.UID != newPod.UID {
			fn(string(oldPod.UID))
		}
	}
}

// logPodEvent renders one watch event for the node-scoped pod informer. It is
// debug-level: on a busy node every pod add/update would otherwise be a log line
// in production, but during on-node validation running the agent at -v debug
// turns this into a live view of the watch. It handles the deletion tombstone
// (cache.DeletedFinalStateUnknown) so a delete arriving after a watch relist is
// still reported rather than silently dropped.
func logPodEvent(log *logrus.Entry, verb string, obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		tombstone, isTombstone := obj.(cache.DeletedFinalStateUnknown)
		if !isTombstone {
			return
		}
		pod, ok = tombstone.Obj.(*corev1.Pod)
		if !ok {
			return
		}
	}
	log.WithFields(logrus.Fields{
		"event": verb,
		"pod":   pod.Namespace + "/" + pod.Name,
		"uid":   string(pod.UID),
		"node":  pod.Spec.NodeName,
		"sa":    pod.Spec.ServiceAccountName,
	}).Debug("podstore: watch event")
}

// newStoreFromIndexer wraps a prepopulated indexer. It exists so the lookup
// and projection logic can be tested without an informer or a cluster.
func newStoreFromIndexer(indexer cache.Indexer) *Store {
	return &Store{indexer: indexer}
}

// HasPod checks the node-scoped cache without calling the API server.
func (s *Store) HasPod(uid string) bool {
	if s == nil || s.indexer == nil || uid == "" {
		return false
	}
	_, found := s.PodByUID(uid)
	return found
}

// PodByUID returns the pod with uid from the node-scoped cache. A UID absent
// from the store is a clean miss, which the attestor treats as an unresolvable
// caller rather than an error.
func (s *Store) PodByUID(uid string) (*PodInfo, bool) {
	objs, err := s.indexer.ByIndex(podByUIDIndex, uid)
	if err != nil || len(objs) == 0 {
		return nil, false
	}
	pod, ok := objs[0].(*corev1.Pod)
	if !ok {
		return nil, false
	}
	return &PodInfo{
		UID:            string(pod.UID),
		Name:           pod.Name,
		Namespace:      pod.Namespace,
		ServiceAccount: pod.Spec.ServiceAccountName,
		NodeName:       pod.Spec.NodeName,
	}, true
}
