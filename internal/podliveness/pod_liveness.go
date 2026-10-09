// Package podliveness answers one question for the credential cache: is the pod
// a stored credential belongs to still present on this node. The cache uses it to
// skip renewing credentials for pods that have already terminated, so a burst of
// pod churn no longer spends AssumeRoleForPodIdentity calls and EKS Auth
// rate-limiter capacity on credentials nobody will read again.
//
// The checker watches only the pods scheduled to this node, through a
// field-selected informer (spec.nodeName=$NODE_NAME), and answers from the local
// cache in O(1) with no per-renewal call to the API server. It fails open: when
// the cache has not synced, or a lookup cannot be resolved, it reports the pod as
// alive so a renewal is only ever skipped when a pod is positively known absent.
package podliveness

import (
	"context"
	"fmt"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
)

const (
	// nodeNameEnv names the node the agent runs on. The daemonset sets it from
	// the downward API (spec.nodeName). Without it the informer cannot scope its
	// watch to this node, so NewChecker returns an error and the caller falls
	// back to the always-alive checker.
	nodeNameEnv = "NODE_NAME"

	// informerQPS and informerBurst bound the client the informer uses. The watch
	// is a single long-lived connection scoped to one node's pods, so a small
	// budget is plenty and keeps the agent a light client of the API server.
	informerQPS   = 5
	informerBurst = 5

	// resyncPeriod is how often the informer re-lists to reconcile its cache with
	// the API server. Pod add and delete events already keep the cache current,
	// so a long resync is enough as a backstop.
	resyncPeriod = 10 * time.Minute

	// syncTimeout bounds the initial cache sync. Until the cache syncs the checker
	// fails open, so this only bounds how long the background sync wait runs.
	syncTimeout = 2 * time.Minute
)

// Checker reports whether a pod is still present on this node.
type Checker interface {
	// IsAlive reports whether the pod identified by namespace, name and uid is
	// still present on this node. It returns true whenever the answer is not
	// known for certain (cache not synced, lookup error), so callers only act on
	// a definite false.
	IsAlive(namespace, name, uid string) bool
	// HasSynced reports whether the underlying cache has completed its initial
	// sync. Before it has, IsAlive always reports alive.
	HasSynced() bool
}

// podChecker answers from a node-scoped pod informer.
type podChecker struct {
	informer cache.SharedIndexInformer
	lister   cache.Store
}

// type assertion
var _ Checker = &podChecker{}

// NewChecker builds a checker backed by an informer that watches only the pods on
// this node, and starts it. It reads the node name from NODE_NAME and builds an
// in-cluster client. The initial cache sync runs in the background; until it
// finishes the checker reports every pod alive, so a renewal is never skipped on
// stale information. The returned checker runs until ctx is cancelled.
func NewChecker(ctx context.Context) (Checker, error) {
	nodeName := os.Getenv(nodeNameEnv)
	if nodeName == "" {
		return nil, fmt.Errorf("%s is not set, cannot scope the pod watch to this node", nodeNameEnv)
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to build in-cluster config: %w", err)
	}
	config.QPS = informerQPS
	config.Burst = informerBurst

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return newCheckerForClient(ctx, clientset, nodeName), nil
}

// newCheckerForClient builds and starts a podChecker over clientset, scoped to
// nodeName. It is separated from NewChecker so tests can inject a fake clientset.
func newCheckerForClient(ctx context.Context, clientset kubernetes.Interface, nodeName string) *podChecker {
	factory := informers.NewSharedInformerFactoryWithOptions(
		clientset,
		resyncPeriod,
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", nodeName).String()
		}),
	)
	podInformer := factory.Core().V1().Pods().Informer()
	pc := &podChecker{
		informer: podInformer,
		lister:   podInformer.GetStore(),
	}

	factory.Start(ctx.Done())
	go func() {
		log := logger.FromContext(ctx)
		if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced) {
			log.Infof("pod liveness informer cache did not sync before shutdown; renewals continue without the liveness check")
			return
		}
		log.Infof("pod liveness informer cache synced; skipping credential renewal for terminated pods on node %s", nodeName)
	}()
	return pc
}

// IsAlive reports whether the pod is still on this node. It fails open: an unsynced
// cache, a store error, or a type that is not a pod all report alive, so a renewal
// is only skipped for a pod the cache positively does not hold. When a pod with the
// same namespace and name is present but its UID differs, the stored pod has been
// replaced by a new one that reused the name, so the original is treated as gone.
func (pc *podChecker) IsAlive(namespace, name, uid string) bool {
	if !pc.informer.HasSynced() {
		return true
	}
	obj, exists, err := pc.lister.GetByKey(namespace + "/" + name)
	if err != nil {
		return true
	}
	if !exists {
		return false
	}
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return true
	}
	// A UID we cannot compare against (empty on either side) should not cause a
	// skip, so only a positive mismatch counts as the pod being gone.
	if uid != "" && string(pod.UID) != "" && string(pod.UID) != uid {
		return false
	}
	return true
}

// HasSynced reports whether the informer cache has completed its initial sync.
func (pc *podChecker) HasSynced() bool {
	return pc.informer.HasSynced()
}

// noopChecker always reports alive. It preserves the agent's behavior from before
// the liveness check for callers that have no checker configured, for example when
// NODE_NAME is unset or no in-cluster config is available.
type noopChecker struct{}

// type assertion
var _ Checker = noopChecker{}

// NewNoopChecker returns a Checker that reports every pod alive and always synced.
func NewNoopChecker() Checker { return noopChecker{} }

func (noopChecker) IsAlive(_, _, _ string) bool { return true }
func (noopChecker) HasSynced() bool             { return true }
