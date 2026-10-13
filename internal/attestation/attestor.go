package attestation

// This file ties the attestation chain together. Given the Peer the transport
// pinned for a connection, it produces the attested Workload the peer belongs to,
// or refuses. It implements workloadidentity.Attestor.
//
// The order is the security argument, not an implementation detail:
//
//  1. the transport pinned the process that connected (pkg/grpcserver/peer.go)
//  2. check the pin is still alive
//  3. resolve the PID to a pod UID from its cgroup (cgroup.go)
//  4. resolve the pod UID to a pod from the node-scoped store (podstore.go)
//  5. refuse a pod bound to another node
//  6. check the pin again, whatever 3-5 concluded
//  7. only then return the Workload
//
// Identity comes from the kernel and from API-server state, never from anything
// the caller sends. Every refusal is counted on its own reason so the two
// security-relevant ones (pod not in store, pod on another node) can be alarmed
// apart from the deployment and liveness failures.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// attestor resolves a pinned Peer to a Workload. Its collaborators are behind
// interfaces so the whole chain is testable with fakes and no cluster: pods is
// the node-scoped store and cgroup is the PID-to-pod-UID resolver.
// podLookupAttempts and podLookupRetryInterval bound the retry that absorbs
// informer cache lag when resolving a pod UID. A pod that has just been
// scheduled can request credentials before its ADD watch event has landed in the
// node-scoped cache, so a miss is retried before it is treated as a real "not on
// this node". This is 5 attempts (the initial lookup plus 4 retries) spaced 50ms
// apart, i.e. up to ~200ms within a 250ms window. The budget is deliberately
// small: every genuine miss (an unknown UID, a probe) pays this latency before
// being refused, and it is also cut short by the request's own context.
const (
	podLookupAttempts      = 5
	podLookupRetryInterval = 50 * time.Millisecond
)

type attestor struct {
	nodeName string
	pods     PodGetter
	cgroup   CgroupResolver

	// podRetryAttempts and podRetryInterval bound the cache-lag retry in
	// resolvePod. They are fields, defaulted by newAttestor, so tests can shrink
	// or disable the retry rather than sleep for the production budget.
	podRetryAttempts int
	podRetryInterval time.Duration
}

// New returns an Attestor for the given node, pod store and cgroup resolver.
func New(nodeName string, pods PodGetter, cgroup CgroupResolver) workloadidentity.Attestor {
	return newAttestor(nodeName, pods, cgroup)
}

// newAttestor returns the concrete type, so tests can shrink the retry budget.
func newAttestor(nodeName string, pods PodGetter, cgroup CgroupResolver) *attestor {
	return &attestor{
		nodeName:         nodeName,
		pods:             pods,
		cgroup:           cgroup,
		podRetryAttempts: podLookupAttempts,
		podRetryInterval: podLookupRetryInterval,
	}
}

// resolvePod looks up the pod by UID, retrying briefly to absorb informer cache
// lag: a pod scheduled moments ago can reach the agent before its ADD watch
// event has updated the local cache. It makes up to podRetryAttempts lookups
// spaced podRetryInterval apart, returning on the first hit. A miss after every
// attempt is a real "no such pod on this node". The wait between attempts is cut
// short if the request's context is cancelled.
func (a *attestor) resolvePod(ctx context.Context, uid string) (*PodInfo, bool) {
	attempts := a.podRetryAttempts
	if attempts < 1 {
		attempts = 1
	}
	for i := 0; ; i++ {
		if pod, ok := a.pods.PodByUID(uid); ok {
			return pod, true
		}
		if i >= attempts-1 {
			return nil, false // the last attempt missed
		}
		select {
		case <-ctx.Done():
			return nil, false
		case <-time.After(a.podRetryInterval):
		}
	}
}

// Attest identifies the workload behind peer, or returns ErrUnattestable.
// Liveness is checked before resolving, to fail fast on a dead connection, and
// after it on every outcome, since whatever resolve concluded was about whoever
// held the PID at the time.
func (a *attestor) Attest(ctx context.Context, peer workloadidentity.Peer) (*workloadidentity.Workload, error) {
	start := time.Now()
	if peer == nil {
		return nil, a.refuse(start, workloadidentity.ReasonPeerCredFailed, errors.New("no peer"))
	}
	// The PID goes in every refusal's cause, which reaches logs and never the caller.
	pid := peer.PID()
	if err := peer.Alive(); err != nil {
		return nil, a.refuse(start, workloadidentity.ReasonPeerGone, fmt.Errorf("pid %d: %w", pid, err))
	}

	w, reason, err := a.resolve(ctx, pid)

	if aliveErr := peer.Alive(); aliveErr != nil {
		return nil, a.refuse(start, workloadidentity.ReasonLivenessRecheckFailed, fmt.Errorf("pid %d: %w", pid, aliveErr))
	}
	if err != nil {
		return nil, a.refuse(start, reason, fmt.Errorf("pid %d: %w", pid, err))
	}

	promAttestationTotal.WithLabelValues(workloadidentity.OutcomeSuccess, reasonNone).Inc()
	promAttestationDuration.WithLabelValues(workloadidentity.OutcomeSuccess).Observe(time.Since(start).Seconds())
	logger.FromContext(ctx).Debugf("attested pod %s/%s (uid %s, sa %s) on node %s",
		w.Namespace, w.PodName, w.PodUID, w.ServiceAccount, w.NodeName)
	return w, nil
}

// resolve maps pid to a Workload through its cgroup and the node's pod store,
// returning the refusal reason on failure. Nothing it reads is trusted until
// the caller has rechecked the peer.
func (a *attestor) resolve(ctx context.Context, pid int) (*workloadidentity.Workload, string, error) {
	podUID, err := a.cgroup.PodUIDForPID(pid)
	if errors.Is(err, ErrNoPodUID) {
		return nil, workloadidentity.ReasonCgroupNoPodUID, err
	}
	if err != nil {
		return nil, workloadidentity.ReasonCgroupReadFailed, err
	}

	pod, ok := a.resolvePod(ctx, podUID)
	if !ok {
		// Security-relevant, after retrying for cache lag. Alarmed on separately.
		return nil, workloadidentity.ReasonPodNotInStore,
			errors.New("pod UID " + podUID + " not present in node-scoped store")
	}
	if pod.NodeName != a.nodeName {
		// Redundant given the field selector, so a selector regression refuses.
		return nil, workloadidentity.ReasonPodNodeMismatch,
			errors.New("pod bound to node " + pod.NodeName + ", agent is on " + a.nodeName)
	}

	return &workloadidentity.Workload{
		PodUID:         pod.UID,
		PodName:        pod.Name,
		Namespace:      pod.Namespace,
		ServiceAccount: pod.ServiceAccount,
		NodeName:       pod.NodeName,
	}, "", nil
}

// refuse records the failure on both attestation metrics under reason and
// returns ErrUnattestable wrapping the cause. Returning one taxonomy member for
// every refusal keeps the caller's branching simple; the reason lives on the
// metric, not in the returned kind.
func (a *attestor) refuse(start time.Time, reason string, cause error) error {
	promAttestationTotal.WithLabelValues(workloadidentity.OutcomeFailure, reason).Inc()
	promAttestationDuration.WithLabelValues(workloadidentity.OutcomeFailure).Observe(time.Since(start).Seconds())
	// The reason stays in the cause, which reaches logs and never the caller.
	return wierrors.ErrUnattestable.Wrapf(fmt.Errorf("%s: %w", reason, cause), "attestation refused")
}
