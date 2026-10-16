package attestation

// NewAttestor is the startup wiring for attestation: start the node-scoped pod
// store over an already-built node-credentialed client and return an Attestor
// over it. It blocks until the pod cache syncs or ctx is done, because the agent
// cannot attest anything without a synced store; the server (T2) stays unready
// until this returns.
//
// The clientset and node name are injected rather than built here. They are
// produced once at startup by internal/kube (NewNodeClient + ResolveNodeName)
// and shared with the token minter (T4), so a single node credential, connection
// pool and rate limiter cover every node-credentialed consumer.

import (
	"context"
	"fmt"

	"k8s.io/client-go/kubernetes"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// NewAttestor builds a fully wired Attestor from a shared node-credentialed
// client and the resolved node name. It starts the node-scoped pod store and
// blocks until its cache syncs or ctx is done. It also returns the store, so a
// tier that tracks pod presence and deletion, such as the JWT-SVID source (T8),
// watches the same cache the attestor resolves callers from.
func NewAttestor(ctx context.Context, clientset kubernetes.Interface, nodeName string) (workloadidentity.Attestor, *PodStore, error) {
	pods, err := NewPodStore(ctx, clientset, nodeName)
	if err != nil {
		return nil, nil, fmt.Errorf("starting node-scoped pod store: %w", err)
	}
	logger.FromContext(ctx).Infof("attestation: pod store synced for node %q", nodeName)

	return New(nodeName, pods, NewCgroupResolver()), pods, nil
}
