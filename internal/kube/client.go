// Package kube builds the Kubernetes client the workload identity path reaches
// the API server with, and resolves the agent's own node name from it.
//
// The client authenticates as the node identity (system:node:<nodeName>) rather
// than as the agent's ServiceAccount. That is what makes the node-scoped reads
// and writes safe: the Node authorizer restricts a node identity to the pods
// bound to its own node, a property no ServiceAccount and RBAC grant can express.
// Both consumers depend on it — the attestor's pod watch and node-name lookup
// (T3), and the token minter's TokenRequest (T4) — so the client is built once
// here and injected into both rather than each constructing its own. One
// construction means one credential path, one connection pool, and one rate
// limiter bounding the agent's total traffic to the API server.
//
// internal/validation/apiserver_client.go still builds its own client from
// rest.InClusterConfig() (the agent's ServiceAccount) for JWKS fetching, which
// does not require the node identity. Whether that path also moves onto the node
// credential is a deliberate T4 decision, not something to fold in by accident.
package kube

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// DefaultKubeletKubeconfigPath is where nodeadm writes the kubelet's kubeconfig on
// an AL2023 or hybrid node. On EKS it execs aws or aws-iam-authenticator, which the
// agent image doesn't ship, and the chart doesn't mount it.
const DefaultKubeletKubeconfigPath = "/var/lib/kubelet/kubeconfig"

const (
	// nodeClientQPS bounds the client's steady-state request rate. It governs
	// every node-credentialed consumer sharing this client: the attestor's pod
	// watch (which reads the informer cache, not the API server, once synced)
	// and the token minter's TokenRequest calls on the pod-startup path. Sized
	// for the mint traffic, since the watch is nearly free after sync.
	nodeClientQPS = 15
	// nodeClientBurst allows a short burst above the QPS ceiling, for the
	// startup pod list, the node-name lookup, and bursts of pod starts.
	nodeClientBurst = 30
)

// NewNodeClient builds a clientset authenticating as the node, from the kubelet
// kubeconfig at kubeconfigPath. An empty path uses DefaultKubeletKubeconfigPath.
// The returned client is intended to be shared across every node-credentialed
// consumer so its rate limiter bounds total API-server traffic.
func NewNodeClient(kubeconfigPath string) (kubernetes.Interface, error) {
	if kubeconfigPath == "" {
		kubeconfigPath = DefaultKubeletKubeconfigPath
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("building node client config from %q: %w", kubeconfigPath, err)
	}
	config.QPS = nodeClientQPS
	config.Burst = nodeClientBurst

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating node kubernetes client: %w", err)
	}
	return clientset, nil
}
