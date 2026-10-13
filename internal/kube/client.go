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
// The node identity comes from an IAM token the agent signs with its own AWS
// credentials, the node's role, the way the kubelet's exec plugin does on EKS. The
// token is aws-iam-authenticator's own, and the agent image ships no exec plugin,
// so it never runs one.
//
// internal/validation/apiserver_client.go still builds its own client from
// rest.InClusterConfig() (the agent's ServiceAccount) for JWKS fetching, which
// does not require the node identity. Whether that path also moves onto the node
// credential is a deliberate T4 decision, not something to fold in by accident.
package kube

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/oauth2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/transport"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
)

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

// NodeClientOpts says where the node client finds the API server and how it
// authenticates as the node.
type NodeClientOpts struct {
	// KubeconfigPath, when set, supplies the server, CA and user. An exec user is
	// replaced by the IAM token, and any other user is used as is. Empty means the
	// in-cluster server and CA, with the IAM token.
	KubeconfigPath string
	// Cfg signs the IAM token, so it has to resolve to the node's role.
	Cfg aws.Config
	// ClusterName goes in x-k8s-aws-id, unless the kubeconfig's exec user names one.
	ClusterName string
}

// inClusterConfig is rest.InClusterConfig. Tests replace it.
var inClusterConfig = rest.InClusterConfig

// NewNodeClient builds a clientset authenticating as the node. The returned client
// is intended to be shared across every node-credentialed consumer so its rate
// limiter bounds total API-server traffic.
func NewNodeClient(opts NodeClientOpts) (kubernetes.Interface, error) {
	config, err := nodeClientConfig(opts)
	if err != nil {
		return nil, err
	}
	config.QPS = nodeClientQPS
	config.Burst = nodeClientBurst

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating node kubernetes client: %w", err)
	}
	return clientset, nil
}

// nodeClientConfig resolves opts to the rest.Config the node client is built from.
func nodeClientConfig(opts NodeClientOpts) (*rest.Config, error) {
	if opts.KubeconfigPath == "" {
		config, err := inClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("building the in-cluster node client config: %w", err)
		}
		// The ServiceAccount token would authenticate as the agent, not the node.
		config.BearerToken, config.BearerTokenFile = "", ""
		return withIAMToken(config, opts.Cfg, opts.ClusterName)
	}

	config, err := clientcmd.BuildConfigFromFlags("", opts.KubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("building node client config from %q: %w", opts.KubeconfigPath, err)
	}
	if config.ExecProvider == nil {
		return config, nil
	}
	cluster := clusterFromExecArgs(config.ExecProvider.Args)
	if cluster == "" {
		cluster = opts.ClusterName
	}
	config.ExecProvider = nil
	return withIAMToken(config, opts.Cfg, cluster)
}

// clusterFromExecArgs returns the cluster an EKS exec user signs for: nodeadm's
// `aws eks get-token --cluster-name`, which on Outposts carries the cluster ID, or
// Bottlerocket's `aws-iam-authenticator token -i`. Empty when it names none.
func clusterFromExecArgs(args []string) string {
	for i, arg := range args {
		for _, flag := range []string{"--cluster-name", "--cluster-id", "-i"} {
			if arg == flag && i+1 < len(args) {
				return args[i+1]
			}
			if value, ok := strings.CutPrefix(arg, flag+"="); ok {
				return value
			}
		}
	}
	return ""
}

// withIAMToken makes config authenticate with the IAM token, cached until shortly
// before it expires and re-signed early when the API server answers 401.
func withIAMToken(config *rest.Config, cfg aws.Config, cluster string) (*rest.Config, error) {
	source, err := newIAMTokenSource(cfg, cluster)
	if err != nil {
		return nil, err
	}
	config.Wrap(transport.ResettableTokenSourceWrapTransport(transport.NewCachedTokenSource(source)))
	return config, nil
}

func newIAMTokenSource(cfg aws.Config, cluster string) (iamTokenSource, error) {
	generator, err := token.NewGenerator(false, false)
	if err != nil {
		return iamTokenSource{}, fmt.Errorf("creating the IAM token generator: %w", err)
	}
	return iamTokenSource{generator: generator, sts: sts.NewFromConfig(cfg), cluster: cluster}, nil
}

// iamTokenSource signs a fresh token on every call with aws-iam-authenticator's
// generator: a presigned sts:GetCallerIdentity bound to the cluster, valid for 15
// minutes and reused for 14. Signing is local, so a call reaches the network only
// when the SDK refreshes the credentials it signs with.
type iamTokenSource struct {
	generator token.Generator
	sts       *sts.Client
	cluster   string
}

func (s iamTokenSource) Token() (*oauth2.Token, error) {
	signed, err := s.generator.GetWithSTS(s.cluster, s.sts)
	if err != nil {
		return nil, fmt.Errorf("signing the node's IAM token: %w", err)
	}
	return &oauth2.Token{AccessToken: signed.Token, Expiry: signed.Expiration}, nil
}
