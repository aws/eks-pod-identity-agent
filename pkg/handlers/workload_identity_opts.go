package handlers

import (
	"github.com/aws/aws-sdk-go-v2/aws"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/credcache"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
)

// Flag names for the workload identity options, shared by cmd and the error
// messages that name them.
const (
	FlagEnableWorkloadIdentity = "enable-workload-identity"
	FlagNodeKubeconfig         = "node-kubeconfig"
	FlagPeerPidfd              = "workload-identity-peer-pidfd"
)

// WorkloadIdentityServerOpts carries configuration from the command line into
// the workload identity tiers, the way EksCredentialHandlerOpts does for the AWS
// credentials path. It is a parallel struct rather than a widening of that one
// because the two paths share almost no tunable. MaxCacheSize is the exception,
// and it is deliberately the same flag on both paths rather than a second one.
//
// The socket path is deliberately absent. It is a contract with the Pod Identity
// webhook, so it is the constant configuration.WorkloadIdentitySocketPath rather
// than a field, and the wiring site passes it to the server the way an HTTP
// server is given its addr today.
type WorkloadIdentityServerOpts struct {
	// Enabled is whether the agent serves the workload identity socket at all.
	// Off, it builds no workload identity tier, so boot needs no API server.
	Enabled bool
	// Cfg is the AWS configuration the STS and EKS Auth clients are built from.
	// Its credentials, the node's, sign the node client's IAM token and
	// GetTrustBundles.
	Cfg aws.Config
	// NodeKubeconfig is the kubeconfig the node client reads. Empty means the
	// in-cluster server and CA. See kube.NodeClientOpts.
	NodeKubeconfig string
	// ClusterName is the EKS cluster the agent runs in.
	ClusterName string
	// MaxCacheSize bounds each per-pod cache, in entries. It is --max-cache-size,
	// the same value the AWS credentials cache is given, because both are sized
	// by the same thing: the number of pods that can run on this node. A node
	// budgeted for N credential entries is budgeted for N token entries.
	//
	// Zero disables caching on the credentials path. It cannot mean that here —
	// an uncached tier would mint per request — so the tiers reject it.
	MaxCacheSize int
	// PeerPidfd lets the socket pin callers by SO_PEERPIDFD where the kernel has
	// it. Off, every caller is pinned through its /proc handle.
	PeerPidfd bool
	// CredentialCache is the credential cache every bind host serves from, so
	// the session tier shares it. Nil when caching is off. It isn't a flag: cmd
	// sets it.
	CredentialCache *credcache.Cache
	// EKSAuth is the EKS Auth client the session tier exchanges with. cmd sets it.
	EKSAuth credentials.CredentialRetriever
}
