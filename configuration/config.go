package configuration

import "strings"

const (
	DefaultIpv6TargetHost = "fd00:ec2::23"
	DefaultIpv4TargetHost = "169.254.170.23"
	AgentLinkName         = "pod-id-link0"
)

// RequestRate indicates the number of request allowed per second
const RequestRate = 1000

// WorkloadIdentityRequestRate bounds admission on the workload identity socket. It
// is a local tunable rather than a contract value, so it sits here beside
// RequestRate rather than in the contract block below: nothing outside the agent
// observes it.
//
// The limiter it configures governs unary calls and stream establishment, never
// messages on an established stream. A message on a credential stream is a renewal
// the agent itself decided to push, so a per-message limit would throttle renewals
// and leave abuse untouched.
//
// It is far below RequestRate because the traffic shape is not the same. Steady
// state on this socket is close to zero: a pod opens its streams once and holds them
// for the life of its containers. The load spike is an agent restart, when every
// enrolled pod on the node reconnects at once with a few streams each, and
// ratelimiter.NewRateLimiter gives that a burst of half this value, so a full default
// node's reconnects drain over a handful of seconds while the clients back off and
// retry. Draining rather than admitting all of them at once is the better shape
// anyway: each first subscribe costs a ServiceAccount token mint and an STS exchange,
// and nothing between admission and those calls bounds their concurrency yet.
const WorkloadIdentityRequestRate = 50

var AgentVersion string

// Workload identity contract values.
//
// Every constant below is shared with something outside this agent: the Pod
// Identity webhook, the CSI driver, or EKS Auth. None of them are tunable, and
// none of them may be copied as a literal into pkg/ or internal/. A drift in any
// one of them is a cluster-wide failure rather than a local bug, because the
// symptom surfaces in the workload rather than here.
//
// The socket triple is the sharpest example. The webhook injects
// SpiffeEnvVarEndpointSocket pointing at WorkloadIdentitySocketPath and mounts a
// volume named WorkloadIdentitySocketVolumeName at
// WorkloadIdentitySocketMountPath; the CSI driver publishes that directory; the
// agent listens on the socket inside it. If the three disagree, every enrolled
// pod fails to get a credential and the operator sees a workload that cannot
// dial its socket, which reads as an application bug.
const (
	// SpiffeEnvVarEndpointSocket is the environment variable the Pod Identity
	// webhook injects into an enrolled pod, naming the SPIFFE Workload API
	// endpoint. The name is fixed by the SPIFFE specification, so a workload's
	// SPIFFE library finds the agent without configuration.
	SpiffeEnvVarEndpointSocket = "SPIFFE_ENDPOINT_SOCKET"

	// WorkloadIdentitySocketPath is the Unix domain socket the agent serves the
	// SPIFFE Workload API and Envoy SDS on, as seen from inside an enrolled pod
	// and from the agent. It is the bare filesystem path, which is what
	// net.Listen takes; the webhook prepends the unix:// scheme when it injects
	// SpiffeEnvVarEndpointSocket, so the scheme does not belong in this value.
	//
	// It is deliberately a constant rather than a flag:
	// making it configurable invites an operator to set it and break the
	// webhook contract silently, and the only party that could legitimately
	// change it is the webhook, which cannot be reconfigured from here.
	WorkloadIdentitySocketPath = "/var/run/secrets/pods.eks.amazonaws.com/workloadidentity/agent.sock"

	// WorkloadIdentitySocketMountPath is the directory the CSI driver publishes
	// into an enrolled pod. It is the parent of WorkloadIdentitySocketPath; the
	// mount is a directory rather than the socket itself so the agent can
	// unlink and rebind the socket without invalidating a live mount.
	WorkloadIdentitySocketMountPath = "/var/run/secrets/pods.eks.amazonaws.com/workloadidentity"

	// WorkloadIdentitySocketVolumeName is the name of the volume the webhook
	// adds to an enrolled pod's spec for the socket directory.
	WorkloadIdentitySocketVolumeName = "eks-workload-identity-socket"

	// WorkloadIdentityCSIDriver is the name of the CSI driver that publishes
	// the socket directory. Its CSIDriver object is also what makes the token
	// mint permissible: the object declares tokenRequests for EksAuthAudience,
	// which is what satisfies the ServiceAccountNodeAudienceRestriction check
	// the API server applies to a node identity calling TokenRequest.
	WorkloadIdentityCSIDriver = "spiffe.csi.eks.amazonaws.com"

	// EksAuthAudience is the only audience EKS Auth accepts, and so the only
	// audience the agent ever mints a ServiceAccount token for. It is also the
	// value that has to appear in the CSI driver's declared tokenRequests for
	// that mint to be permitted, and the audience the existing AWS credentials
	// path validates on a token a pod presents.
	EksAuthAudience = "pods.eks.amazonaws.com"
)

// isolatedRegionInfix matches every isolated partition's region names: us-iso-*,
// us-isob-*, eu-isoe-*, us-isof-*. The chart's own gate is the same literal in Helm
// (contains "-iso"), since a template cannot read a Go constant.
const isolatedRegionInfix = "-iso"

// IsIsolatedRegion reports whether region belongs to an isolated partition, where
// the chart doesn't enable workload identity. Nothing in the agent calls it; it is
// the Go definition the chart's region gate is tested against. An empty region
// reads as not isolated.
func IsIsolatedRegion(region string) bool {
	return strings.Contains(region, isolatedRegionInfix)
}

// Kubelet paths for the CSI node service. The chart mounts each at the path it has on
// the host, which is load-bearing: the kubelet opens the registered endpoint in the host
// mount namespace, so a different mount path reports one it cannot open and the plugin
// registers and is never called.
const (
	// KubeletPluginDir serves the CSI Identity and Node services. The kubelet convention
	// is one directory per driver, named after it.
	KubeletPluginDir = "/var/lib/kubelet/plugins/" + WorkloadIdentityCSIDriver

	// KubeletPluginSocketPath is the endpoint reported to the kubelet at registration.
	KubeletPluginSocketPath = KubeletPluginDir + "/csi.sock"

	// KubeletPluginRegistrationDir is watched by the kubelet. A socket appearing here is
	// the only thing that advertises the driver to it.
	KubeletPluginRegistrationDir = "/var/lib/kubelet/plugins_registry"

	// KubeletRegistrationSocketPath serves the registration handshake. The name carries
	// the driver so the directory can hold one socket per plugin.
	KubeletRegistrationSocketPath = KubeletPluginRegistrationDir + "/" + WorkloadIdentityCSIDriver + "-reg.sock"

	// KubeletPodsDir roots the per-pod volume directories. Every publish target lives
	// under it, which is what lets the node service refuse one that does not.
	KubeletPodsDir = "/var/lib/kubelet/pods"
)
