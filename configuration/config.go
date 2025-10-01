package configuration

const (
	DefaultIpv6TargetHost = "fd00:ec2::23"
	DefaultIpv4TargetHost = "169.254.170.23"
	AgentLinkName         = "pod-id-link0"
)

// RequestRate indicates the number of request allowed per second
const RequestRate = 1000

var AgentVersion string
