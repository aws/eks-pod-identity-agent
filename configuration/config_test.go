package configuration

import (
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// TestWorkloadIdentityContract_FrozenValues_MatchTheAgreedStrings pins every
// value that is a contract with the Pod Identity webhook, the CSI driver, or EKS
// Auth. The literals below are the agreed strings; a change to one of the
// constants is a change to the contract and has to be made with the other
// components, not here.
func TestWorkloadIdentityContract_FrozenValues_MatchTheAgreedStrings(t *testing.T) {
	testCases := []struct {
		name     string
		actual   string
		expected string
	}{
		{
			name:     "endpoint socket env var",
			actual:   SpiffeEnvVarEndpointSocket,
			expected: "SPIFFE_ENDPOINT_SOCKET",
		},
		{
			name:     "socket path",
			actual:   WorkloadIdentitySocketPath,
			expected: "/var/run/secrets/pods.eks.amazonaws.com/workloadidentity/agent.sock",
		},
		{
			name:     "socket mount path",
			actual:   WorkloadIdentitySocketMountPath,
			expected: "/var/run/secrets/pods.eks.amazonaws.com/workloadidentity",
		},
		{
			name:     "socket volume name",
			actual:   WorkloadIdentitySocketVolumeName,
			expected: "eks-workload-identity-socket",
		},
		{
			name:     "CSI driver name",
			actual:   WorkloadIdentityCSIDriver,
			expected: "spiffe.csi.eks.amazonaws.com",
		},
		{
			name:     "EKS Auth audience",
			actual:   EksAuthAudience,
			expected: "pods.eks.amazonaws.com",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(tc.actual).To(Equal(tc.expected))
		})
	}
}

// TestWorkloadIdentitySocketPath_IsMountPathPlusOneComponent catches the class of
// edit that breaks the webhook contract: moving the socket out of the directory
// the CSI driver publishes, or turning the mount path into the socket itself. The
// webhook mounts the directory and injects the socket path, so the socket has to
// be exactly one filename component inside the mount.
func TestWorkloadIdentitySocketPath_IsMountPathPlusOneComponent(t *testing.T) {
	g := NewWithT(t)

	g.Expect(filepath.IsAbs(WorkloadIdentitySocketMountPath)).To(BeTrue(),
		"the mount path is a volume mount target and has to be absolute")
	g.Expect(filepath.IsAbs(WorkloadIdentitySocketPath)).To(BeTrue(),
		"the socket path is injected into a pod's environment and has to be absolute")

	// the socket sits directly in the mount, not in a subdirectory of it and not
	// beside it
	g.Expect(filepath.Dir(WorkloadIdentitySocketPath)).To(Equal(WorkloadIdentitySocketMountPath))

	// and the last component is a plain filename, so the socket path names a
	// file rather than the directory itself
	socketFile := filepath.Base(WorkloadIdentitySocketPath)
	g.Expect(socketFile).ToNot(BeEmpty())
	g.Expect(socketFile).ToNot(Equal("."))
	g.Expect(socketFile).ToNot(Equal(".."))
	g.Expect(socketFile).ToNot(ContainSubstring("/"))

	// neither path is cleaned on the way through, so what the webhook injects is
	// byte for byte what the agent binds
	g.Expect(WorkloadIdentitySocketPath).To(Equal(filepath.Clean(WorkloadIdentitySocketPath)))
	g.Expect(WorkloadIdentitySocketMountPath).To(Equal(filepath.Clean(WorkloadIdentitySocketMountPath)))
	g.Expect(strings.HasSuffix(WorkloadIdentitySocketMountPath, "/")).To(BeFalse(),
		"a trailing separator on the mount path silently breaks any join against it")
}
