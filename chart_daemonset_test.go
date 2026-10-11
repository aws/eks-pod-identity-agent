package main

// Pins the DaemonSet's side of the CSI driver sidecar against the paths it binds and the
// privilege its mounts need, and keeps that privilege off the agent container. Nothing else
// would notice if they drifted: the driver's tests use temporary directories, and the goldens
// only prove the chart still renders what it rendered yesterday.
//
// Unmarshals strictly, which also checks field names. A misspelled mountPropagation
// renders fine, is dropped by the API server, and produces a publish into a directory the
// kubelet sees as empty.

import (
	"os"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
)

// renderedChartPaths is every scenario make helm-verify renders that gets the CSI wiring.
// A hybrid node runs the same binary and kubelet layout, so it carries it too. The isolated
// region rendering is deliberately absent and is asserted against separately.
var renderedChartPaths = []string{
	"hack/testdata/expected_eks_pod_identity_agent_default_helm_template.yaml",
	"hack/testdata/expected_eks_pod_identity_agent_hybrid_helm_template.yaml",
	"hack/testdata/expected_eks_pod_identity_agent_hybrid_bottlerocket_helm_template.yaml",
}

func daemonSetsFromRenderedChart(t *testing.T, path string) []appsv1.DaemonSet {
	t.Helper()

	rendered, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading rendered chart %s: %v", path, err)
	}

	var daemonSets []appsv1.DaemonSet
	for _, doc := range strings.Split(string(rendered), "\n---\n") {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var meta struct {
			Kind string `json:"kind"`
		}
		if err := yaml.Unmarshal([]byte(doc), &meta); err != nil {
			t.Fatalf("unmarshalling a document of %s: %v", path, err)
		}
		if meta.Kind != "DaemonSet" {
			continue
		}

		var daemonSet appsv1.DaemonSet
		if err := yaml.UnmarshalStrict([]byte(doc), &daemonSet); err != nil {
			t.Fatalf("unmarshalling a DaemonSet of %s: %v", path, err)
		}
		daemonSets = append(daemonSets, daemonSet)
	}

	if len(daemonSets) == 0 {
		t.Fatalf("no DaemonSet in %s", path)
	}
	return daemonSets
}

const (
	agentContainerName     = "eks-pod-identity-agent"
	csiDriverContainerName = "eks-pod-identity-agent-csi-driver"
	// csiDriverBinary is where the image puts the CSI driver binary.
	csiDriverBinary = "/eks-pod-identity-csi-driver"
)

// container returns the named container, or nil when the DaemonSet has none.
func container(daemonSet appsv1.DaemonSet, name string) *corev1.Container {
	for i, c := range daemonSet.Spec.Template.Spec.Containers {
		if c.Name == name {
			return &daemonSet.Spec.Template.Spec.Containers[i]
		}
	}
	return nil
}

func mustContainer(t *testing.T, daemonSet appsv1.DaemonSet, name string) corev1.Container {
	t.Helper()
	c := container(daemonSet, name)
	if c == nil {
		t.Fatalf("DaemonSet %s has no %s container", daemonSet.Name, name)
	}
	return *c
}

func mountAt(c corev1.Container, path string) *corev1.VolumeMount {
	for i, mount := range c.VolumeMounts {
		if mount.MountPath == path {
			return &c.VolumeMounts[i]
		}
	}
	return nil
}

func hostPathOf(daemonSet appsv1.DaemonSet, volumeName string) string {
	for _, volume := range daemonSet.Spec.Template.Spec.Volumes {
		if volume.Name == volumeName && volume.HostPath != nil {
			return volume.HostPath.Path
		}
	}
	return ""
}

func privileged(c corev1.Container) bool {
	return c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged
}

// TestChartDaemonSetMountsTheCSIPathsAtTheirHostPaths is the one that matters most. Each
// path is mounted at its host path, which is what makes the endpoint reported at
// registration openable by the kubelet: the sidecar binds it in its own mount namespace and
// the kubelet opens it in the host's. Mounting elsewhere gives a plugin that registers and
// is never called.
func TestChartDaemonSetMountsTheCSIPathsAtTheirHostPaths(t *testing.T) {
	expected := map[string][]string{
		agentContainerName: {configuration.WorkloadIdentitySocketMountPath},
		csiDriverContainerName: {
			configuration.WorkloadIdentitySocketMountPath,
			configuration.KubeletPluginDir,
			configuration.KubeletPluginRegistrationDir,
			configuration.KubeletPodsDir,
		},
	}

	for _, chartPath := range renderedChartPaths {
		for _, daemonSet := range daemonSetsFromRenderedChart(t, chartPath) {
			for containerName, paths := range expected {
				c := mustContainer(t, daemonSet, containerName)
				for _, path := range paths {
					mount := mountAt(c, path)
					if mount == nil {
						t.Errorf("%s: %s in DaemonSet %s does not mount %s", chartPath, containerName, daemonSet.Name, path)
						continue
					}
					if hostPath := hostPathOf(daemonSet, mount.Name); hostPath != path {
						t.Errorf("%s: %s in DaemonSet %s mounts volume %s at %s but its host path is %q: the two "+
							"have to be equal", chartPath, containerName, daemonSet.Name, mount.Name, path, hostPath)
					}
				}
			}
		}
	}
}

// The agent writes its socket into the shared directory and the sidecar only publishes it.
// The sidecar's mount being read-only is what makes every bind of it read-only on the host.
func TestChartDaemonSetSharesTheSocketDirectoryReadOnlyWithTheSidecar(t *testing.T) {
	for _, chartPath := range renderedChartPaths {
		for _, daemonSet := range daemonSetsFromRenderedChart(t, chartPath) {
			agentMount := mountAt(mustContainer(t, daemonSet, agentContainerName), configuration.WorkloadIdentitySocketMountPath)
			sidecarMount := mountAt(mustContainer(t, daemonSet, csiDriverContainerName), configuration.WorkloadIdentitySocketMountPath)
			if agentMount == nil || sidecarMount == nil {
				t.Fatalf("%s: DaemonSet %s does not mount the socket directory in both containers", chartPath, daemonSet.Name)
			}
			if agentMount.ReadOnly {
				t.Errorf("%s: DaemonSet %s mounts the socket directory read-only in the agent, which binds its socket there",
					chartPath, daemonSet.Name)
			}
			if !sidecarMount.ReadOnly {
				t.Errorf("%s: DaemonSet %s mounts the socket directory writable in the CSI driver sidecar, so the "+
					"bind mounts it publishes are writable on the host", chartPath, daemonSet.Name)
			}
			if agentMount.Name != sidecarMount.Name {
				t.Errorf("%s: DaemonSet %s mounts the socket directory from volumes %s and %s",
					chartPath, daemonSet.Name, agentMount.Name, sidecarMount.Name)
			}
		}
	}
}

// TestChartDaemonSetPublishesWithBidirectionalPropagation covers what makes the bind mount
// visible outside the sidecar's namespace. With any other propagation the publish reports
// success, the kubelet finds an empty directory, and the pod starts with no socket.
func TestChartDaemonSetPublishesWithBidirectionalPropagation(t *testing.T) {
	for _, chartPath := range renderedChartPaths {
		for _, daemonSet := range daemonSetsFromRenderedChart(t, chartPath) {
			mount := mountAt(mustContainer(t, daemonSet, csiDriverContainerName), configuration.KubeletPodsDir)
			if mount == nil {
				t.Errorf("%s: DaemonSet %s does not mount %s in the CSI driver sidecar",
					chartPath, daemonSet.Name, configuration.KubeletPodsDir)
				continue
			}
			if mount.MountPropagation == nil || *mount.MountPropagation != corev1.MountPropagationBidirectional {
				t.Errorf("%s: DaemonSet %s mounts %s with propagation %v, so a published mount is invisible to "+
					"the kubelet", chartPath, daemonSet.Name, mount.MountPath, mount.MountPropagation)
			}
		}
	}
}

// TestChartDaemonSetKeepsTheAgentUnprivileged records the point of the split: Kubernetes
// allows Bidirectional propagation only for a privileged container, and that container is
// the sidecar, not the agent every pod on the node talks to. The sidecar gets exactly the
// mounts it needs and a read-only root filesystem.
func TestChartDaemonSetKeepsTheAgentUnprivileged(t *testing.T) {
	kubeletDirs := []string{
		configuration.KubeletPluginDir,
		configuration.KubeletPluginRegistrationDir,
		configuration.KubeletPodsDir,
	}
	sidecarMounts := append([]string{configuration.WorkloadIdentitySocketMountPath}, kubeletDirs...)

	for _, chartPath := range renderedChartPaths {
		for _, daemonSet := range daemonSetsFromRenderedChart(t, chartPath) {
			agent := mustContainer(t, daemonSet, agentContainerName)
			if privileged(agent) {
				t.Errorf("%s: DaemonSet %s runs the agent privileged", chartPath, daemonSet.Name)
			}
			if c := agent.SecurityContext; c == nil || c.Capabilities == nil ||
				!slices.Equal(c.Capabilities.Add, []corev1.Capability{"CAP_NET_BIND_SERVICE"}) {
				t.Errorf("%s: DaemonSet %s adds capabilities other than CAP_NET_BIND_SERVICE to the agent: %v",
					chartPath, daemonSet.Name, agent.SecurityContext)
			}
			for _, path := range kubeletDirs {
				if mountAt(agent, path) != nil {
					t.Errorf("%s: DaemonSet %s mounts %s in the agent, which only the sidecar needs",
						chartPath, daemonSet.Name, path)
				}
			}

			sidecar := mustContainer(t, daemonSet, csiDriverContainerName)
			if !privileged(sidecar) {
				t.Errorf("%s: DaemonSet %s does not run the CSI driver sidecar privileged, which Bidirectional "+
					"propagation requires", chartPath, daemonSet.Name)
			}
			if c := sidecar.SecurityContext; c == nil || c.ReadOnlyRootFilesystem == nil || !*c.ReadOnlyRootFilesystem {
				t.Errorf("%s: DaemonSet %s gives the privileged sidecar a writable root filesystem", chartPath, daemonSet.Name)
			}
			var mounted []string
			for _, mount := range sidecar.VolumeMounts {
				mounted = append(mounted, mount.MountPath)
			}
			if !slices.Equal(slices.Sorted(slices.Values(mounted)), slices.Sorted(slices.Values(sidecarMounts))) {
				t.Errorf("%s: DaemonSet %s mounts %v in the privileged sidecar, want exactly %v",
					chartPath, daemonSet.Name, mounted, sidecarMounts)
			}
		}
	}
}

// The sidecar runs a binary the agent's image has to ship. A mismatch renders fine and
// crash loops on every node.
func TestChartDaemonSetRunsTheCSIDriverBinaryTheImageShips(t *testing.T) {
	dockerfile, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatalf("reading the Dockerfile: %v", err)
	}
	if !strings.Contains(string(dockerfile), "bin/eks-pod-identity-csi-driver "+csiDriverBinary) {
		t.Errorf("the Dockerfile does not copy the CSI driver binary to %s", csiDriverBinary)
	}

	for _, chartPath := range renderedChartPaths {
		for _, daemonSet := range daemonSetsFromRenderedChart(t, chartPath) {
			sidecar := mustContainer(t, daemonSet, csiDriverContainerName)
			agent := mustContainer(t, daemonSet, agentContainerName)
			if !slices.Contains(sidecar.Command, csiDriverBinary) {
				t.Errorf("%s: DaemonSet %s runs %v in the CSI driver sidecar, not %s",
					chartPath, daemonSet.Name, sidecar.Command, csiDriverBinary)
			}
			if sidecar.Image != agent.Image {
				t.Errorf("%s: DaemonSet %s runs the sidecar from %s and the agent from %s; the binary ships in the "+
					"agent's image", chartPath, daemonSet.Name, sidecar.Image, agent.Image)
			}
		}
	}
}

// TestChartDaemonSetSetsTheNodeNameFromTheDownwardAPI keeps the ordinary path off the
// driver's hostname fallback.
func TestChartDaemonSetSetsTheNodeNameFromTheDownwardAPI(t *testing.T) {
	for _, chartPath := range renderedChartPaths {
		for _, daemonSet := range daemonSetsFromRenderedChart(t, chartPath) {
			var found bool
			for _, env := range mustContainer(t, daemonSet, csiDriverContainerName).Env {
				if env.Name != "NODE_NAME" {
					continue
				}
				found = true
				if env.ValueFrom == nil || env.ValueFrom.FieldRef == nil ||
					env.ValueFrom.FieldRef.FieldPath != "spec.nodeName" {
					t.Errorf("%s: DaemonSet %s sets NODE_NAME from %v rather than from spec.nodeName",
						chartPath, daemonSet.Name, env.ValueFrom)
				}
			}
			if !found {
				t.Errorf("%s: DaemonSet %s does not set NODE_NAME on the CSI driver sidecar, so it falls back to "+
					"the hostname for its node ID", chartPath, daemonSet.Name)
			}
		}
	}
}

// TestChartDaemonSetOmitsTheCSIWiringInAnIsolatedRegion is the DaemonSet half of the region
// gate: no sidecar, so no privileged container and no kubelet or socket directory mounts.
func TestChartDaemonSetOmitsTheCSIWiringInAnIsolatedRegion(t *testing.T) {
	absent := []string{
		configuration.WorkloadIdentitySocketMountPath,
		configuration.KubeletPluginDir,
		configuration.KubeletPluginRegistrationDir,
		configuration.KubeletPodsDir,
	}

	for _, daemonSet := range daemonSetsFromRenderedChart(t, isolatedRegionChartPath) {
		if container(daemonSet, csiDriverContainerName) != nil {
			t.Errorf("%s: DaemonSet %s runs the CSI driver sidecar, which an isolated region does not use",
				isolatedRegionChartPath, daemonSet.Name)
		}
		agent := mustContainer(t, daemonSet, agentContainerName)
		if privileged(agent) {
			t.Errorf("%s: DaemonSet %s runs the agent privileged", isolatedRegionChartPath, daemonSet.Name)
		}
		for _, path := range absent {
			if mountAt(agent, path) != nil {
				t.Errorf("%s: DaemonSet %s mounts %s in the agent", isolatedRegionChartPath, daemonSet.Name, path)
			}
			for _, volume := range daemonSet.Spec.Template.Spec.Volumes {
				if volume.HostPath != nil && volume.HostPath.Path == path {
					t.Errorf("%s: DaemonSet %s declares host volume %s for %s, which nothing in this rendering "+
						"consumes", isolatedRegionChartPath, daemonSet.Name, volume.Name, path)
				}
			}
		}
	}
}
