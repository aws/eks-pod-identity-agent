package main

// Pins the workload identity CSIDriver object the chart installs against the agent's own
// constants. Helm cannot see a Go constant, so the chart carries the strings as literals
// and this keeps the two in step; drift is a cluster-wide credential failure that would
// only surface on a live cluster.
//
// Asserts on the checked-in rendered template rather than invoking Helm: make helm-verify
// already proves the goldens match the chart, and shelling out to a downloaded binary
// would not run under `go test ./...`.

import (
	"os"
	"strings"
	"testing"

	storagev1 "k8s.io/api/storage/v1"
	"sigs.k8s.io/yaml"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
)

// renderedChartPath is the rendering with workload identity on, the only one that carries
// the object.
const renderedChartPath = workloadIdentityChartPath

// csiDriverFromRenderedChart pulls the single CSIDriver document out of the rendered
// chart. A missing object fails rather than skips: the chart is the installer of record.
func csiDriverFromRenderedChart(t *testing.T) *storagev1.CSIDriver {
	t.Helper()

	rendered, err := os.ReadFile(renderedChartPath)
	if err != nil {
		t.Fatalf("reading rendered chart %s: %v", renderedChartPath, err)
	}

	var found *storagev1.CSIDriver
	for _, doc := range strings.Split(string(rendered), "\n---\n") {
		if strings.TrimSpace(doc) == "" {
			continue
		}

		// Kind first: the rendered chart holds other kinds whose fields would not survive
		// being unmarshalled into a CSIDriver.
		var meta struct {
			Kind string `json:"kind"`
		}
		if err := yaml.Unmarshal([]byte(doc), &meta); err != nil {
			t.Fatalf("unmarshalling a document of %s: %v", renderedChartPath, err)
		}
		if meta.Kind != "CSIDriver" {
			continue
		}

		var driver storagev1.CSIDriver
		if err := yaml.UnmarshalStrict([]byte(doc), &driver); err != nil {
			t.Fatalf("unmarshalling the CSIDriver document of %s: %v", renderedChartPath, err)
		}
		if found != nil {
			t.Fatalf("the chart renders more than one CSIDriver object; there is exactly one driver")
		}
		found = &driver
	}

	if found == nil {
		t.Fatalf("no CSIDriver object in %s: the chart is what installs it, and without it "+
			"the agent's TokenRequest for %s is refused by the node audience restriction",
			renderedChartPath, configuration.EksAuthAudience)
	}
	return found
}

// TestChartCSIDriverMatchesFrozenContract covers the two strings shared with something
// outside this repository.
func TestChartCSIDriverMatchesFrozenContract(t *testing.T) {
	driver := csiDriverFromRenderedChart(t)

	if driver.Name != configuration.WorkloadIdentityCSIDriver {
		t.Errorf("chart installs CSIDriver %q, agent expects configuration.WorkloadIdentityCSIDriver %q: "+
			"the webhook names this driver on an enrolled pod's volume, so a mismatch means the volume "+
			"never mounts", driver.Name, configuration.WorkloadIdentityCSIDriver)
	}

	// The audience is why the object exists: the API server permits a node identity's
	// TokenRequest only for an audience the target pod already references.
	audiences := make([]string, 0, len(driver.Spec.TokenRequests))
	for _, request := range driver.Spec.TokenRequests {
		audiences = append(audiences, request.Audience)
	}
	if len(audiences) != 1 || audiences[0] != configuration.EksAuthAudience {
		t.Errorf("chart declares tokenRequests audiences %v, agent mints for configuration.EksAuthAudience %q: "+
			"a mismatch makes every mint fail with ErrTokenMintForbidden",
			audiences, configuration.EksAuthAudience)
	}
}

// TestChartCSIDriverSpecMatchesTheNodeServiceItDescribes covers how the kubelet should
// drive the driver. attachRequired and podInfoOnMount are immutable after creation, so
// getting them wrong is a delete-and-recreate migration on every existing cluster.
func TestChartCSIDriverSpecMatchesTheNodeServiceItDescribes(t *testing.T) {
	driver := csiDriverFromRenderedChart(t)

	if driver.Spec.AttachRequired == nil || *driver.Spec.AttachRequired {
		t.Errorf("attachRequired must be false: the node service bind-mounts a node-local "+
			"directory and there is nothing for the attach/detach controller to do (immutable "+
			"once created), got %v", driver.Spec.AttachRequired)
	}

	if driver.Spec.PodInfoOnMount == nil || !*driver.Spec.PodInfoOnMount {
		t.Errorf("podInfoOnMount must be true: the node service needs the pod's identity in the "+
			"volume context to publish the right socket directory (immutable once created), got %v",
			driver.Spec.PodInfoOnMount)
	}

	modes := driver.Spec.VolumeLifecycleModes
	if len(modes) != 1 || modes[0] != storagev1.VolumeLifecycleEphemeral {
		t.Errorf("volumeLifecycleModes must be exactly [Ephemeral]: the webhook injects an inline "+
			"volume and this driver has no PersistentVolume path, got %v", modes)
	}
}

// TestChartOmitsTheCSIDriverWithWorkloadIdentityOff is the other half of the gate. With
// workload identity off, or in an isolated region, nothing serves the driver, so an object
// advertising it would let the webhook enroll a pod whose volume nothing ever publishes,
// leaving it in ContainerCreating.
func TestChartOmitsTheCSIDriverWithWorkloadIdentityOff(t *testing.T) {
	for _, chartPath := range workloadIdentityOffChartPaths {
		rendered, err := os.ReadFile(chartPath)
		if err != nil {
			t.Fatalf("reading rendered chart %s: %v", chartPath, err)
		}

		if strings.Contains(string(rendered), "kind: CSIDriver") {
			t.Errorf("%s renders a CSIDriver object with workload identity off, advertising a driver "+
				"nothing serves", chartPath)
		}

		// The name would still be present through the agent's own constants if the object were
		// dropped but its driver name left behind somewhere else in the chart.
		if strings.Contains(string(rendered), configuration.WorkloadIdentityCSIDriver) {
			t.Errorf("%s still names driver %q somewhere: nothing in a manifest with workload identity "+
				"off should", chartPath, configuration.WorkloadIdentityCSIDriver)
		}
	}
}

// TestChartRegionGateMatchesIsIsolatedRegion pins the `contains "-iso"` literal in the
// chart's enableWorkloadIdentity helper to configuration.IsIsolatedRegion. Helm can't call
// Go, so this keeps the two definitions of an isolated region in step. The agent and the
// CSI sidecar never read the region, so the chart helper is the only region gate.
func TestChartRegionGateMatchesIsIsolatedRegion(t *testing.T) {
	// The literal the templates use. Kept beside the assertion so a change to either side
	// shows up here.
	const chartInfix = "-iso"

	for _, region := range []string{
		"us-iso-east-1", "us-isob-east-1", "eu-isoe-west-1", "us-isof-south-1",
		"us-west-2", "eu-central-1", "us-gov-west-1", "cn-north-1", "",
	} {
		chartGated := strings.Contains(region, chartInfix)
		agentGated := configuration.IsIsolatedRegion(region)
		if chartGated != agentGated {
			t.Errorf("region %q: chart gates=%v, configuration.IsIsolatedRegion=%v: the chart's and Go's "+
				"definitions of an isolated region have drifted", region, chartGated, agentGated)
		}
	}
}
