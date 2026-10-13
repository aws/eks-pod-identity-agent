package attestation

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	. "github.com/onsi/gomega"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// fixturePodUID is the canonical (dash-separated) pod UID encoded in every
// pod-bearing fixture under testdata/. The systemd fixture stores it with
// underscore separators; parsePodUID is expected to normalize it back to this.
const fixturePodUID = "4e8f8d3a-9c3d-4b7e-8f2a-1c2d3e4f5a6b"

func readFixture(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return string(content)
}

// TestParsePodUID_ExtractsUID_AcrossCgroupLayouts pins that the same pod UID is
// recovered from every cgroup v2 layout the fleet produces. It sweeps both
// cgroup drivers (cgroupfs with dash separators, systemd with underscore
// separators) across all three Kubernetes QoS classes, because the QoS class is
// encoded into the cgroup path: Guaranteed pods sit directly under kubepods with
// no QoS segment, while Burstable and BestEffort pods are nested under a
// "burstable"/"besteffort" segment. The pod UID must be recovered identically in
// every case.
func TestParsePodUID_ExtractsUID_AcrossCgroupLayouts(t *testing.T) {
	testCases := []struct {
		name    string
		fixture string
	}{
		{name: "cgroupfs driver, guaranteed QoS, no QoS segment", fixture: "cgroup_v2_cgroupfs_guaranteed"},
		{name: "cgroupfs driver, burstable QoS", fixture: "cgroup_v2_cgroupfs_burstable"},
		{name: "cgroupfs driver, besteffort QoS", fixture: "cgroup_v2_cgroupfs_besteffort"},
		{name: "systemd driver, guaranteed QoS, no QoS segment", fixture: "cgroup_v2_systemd_guaranteed"},
		{name: "systemd driver, burstable QoS", fixture: "cgroup_v2_systemd_burstable"},
		{name: "systemd driver, besteffort QoS", fixture: "cgroup_v2_systemd_besteffort"},
		{name: "bottlerocket, systemd driver, containerd runtime", fixture: "cgroup_v2_bottlerocket"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			uid, err := parsePodUID(readFixture(t, tc.fixture))

			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(uid).To(Equal(fixturePodUID),
				"the UID must come back in canonical dash form regardless of cgroup driver")
		})
	}
}

// TestParsePodUID_ReturnsErrNoPodUID covers the inputs that carry no pod: a host
// process under system.slice, empty content, and cgroup-shaped lines whose paths
// hold no pod segment. Each must return the ErrNoPodUID sentinel so the attestor
// can map it onto ReasonCgroupNoPodUID rather than mistaking it for a read error.
func TestParsePodUID_ReturnsErrNoPodUID(t *testing.T) {
	testCases := []struct {
		name    string
		content string
	}{
		{name: "host process under system.slice", content: readFixtureLazy("cgroup_no_pod")},
		{name: "empty file", content: ""},
		{name: "blank lines only", content: "\n\n  \n"},
		{name: "cgroup line with no pod segment", content: "0::/user.slice/user-1000.slice/session-3.scope"},
		{name: "a bare uuid without the pod prefix is not a match", content: "0::/foo/4e8f8d3a-9c3d-4b7e-8f2a-1c2d3e4f5a6b/bar"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			_, err := parsePodUID(tc.content)

			g.Expect(err).To(MatchError(ErrNoPodUID))
		})
	}
}

// readFixtureLazy reads a fixture outside a *testing.T (for use in table
// literals). It panics on failure, which surfaces as a test setup failure.
func readFixtureLazy(name string) string {
	content, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		panic(err)
	}
	return string(content)
}

// TestPodUIDForPID_ReadsProcCgroup drives the resolver end to end against a /proc
// laid out in a temp dir, proving it reads the right file and returns the parsed
// UID.
func TestPodUIDForPID_ReadsProcCgroup(t *testing.T) {
	g := NewWithT(t)

	const pid = 4242
	procRoot := t.TempDir()
	pidDir := filepath.Join(procRoot, strconv.Itoa(pid))
	g.Expect(os.MkdirAll(pidDir, 0o755)).To(Succeed())
	g.Expect(os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte(readFixture(t, "cgroup_v2_systemd_besteffort")), 0o644)).To(Succeed())

	r := &procResolver{procRoot: procRoot}
	uid, err := r.PodUIDForPID(pid)

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(uid).To(Equal(fixturePodUID))
}

// TestPodUIDForPID_MissingProcEntry_WrapsReadError proves a gone process (no
// /proc/<pid>/cgroup) surfaces as a read error, not as ErrNoPodUID. The attestor
// counts it as liveness_recheck_failed when the pin is dead, never as
// cgroup_no_pod_uid, which means the process exists but is not in a pod.
func TestPodUIDForPID_MissingProcEntry_WrapsReadError(t *testing.T) {
	g := NewWithT(t)

	r := &procResolver{procRoot: t.TempDir()}
	_, err := r.PodUIDForPID(999999)

	g.Expect(err).To(HaveOccurred())
	g.Expect(err).NotTo(MatchError(ErrNoPodUID))
	g.Expect(errors.Is(err, os.ErrNotExist)).To(BeTrue(), "the underlying os error must remain inspectable through the wrap")
}
