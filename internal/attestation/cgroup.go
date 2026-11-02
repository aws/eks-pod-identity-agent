// Package attestation resolves the process on the other end of an accepted Unix
// socket connection to the Kubernetes pod it belongs to. Identity is established
// from the kernel and from API-server state, never from anything the caller
// sends.
//
// This file covers one link in that chain: turning a process ID into the UID of
// the pod that process belongs to, by reading the process's cgroup membership
// under /proc.
package attestation

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ErrNoPodUID is returned when a process's cgroup paths carry no recognizable
// pod UID. It is a distinct sentinel, rather than the taxonomy's ErrUnattestable,
// so the cgroup layer stays testable without importing the error package: the
// attestor maps this onto the ReasonCgroupNoPodUID metric reason and refuses with
// ErrUnattestable.
var ErrNoPodUID = errors.New("no pod UID found in cgroup paths")

// CgroupResolver turns a process ID into the UID of the Kubernetes pod that
// process belongs to. It is a small interface so the attestor can be tested with
// a fake and this implementation can be tested against recorded /proc fixtures,
// neither needing a live kernel cgroup hierarchy.
type CgroupResolver interface {
	// PodUIDForPID reads the cgroup membership of pid and returns the UID of the
	// pod it belongs to, in canonical dash-separated form. It returns ErrNoPodUID
	// when the process is not part of a pod (a host process, or the agent
	// itself), and a wrapped read error when /proc cannot be read for pid.
	PodUIDForPID(pid int) (string, error)
}

// procResolver reads cgroup membership from a /proc filesystem. procRoot is a
// field rather than the literal "/proc" so tests point it at recorded fixtures.
type procResolver struct {
	procRoot string
}

// NewCgroupResolver returns a CgroupResolver that reads the live /proc.
func NewCgroupResolver() CgroupResolver {
	return &procResolver{procRoot: "/proc"}
}

// PodUIDForPID reads <procRoot>/<pid>/cgroup and extracts the pod UID from it.
func (r *procResolver) PodUIDForPID(pid int) (string, error) {
	path := filepath.Join(r.procRoot, strconv.Itoa(pid), "cgroup")
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading cgroup for pid %d: %w", pid, err)
	}
	return parsePodUID(string(content))
}

// podUIDPattern matches a "pod<uuid>" segment in a cgroup path. The UUID's group
// separators are matched as either "-" or "_": the systemd cgroup driver renders
// them as underscores (kubepods-besteffort-pod<uid>.slice) while the cgroupfs
// driver keeps dashes (kubepods/besteffort/pod<uid>). The hex is matched
// case-insensitively even though Kubernetes UIDs are lowercase, so a differently
// cased value is still recognized rather than silently missed.
var podUIDPattern = regexp.MustCompile(`pod([0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12})`)

// parsePodUID scans a /proc/<pid>/cgroup file for the pod UID. The agent targets
// AL2023 and Bottlerocket nodes, which both use cgroup v2 with the systemd
// cgroup driver: a single unified line of the form 0::<cgroup-path>, where pods
// sit under kubepods.slice/.../cri-containerd-<id>.scope. Only the third
// colon-separated field, the path, is inspected; the first match wins and its
// separators are normalized to dashes so the result is the pod's canonical UID
// regardless of cgroup driver.
//
// This is independent of the pod's QoS class. Kubernetes encodes the QoS class in
// the cgroup path -- Burstable and BestEffort pods are nested under a
// "burstable"/"besteffort" segment, while Guaranteed pods sit directly under
// kubepods with no QoS segment -- but the "pod<uid>" segment is present in every
// case, so matching it recovers the UID for all three classes.
func parsePodUID(cgroupFile string) (string, error) {
	for _, line := range strings.Split(cgroupFile, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// cgroup v2 unified line: 0::<cgroup-path>. SplitN with 3 keeps any ':'
		// inside the path intact in the last field.
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		if m := podUIDPattern.FindStringSubmatch(parts[2]); m != nil {
			return strings.ReplaceAll(m[1], "_", "-"), nil
		}
	}
	return "", ErrNoPodUID
}
