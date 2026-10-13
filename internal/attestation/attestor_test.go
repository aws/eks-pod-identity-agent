package attestation

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// fakePeer is a workloadidentity.Peer. aliveErrs is consumed one per Alive
// call, so a test can fail the pre-check or only the post-check.
type fakePeer struct {
	fakePID   int
	aliveErrs []error
	events    *[]string
}

func (f *fakePeer) PID() int { return f.fakePID }

func (f *fakePeer) Alive() error {
	if f.events != nil {
		*f.events = append(*f.events, "alive")
	}
	if len(f.aliveErrs) == 0 {
		return nil
	}
	err := f.aliveErrs[0]
	f.aliveErrs = f.aliveErrs[1:]
	return err
}

// fakePods is an injected PodGetter. It records each lookup against the shared
// event sink.
type fakePods struct {
	byUID  map[string]*PodInfo
	events *[]string
}

func (f *fakePods) PodByUID(uid string) (*PodInfo, bool) {
	if f.events != nil {
		*f.events = append(*f.events, "resolve")
	}
	p, ok := f.byUID[uid]
	return p, ok
}

// fakeCgroup is an injected CgroupResolver returning a fixed UID or error,
// ignoring the PID.
type fakeCgroup struct {
	uid string
	err error
}

func (f *fakeCgroup) PodUIDForPID(int) (string, error) { return f.uid, f.err }

const (
	testNode   = "ip-10-0-1-23.us-west-2.compute.internal"
	testPodUID = "4e8f8d3a-9c3d-4b7e-8f2a-1c2d3e4f5a6b"
)

func knownPod(node string) *PodInfo {
	return &PodInfo{
		UID:            testPodUID,
		Name:           "web-0",
		Namespace:      "team-a",
		ServiceAccount: "web",
		NodeName:       node,
	}
}

// TestAttest_KnownPod_ReturnsPopulatedWorkload proves the happy path fills every
// Workload field and closes the peer handle.
func TestAttest_KnownPod_ReturnsPopulatedWorkload(t *testing.T) {
	g := NewWithT(t)

	peer := &fakePeer{fakePID: 4242}
	att := newAttestor(testNode,
		&fakePods{byUID: map[string]*PodInfo{testPodUID: knownPod(testNode)}},
		&fakeCgroup{uid: testPodUID})

	w, err := att.Attest(context.Background(), peer)

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(w.PodUID).To(Equal(testPodUID))
	g.Expect(w.PodName).To(Equal("web-0"))
	g.Expect(w.Namespace).To(Equal("team-a"))
	g.Expect(w.ServiceAccount).To(Equal("web"))
	g.Expect(w.NodeName).To(Equal(testNode))
}

// TestAttest_RechecksAfterResolution asserts ordering rather than outcome: the
// liveness recheck must run after the pod has been resolved, since a recheck
// before resolution proves nothing about the window that matters.
func TestAttest_RechecksAfterResolution(t *testing.T) {
	g := NewWithT(t)

	var events []string
	peer := &fakePeer{fakePID: 4242, events: &events}
	att := newAttestor(testNode,
		&fakePods{byUID: map[string]*PodInfo{testPodUID: knownPod(testNode)}, events: &events},
		&fakeCgroup{uid: testPodUID})

	_, err := att.Attest(context.Background(), peer)

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(events).To(Equal([]string{"alive", "resolve", "alive"}),
		"liveness must be rechecked after pod resolution")
}

// TestAttest_RefusalPaths covers every refusal reachable through the injected
// seams, asserting each returns ErrUnattestable and names its reason.
func TestAttest_RefusalPaths(t *testing.T) {
	errDead := errors.New("process exited")
	testCases := []struct {
		name   string
		pods   *fakePods
		cgroup *fakeCgroup
		peer   *fakePeer
		reason string
	}{
		{
			name:   "peer gone before this RPC",
			peer:   &fakePeer{fakePID: 1, aliveErrs: []error{errDead}},
			reason: workloadidentity.ReasonPeerGone,
		},
		{
			name:   "cgroup carries no pod uid",
			peer:   &fakePeer{fakePID: 1},
			cgroup: &fakeCgroup{err: ErrNoPodUID},
			reason: workloadidentity.ReasonCgroupNoPodUID,
		},
		{
			name:   "cgroup entry gone because the peer exited mid-read",
			peer:   &fakePeer{fakePID: 1, aliveErrs: []error{nil, errDead}},
			cgroup: &fakeCgroup{err: os.ErrNotExist},
			reason: workloadidentity.ReasonLivenessRecheckFailed,
		},
		{
			name:   "cgroup read fails, peer alive (permission/io)",
			peer:   &fakePeer{fakePID: 1},
			cgroup: &fakeCgroup{err: os.ErrPermission},
			reason: workloadidentity.ReasonCgroupReadFailed,
		},
		{
			name:   "pod not in node store",
			peer:   &fakePeer{fakePID: 1},
			cgroup: &fakeCgroup{uid: testPodUID},
			pods:   &fakePods{byUID: map[string]*PodInfo{}},
			reason: workloadidentity.ReasonPodNotInStore,
		},
		{
			name:   "pod not in store, but the PID was reused: the recheck wins",
			peer:   &fakePeer{fakePID: 1, aliveErrs: []error{nil, errDead}},
			cgroup: &fakeCgroup{uid: testPodUID},
			pods:   &fakePods{byUID: map[string]*PodInfo{}},
			reason: workloadidentity.ReasonLivenessRecheckFailed,
		},
		{
			name:   "pod bound to another node",
			peer:   &fakePeer{fakePID: 1},
			cgroup: &fakeCgroup{uid: testPodUID},
			pods:   &fakePods{byUID: map[string]*PodInfo{testPodUID: knownPod("some-other-node")}},
			reason: workloadidentity.ReasonPodNodeMismatch,
		},
		{
			name:   "liveness recheck fails after resolution",
			peer:   &fakePeer{fakePID: 1, aliveErrs: []error{nil, errDead}},
			cgroup: &fakeCgroup{uid: testPodUID},
			pods:   &fakePods{byUID: map[string]*PodInfo{testPodUID: knownPod(testNode)}},
			reason: workloadidentity.ReasonLivenessRecheckFailed,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			pods := tc.pods
			if pods == nil {
				pods = &fakePods{byUID: map[string]*PodInfo{}}
			}
			cgroup := tc.cgroup
			if cgroup == nil {
				cgroup = &fakeCgroup{}
			}
			att := newAttestor(testNode, pods, cgroup)
			att.podRetryAttempts = 1 // single-shot; retry is covered separately

			w, err := att.Attest(context.Background(), tc.peer)

			g.Expect(w).To(BeNil())
			g.Expect(err).To(MatchError(wierrors.ErrUnattestable))
			g.Expect(err.Error()).To(ContainSubstring(tc.reason), "the cause names the reason")
			wiErr, ok := wierrors.AsWorkloadIdentityError(err)
			g.Expect(ok).To(BeTrue())
			g.Expect(wiErr.Message()).To(Equal("attestation refused"), "the caller sees one fixed text")
		})
	}
}

// flakyPods returns a miss for the first hitAfter-1 lookups, then the pod. It
// simulates informer cache lag: the pod's ADD watch event lands only after the
// caller has already asked for it.
type flakyPods struct {
	pod      *PodInfo
	hitAfter int
	calls    int
}

func (f *flakyPods) PodByUID(string) (*PodInfo, bool) {
	f.calls++
	if f.calls >= f.hitAfter {
		return f.pod, true
	}
	return nil, false
}

// TestAttest_PodAppearsAfterCacheLag_Retries proves a pod that is missing on the
// first lookup but appears shortly after (the informer catching up) is attested
// rather than refused.
func TestAttest_PodAppearsAfterCacheLag_Retries(t *testing.T) {
	g := NewWithT(t)

	pods := &flakyPods{
		pod:      &PodInfo{UID: testPodUID, Name: "web-0", Namespace: "team-a", ServiceAccount: "web", NodeName: testNode},
		hitAfter: 3, // miss, miss, then hit
	}
	att := newAttestor(testNode, pods, &fakeCgroup{uid: testPodUID})
	att.podRetryInterval = time.Millisecond
	att.podRetryAttempts = 5

	w, err := att.Attest(context.Background(), &fakePeer{fakePID: 1})

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(w.PodUID).To(Equal(testPodUID))
	g.Expect(pods.calls).To(BeNumerically(">=", 3), "the store must be retried until the pod appears")
}

// TestAttest_PodNeverAppears_RefusesAfterRetry proves the retry is bounded: a UID
// that never appears is refused once the budget is exhausted, rather than
// blocking forever.
func TestAttest_PodNeverAppears_RefusesAfterRetry(t *testing.T) {
	g := NewWithT(t)

	pods := &flakyPods{hitAfter: 1 << 30} // never hits
	att := newAttestor(testNode, pods, &fakeCgroup{uid: testPodUID})
	att.podRetryInterval = time.Millisecond
	att.podRetryAttempts = 3

	_, err := att.Attest(context.Background(), &fakePeer{fakePID: 1})

	g.Expect(err).To(MatchError(wierrors.ErrUnattestable))
	g.Expect(err.Error()).To(ContainSubstring(workloadidentity.ReasonPodNotInStore))
	g.Expect(pods.calls).To(Equal(3), "must make exactly podRetryAttempts lookups before giving up")
}

// TestAttest_NodeMismatch_CountsOwnMetric proves the security-relevant refusal
// increments its own reason series, which is what an operator alarms on.
func TestAttest_NodeMismatch_CountsOwnMetric(t *testing.T) {
	g := NewWithT(t)

	before := testutil.ToFloat64(
		promAttestationTotal.WithLabelValues(workloadidentity.OutcomeFailure, workloadidentity.ReasonPodNodeMismatch))

	att := newAttestor(testNode,
		&fakePods{byUID: map[string]*PodInfo{testPodUID: knownPod("some-other-node")}},
		&fakeCgroup{uid: testPodUID})

	_, err := att.Attest(context.Background(), &fakePeer{fakePID: 1})
	g.Expect(err).To(HaveOccurred())

	after := testutil.ToFloat64(
		promAttestationTotal.WithLabelValues(workloadidentity.OutcomeFailure, workloadidentity.ReasonPodNodeMismatch))
	g.Expect(after - before).To(Equal(1.0))
}
