package fake

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// attestorTestTimeout bounds every wait in this file, so a fake that never
// returns fails the test instead of hanging the suite.
const attestorTestTimeout = 2 * time.Second

// errAttestorCanned is the canned error the fake is told to return.
var errAttestorCanned = errors.New("attestor fake: canned failure")

// errAttestorFromFunc is returned by a Func override, so a test can tell the two
// error paths apart.
var errAttestorFromFunc = errors.New("attestor fake: failure from Func")

// attestorResult carries what Attest returned from the goroutine it ran on.
type attestorResult struct {
	workload *workloadidentity.Workload
	err      error
}

// attestorTestContext returns a context that expires after attestorTestTimeout
// and is cancelled when the test ends.
func attestorTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), attestorTestTimeout)
	t.Cleanup(cancel)
	return ctx
}

// attestorWorkload builds the canned attestation result. It returns a fresh
// value each time so a test that mutates one does not affect another.
func attestorWorkload() *workloadidentity.Workload {
	return &workloadidentity.Workload{
		PodUID:         "1f0a5c9e-6f1b-4f4a-9f2a-0d8e2b6c1a33",
		PodName:        "shipping-7d9f4c",
		Namespace:      "shipping",
		ServiceAccount: "shipping-sa",
		NodeName:       "ip-10-0-1-7.ec2.internal",
	}
}

// attestorOtherWorkload builds a second canned result, distinct from
// attestorWorkload in every field.
func attestorOtherWorkload() *workloadidentity.Workload {
	return &workloadidentity.Workload{
		PodUID:         "9c3d7a11-2b44-4c8e-bb01-5e7d9f0c2a41",
		PodName:        "billing-5b1c2d",
		Namespace:      "billing",
		ServiceAccount: "billing-sa",
		NodeName:       "ip-10-0-2-9.ec2.internal",
	}
}

// stubPeer is a distinct workloadidentity.Peer per call, compared by identity.
type stubPeer struct{ pid int }

func (p *stubPeer) PID() int     { return p.pid }
func (p *stubPeer) Alive() error { return nil }

func attestorPeer(t *testing.T) workloadidentity.Peer {
	t.Helper()
	return &stubPeer{pid: 1}
}

// attestorExpectWorkload asserts every field of got against want, or that got is
// nil when want is nil.
func attestorExpectWorkload(g *WithT, got, want *workloadidentity.Workload) {
	if want == nil {
		g.Expect(got).To(BeNil())
		return
	}
	g.Expect(got).ToNot(BeNil())
	g.Expect(got.PodUID).To(Equal(want.PodUID))
	g.Expect(got.PodName).To(Equal(want.PodName))
	g.Expect(got.Namespace).To(Equal(want.Namespace))
	g.Expect(got.ServiceAccount).To(Equal(want.ServiceAccount))
	g.Expect(got.NodeName).To(Equal(want.NodeName))
}

// attestorExpectPeers asserts the recorded peers are exactly want, by
// identity and in order.
func attestorExpectPeers(g *WithT, got, want []workloadidentity.Peer) {
	g.Expect(got).To(HaveLen(len(want)))
	for i := range want {
		if want[i] == nil {
			g.Expect(got[i]).To(BeNil())
			continue
		}
		g.Expect(got[i]).To(BeIdenticalTo(want[i]))
	}
}

// attestorAwait receives one result, failing the test rather than blocking
// forever if Attest never returns.
func attestorAwait(t *testing.T, ctx context.Context, results <-chan attestorResult) attestorResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-ctx.Done():
		t.Fatalf("Attest did not return before the test context expired: %v", ctx.Err())
		return attestorResult{}
	}
}

// attestorAttestAsync calls Attest on a new goroutine and returns the channel
// its result arrives on.
func attestorAttestAsync(ctx context.Context, a *Attestor, conn workloadidentity.Peer) <-chan attestorResult {
	results := make(chan attestorResult, 1)
	go func() {
		workload, err := a.Attest(ctx, conn)
		results <- attestorResult{workload: workload, err: err}
	}()
	return results
}

func TestAttestorAttest_CannedBehaviour_ReturnsThatBehaviourAndRecordsTheCall(t *testing.T) {
	conn := attestorPeer(t)

	testCases := []struct {
		name         string
		attestor     *Attestor
		conn         workloadidentity.Peer
		wantWorkload *workloadidentity.Workload
		wantErr      error
	}{
		{
			name:         "canned workload",
			attestor:     &Attestor{Result: attestorWorkload()},
			conn:         conn,
			wantWorkload: attestorWorkload(),
		},
		{
			name:         "canned workload with a nil conn",
			attestor:     &Attestor{Result: attestorWorkload()},
			conn:         nil,
			wantWorkload: attestorWorkload(),
		},
		{
			name:     "canned error wins over canned workload",
			attestor: &Attestor{Result: attestorWorkload(), Err: errAttestorCanned},
			conn:     conn,
			wantErr:  errAttestorCanned,
		},
		{
			name: "Func wins over canned workload and canned error",
			attestor: &Attestor{
				Result: attestorOtherWorkload(),
				Err:    errAttestorCanned,
				Func: func(ctx context.Context, conn workloadidentity.Peer) (*workloadidentity.Workload, error) {
					return attestorWorkload(), nil
				},
			},
			conn:         conn,
			wantWorkload: attestorWorkload(),
		},
		{
			name: "Func returning an error",
			attestor: &Attestor{
				Result: attestorWorkload(),
				Func: func(ctx context.Context, conn workloadidentity.Peer) (*workloadidentity.Workload, error) {
					return nil, errAttestorFromFunc
				},
			},
			conn:    conn,
			wantErr: errAttestorFromFunc,
		},
		{
			name:     "zero value returns no workload and no error",
			attestor: &Attestor{},
			conn:     conn,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			ctx := attestorTestContext(t)

			got, err := tc.attestor.Attest(ctx, tc.conn)

			if tc.wantErr != nil {
				g.Expect(err).To(MatchError(tc.wantErr))
				g.Expect(got).To(BeNil())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				attestorExpectWorkload(g, got, tc.wantWorkload)
			}
			g.Expect(tc.attestor.Calls()).To(Equal(1))
			attestorExpectPeers(g, tc.attestor.Peers(), []workloadidentity.Peer{tc.conn})
		})
	}
}

func TestAttestorAttest_CalledRepeatedly_CountsCallsAndRecordsPeersInCallOrder(t *testing.T) {
	g := NewWithT(t)
	ctx := attestorTestContext(t)

	first := attestorPeer(t)
	second := attestorPeer(t)

	a := &Attestor{Result: attestorWorkload()}
	g.Expect(a.Calls()).To(Equal(0))
	g.Expect(a.Peers()).To(BeEmpty())

	// nil in the middle, because the fake documents that ignoring the conn makes
	// nil a legal argument.
	wantPeers := []workloadidentity.Peer{first, nil, second, first}
	for _, conn := range wantPeers {
		got, err := a.Attest(ctx, conn)
		g.Expect(err).ToNot(HaveOccurred())
		attestorExpectWorkload(g, got, attestorWorkload())
	}

	g.Expect(a.Calls()).To(Equal(len(wantPeers)))
	attestorExpectPeers(g, a.Peers(), wantPeers)
}

func TestAttestorPeers_ReturnedSliceMutated_FakeIsUnaffected(t *testing.T) {
	g := NewWithT(t)
	ctx := attestorTestContext(t)

	conn := attestorPeer(t)
	a := &Attestor{Result: attestorWorkload()}

	_, err := a.Attest(ctx, conn)
	g.Expect(err).ToNot(HaveOccurred())

	recorded := a.Peers()
	g.Expect(recorded).To(HaveLen(1))
	recorded[0] = nil

	attestorExpectPeers(g, a.Peers(), []workloadidentity.Peer{conn})
}

func TestAttestorAttest_Func_ReceivesCallerArgumentsAndMayCallBackIntoTheFake(t *testing.T) {
	g := NewWithT(t)
	ctx := attestorTestContext(t)

	conn := attestorPeer(t)

	type funcArgs struct {
		ctx           context.Context
		conn          workloadidentity.Peer
		callsSeen     int
		connsSeenLen  int
		firstConnSeen workloadidentity.Peer
	}
	seen := make(chan funcArgs, 1)

	a := &Attestor{}
	a.Func = func(funcCtx context.Context, funcConn workloadidentity.Peer) (*workloadidentity.Workload, error) {
		// Calls and Conns from inside Func would deadlock if the fake held its
		// own lock across the callback.
		conns := a.Peers()
		var firstConn workloadidentity.Peer
		if len(conns) > 0 {
			firstConn = conns[0]
		}
		seen <- funcArgs{
			ctx:           funcCtx,
			conn:          funcConn,
			callsSeen:     a.Calls(),
			connsSeenLen:  len(conns),
			firstConnSeen: firstConn,
		}
		return attestorWorkload(), nil
	}

	results := attestorAttestAsync(ctx, a, conn)
	result := attestorAwait(t, ctx, results)

	g.Expect(result.err).ToNot(HaveOccurred())
	attestorExpectWorkload(g, result.workload, attestorWorkload())

	// Func sent before it returned, and Attest has returned, so the recorded
	// arguments are already in the buffer.
	var args funcArgs
	select {
	case args = <-seen:
	default:
		t.Fatal("Func did not record the arguments it was called with")
	}

	g.Expect(args.ctx).To(BeIdenticalTo(ctx))
	g.Expect(args.conn).To(BeIdenticalTo(conn))
	// The call is counted and recorded before Func runs.
	g.Expect(args.callsSeen).To(Equal(1))
	g.Expect(args.connsSeenLen).To(Equal(1))
	g.Expect(args.firstConnSeen).To(BeIdenticalTo(conn))

	g.Expect(a.Calls()).To(Equal(1))
	attestorExpectPeers(g, a.Peers(), []workloadidentity.Peer{conn})
}

func TestAttestorSetResult_CalledWhileLive_ReplacesCannedBehaviour(t *testing.T) {
	g := NewWithT(t)
	ctx := attestorTestContext(t)

	conn := attestorPeer(t)
	a := &Attestor{Result: attestorWorkload()}

	got, err := a.Attest(ctx, conn)
	g.Expect(err).ToNot(HaveOccurred())
	attestorExpectWorkload(g, got, attestorWorkload())

	a.SetResult(nil, errAttestorCanned)

	got, err = a.Attest(ctx, conn)
	g.Expect(err).To(MatchError(errAttestorCanned))
	g.Expect(got).To(BeNil())

	a.SetResult(attestorOtherWorkload(), nil)

	got, err = a.Attest(ctx, conn)
	g.Expect(err).ToNot(HaveOccurred())
	attestorExpectWorkload(g, got, attestorOtherWorkload())

	g.Expect(a.Calls()).To(Equal(3))
	attestorExpectPeers(g, a.Peers(), []workloadidentity.Peer{conn, conn, conn})
}

func TestAttestorAttest_GateBlocked_ParksUntilReleasedThenReturnsCannedWorkload(t *testing.T) {
	g := NewWithT(t)
	ctx := attestorTestContext(t)

	conn := attestorPeer(t)
	a := &Attestor{Result: attestorWorkload()}
	a.Block()

	results := attestorAttestAsync(ctx, a, conn)

	g.Expect(a.WaitForBlocked(ctx, 1)).To(Succeed())
	g.Expect(a.Blocked()).To(Equal(1))

	// Parked, so nothing has been returned, counted or recorded yet.
	select {
	case result := <-results:
		t.Fatalf("Attest returned %+v while the gate was closed", result)
	default:
	}
	g.Expect(a.Calls()).To(Equal(0))
	g.Expect(a.Peers()).To(BeEmpty())

	a.Release()

	result := attestorAwait(t, ctx, results)
	g.Expect(result.err).ToNot(HaveOccurred())
	attestorExpectWorkload(g, result.workload, attestorWorkload())
	g.Expect(a.Calls()).To(Equal(1))
	attestorExpectPeers(g, a.Peers(), []workloadidentity.Peer{conn})
	g.Expect(a.Blocked()).To(Equal(0))
}

func TestAttestorAttest_SetResultWhileParked_ParkedCallReturnsTheNewResult(t *testing.T) {
	g := NewWithT(t)
	ctx := attestorTestContext(t)

	conn := attestorPeer(t)
	a := &Attestor{Result: attestorWorkload()}
	a.Block()

	results := attestorAttestAsync(ctx, a, conn)
	g.Expect(a.WaitForBlocked(ctx, 1)).To(Succeed())

	a.SetResult(attestorOtherWorkload(), nil)
	a.Release()

	result := attestorAwait(t, ctx, results)
	g.Expect(result.err).ToNot(HaveOccurred())
	attestorExpectWorkload(g, result.workload, attestorOtherWorkload())
	g.Expect(a.Calls()).To(Equal(1))
	attestorExpectPeers(g, a.Peers(), []workloadidentity.Peer{conn})
}

func TestAttestorAttest_ParkedCallContextCancelled_ReturnsContextError(t *testing.T) {
	g := NewWithT(t)
	ctx := attestorTestContext(t)

	conn := attestorPeer(t)
	a := &Attestor{Result: attestorWorkload()}
	a.Block()

	callCtx, cancelCall := context.WithCancel(context.Background())
	t.Cleanup(cancelCall)

	results := attestorAttestAsync(callCtx, a, conn)
	g.Expect(a.WaitForBlocked(ctx, 1)).To(Succeed())

	cancelCall()

	result := attestorAwait(t, ctx, results)
	g.Expect(result.err).To(MatchError(context.Canceled))
	g.Expect(result.workload).To(BeNil())
	g.Expect(a.Calls()).To(Equal(0))
	g.Expect(a.Peers()).To(BeEmpty())
	g.Expect(a.Blocked()).To(Equal(0))

	// The gate is still closed, so a fresh call parks rather than running.
	nextResults := attestorAttestAsync(ctx, a, conn)
	g.Expect(a.WaitForBlocked(ctx, 1)).To(Succeed())
	a.Release()

	next := attestorAwait(t, ctx, nextResults)
	g.Expect(next.err).ToNot(HaveOccurred())
	attestorExpectWorkload(g, next.workload, attestorWorkload())
	g.Expect(a.Calls()).To(Equal(1))
}

func TestAttestorAttest_ContextAlreadyDone_ReturnsContextErrorAndCountsNothing(t *testing.T) {
	testCases := []struct {
		name    string
		block   bool
		callCtx func(t *testing.T) context.Context
		wantErr error
	}{
		{
			name:    "cancelled context, open gate",
			block:   false,
			callCtx: gateCancelledContext,
			wantErr: context.Canceled,
		},
		{
			name:    "cancelled context, closed gate",
			block:   true,
			callCtx: gateCancelledContext,
			wantErr: context.Canceled,
		},
		{
			name:    "expired deadline, closed gate",
			block:   true,
			callCtx: gateExpiredContext,
			wantErr: context.DeadlineExceeded,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			ctx := attestorTestContext(t)

			conn := attestorPeer(t)
			a := &Attestor{Result: attestorWorkload()}
			if tc.block {
				a.Block()
			}

			results := attestorAttestAsync(tc.callCtx(t), a, conn)

			result := attestorAwait(t, ctx, results)
			g.Expect(result.err).To(MatchError(tc.wantErr))
			g.Expect(result.workload).To(BeNil())
			g.Expect(a.Calls()).To(Equal(0))
			g.Expect(a.Peers()).To(BeEmpty())
			g.Expect(a.Blocked()).To(Equal(0))
		})
	}
}

func TestAttestorAttest_ManyParkedCalls_AllReturnCannedWorkloadAfterOneRelease(t *testing.T) {
	g := NewWithT(t)
	ctx := attestorTestContext(t)

	const callers = 5

	conn := attestorPeer(t)
	a := &Attestor{Result: attestorWorkload()}
	a.Block()

	pending := make([]<-chan attestorResult, 0, callers)
	for i := 0; i < callers; i++ {
		pending = append(pending, attestorAttestAsync(ctx, a, conn))
	}

	g.Expect(a.WaitForBlocked(ctx, callers)).To(Succeed())
	g.Expect(a.Blocked()).To(Equal(callers))
	g.Expect(a.Calls()).To(Equal(0))

	a.Release()

	for i, results := range pending {
		result := attestorAwait(t, ctx, results)
		g.Expect(result.err).ToNot(HaveOccurred(), "caller %d", i)
		attestorExpectWorkload(g, result.workload, attestorWorkload())
	}

	g.Expect(a.Calls()).To(Equal(callers))
	g.Expect(a.Blocked()).To(Equal(0))

	recorded := a.Peers()
	g.Expect(recorded).To(HaveLen(callers))
	for i := range recorded {
		g.Expect(recorded[i]).To(BeIdenticalTo(conn), "recorded conn %d", i)
	}
}

func TestAttestorAttest_ConcurrentCallers_CountsEveryCallExactlyOnce(t *testing.T) {
	g := NewWithT(t)
	ctx := attestorTestContext(t)

	const (
		callers        = 8
		callsPerCaller = 25
	)

	conn := attestorPeer(t)
	a := &Attestor{Result: attestorWorkload()}

	failures := make(chan error, callers)
	var wg sync.WaitGroup
	for caller := 0; caller < callers; caller++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for call := 0; call < callsPerCaller; call++ {
				got, err := a.Attest(ctx, conn)
				if err != nil {
					failures <- err
					return
				}
				if got == nil || got.PodUID != attestorWorkload().PodUID {
					failures <- errors.New("Attest returned an unexpected workload")
					return
				}
				// Reading the counters concurrently is what the race detector
				// needs to see.
				_ = a.Calls()
				_ = a.Peers()
			}
		}()
	}
	wg.Wait()
	close(failures)

	var collected []error
	for err := range failures {
		collected = append(collected, err)
	}
	g.Expect(collected).To(BeEmpty())

	g.Expect(a.Calls()).To(Equal(callers * callsPerCaller))
	recorded := a.Peers()
	g.Expect(recorded).To(HaveLen(callers * callsPerCaller))
	for i := range recorded {
		g.Expect(recorded[i]).To(BeIdenticalTo(conn), "recorded conn %d", i)
	}
}

func TestAttestor_ImplementsTheInterfaceAndIsUsableAsAZeroValue(t *testing.T) {
	g := NewWithT(t)
	ctx := attestorTestContext(t)

	var attestor workloadidentity.Attestor = &Attestor{}

	got, err := attestor.Attest(ctx, nil)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(got).To(BeNil())
}
