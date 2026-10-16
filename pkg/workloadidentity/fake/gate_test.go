package fake

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

// gateTestTimeout bounds every wait in this file, so a gate that fails to wake a
// parked call fails the test instead of hanging the suite.
const gateTestTimeout = 2 * time.Second

// gateChurnTimeout bounds the concurrency churn test, which does far more work
// per goroutine than the single-call tests.
const gateChurnTimeout = 10 * time.Second

// gateTestContext returns a context that expires after gateTestTimeout and is
// cancelled when the test ends.
func gateTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), gateTestTimeout)
	t.Cleanup(cancel)
	return ctx
}

// gateCancelledContext returns a context that is already cancelled, together
// with the error it reports.
func gateCancelledContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// gateExpiredContext returns a context whose deadline is already in the past, so
// it is done without the test waiting for anything.
func gateExpiredContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	t.Cleanup(cancel)
	return ctx
}

// gateEnterAsync parks a call at the gate on a new goroutine and returns the
// channel its error arrives on. The channel is buffered so the goroutine
// finishes even if the test stops reading.
func gateEnterAsync(ctx context.Context, gate *Gate) <-chan error {
	errs := make(chan error, 1)
	go func() { errs <- gate.enter(ctx) }()
	return errs
}

// gateAwait receives one error from errs, failing the test rather than blocking
// forever if the call never returns.
func gateAwait(t *testing.T, ctx context.Context, errs <-chan error) error {
	t.Helper()
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		t.Fatalf("call did not return before the test context expired: %v", ctx.Err())
		return nil
	}
}

// gateExpectStillParked fails the test if a call has already returned, which is
// how a gate that does not park is caught.
func gateExpectStillParked(t *testing.T, errs <-chan error) {
	t.Helper()
	select {
	case err := <-errs:
		t.Fatalf("call returned early with %v, want it still waiting", err)
	default:
	}
}

func TestGate_ZeroValue_IsOpenAndDoesNotPark(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)

	var gate Gate

	g.Expect(gate.Blocked()).To(Equal(0))
	g.Expect(gate.enter(ctx)).To(Succeed())
	g.Expect(gate.enter(ctx)).To(Succeed())
	g.Expect(gate.Blocked()).To(Equal(0))
}

func TestGate_Blocked_ParksCallUntilReleased(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)

	var gate Gate
	gate.Block()

	errs := gateEnterAsync(ctx, &gate)

	g.Expect(gate.WaitForBlocked(ctx, 1)).To(Succeed())
	gateExpectStillParked(t, errs)
	g.Expect(gate.Blocked()).To(Equal(1))

	gate.Release()

	g.Expect(gateAwait(t, ctx, errs)).To(Succeed())
	// Release zeroed the count of the generation it ended and the released call
	// leaves the count alone, so this is settled whether or not that call has
	// been scheduled yet.
	g.Expect(gate.Blocked()).To(Equal(0))
	// The gate is open again, so a fresh call is not parked.
	g.Expect(gate.enter(ctx)).To(Succeed())
}

func TestGate_TwoParkedCalls_BothWokenBySingleRelease(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)

	var gate Gate
	gate.Block()

	first := gateEnterAsync(ctx, &gate)
	second := gateEnterAsync(ctx, &gate)

	g.Expect(gate.WaitForBlocked(ctx, 2)).To(Succeed())
	g.Expect(gate.Blocked()).To(Equal(2))
	gateExpectStillParked(t, first)
	gateExpectStillParked(t, second)

	gate.Release()

	g.Expect(gateAwait(t, ctx, first)).To(Succeed())
	g.Expect(gateAwait(t, ctx, second)).To(Succeed())
	g.Expect(gate.Blocked()).To(Equal(0))
}

func TestGate_ReleaseWithNothingParked_LeavesGateOpen(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)

	var gate Gate

	// Release on a never-blocked, zero-valued gate must not panic.
	gate.Release()

	g.Expect(gate.Blocked()).To(Equal(0))
	g.Expect(gate.enter(ctx)).To(Succeed())
}

func TestGate_ReleaseTwiceThenBlock_ParksAgain(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)

	var gate Gate
	gate.Block()
	gate.Release()
	gate.Release()

	gate.Block()
	errs := gateEnterAsync(ctx, &gate)

	// A call parked after two Releases must wait on a fresh signal channel
	// rather than an already closed one.
	g.Expect(gate.WaitForBlocked(ctx, 1)).To(Succeed())
	gateExpectStillParked(t, errs)

	gate.Release()

	g.Expect(gateAwait(t, ctx, errs)).To(Succeed())
	g.Expect(gate.Blocked()).To(Equal(0))
}

func TestGate_BlockReleaseRepeated_ParksOnEveryCycle(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)

	var gate Gate

	for cycle := 1; cycle <= 3; cycle++ {
		gate.Block()
		errs := gateEnterAsync(ctx, &gate)

		g.Expect(gate.WaitForBlocked(ctx, 1)).To(Succeed(), "cycle %d", cycle)
		gateExpectStillParked(t, errs)
		g.Expect(gate.Blocked()).To(Equal(1), "cycle %d", cycle)

		gate.Release()

		g.Expect(gateAwait(t, ctx, errs)).To(Succeed(), "cycle %d", cycle)
		g.Expect(gate.Blocked()).To(Equal(0), "cycle %d", cycle)
		g.Expect(gate.enter(ctx)).To(Succeed(), "cycle %d", cycle)
	}
}

// gateSettleIterations is how many Block/Release cycles the two tests below run.
// One cycle is enough to fail a gate that accounts for a released call
// correctly, because Release settles the count under g.mu; the repetition is
// there to catch a gate that leaves the accounting to the woken goroutine, which
// only sometimes loses the race to the test.
const gateSettleIterations = 50

// gateSettleObservation bounds one observation of a gate that must hold nothing,
// so a false ready signal is caught without the test waiting long for it.
const gateSettleObservation = 5 * time.Millisecond

func TestGate_Release_StopsCountingTheWokenCallBeforeItReturns(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)

	for i := 0; i < gateSettleIterations; i++ {
		var gate Gate
		gate.Block()

		errs := gateEnterAsync(ctx, &gate)
		g.Expect(gate.WaitForBlocked(ctx, 1)).To(Succeed(), "iteration %d", i)

		gate.Release()

		// Read before receiving the call's own result, so the woken goroutine
		// has had no chance to account for itself. Nothing is parked any more,
		// so the only correct answer is zero.
		g.Expect(gate.Blocked()).To(Equal(0), "iteration %d", i)

		g.Expect(gateAwait(t, ctx, errs)).To(Succeed(), "iteration %d", i)
		g.Expect(gate.Blocked()).To(Equal(0), "iteration %d", i)
	}
}

func TestGate_BlockAfterRelease_DoesNotCountThePreviousCyclesCall(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)

	for i := 0; i < gateSettleIterations; i++ {
		var gate Gate
		gate.Block()

		errs := gateEnterAsync(ctx, &gate)
		g.Expect(gate.WaitForBlocked(ctx, 1)).To(Succeed(), "iteration %d", i)
		gate.Release()

		// The new cycle holds nothing, so a wait in it must time out rather than
		// report the call released by the previous cycle as parked. A test that
		// re-blocks and waits again would otherwise proceed against a fake that
		// is holding no call at all.
		gate.Block()
		g.Expect(gate.Blocked()).To(Equal(0), "iteration %d", i)

		waitCtx, cancelWait := context.WithTimeout(ctx, gateSettleObservation)
		err := gate.WaitForBlocked(waitCtx, 1)
		cancelWait()
		g.Expect(err).To(MatchError(context.DeadlineExceeded), "iteration %d", i)

		gate.Release()
		g.Expect(gateAwait(t, ctx, errs)).To(Succeed(), "iteration %d", i)
	}
}

func TestGateEnter_ContextAlreadyDone_ReturnsContextErrorWithoutParking(t *testing.T) {
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
			name:    "expired deadline, open gate",
			block:   false,
			callCtx: gateExpiredContext,
			wantErr: context.DeadlineExceeded,
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
			ctx := gateTestContext(t)

			var gate Gate
			if tc.block {
				gate.Block()
			}

			// Called on a goroutine so a gate that wrongly parks a done call
			// fails the test instead of hanging it.
			errs := gateEnterAsync(tc.callCtx(t), &gate)

			g.Expect(gateAwait(t, ctx, errs)).To(MatchError(tc.wantErr))
			g.Expect(gate.Blocked()).To(Equal(0))
		})
	}
}

func TestGate_ParkedCallContextCancelled_ReturnsContextErrorAndStopsCountingAsBlocked(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)

	var gate Gate
	gate.Block()

	doomedCtx, cancelDoomed := context.WithCancel(context.Background())
	t.Cleanup(cancelDoomed)
	doomed := gateEnterAsync(doomedCtx, &gate)

	survivor := gateEnterAsync(ctx, &gate)

	g.Expect(gate.WaitForBlocked(ctx, 2)).To(Succeed())

	cancelDoomed()

	g.Expect(gateAwait(t, ctx, doomed)).To(MatchError(context.Canceled))
	// The cancelled call decrements before returning, so exactly the surviving
	// call is still counted.
	g.Expect(gate.Blocked()).To(Equal(1))
	// One caller giving up does not reopen the gate.
	gateExpectStillParked(t, survivor)

	gate.Release()

	g.Expect(gateAwait(t, ctx, survivor)).To(Succeed())
	g.Expect(gate.Blocked()).To(Equal(0))
}

// gateTieIterations is how many release-and-cancel rounds the two tie-break
// tests run. A single tie is enough to catch a gate that lets Go's uniformly
// random select pick the loser, but only about half the time, so the loop is
// sized to make missing it implausible.
const gateTieIterations = 200

// gateTieContext is a context that releases a gate and reports itself cancelled
// at the moment enter's select reads its Done channel, so both of that select's
// cases are ready when it runs.
//
// It exists because cancelling a real context and calling Release from the test
// goroutine hardly ever produces the tie those two calls look like they produce:
// a call already parked in the select wakes on whichever channel closes first,
// whatever the other one does afterwards. Only a call that has not reached its
// select yet sees both cases ready, and a test cannot force that. Closing both
// from inside Done can.
type gateTieContext struct {
	release func()
	done    chan struct{}
	once    sync.Once
}

// newGateTieContext returns a context that releases gate and then cancels
// itself, both on the first read of its Done channel.
func newGateTieContext(gate *Gate) *gateTieContext {
	return &gateTieContext{release: gate.Release, done: make(chan struct{})}
}

// Deadline reports no deadline, because this context is cancelled rather than
// timed out.
func (c *gateTieContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done releases the gate and closes the returned channel on its first call, so a
// reader cannot observe one without the other.
func (c *gateTieContext) Done() <-chan struct{} {
	c.once.Do(func() {
		c.release()
		close(c.done)
	})
	return c.done
}

// Err reports context.Canceled once Done has closed the channel and nil before
// that, which is what makes enter park rather than return at its entry check.
func (c *gateTieContext) Err() error {
	select {
	case <-c.done:
		return context.Canceled
	default:
		return nil
	}
}

// Value holds nothing, because no fake in this package reads a context value.
func (c *gateTieContext) Value(any) any { return nil }

func TestGateEnter_ReleasedAndContextCancelledTogether_ReturnsNil(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)

	for i := 0; i < gateTieIterations; i++ {
		var gate Gate
		gate.Block()

		// The call parks, then finds itself released and cancelled at once. It was
		// released, so nil is the only correct answer on every iteration: a gate
		// that leaves the choice to select reports ctx.Err() about half the time.
		errs := gateEnterAsync(newGateTieContext(&gate), &gate)

		g.Expect(gateAwait(t, ctx, errs)).To(Succeed(), "iteration %d", i)
		g.Expect(gate.Blocked()).To(Equal(0), "iteration %d", i)
	}
}

func TestGateEnter_ReleasedThenContextCancelled_ReturnsNil(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)

	for i := 0; i < gateTieIterations; i++ {
		var gate Gate
		gate.Block()

		callCtx, cancelCall := context.WithCancel(context.Background())
		errs := gateEnterAsync(callCtx, &gate)
		g.Expect(gate.WaitForBlocked(ctx, 1)).To(Succeed(), "iteration %d", i)

		// Release closes the parked call's signal channel, then the cancellation
		// closes its ctx, with nothing in between that makes the parked call run.
		// The release is first either way the call is scheduled, so it was
		// released. Cancelling first would be the other case, which must report
		// ctx.Err().
		gate.Release()
		cancelCall()

		g.Expect(gateAwait(t, ctx, errs)).To(Succeed(), "iteration %d", i)
		g.Expect(gate.Blocked()).To(Equal(0), "iteration %d", i)
	}
}

func TestGateEnter_WokenByContextAlone_ReturnsContextErrorAndStopsCountingAsBlocked(t *testing.T) {
	testCases := []struct {
		name    string
		callCtx func(t *testing.T) (ctx context.Context, wake func())
		wantErr error
	}{
		{
			name: "cancelled while parked",
			callCtx: func(t *testing.T) (context.Context, func()) {
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				return ctx, cancel
			},
			wantErr: context.Canceled,
		},
		{
			name: "deadline expires while parked",
			callCtx: func(t *testing.T) (context.Context, func()) {
				ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
				t.Cleanup(cancel)
				return ctx, func() {}
			},
			wantErr: context.DeadlineExceeded,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			ctx := gateTestContext(t)

			var gate Gate
			gate.Block()

			callCtx, wake := tc.callCtx(t)
			errs := gateEnterAsync(callCtx, &gate)
			// Waiting for the count proves the call parked rather than returning
			// on a ctx that was already done.
			g.Expect(gate.WaitForBlocked(ctx, 1)).To(Succeed())

			wake()

			// Release is never called, so the tie-break cannot apply and the call
			// reports its own context, taking itself off the count first.
			g.Expect(gateAwait(t, ctx, errs)).To(MatchError(tc.wantErr))
			g.Expect(gate.Blocked()).To(Equal(0))
		})
	}
}

func TestGateEnter_ReleaseRacesOneCallersCancellation_SettlesBothCallsAndTheCount(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)

	var gate Gate
	gate.Block()

	doomedCtx, cancelDoomed := context.WithCancel(context.Background())
	t.Cleanup(cancelDoomed)
	doomed := gateEnterAsync(doomedCtx, &gate)
	survivor := gateEnterAsync(ctx, &gate)

	g.Expect(gate.WaitForBlocked(ctx, 2)).To(Succeed())

	// Nothing orders these two, so the doomed call either wakes on its ctx before
	// Release runs, which is a real cancellation, or finds both ready, which the
	// tie-break resolves as released. Either answer is correct for it; the
	// survivor has only Release to wake on, so nil is its only answer.
	cancelDoomed()
	gate.Release()

	g.Expect(gateAwait(t, ctx, doomed)).To(SatisfyAny(BeNil(), MatchError(context.Canceled)))
	g.Expect(gateAwait(t, ctx, survivor)).To(Succeed())
	g.Expect(gate.Blocked()).To(Equal(0))

	// The next generation has to start from an exact zero. A call that took the
	// release and also decremented would have driven the count negative, which
	// shows up here as a park that the gate never counts.
	gate.Block()
	next := gateEnterAsync(ctx, &gate)

	g.Expect(gate.WaitForBlocked(ctx, 1)).To(Succeed())
	g.Expect(gate.Blocked()).To(Equal(1))

	gate.Release()

	g.Expect(gateAwait(t, ctx, next)).To(Succeed())
	g.Expect(gate.Blocked()).To(Equal(0))
}

func TestGate_WaitForBlockedTargetNeverReached_ReturnsContextCanceled(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)

	var gate Gate
	gate.Block()

	waitCtx, cancelWait := context.WithCancel(context.Background())
	t.Cleanup(cancelWait)

	errs := make(chan error, 1)
	go func() { errs <- gate.WaitForBlocked(waitCtx, 1) }()

	// Nothing is parked, so WaitForBlocked must still be waiting.
	gateExpectStillParked(t, errs)

	cancelWait()

	g.Expect(gateAwait(t, ctx, errs)).To(MatchError(context.Canceled))
	g.Expect(gate.Blocked()).To(Equal(0))
}

func TestGate_WaitForBlockedTargetNeverReached_ReturnsDeadlineExceeded(t *testing.T) {
	g := NewWithT(t)

	var gate Gate
	gate.Block()

	waitCtx, cancelWait := context.WithTimeout(context.Background(), 50*time.Millisecond)
	t.Cleanup(cancelWait)

	g.Expect(gate.WaitForBlocked(waitCtx, 1)).To(MatchError(context.DeadlineExceeded))
	g.Expect(gate.Blocked()).To(Equal(0))
}

func TestGate_WaitForBlockedTargetAlreadyReached_ReturnsNilEvenWithDoneContext(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)

	var gate Gate
	gate.Block()

	errs := gateEnterAsync(ctx, &gate)
	g.Expect(gate.WaitForBlocked(ctx, 1)).To(Succeed())

	// The condition is checked before the context, so an already satisfied
	// target succeeds under a context that is done.
	g.Expect(gate.WaitForBlocked(gateCancelledContext(t), 1)).To(Succeed())
	g.Expect(gate.WaitForBlocked(gateExpiredContext(t), 1)).To(Succeed())

	gate.Release()
	g.Expect(gateAwait(t, ctx, errs)).To(Succeed())
}

func TestGate_WaitForBlockedNonPositiveTarget_ReturnsNilImmediately(t *testing.T) {
	testCases := []struct {
		name    string
		target  int
		waitCtx func(t *testing.T) context.Context
	}{
		{name: "zero target, live context", target: 0, waitCtx: func(t *testing.T) context.Context { return gateTestContext(t) }},
		{name: "zero target, cancelled context", target: 0, waitCtx: gateCancelledContext},
		{name: "negative target, live context", target: -1, waitCtx: func(t *testing.T) context.Context { return gateTestContext(t) }},
		{name: "negative target, expired deadline", target: -3, waitCtx: gateExpiredContext},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			// A zero-valued gate also proves the lazily built internals are
			// created rather than panicking on a nil condition variable.
			var gate Gate

			g.Expect(gate.WaitForBlocked(tc.waitCtx(t), tc.target)).To(Succeed())
			g.Expect(gate.Blocked()).To(Equal(0))
		})
	}
}

func TestGate_ManyConcurrentCallers_AllParkAndAllWakeOnOneRelease(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)

	const callers = 8

	var gate Gate
	gate.Block()

	results := make([]<-chan error, 0, callers)
	for i := 0; i < callers; i++ {
		results = append(results, gateEnterAsync(ctx, &gate))
	}

	g.Expect(gate.WaitForBlocked(ctx, callers)).To(Succeed())
	g.Expect(gate.Blocked()).To(Equal(callers))
	for _, errs := range results {
		gateExpectStillParked(t, errs)
	}

	gate.Release()

	for i, errs := range results {
		g.Expect(gateAwait(t, ctx, errs)).To(Succeed(), "caller %d", i)
	}
	g.Expect(gate.Blocked()).To(Equal(0))
}

func TestGate_ConcurrentBlockReleaseChurn_EveryCallCompletesWithoutError(t *testing.T) {
	g := NewWithT(t)

	ctx, cancel := context.WithTimeout(context.Background(), gateChurnTimeout)
	t.Cleanup(cancel)

	const (
		callers        = 5
		callsPerCaller = 100
		observers      = 2
	)

	var gate Gate

	failures := make(chan error, callers+observers)
	callersDone := make(chan struct{})

	var callersWG sync.WaitGroup
	for caller := 0; caller < callers; caller++ {
		callersWG.Add(1)
		go func(caller int) {
			defer callersWG.Done()
			for call := 0; call < callsPerCaller; call++ {
				if err := gate.enter(ctx); err != nil {
					failures <- fmt.Errorf("caller %d call %d: %w", caller, call, err)
					return
				}
			}
		}(caller)
	}

	// The toggler keeps closing and reopening the gate while the callers run, so
	// every caller sees both states, and it reopens the gate once for good when
	// they are done.
	var togglerWG sync.WaitGroup
	togglerWG.Add(1)
	go func() {
		defer togglerWG.Done()
		for {
			select {
			case <-callersDone:
				gate.Release()
				return
			default:
			}
			gate.Block()
			runtime.Gosched()
			gate.Release()
		}
	}()

	// The observers read the gate concurrently with everything else, which is
	// what the race detector needs to see.
	var observersWG sync.WaitGroup
	for observer := 0; observer < observers; observer++ {
		observersWG.Add(1)
		go func(observer int) {
			defer observersWG.Done()
			for {
				select {
				case <-callersDone:
					return
				default:
				}
				if blocked := gate.Blocked(); blocked < 0 || blocked > callers {
					failures <- fmt.Errorf("observer %d saw %d blocked calls, want 0..%d", observer, blocked, callers)
					return
				}
				observerCtx, cancelObserver := context.WithTimeout(ctx, 20*time.Millisecond)
				err := gate.WaitForBlocked(observerCtx, 1)
				cancelObserver()
				// Either a caller was parked, or the short observation window
				// closed first. Nothing else is legal.
				if err != nil && !errors.Is(err, context.DeadlineExceeded) {
					failures <- fmt.Errorf("observer %d: unexpected wait error: %w", observer, err)
					return
				}
				runtime.Gosched()
			}
		}(observer)
	}

	callersWG.Wait()
	close(callersDone)
	togglerWG.Wait()
	observersWG.Wait()
	close(failures)

	var collected []error
	for err := range failures {
		collected = append(collected, err)
	}
	g.Expect(collected).To(BeEmpty())

	g.Expect(gate.Blocked()).To(Equal(0))
	g.Expect(gate.enter(ctx)).To(Succeed())
}
