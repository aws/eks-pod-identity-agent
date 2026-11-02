package eksauthtest

import (
	"context"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

// gateTestTimeout bounds every wait in this file, so a gate that fails to wake a
// parked call fails the test instead of hanging the suite.
const gateTestTimeout = 2 * time.Second

func gateTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), gateTestTimeout)
	t.Cleanup(cancel)
	return ctx
}

// enterAsync parks a call at the gate on a new goroutine and returns the
// channel its error arrives on.
func enterAsync(ctx context.Context, g *gate) <-chan error {
	errs := make(chan error, 1)
	go func() { errs <- g.enter(ctx) }()
	return errs
}

func await(t *testing.T, ctx context.Context, errs <-chan error) error {
	t.Helper()
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		t.Fatalf("call did not return before the test context expired: %v", ctx.Err())
		return nil
	}
}

func expectStillParked(t *testing.T, errs <-chan error) {
	t.Helper()
	select {
	case err := <-errs:
		t.Fatalf("call returned early with %v, want it still parked", err)
	default:
	}
}

func TestGate_ZeroValueIsOpen(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)
	var gt gate

	g.Expect(gt.enter(ctx)).To(Succeed())
	g.Expect(gt.blockedCount()).To(Equal(0))
	gt.releaseAll()
	g.Expect(gt.enter(ctx)).To(Succeed())
}

func TestGate_ParksUntilReleasedAndIsReusable(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)
	var gt gate

	for cycle := 1; cycle <= 3; cycle++ {
		gt.block()
		first, second := enterAsync(ctx, &gt), enterAsync(ctx, &gt)
		g.Expect(gt.waitForBlocked(ctx, 2)).To(Succeed(), "cycle %d", cycle)
		expectStillParked(t, first)
		expectStillParked(t, second)
		g.Expect(gt.blockedCount()).To(Equal(2), "cycle %d", cycle)

		gt.releaseAll()
		// Settled before the released calls are even scheduled.
		g.Expect(gt.blockedCount()).To(Equal(0), "cycle %d", cycle)
		g.Expect(await(t, ctx, first)).To(Succeed(), "cycle %d", cycle)
		g.Expect(await(t, ctx, second)).To(Succeed(), "cycle %d", cycle)
		g.Expect(gt.enter(ctx)).To(Succeed(), "the gate is open again after cycle %d", cycle)
	}
}

func TestGate_ParkedCallGivesUpOnItsContext(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)
	var gt gate
	gt.block()

	callCtx, cancel := context.WithCancel(ctx)
	errs := enterAsync(callCtx, &gt)
	g.Expect(gt.waitForBlocked(ctx, 1)).To(Succeed())
	cancel()

	g.Expect(await(t, ctx, errs)).To(MatchError(context.Canceled))
	// The call took itself off the count before returning.
	g.Expect(gt.blockedCount()).To(Equal(0))
	// And the gate is still closed for everyone else.
	other := enterAsync(ctx, &gt)
	g.Expect(gt.waitForBlocked(ctx, 1)).To(Succeed())
	gt.releaseAll()
	g.Expect(await(t, ctx, other)).To(Succeed())
}

func TestGate_ReleaseThenCancelReportsTheRelease(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)
	var gt gate

	for i := 0; i < 50; i++ {
		gt.block()
		callCtx, cancel := context.WithCancel(ctx)
		errs := enterAsync(callCtx, &gt)
		g.Expect(gt.waitForBlocked(ctx, 1)).To(Succeed())
		// Released first, cancelled straight after. The parked call wakes on the
		// release, and the cancel that follows must not change its answer or the
		// count. TestGate_ReleaseWinsATieWithTheContext covers the two arriving
		// together.
		gt.releaseAll()
		cancel()
		g.Expect(await(t, ctx, errs)).To(Succeed(), "iteration %d", i)
		g.Expect(gt.blockedCount()).To(Equal(0), "iteration %d", i)
	}
}

// gateTieIterations is how many rounds each tie-break test runs. Go's select
// picks uniformly among ready cases, so one tie catches a gate that leaves the
// choice to select only about half the time; the loop makes missing it
// implausible.
const gateTieIterations = 200

// gateTieContext is a context that runs onDone and then reports itself
// cancelled, both on the first read of its Done channel, so a select reading it
// finds what onDone readied and the context done at the same time.
//
// It exists because doing the two from the test goroutine hardly ever produces
// a tie: a call already parked in its select wakes on whichever channel closes
// first. Doing both inside Done does. pkg/workloadidentity/fake's gate tests use
// the same device.
type gateTieContext struct {
	onDone func()
	done   chan struct{}
	once   sync.Once
}

func newGateTieContext(onDone func()) *gateTieContext {
	return &gateTieContext{onDone: onDone, done: make(chan struct{})}
}

func (c *gateTieContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done runs onDone and closes the returned channel on its first call, so a
// reader cannot observe one without the other.
func (c *gateTieContext) Done() <-chan struct{} {
	c.once.Do(func() {
		c.onDone()
		close(c.done)
	})
	return c.done
}

// Err reports nil until Done has closed the channel, which is what gets a call
// past enter's entry check and into its select.
func (c *gateTieContext) Err() error {
	select {
	case <-c.done:
		return context.Canceled
	default:
		return nil
	}
}

func (c *gateTieContext) Value(any) any { return nil }

func TestGate_ReleaseWinsATieWithTheContext(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)

	for i := 0; i < gateTieIterations; i++ {
		var gt gate
		gt.block()

		// The call parks, then finds itself released and cancelled at once. It
		// was released, so nil is the only right answer on every iteration.
		errs := enterAsync(newGateTieContext(gt.releaseAll), &gt)

		g.Expect(await(t, ctx, errs)).To(Succeed(), "iteration %d", i)
		g.Expect(gt.blockedCount()).To(Equal(0), "iteration %d", i)
	}
}

func TestGate_WaitForBlockedReportsACountReachedAsTheContextEnds(t *testing.T) {
	g := NewWithT(t)

	for i := 0; i < gateTieIterations; i++ {
		var gt gate
		// A call parks in the same instant the waiter's context ends. The count
		// was reached, so success is the only right answer on every iteration.
		parkOne := func() {
			gt.mu.Lock()
			defer gt.mu.Unlock()
			gt.initLocked()
			gt.blocked++
			gt.notifyLocked()
		}

		g.Expect(gt.waitForBlocked(newGateTieContext(parkOne), 1)).To(Succeed(), "iteration %d", i)
	}
}

func TestGate_EnterWithADoneContextDoesNotPark(t *testing.T) {
	g := NewWithT(t)
	var gt gate
	gt.block()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	g.Expect(gt.enter(ctx)).To(MatchError(context.Canceled))
	g.Expect(gt.blockedCount()).To(Equal(0))
}

func TestGate_WaitForBlockedChecksTheCountBeforeTheContext(t *testing.T) {
	g := NewWithT(t)
	var gt gate
	done, cancel := context.WithCancel(context.Background())
	cancel()

	g.Expect(gt.waitForBlocked(done, 0)).To(Succeed())
	g.Expect(gt.waitForBlocked(done, 1)).To(MatchError(context.Canceled))

	short, cancelShort := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelShort()
	g.Expect(gt.waitForBlocked(short, 1)).To(MatchError(context.DeadlineExceeded))
}

func TestGate_ShutdownReleasesAndStaysOpen(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)
	var gt gate
	gt.block()
	errs := enterAsync(ctx, &gt)
	g.Expect(gt.waitForBlocked(ctx, 1)).To(Succeed())

	gt.shutdown()

	g.Expect(await(t, ctx, errs)).To(Succeed())
	gt.block()
	g.Expect(gt.enter(ctx)).To(Succeed(), "a shut down gate never parks again")
}

func TestGate_ConcurrentChurn(t *testing.T) {
	g := NewWithT(t)
	ctx := gateTestContext(t)
	var gt gate

	var callers sync.WaitGroup
	for i := 0; i < 20; i++ {
		callers.Add(1)
		go func() {
			defer callers.Done()
			for j := 0; j < 20; j++ {
				callCtx, cancel := context.WithTimeout(ctx, time.Millisecond)
				_ = gt.enter(callCtx)
				cancel()
			}
		}()
	}
	var toggler sync.WaitGroup
	toggler.Add(1)
	go func() {
		defer toggler.Done()
		for i := 0; i < 100; i++ {
			gt.block()
			_ = gt.blockedCount()
			gt.releaseAll()
		}
	}()
	toggler.Wait()
	gt.releaseAll()
	callers.Wait()

	g.Expect(gt.blockedCount()).To(Equal(0))
}
