// Package fake holds a hand-written fake for every interface declared in
// pkg/workloadidentity, so each tier of the workload identity path can be unit
// tested without importing any other tier.
//
// The fakes are hand-written rather than generated because every one of them has
// to do four things a generated mock does not: return a canned value, return an
// error, count calls, and park an in-flight call until a test releases it. The
// last one is what makes the notification and renewal tiers testable, and it is
// provided by the embedded Gate.
//
// Every fake is safe for concurrent use and safe under the race detector. Every
// fake is usable as a zero-valued struct literal, so a test that needs one
// canned answer writes one line.
//
// One tie-break rule applies to every fake. A call parked at the gate wakes on
// Release, returning nil, or on its own context being cancelled, returning that
// context's error. Release wins a tie: a call that is released before it notices
// its context is done returns nil even when the two happen too close together to
// order, so a test may release a call whose context is expiring and still assert
// success. A call whose context is done before the Release still reports the
// context's error.
//
// One ordering rule applies to every fake. Gate.Release settles the Gate's own
// parked count before it returns, so Blocked is exact immediately afterwards, but
// it does not settle a fake's call counters: a released call still has to be
// scheduled before it counts and records itself. A test that drives a fake from
// another goroutine and then asserts on anything that call records, whether a
// counter such as Attestor.Calls, BundleSource.X509BundlesCalls or
// Subscriber.SubscribeCalls or a recording such as Workloads, Conns or Requests,
// must first observe the call's own return, usually by receiving the call's
// result from a channel the goroutine writes to.
package fake

import (
	"context"
	"sync"
)

// Gate parks a fake's in-flight calls until a test releases them. It exists
// because the notification tier's delivery semantics and the renewal tier's
// timing are concurrency behaviour, and testing either needs a call held open at
// a known point.
//
// A Gate is open by default, so a fake that is never told to block behaves like
// a plain stub. A Gate is reusable: Block after Release parks calls again.
//
// A parked call also gives up if its own context is cancelled, reporting that
// context's error. Release wins a tie, as described on the package: a call that
// is released before it notices its context is done returns nil.
//
// A Gate must not be copied once it has been used, because it holds a mutex and
// a condition variable bound to that mutex. Embed it and take the fake by
// pointer, which is how every fake in this package is written.
type Gate struct {
	mu   sync.Mutex
	cond *sync.Cond
	// blocking is true between Block and Release.
	blocking bool
	// blocked counts the calls currently parked in enter.
	blocked int
	// generation counts Releases. A parked call records the generation it
	// parked in, so it can tell whether it was woken by the Release that ended
	// that generation, which already took it off blocked, or by its own ctx,
	// which did not. Without it a released call would decrement whenever it
	// next happened to be scheduled, which is after Release has returned and
	// possibly inside a later generation.
	generation uint64
	// release is closed by Release and replaced, so every call parked against
	// the old channel wakes exactly once.
	release chan struct{}
}

// initLocked creates the lazily built internals so a zero-valued Gate works.
// The caller must hold g.mu.
func (g *Gate) initLocked() {
	if g.cond == nil {
		g.cond = sync.NewCond(&g.mu)
	}
	if g.release == nil {
		g.release = make(chan struct{})
	}
}

// Block closes the gate. Every call entering the fake afterwards parks until
// Release. Calls already in flight past the gate are unaffected.
func (g *Gate) Block() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.initLocked()
	g.blocking = true
}

// Release wakes every parked call and reopens the gate. It is safe to call when
// nothing is parked and safe to call more than once.
//
// Release takes the calls it wakes off the parked count before it returns, so
// Blocked is 0 by the time Release returns and a later Block starts counting
// from zero. It does not wait for the woken calls to run: each one still has to
// be scheduled before it records itself on the fake, so a fake's own counters,
// such as Attestor.Calls, can still be stale immediately after Release. A test
// asserting one of those must first observe the call's own return, usually by
// receiving from a channel the calling goroutine writes to.
func (g *Gate) Release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.initLocked()
	g.blocking = false
	// Every call counted in blocked is parked on the channel about to be closed,
	// because enter increments the count and captures the channel under g.mu.
	// Ending the generation here is what makes the count settled synchronously.
	g.blocked = 0
	g.generation++
	close(g.release)
	g.release = make(chan struct{})
}

// Blocked reports how many calls are currently parked at the gate. It is exact
// at every point a test can observe it: a call that woke on its context being
// cancelled has stopped counting before it returns, and a call woken by Release
// has stopped counting before Release returns.
func (g *Gate) Blocked() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.blocked
}

// WaitForBlocked returns nil once at least n calls are parked at the gate, and
// ctx's error if ctx is done before that happens. It does not poll. The
// condition is checked before ctx, so WaitForBlocked with an already satisfied n
// returns nil even under a cancelled ctx.
//
// It observes the same count as Blocked, so it never reports a call parked in an
// earlier Block cycle: Release ends that cycle's count synchronously.
func (g *Gate) WaitForBlocked(ctx context.Context, n int) error {
	g.mu.Lock()
	g.initLocked()
	cond := g.cond
	g.mu.Unlock()

	// sync.Cond has no deadline, so a watcher goroutine broadcasts when ctx is
	// done to wake the loop below. done stops the watcher on every return path.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			g.mu.Lock()
			cond.Broadcast()
			g.mu.Unlock()
		case <-done:
		}
	}()

	g.mu.Lock()
	defer g.mu.Unlock()
	for g.blocked < n {
		if err := ctx.Err(); err != nil {
			return err
		}
		cond.Wait()
	}
	return nil
}

// enter gates every context-taking fake method except BundleSource.Lease. A done
// ctx returns ctx.Err() at once; a closed gate parks the call until Release
// (nil) or ctx ends (ctx.Err()). Release wins a tie, so releasing a call whose ctx
// is also expiring is not a coin flip.
func (g *Gate) enter(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	g.mu.Lock()
	g.initLocked()
	if !g.blocking {
		g.mu.Unlock()
		return nil
	}
	release := g.release
	generation := g.generation
	g.blocked++
	g.cond.Broadcast()
	g.mu.Unlock()

	var err error
	select {
	case <-release:
	case <-ctx.Done():
		// Both cases can be ready at once, and select then picks one of them at
		// random, so without this re-check a call that Release woke would report
		// ctx.Err() on about half the runs. A closed release channel means this
		// call was released, whichever case select chose.
		select {
		case <-release:
		default:
			err = ctx.Err()
		}
	}

	g.mu.Lock()
	// Release zeroes the count of the generation it ends, so only a call that
	// gave up inside its own generation, which means it woke on its ctx, takes
	// itself off the count. A released call that reaches here late must not
	// decrement, because that count no longer includes it and may already be
	// counting a later cycle's parked calls.
	//
	// That is also what keeps the tie-break above from double counting, with no
	// extra bookkeeping: Release advances the generation before it closes the
	// channel, so a call that took the release on a tie always finds a newer
	// generation here and leaves the count alone, while a call that woke on its
	// ctx with the release still open finds its own generation and decrements.
	if g.generation == generation {
		g.blocked--
		g.cond.Broadcast()
	}
	g.mu.Unlock()
	return err
}
