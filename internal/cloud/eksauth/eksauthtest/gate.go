package eksauthtest

import (
	"context"
	"sync"
)

// gate parks the fake's exchanges until a test releases them. It copies the
// semantics of pkg/workloadidentity/fake.Gate, which can't be reused because
// its entry point is unexported: open by default and reusable, Release wins a
// tie with a parked call's context, the parked count is exact whenever a test
// reads it, and waiting for a count never polls.
//
// It adds shutdown, which releases every parked call and keeps the gate open
// so that Server.Close can't hang on a parked request.
type gate struct {
	mu sync.Mutex
	// blocking is true between block and release.
	blocking bool
	// closed is set by shutdown. A closed gate never blocks again.
	closed bool
	// blocked counts the calls currently parked in enter.
	blocked int
	// generation counts releases. A parked call compares it with the
	// generation it parked in to tell whether a release already took it off
	// blocked.
	generation uint64
	// release is closed by release and replaced, so every call parked against
	// the old channel wakes exactly once.
	release chan struct{}
	// changed is closed and replaced whenever blocked changes. It is what
	// waitForBlocked waits on instead of polling.
	changed chan struct{}
}

// initLocked creates the lazily built channels so a zero-valued gate works. The
// caller must hold g.mu.
func (g *gate) initLocked() {
	if g.release == nil {
		g.release = make(chan struct{})
	}
	if g.changed == nil {
		g.changed = make(chan struct{})
	}
}

// notifyLocked wakes every waitForBlocked. The caller must hold g.mu.
func (g *gate) notifyLocked() {
	close(g.changed)
	g.changed = make(chan struct{})
}

func (g *gate) block() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.initLocked()
	if g.closed {
		return
	}
	g.blocking = true
}

func (g *gate) releaseAll() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.releaseLocked()
}

// releaseLocked wakes every parked call and reopens the gate. The caller must
// hold g.mu.
func (g *gate) releaseLocked() {
	g.initLocked()
	g.blocking = false
	// Every call counted in blocked is parked on the channel about to be
	// closed, because enter increments the count and captures the channel under
	// g.mu, so zeroing the count here is exact.
	if g.blocked != 0 {
		g.blocked = 0
		g.notifyLocked()
	}
	g.generation++
	close(g.release)
	g.release = make(chan struct{})
}

func (g *gate) shutdown() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	g.releaseLocked()
}

func (g *gate) blockedCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.blocked
}

func (g *gate) waitForBlocked(ctx context.Context, n int) error {
	for {
		g.mu.Lock()
		g.initLocked()
		if g.blocked >= n {
			g.mu.Unlock()
			return nil
		}
		changed := g.changed
		g.mu.Unlock()

		select {
		case <-changed:
		case <-ctx.Done():
			// The count is checked before the context, as it is on every other
			// pass, so a count reached as ctx ends still reports success.
			g.mu.Lock()
			reached := g.blocked >= n
			g.mu.Unlock()
			if reached {
				return nil
			}
			return ctx.Err()
		}
	}
}

// enter parks the call while the gate is blocked. It returns ctx.Err() without
// parking if ctx is already done. A parked call wakes on release, returning
// nil, or on ctx ending, returning ctx.Err(); release wins a tie.
func (g *gate) enter(ctx context.Context) error {
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
	g.notifyLocked()
	g.mu.Unlock()

	var err error
	select {
	case <-release:
	case <-ctx.Done():
		// Both cases can be ready at once and select picks at random, so a
		// closed release channel is re-checked: it means this call was released,
		// whichever case select chose.
		select {
		case <-release:
		default:
			err = ctx.Err()
		}
	}

	g.mu.Lock()
	// A call still in its own generation woke on its ctx and takes itself off
	// the count. A released call must not: release already zeroed its count,
	// and the count may now belong to a later cycle.
	if g.generation == generation {
		g.blocked--
		g.notifyLocked()
	}
	g.mu.Unlock()
	return err
}
