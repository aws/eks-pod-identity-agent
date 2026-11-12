package session

import (
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/eksauth/eksauthtest"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// TestSessionProvider_MinRemaining_ServesACachedSessionThatLastsLongEnough: a
// cached session with enough left is served without an exchange.
func TestSessionProvider_MinRemaining_ServesACachedSessionThatLastsLongEnough(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())

	got, err := h.session(testSessionPodUID, workloadidentity.MinRemaining(30*time.Minute))

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got.Credentials.AccessKeyID).To(Equal(exchangeKey(1)))
	g.Expect(h.server.Calls()).To(Equal(1))
	g.Expect(h.cacheCount(workloadidentity.CacheResultHit)).To(Equal(1.0))
}

// TestSessionProvider_MinRemaining_ReplacesAShortSessionWithoutDroppingIt: a
// usable session with too little left is replaced by an exchange. Until that
// exchange stores, the old session stays cached and other callers are served it.
func TestSessionProvider_MinRemaining_ReplacesAShortSessionWithoutDroppingIt(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	h.clock.Advance(40 * time.Minute)

	h.server.Block()
	pending := h.sessionAsync(t.Context(), testSessionPodUID, workloadidentity.MinRemaining(30*time.Minute))
	h.waitForBlocked(t, 1)
	g.Expect(h.cachedKey(testSessionPodUID)).To(Equal(exchangeKey(1)), "the short session stays cached during the exchange")
	other, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(other.Credentials.AccessKeyID).To(Equal(exchangeKey(1)), "a caller needing any usable session is still served")
	h.server.Release()

	r := awaitResult(t, pending)
	g.Expect(r.err).NotTo(HaveOccurred())
	g.Expect(r.session.Credentials.AccessKeyID).To(Equal(exchangeKey(2)))
	g.Expect(h.cachedKey(testSessionPodUID)).To(Equal(exchangeKey(2)))
	g.Expect(h.server.Calls()).To(Equal(2))
	g.Expect(h.cacheCount(workloadidentity.CacheResultExpired)).To(Equal(1.0))
}

// TestSessionProvider_MinRemaining_AFailedExchangeKeepsTheCachedSession: when
// EKS Auth fails the exchange, the caller gets the failure and the short session
// stays cached, served to callers that need any usable session.
func TestSessionProvider_MinRemaining_AFailedExchangeKeepsTheCachedSession(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	h.answerByExchange(func(n int64) (*eksauthtest.Session, *eksauthtest.APIError) {
		if n == 1 {
			return h.sessionFor(n), nil
		}
		return nil, eksauthtest.ServiceUnavailable()
	})
	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	h.clock.Advance(40 * time.Minute)

	_, err = h.session(testSessionPodUID, workloadidentity.MinRemaining(30*time.Minute))

	g.Expect(err).To(MatchError(wierrors.ErrSessionUnavailable))
	g.Expect(wierrors.IsRetryable(err)).To(BeTrue())
	g.Expect(h.cachedKey(testSessionPodUID)).To(Equal(exchangeKey(1)))
	calls := h.server.Calls()
	kept, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(kept.Credentials.AccessKeyID).To(Equal(exchangeKey(1)))
	g.Expect(h.server.Calls()).To(Equal(calls), "serving the kept session needs no exchange")
}

// TestSessionProvider_MinRemaining_AFreshSessionShorterThanAskedIsReturned: EKS
// Auth may issue no session as long as the caller asks for. The fresh one is
// returned after one exchange rather than exchanged for again.
func TestSessionProvider_MinRemaining_AFreshSessionShorterThanAskedIsReturned(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	h.answerByExchange(func(n int64) (*eksauthtest.Session, *eksauthtest.APIError) {
		return h.sessionLiving(n, 59*time.Minute), nil
	})
	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())

	got, err := h.session(testSessionPodUID, workloadidentity.MinRemaining(time.Hour))

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got.Credentials.AccessKeyID).To(Equal(exchangeKey(2)))
	g.Expect(h.server.Calls()).To(Equal(2))
}

// TestSessionProvider_MinRemaining_ConcurrentCallersShareOneExchange: callers
// needing more than the cached session has share one exchange.
func TestSessionProvider_MinRemaining_ConcurrentCallersShareOneExchange(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	h.clock.Advance(40 * time.Minute)

	h.server.Block()
	var pending []<-chan sessionResult
	for range 3 {
		pending = append(pending, h.sessionAsync(t.Context(), testSessionPodUID, workloadidentity.MinRemaining(30*time.Minute)))
	}
	// The first exchange's caller and the three waiting now.
	h.waitForJoined(t, testSessionPodUID, 4)
	h.server.Release()

	for _, results := range pending {
		r := awaitResult(t, results)
		g.Expect(r.err).NotTo(HaveOccurred())
		g.Expect(r.session.Credentials.AccessKeyID).To(Equal(exchangeKey(2)))
	}
	g.Expect(h.server.Calls()).To(Equal(2))
}

// TestSessionProvider_MinRemaining_JoiningAnExchangeThatNeededLessAsksAgain: a
// caller that joins an exchange started by one needing less can be handed the
// session it turned down. It asks once more and is exchanged a fresh one.
func TestSessionProvider_MinRemaining_JoiningAnExchangeThatNeededLessAsksAgain(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	h.clock.Advance(40 * time.Minute)

	// An exchange needing ten minutes is held at the clock read that decides it
	// can keep the cached session, which has twenty.
	clockGate := h.gateNextCacheRead(t)
	lenient := make(chan sessionResult, 1)
	go func() {
		entry, err := h.provider.await(t.Context(), testSessionPodUID,
			h.provider.joinForRequest(t.Context(), sessionTestWorkload(testSessionPodUID), 10*time.Minute))
		r := sessionResult{err: err}
		if err == nil {
			r.session = toWorkloadSession(entry)
		}
		lenient <- r
	}()
	clockGate.waitUntilHeld(t)
	strict := h.sessionAsync(t.Context(), testSessionPodUID, workloadidentity.MinRemaining(30*time.Minute))
	// The first exchange's caller, the lenient one and the strict one.
	h.waitForJoined(t, testSessionPodUID, 3)
	clockGate.open()

	r := awaitResult(t, lenient)
	g.Expect(r.err).NotTo(HaveOccurred())
	g.Expect(r.session.Credentials.AccessKeyID).To(Equal(exchangeKey(1)))
	r = awaitResult(t, strict)
	g.Expect(r.err).NotTo(HaveOccurred())
	g.Expect(r.session.Credentials.AccessKeyID).To(Equal(exchangeKey(2)))
	g.Expect(h.server.Calls()).To(Equal(2))
}
