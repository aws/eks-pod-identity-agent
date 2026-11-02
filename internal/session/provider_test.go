package session

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/smithy-go"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/mock/gomock"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/eksauth/eksauthtest"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/credcache"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/podstore/podstoretest"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials/mockcreds"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity/fake"
)

// TestSessionProvider_ObtainsASessionForAnAttestedWorkloadAndRetainsTheProviderArn
// is DoD 1: a session is obtained for an attested workload against a fake EKS
// Auth, through the real client, and the provider ARN is retained, on the
// exchanged session and on the cached one.
func TestSessionProvider_ObtainsASessionForAnAttestedWorkloadAndRetainsTheProviderArn(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	want := eksauthtest.EnrolledSession(h.clock.Now().Add(time.Hour))
	h.server.SetSession(want)
	w := sessionTestWorkload(testSessionPodUID)

	exchanged, err := h.provider.Session(t.Context(), w)
	g.Expect(err).NotTo(HaveOccurred())
	cached, err := h.provider.Session(t.Context(), w)
	g.Expect(err).NotTo(HaveOccurred())

	for _, got := range []*workloadidentity.WorkloadSession{exchanged, cached} {
		g.Expect(got.ProviderArn).To(Equal(want.ProviderArn))
		g.Expect(got.Credentials.AccessKeyID).To(Equal(want.AccessKeyID))
		g.Expect(got.Credentials.SecretAccessKey).To(Equal(want.SecretAccessKey))
		g.Expect(got.Credentials.SessionToken).To(Equal(want.SessionToken))
		g.Expect(got.Credentials.AccountID).To(Equal(eksauthtest.AccountID))
		g.Expect(got.Credentials.CanExpire).To(BeTrue())
		g.Expect(got.ExpiresAt).To(BeTemporally("~", want.Expiration, time.Millisecond))
		g.Expect(got.ExpiresAt).To(Equal(got.Credentials.Expires))
	}
	g.Expect(h.server.Calls()).To(Equal(1), "the second call must be served from cache")
	g.Expect(h.minter.Calls()).To(Equal(1))

	requests := h.server.Requests()
	g.Expect(requests[0].ClusterName).To(Equal(testClusterName))
	g.Expect(requests[0].Token).To(Equal(h.minted(1)), "EKS Auth must see the minted token")
	g.Expect(*h.minter.Workloads()[0]).To(Equal(*w), "the token must be minted for the attested workload")
}

// TestSessionProvider_ConcurrentRequestsForOnePodProduceOneExchange is DoD 2.
// Every caller joins before the one exchange is let through, so a provider that
// started an exchange per caller would park more than one at the fake.
func TestSessionProvider_ConcurrentRequestsForOnePodProduceOneExchange(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	h.server.Block()

	const n = 16
	var pending []<-chan sessionResult
	for i := 0; i < n; i++ {
		pending = append(pending, h.sessionAsync(t.Context(), testSessionPodUID))
	}
	h.waitForBlocked(t, 1)
	h.waitForJoined(t, testSessionPodUID, n)
	g.Expect(h.server.Calls()).To(Equal(1))
	g.Expect(h.server.Blocked()).To(Equal(1))
	g.Expect(h.minter.Calls()).To(Equal(1))

	h.server.Release()

	var sessions []*workloadidentity.WorkloadSession
	for _, results := range pending {
		r := awaitResult(t, results)
		g.Expect(r.err).NotTo(HaveOccurred())
		sessions = append(sessions, r.session)
	}
	for i, s := range sessions {
		g.Expect(*s).To(Equal(*sessions[0]))
		g.Expect(s.Credentials.AccessKeyID).To(Equal(exchangeKey(1)))
		for _, other := range sessions[i+1:] {
			g.Expect(s).NotTo(BeIdenticalTo(other), "every caller must get its own copy")
		}
	}
	g.Expect(h.server.Calls()).To(Equal(1))
	g.Expect(h.minter.Calls()).To(Equal(1))
}

// TestSessionProvider_ConcurrentRequestsForOnePodSurviveOneCallerCancelling
// proves one waiter's cancellation fails that waiter alone, even when it's the
// caller that started the exchange: the exchange runs on, the other waiter gets
// the session, and the session is cached.
func TestSessionProvider_ConcurrentRequestsForOnePodSurviveOneCallerCancelling(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	h.server.Block()

	starterCtx, cancelStarter := context.WithCancel(t.Context())
	defer cancelStarter()
	starter := h.sessionAsync(starterCtx, testSessionPodUID)
	h.waitForBlocked(t, 1)
	joiner := h.sessionAsync(t.Context(), testSessionPodUID)
	h.waitForJoined(t, testSessionPodUID, 2)

	cancelStarter()
	cancelled := awaitResult(t, starter)
	g.Expect(cancelled.session).To(BeNil())
	g.Expect(cancelled.err).To(MatchError(wierrors.ErrSessionUnavailable))
	g.Expect(errors.Is(cancelled.err, context.Canceled)).To(BeTrue())
	g.Expect(wierrors.IsRetryable(cancelled.err)).To(BeTrue(), "a waiter giving up must read as worth retrying")

	h.server.Release()
	joined := awaitResult(t, joiner)
	g.Expect(joined.err).NotTo(HaveOccurred())
	g.Expect(joined.session.Credentials.AccessKeyID).To(Equal(exchangeKey(1)))

	again, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(again.Credentials.AccessKeyID).To(Equal(exchangeKey(1)))
	g.Expect(h.server.Calls()).To(Equal(1))
}

// TestSessionProvider_AnExchangeOutlivingItsCallerKeepsTheWorkloadAsAttested
// proves an exchange its caller gave up on reads its own copy of the workload. The
// caller changes the struct it passed while the exchange is parked at EKS Auth,
// and the exchange still stores for the attested pod.
func TestSessionProvider_AnExchangeOutlivingItsCallerKeepsTheWorkloadAsAttested(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	h.server.Block()
	w := sessionTestWorkload(testSessionPodUID)
	attested := *w
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	results := make(chan sessionResult, 1)
	go func() {
		got, err := h.provider.Session(ctx, w)
		results <- sessionResult{session: got, err: err}
	}()
	h.waitForBlocked(t, 1)

	cancel()
	g.Expect(awaitResult(t, results).err).To(MatchError(wierrors.ErrSessionUnavailable))
	*w = *sessionTestWorkload(otherSessionPodUID)
	h.server.Release()

	h.eventuallyCached(t, testSessionPodUID, exchangeKey(1))
	g.Expect(h.cachedKey(otherSessionPodUID)).To(BeEmpty())
	g.Expect(h.minter.Workloads()).To(HaveLen(1))
	g.Expect(*h.minter.Workloads()[0]).To(Equal(attested))
}

// TestSessionProvider_ACallerAlreadyGoneStartsNoExchange proves a caller whose
// context is done before it misses the cache is refused without an exchange.
// A mistaken exchange would mint on its own goroutine, often after the counts
// are read, but its caller would be counted as joined before Session returned,
// so the joined count is the check that catches it.
func TestSessionProvider_ACallerAlreadyGoneStartsNoExchange(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	h.server.Block()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	got, err := h.provider.Session(ctx, sessionTestWorkload(testSessionPodUID))

	g.Expect(got).To(BeNil())
	g.Expect(err).To(MatchError(wierrors.ErrSessionUnavailable))
	g.Expect(errors.Is(err, context.Canceled)).To(BeTrue())
	g.Expect(h.joined(testSessionPodUID)).To(BeZero(), "a caller already gone must not start an exchange")
	g.Expect(h.minter.Calls()).To(Equal(0))
	g.Expect(h.server.Calls()).To(Equal(0))
}

// TestSessionProvider_AnExchangeAndARefreshMintUnderADeadline proves the one
// bound on an exchange, which runs detached from its callers' cancellation: the
// minter, which no HTTP timeout covers, is called under a deadline
// renewalTimeout away for a caller with no deadline of its own. A refresh mints
// under the cache's deadline for the refresh, which is as long.
func TestSessionProvider_AnExchangeAndARefreshMintUnderADeadline(t *testing.T) {
	g := NewWithT(t)
	type observed struct {
		deadline time.Time
		ok       bool
	}
	seen := make(chan observed, 2)
	var h *sessionFixture
	h = newSessionFixture(t, sweeping, expiringTokens, func(o *fixtureOpts) {
		o.minter = &fake.TokenMinter{Func: func(ctx context.Context, w *workloadidentity.Workload) (*workloadidentity.ProjectedToken, error) {
			deadline, ok := ctx.Deadline()
			select {
			case seen <- observed{deadline: deadline, ok: ok}:
			default:
			}
			return h.mint(ctx, w)
		}}
	})
	h.dueFirst()
	nextMint := func() observed {
		t.Helper()
		select {
		case got := <-seen:
			return got
		case <-time.After(sessionTestTimeout):
			t.Fatalf("the minter was not called within %s", sessionTestTimeout)
			return observed{}
		}
	}

	start := time.Now()
	_, err := h.provider.Session(context.Background(), sessionTestWorkload(testSessionPodUID))
	g.Expect(err).NotTo(HaveOccurred())
	got := nextMint()
	g.Expect(got.ok).To(BeTrue(), "a request's exchange must run under a deadline")
	g.Expect(got.deadline).To(BeTemporally("~", start.Add(renewalTimeout), 5*time.Second))

	start = time.Now()
	got = nextMint()
	g.Expect(got.ok).To(BeTrue(), "a refresh's mint must run under a deadline")
	g.Expect(got.deadline).To(BeTemporally("~", start.Add(renewalTimeout), 5*time.Second))
	h.eventuallyCached(t, testSessionPodUID, exchangeKey(2))
}

// TestSessionProvider_ConcurrentRequestsForDifferentPodsExchangeIndependently
// proves single-flight is per pod: two pods' exchanges are in flight at once and
// each pod gets the session exchanged for its own token.
func TestSessionProvider_ConcurrentRequestsForDifferentPodsExchangeIndependently(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	h.server.Block()

	first := h.sessionAsync(t.Context(), testSessionPodUID)
	second := h.sessionAsync(t.Context(), otherSessionPodUID)
	h.waitForBlocked(t, 2)
	g.Expect(h.server.Calls()).To(Equal(2))

	h.server.Release()
	a, b := awaitResult(t, first), awaitResult(t, second)
	g.Expect(a.err).NotTo(HaveOccurred())
	g.Expect(b.err).NotTo(HaveOccurred())
	g.Expect(a.session.Credentials.AccessKeyID).NotTo(Equal(b.session.Credentials.AccessKeyID))

	for _, s := range []*workloadidentity.WorkloadSession{a.session, b.session} {
		var n int64
		_, err := fmt.Sscanf(s.Credentials.AccessKeyID, "ASIAEXCHANGE%d", &n)
		g.Expect(err).NotTo(HaveOccurred())
		podUID := testSessionPodUID
		if s == b.session {
			podUID = otherSessionPodUID
		}
		g.Expect(tokenPod(h.presentedBy(n))).To(Equal(podUID), "each pod's session must come from its own token")
	}
}

// TestSessionProvider_ARequestDuringARefreshExchangesOnItsOwn proves the cache's
// refreshes share no exchange with Session callers. A request for a pod whose
// refresh is parked at EKS Auth, and whose cached session is past its eviction
// time, exchanges on its own and stores its session. The parked refresh then
// stores its renewal over it, as the cache stores every renewal.
func TestSessionProvider_ARequestDuringARefreshExchangesOnItsOwn(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t, sweeping)
	exchanges := map[int64]*heldExchange{2: {}}
	h.holdExchanges(t, exchanges, func(n int64) *eksauthtest.Session {
		if n == 1 {
			return h.shortSessionFor(n)
		}
		return h.sessionFor(n)
	})
	first, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(first.Credentials.AccessKeyID).To(Equal(exchangeKey(1)))

	h.waitForCalls(t, 2)
	second, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(second.Credentials.AccessKeyID).To(Equal(exchangeKey(3)), "the request must not wait on the refresh")
	g.Expect(h.joined(testSessionPodUID)).To(Equal(2), "only Session callers join an exchange")
	exchanges[2].release()

	h.eventuallyCached(t, testSessionPodUID, exchangeKey(2))
	g.Expect(h.server.Calls()).To(Equal(3))
}

// TestSessionProvider_ACallerThatMissedTheCacheJustBeforeAnExchangeFinishedFindsItsSession
// proves a request's exchange looks at the cache before it exchanges. Calling
// joinForRequest directly skips Session's own look, so the caller reaches group
// after the first exchange stored its session, as one that just missed the
// cache would, and must be handed that session without exchanging again.
func TestSessionProvider_ACallerThatMissedTheCacheJustBeforeAnExchangeFinishedFindsItsSession(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())

	ctx := t.Context()
	entry, err := h.provider.await(ctx, testSessionPodUID,
		h.provider.joinForRequest(ctx, sessionTestWorkload(testSessionPodUID)))

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(entry.Credentials.AccessKeyId).To(Equal(exchangeKey(1)))
	g.Expect(h.server.Calls()).To(Equal(1))
	g.Expect(h.minter.Calls()).To(Equal(1))
}

// TestSessionProvider_ARefreshPresentsTheStoredTokenWhileItHasLifeLeft is DoD 3,
// first half: nothing but the cache's sweep refreshes a due session, through EKS
// Auth, with the token it was exchanged with while that token is outside the
// cache's token floor. Nothing is minted, and the refreshed session is what
// callers get next.
func TestSessionProvider_ARefreshPresentsTheStoredTokenWhileItHasLifeLeft(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t, sweeping)
	h.dueFirst()
	first, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(first.Credentials.AccessKeyID).To(Equal(exchangeKey(1)))

	h.eventuallyCached(t, testSessionPodUID, exchangeKey(2))

	g.Expect(h.presentedBy(2)).To(Equal(h.minted(1)), "a token with an hour left must be presented again")
	g.Expect(h.minter.Calls()).To(Equal(1), "the refresh mints nothing")
	entry, _ := h.cache.Get(testSessionPodUID)
	g.Expect(*entry.Request).To(Equal(credentials.EksCredentialsRequest{
		ClusterName: testClusterName, ServiceAccountToken: h.minted(1),
	}))
	refreshed, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(refreshed.Credentials.AccessKeyID).To(Equal(exchangeKey(2)))
	g.Expect(h.server.Calls()).To(Equal(2), "the refreshed session must be served from cache")
}

// TestSessionProvider_ARefreshPastTheTokenFloorPresentsAFreshlyMintedToken
// proves a refresh whose stored token is within the cache's token floor mints a
// fresh one first, from the minter the tier exchanges with, for the workload the
// token's claims name rather than the struct the caller passed. It presents that
// token and stores the request it presented.
func TestSessionProvider_ARefreshPastTheTokenFloorPresentsAFreshlyMintedToken(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t, sweeping, expiringTokens)
	h.dueFirst()
	w := sessionTestWorkload(testSessionPodUID)
	_, err := h.provider.Session(t.Context(), w)
	g.Expect(err).NotTo(HaveOccurred())
	w.Namespace, w.ServiceAccount = "tampered-namespace", "tampered-sa"

	h.eventuallyCached(t, testSessionPodUID, exchangeKey(2))

	g.Expect(h.minter.Calls()).To(Equal(2), "the refresh mints once")
	g.Expect(h.presentedBy(2)).To(Equal(h.minted(2)), "the refresh must present the token it minted")
	want := *sessionTestWorkload(testSessionPodUID)
	want.NodeName = ""
	g.Expect(*h.minter.Workloads()[1]).To(Equal(want), "the refresh mints for the workload its token names")
	entry, _ := h.cache.Get(testSessionPodUID)
	g.Expect(entry.Request.ServiceAccountToken).To(Equal(h.minted(2)))
}

// TestSessionProvider_ARecoverableRefreshFailureKeepsTheOldSessionWhileValid
// proves a refresh EKS Auth fails transiently leaves the old session cached and
// served, and no longer served once inside the floor.
func TestSessionProvider_ARecoverableRefreshFailureKeepsTheOldSessionWhileValid(t *testing.T) {
	g := NewWithT(t)
	capture := captureLogs(t)
	h := newSessionFixture(t, sweeping)
	// Kept over each failure, the session is refreshed again only this long
	// after, which leaves the test time to read it.
	const lifetime = 4 * dueSoon
	h.answerByExchange(func(n int64) (*eksauthtest.Session, *eksauthtest.APIError) {
		if n == 1 {
			return h.sessionLiving(n, lifetime), nil
		}
		return nil, eksauthtest.InternalServer()
	})
	first, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())

	capture.waitFor(t, testSessionPodUID, "Credentials still valid, keeping them", 1)
	g.Expect(capture.fieldsAbout(testSessionPodUID, keptLine(testSessionPodUID))).NotTo(BeEmpty())
	g.Expect(h.server.Calls()).To(BeNumerically(">=", 2))
	kept, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(kept.Credentials.AccessKeyID).To(Equal(first.Credentials.AccessKeyID), "the kept session must be served")

	// Once the kept session is inside the floor it isn't served any more, and
	// with EKS Auth still failing the caller gets the failure.
	h.clock.Set(first.ExpiresAt.Add(-h.minTtl))
	got, err := h.session(testSessionPodUID)
	g.Expect(got).To(BeNil())
	g.Expect(err).To(MatchError(wierrors.ErrSessionUnavailable))
}

// TestSessionProvider_ARecoverableRefreshFailureInsideTheFloorIsNeverServed
// proves the cache keeps no session it couldn't serve: a refresh that fails
// once the session is inside the floor leaves it to expire, and Session
// exchanges instead of serving it.
func TestSessionProvider_ARecoverableRefreshFailureInsideTheFloorIsNeverServed(t *testing.T) {
	g := NewWithT(t)
	capture := captureLogs(t)
	h := newSessionFixture(t, sweeping)
	exchanges := map[int64]*heldExchange{2: {fail: eksauthtest.InternalServer()}}
	h.holdExchanges(t, exchanges, h.shortSessionFor)
	first, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	h.waitForCalls(t, 2)
	h.clock.Set(first.ExpiresAt.Add(-h.minTtl + time.Millisecond))
	h.answerWithSessions()
	exchanges[2].release()

	capture.waitFor(t, testSessionPodUID, "Background refresh failed for pod", 1)
	next, err := h.session(testSessionPodUID)

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(next.Credentials.AccessKeyID).To(Equal(exchangeKey(3)), "a session inside the floor must not be served")
}

// TestSessionProvider_AnIrrecoverableRefreshFailureDropsTheSession proves a
// refresh refused for good drops the session instead of serving it until it
// expires, and that the next caller exchanges again. EKS Auth's client
// classifies its own refusals, and MinterTokens a refused mint.
func TestSessionProvider_AnIrrecoverableRefreshFailureDropsTheSession(t *testing.T) {
	refused := func(apiErr *eksauthtest.APIError) func(h *sessionFixture) {
		return func(h *sessionFixture) {
			h.answerByExchange(func(n int64) (*eksauthtest.Session, *eksauthtest.APIError) {
				switch n {
				case 1:
					return h.shortSessionFor(n), nil
				case 2:
					return nil, apiErr
				}
				return h.sessionFor(n), nil
			})
		}
	}
	testCases := []struct {
		name  string
		opts  []func(*fixtureOpts)
		fail  func(h *sessionFixture)
		calls int
	}{
		{name: "AccessDenied", fail: refused(eksauthtest.AccessDenied()), calls: 2},
		{name: "InvalidToken", fail: refused(eksauthtest.InvalidToken()), calls: 2},
		{name: "ResourceNotFound", fail: refused(eksauthtest.ResourceNotFound()), calls: 2},
		{name: "ExpiredToken", fail: refused(eksauthtest.ExpiredToken()), calls: 2},
		{
			name: "a token mint the API server forbids",
			opts: []func(*fixtureOpts){expiringTokens},
			fail: func(h *sessionFixture) {
				h.dueFirst()
				h.failMintAttempts(func(attempt int64) error {
					if attempt == 2 {
						return wierrors.ErrTokenMintForbidden.Wrapf(nil, "CSIDriver does not declare the audience")
					}
					return nil
				})
			},
			calls: 1,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			capture := captureLogs(t)
			h := newSessionFixture(t, append([]func(*fixtureOpts){sweeping}, tc.opts...)...)
			tc.fail(h)
			_, err := h.session(testSessionPodUID)
			g.Expect(err).NotTo(HaveOccurred())
			picked, _ := h.cache.Get(testSessionPodUID)

			capture.waitFor(t, testSessionPodUID, droppedLine(testSessionPodUID), 1)
			g.Expect(h.provider.cached(testSessionPodUID, picked)).To(BeFalse(), "an irrecoverable refresh failure must drop the session")
			g.Expect(h.server.Calls()).To(Equal(tc.calls))

			next, err := h.session(testSessionPodUID)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(h.server.Calls()).To(Equal(tc.calls+1), "the next caller must exchange again")
			g.Expect(next.Credentials.AccessKeyID).To(Equal(exchangeKey(h.exchanges.Load())))
		})
	}
}

// TestSessionProvider_ARefreshAnsweredUndecoratedLeavesSessionToExchange proves
// a refresh EKS Auth answers without a provider ARN, as for an association that
// lost its workload identity template, is stored like any other answer. Session
// then reads the entry as a miss and exchanges, and that exchange's
// ErrNotEnrolled leaves the entry serving HTTP.
func TestSessionProvider_ARefreshAnsweredUndecoratedLeavesSessionToExchange(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t, sweeping)
	h.answerByExchange(func(n int64) (*eksauthtest.Session, *eksauthtest.APIError) {
		if n == 1 {
			return h.shortSessionFor(n), nil
		}
		session := eksauthtest.NotEnrolledSession(h.clock.Now().Add(time.Hour))
		session.AccessKeyID = exchangeKey(n)
		return &session, nil
	})
	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())

	h.eventuallyCached(t, testSessionPodUID, exchangeKey(2))
	refreshed, _ := h.cache.Get(testSessionPodUID)
	g.Expect(refreshed.Metadata.ProviderArn()).To(BeEmpty())

	got, err := h.session(testSessionPodUID)
	g.Expect(got).To(BeNil())
	g.Expect(err).To(MatchError(wierrors.ErrNotEnrolled))
	g.Expect(h.server.Calls()).To(Equal(3))
	g.Expect(h.provider.cached(testSessionPodUID, refreshed)).To(BeTrue(), "ErrNotEnrolled stores nothing over the entry")
}

// TestSessionProvider_ARefreshWhoseMintIsRefusedDropsTheSession proves a
// refresh whose mint fails non-retryably, as the token minter's ErrTokenMintForbidden does,
// drops the session without reaching EKS Auth. A refresh isn't a Session
// exchange, so the failure isn't on the exchange metrics.
func TestSessionProvider_ARefreshWhoseMintIsRefusedDropsTheSession(t *testing.T) {
	g := NewWithT(t)
	capture := captureLogs(t)
	h := newSessionFixture(t, sweeping, expiringTokens)
	h.dueFirst()
	mintErr := wierrors.ErrTokenMintForbidden.Wrapf(nil, "the pod is gone")
	g.Expect(wierrors.IsRetryable(mintErr)).To(BeFalse())
	h.failMintAttempts(func(attempt int64) error {
		if attempt > 1 {
			return mintErr
		}
		return nil
	})
	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	picked, _ := h.cache.Get(testSessionPodUID)

	capture.waitFor(t, testSessionPodUID, droppedLine(testSessionPodUID), 1)
	g.Expect(h.provider.cached(testSessionPodUID, picked)).To(BeFalse(), "a refresh whose mint is refused must drop the session")

	g.Expect(h.minter.Calls()).To(Equal(2), "the refresh must have tried to mint")
	g.Expect(h.server.Calls()).To(Equal(1), "a refresh whose mint failed must not reach EKS Auth")
	g.Expect(h.exchangeCount(workloadidentity.OutcomeSuccess, wierrors.MetricLabelNone)).To(Equal(1.0))
	g.Expect(h.exchangeCount(workloadidentity.OutcomeFailure, wierrors.MetricLabel(mintErr))).To(BeZero())
}

// TestSessionProvider_ASessionPastExpiryIsNeverReturned is DoD 3, second half:
// a cached session is served up to the floor and not at it, is exchanged again
// instead, and when that exchange fails the caller gets the error, never the
// stale session.
func TestSessionProvider_ASessionPastExpiryIsNeverReturned(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	first, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())

	h.clock.Set(first.ExpiresAt.Add(-h.minTtl - time.Second))
	got, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got.Credentials.AccessKeyID).To(Equal(exchangeKey(1)), "just outside the floor the session is still served")
	g.Expect(h.server.Calls()).To(Equal(1))

	h.clock.Set(first.ExpiresAt.Add(-h.minTtl))
	second, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(second.Credentials.AccessKeyID).To(Equal(exchangeKey(2)), "at the floor the session must be exchanged again")
	g.Expect(h.cacheCount(workloadidentity.CacheResultExpired)).To(Equal(1.0))

	h.server.SetError(eksauthtest.InternalServer())
	h.clock.Set(second.ExpiresAt.Add(time.Minute))
	got, err = h.session(testSessionPodUID)
	g.Expect(got).To(BeNil(), "an expired session must never be returned, even when the exchange fails")
	g.Expect(err).To(MatchError(wierrors.ErrSessionUnavailable))
	g.Expect(h.server.Calls()).To(Equal(3))
}

// TestSessionProvider_AStoreRefusesASessionThatCrossedTheFloorSinceItsExchange
// proves a session outside the floor when it was exchanged but at the floor
// when it's stored isn't cached, and fails its caller with
// ErrSessionUnavailable, while one a millisecond outside the floor is cached.
// The cache's clock moves to the given point after the exchange's own check.
func TestSessionProvider_AStoreRefusesASessionThatCrossedTheFloorSinceItsExchange(t *testing.T) {
	for name, tc := range map[string]struct {
		beforeFloor time.Duration
		wantStored  bool
	}{
		"at the floor":                       {beforeFloor: 0, wantStored: false},
		"a millisecond outside of the floor": {beforeFloor: time.Millisecond, wantStored: true},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			h := newSessionFixture(t)
			floor := h.clock.Now().Add(time.Hour - h.minTtl)
			var reads atomic.Int64
			hook := func() {
				// The exchange's check is the first read, the store's the second.
				if reads.Add(1) == 2 {
					h.clock.Set(floor.Add(-tc.beforeFloor))
				}
			}
			h.onCacheNow.Store(&hook)

			got, err := h.session(testSessionPodUID)

			if tc.wantStored {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(h.cachedKey(testSessionPodUID)).To(Equal(got.Credentials.AccessKeyID))
				return
			}
			g.Expect(got).To(BeNil())
			g.Expect(err).To(MatchError(wierrors.ErrSessionUnavailable))
			g.Expect(err.Error()).To(ContainSubstring("caching the session"))
			g.Expect(h.cachedKey(testSessionPodUID)).To(BeEmpty(), "a session at the floor must not be cached")
		})
	}
}

// TestSessionProvider_InvalidateDropsTheEntryAndTheNextCallReExchanges is DoD 4.
func TestSessionProvider_InvalidateDropsTheEntryAndTheNextCallReExchanges(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())

	h.provider.Invalidate(testSessionPodUID)

	g.Expect(h.cachedKey(testSessionPodUID)).To(BeEmpty())
	next, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(next.Credentials.AccessKeyID).To(Equal(exchangeKey(2)))
	g.Expect(h.server.Calls()).To(Equal(2))

	// Invalidating a pod with nothing cached, or no pod at all, touches nothing.
	h.provider.Invalidate(otherSessionPodUID)
	h.provider.Invalidate("")
	again, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(again.Credentials.AccessKeyID).To(Equal(exchangeKey(2)))
	g.Expect(h.server.Calls()).To(Equal(2))
}

// TestSessionProvider_InvalidateDuringAnInFlightExchangeLeavesItsSessionCached
// proves Invalidate leaves an exchange in flight alone. Nobody has been handed
// its session, so it can't be the session the invalidating caller saw fail:
// the exchange answers the caller waiting on it, its session is cached, and the
// next call is served from the cache.
func TestSessionProvider_InvalidateDuringAnInFlightExchangeLeavesItsSessionCached(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	h.server.Block()
	pending := h.sessionAsync(t.Context(), testSessionPodUID)
	h.waitForBlocked(t, 1)

	h.provider.Invalidate(testSessionPodUID)
	h.server.Release()

	r := awaitResult(t, pending)
	g.Expect(r.err).NotTo(HaveOccurred())
	g.Expect(r.session.Credentials.AccessKeyID).To(Equal(exchangeKey(1)))
	g.Expect(h.cachedKey(testSessionPodUID)).To(Equal(exchangeKey(1)), "an exchange in flight at an invalidation must still be cached")

	next, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(next.Credentials.AccessKeyID).To(Equal(exchangeKey(1)))
	g.Expect(h.server.Calls()).To(Equal(1))
}

// TestSessionProvider_InvalidateDuringAnInFlightExchangeLetsTheNextCallJoinIt
// proves a caller that invalidates and asks again joins the exchange already in
// flight rather than starting another. The cached session has crossed the
// floor, so a request is already exchanging for a new one, and both callers get
// that exchange's session.
func TestSessionProvider_InvalidateDuringAnInFlightExchangeLetsTheNextCallJoinIt(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	first, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	h.clock.Set(first.ExpiresAt.Add(-h.minTtl))

	h.server.Block()
	inFlight := h.sessionAsync(t.Context(), testSessionPodUID)
	h.waitForBlocked(t, 1)
	h.provider.Invalidate(testSessionPodUID)
	next := h.sessionAsync(t.Context(), testSessionPodUID)
	// The first exchange's caller, the exchange in flight's, and the next one.
	h.waitForJoined(t, testSessionPodUID, 3)
	g.Expect(h.server.Calls()).To(Equal(2))
	h.server.Release()

	for _, results := range []<-chan sessionResult{inFlight, next} {
		r := awaitResult(t, results)
		g.Expect(r.err).NotTo(HaveOccurred())
		g.Expect(r.session.Credentials.AccessKeyID).To(Equal(exchangeKey(2)))
	}
	g.Expect(h.cachedKey(testSessionPodUID)).To(Equal(exchangeKey(2)))
	g.Expect(h.server.Calls()).To(Equal(2), "exactly one exchange beyond the first")
}

// TestSessionProvider_InvalidateDuringARefreshNeverBringsBackTheOldSession
// proves a refresh in flight at an invalidation can't put the old session back.
// A failing one keeps an entry only while the cache holds it, so nothing stays
// cached and the next caller exchanges. A succeeding one stores its renewal, a
// new session, which the next caller is served.
func TestSessionProvider_InvalidateDuringARefreshNeverBringsBackTheOldSession(t *testing.T) {
	for name, tc := range map[string]struct {
		fail *eksauthtest.APIError
		// wantKey is what the next caller gets, wantCalls the exchanges by then.
		wantKey   string
		wantCalls int
	}{
		"failing refresh":    {fail: eksauthtest.InternalServer(), wantKey: exchangeKey(3), wantCalls: 3},
		"succeeding refresh": {wantKey: exchangeKey(2), wantCalls: 2},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			capture := captureLogs(t)
			h := newSessionFixture(t, sweeping, dueEverySecond)
			exchanges := map[int64]*heldExchange{2: {fail: tc.fail}}
			h.holdExchanges(t, exchanges, h.sessionFor)
			_, err := h.session(testSessionPodUID)
			g.Expect(err).NotTo(HaveOccurred())

			h.waitForCalls(t, 2)
			h.provider.Invalidate(testSessionPodUID)
			exchanges[2].release()

			if tc.fail != nil {
				capture.waitFor(t, testSessionPodUID,
					"Credentials for pod "+testSessionPodUID+" were replaced or removed while refreshing", 1)
				g.Expect(h.cachedKey(testSessionPodUID)).To(BeEmpty(), "a failed refresh must not bring back an invalidated session")
			} else {
				h.eventuallyCached(t, testSessionPodUID, exchangeKey(2))
			}
			next, err := h.session(testSessionPodUID)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(next.Credentials.AccessKeyID).To(Equal(tc.wantKey))
			g.Expect(h.server.Calls()).To(Equal(tc.wantCalls))
		})
	}
}

// TestSessionProvider_CallersThatInvalidateOneSessionShareOneReExchange proves
// callers that saw one session fail, each calling Invalidate then Session as
// the JWT-SVID source's per-audience calls would, cost one re-exchange between them. Every
// invalidation after the first finds nothing cached to drop, since the first
// one's re-exchange is still running, and its caller joins that re-exchange.
func TestSessionProvider_CallersThatInvalidateOneSessionShareOneReExchange(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())

	h.server.Block()
	const n = 4
	var pending []<-chan sessionResult
	for i := 1; i <= n; i++ {
		h.provider.Invalidate(testSessionPodUID)
		pending = append(pending, h.sessionAsync(t.Context(), testSessionPodUID))
		// The first session's caller and every caller started so far.
		h.waitForJoined(t, testSessionPodUID, 1+i)
	}
	h.waitForBlocked(t, 1)
	g.Expect(h.server.Calls()).To(Equal(2))
	h.server.Release()

	for _, results := range pending {
		r := awaitResult(t, results)
		g.Expect(r.err).NotTo(HaveOccurred())
		g.Expect(r.session.Credentials.AccessKeyID).To(Equal(exchangeKey(2)))
	}
	g.Expect(h.server.Calls()).To(Equal(2))
	g.Expect(h.cachedKey(testSessionPodUID)).To(Equal(exchangeKey(2)), "the shared re-exchange must be cached")
}

// TestSessionProvider_ACallerThatInvalidatesASessionIsNotHandedItBack proves
// Session asks again when it's answered with an entry no longer cached. A
// caller that invalidates the cached session and asks again joins a request
// that found that session cached just before the invalidation. It must be
// handed a new session from one more exchange, not the one it invalidated.
func TestSessionProvider_ACallerThatInvalidatesASessionIsNotHandedItBack(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)

	// Nothing is cached yet, so this caller misses the cache before it's held.
	ctxGate := newGate(t)
	held := h.sessionAsync(&gatedErrContext{Context: t.Context(), gate: ctxGate}, testSessionPodUID)
	ctxGate.waitUntilHeld(t)

	first, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(first.Credentials.AccessKeyID).To(Equal(exchangeKey(1)))
	handed, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(handed.Credentials.AccessKeyID).To(Equal(exchangeKey(1)))

	// The held caller's request looks at the cache, finds the first session,
	// and is held at the clock read that decides whether it can be served.
	clockGate := h.gateNextCacheRead(t)
	ctxGate.open()
	clockGate.waitUntilHeld(t)

	h.provider.Invalidate(testSessionPodUID)
	again := h.sessionAsync(t.Context(), testSessionPodUID)
	// The first exchange's caller, the held caller and the invalidating caller
	// asking again.
	h.waitForJoined(t, testSessionPodUID, 3)
	clockGate.open()

	r := awaitResult(t, held)
	g.Expect(r.err).NotTo(HaveOccurred())
	r = awaitResult(t, again)
	g.Expect(r.err).NotTo(HaveOccurred())
	g.Expect(r.session.Credentials.AccessKeyID).To(Equal(exchangeKey(2)),
		"a caller that invalidated a session must not be handed it back")
	g.Expect(h.server.Calls()).To(Equal(2))
}

// TestSessionProvider_AFailedRefreshAfterAReplacement proves what a failed
// refresh does to a session cached while it was out. The sweep is held just
// before acting on the failure while the session is invalidated and a request
// caches a replacement. Failing recoverably never puts the old session back;
// failing irrecoverably drops whatever the pod holds, as upstream's delete does.
func TestSessionProvider_AFailedRefreshAfterAReplacement(t *testing.T) {
	testCases := []struct {
		name            string
		fail            *eksauthtest.APIError
		wantReplacement bool
	}{
		{name: "recoverably", fail: eksauthtest.InternalServer(), wantReplacement: true},
		{name: "irrecoverably", fail: eksauthtest.AccessDenied(), wantReplacement: false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			// Due a refresh after a second but living an hour, so Invalidate finds it.
			h := newSessionFixture(t, sweeping, dueEverySecond)
			h.answerByExchange(func(n int64) (*eksauthtest.Session, *eksauthtest.APIError) {
				if n == 2 {
					return nil, tc.fail
				}
				return h.sessionFor(n), nil
			})
			pause := pauseAtLog(t, testSessionPodUID, "Background refresh failed for pod")
			_, err := h.session(testSessionPodUID)
			g.Expect(err).NotTo(HaveOccurred())
			picked, ok := h.cache.Get(testSessionPodUID)
			g.Expect(ok).To(BeTrue())

			pause.waitUntilPaused(t)
			cached, ok := h.cache.Get(testSessionPodUID)
			g.Expect(ok).To(BeTrue(), "the session must still be cached")
			g.Expect(cached.Credentials).To(BeIdenticalTo(picked.Credentials))
			h.provider.Invalidate(testSessionPodUID)
			g.Expect(h.provider.cached(testSessionPodUID, picked)).To(BeFalse(), "Invalidate must have dropped the session")
			replacement, err := h.session(testSessionPodUID)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(replacement.Credentials.AccessKeyID).To(Equal(exchangeKey(3)))
			replaced, ok := h.cache.Get(testSessionPodUID)
			g.Expect(ok).To(BeTrue())

			pause.resume()
			if !tc.wantReplacement {
				g.Eventually(func() bool { return h.provider.cached(testSessionPodUID, replaced) }).
					WithTimeout(sessionTestTimeout).Should(BeFalse(), "an irrecoverable failure drops what the pod holds")
				g.Expect(h.provider.cached(testSessionPodUID, picked)).To(BeFalse(), "nor puts the old session back")
				return
			}
			// The sweep acts on the failed refresh as soon as it's resumed, and
			// the replacement's own refresh is a second away.
			g.Consistently(func() bool { return h.provider.cached(testSessionPodUID, replaced) }).
				WithTimeout(300*time.Millisecond).WithPolling(5*time.Millisecond).Should(BeTrue(),
				"keeping must neither overwrite the replacement nor put the old session back")
			g.Expect(h.server.Calls()).To(Equal(3))
		})
	}
}

// TestSessionProvider_InvalidateDropsWhatThePodHolds proves Invalidate deletes
// by pod UID. It's held between its look and its drop while an exchange stores a
// new session: the caller that got that session keeps it, Invalidate drops it
// from the cache, and the next caller exchanges again.
func TestSessionProvider_InvalidateDropsWhatThePodHolds(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	first, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	// Inside the floor, so the next request exchanges while the session is cached.
	h.clock.Set(first.ExpiresAt.Add(-h.minTtl))
	h.server.Block()
	pending := h.sessionAsync(t.Context(), testSessionPodUID)
	h.waitForBlocked(t, 1)

	pause := pauseAtLog(t, testSessionPodUID, "Session invalidated")
	invalidated := make(chan struct{})
	go func() {
		defer close(invalidated)
		h.provider.Invalidate(testSessionPodUID)
	}()
	pause.waitUntilPaused(t)
	h.server.Release()
	r := awaitResult(t, pending)
	pause.resume()
	select {
	case <-invalidated:
	case <-time.After(sessionTestTimeout):
		t.Fatalf("Invalidate did not return within %s", sessionTestTimeout)
	}

	g.Expect(r.err).NotTo(HaveOccurred())
	g.Expect(r.session.Credentials.AccessKeyID).To(Equal(exchangeKey(2)))
	g.Expect(h.cachedKey(testSessionPodUID)).To(BeEmpty(), "Invalidate deletes whatever the pod holds")
	next, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(next.Credentials.AccessKeyID).To(Equal(exchangeKey(3)))
}

// TestSessionProvider_APodDeletionDropsItsSession proves a pod's deletion drops
// its session, logging under the session's pod and association, and that the
// next exchange for the pod is ErrUnattestable and caches nothing. Another pod's
// session stays cached.
func TestSessionProvider_APodDeletionDropsItsSession(t *testing.T) {
	g := NewWithT(t)
	capture := captureLogs(t)
	h := newSessionFixture(t)
	for _, podUID := range []string{testSessionPodUID, otherSessionPodUID} {
		_, err := h.session(podUID)
		g.Expect(err).NotTo(HaveOccurred())
	}

	h.pods.Delete(testSessionPodUID)

	g.Expect(h.cachedKey(testSessionPodUID)).To(BeEmpty())
	g.Expect(h.cachedKey(otherSessionPodUID)).To(Equal(exchangeKey(2)))
	g.Expect(capture.fieldsAbout(testSessionPodUID, "Pod deleted, dropping its cached credentials")).To(HaveExactElements(
		HaveKeyWithValue("association-id", eksauthtest.EnrolledSession(time.Time{}).AssociationID)))
	got, err := h.session(testSessionPodUID)
	g.Expect(got).To(BeNil())
	g.Expect(err).To(MatchError(wierrors.ErrUnattestable))
	g.Expect(err).To(MatchError(credcache.ErrForgotten))
	g.Expect(wierrors.IsRetryable(err)).To(BeFalse())
	g.Expect(h.cachedKey(testSessionPodUID)).To(BeEmpty())
	g.Expect(h.cachedKey(otherSessionPodUID)).To(Equal(exchangeKey(2)))
}

// TestSessionProvider_APodDeletedDuringAnExchangeIsUnattestable proves an
// exchange in flight when its pod is deleted caches nothing, unlike one in
// flight at an Invalidate, and its caller gets ErrUnattestable naming the pod.
func TestSessionProvider_APodDeletedDuringAnExchangeIsUnattestable(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	h.server.Block()
	pending := h.sessionAsync(t.Context(), testSessionPodUID)
	h.waitForBlocked(t, 1)

	h.pods.Delete(testSessionPodUID)
	h.server.Release()

	r := awaitResult(t, pending)
	g.Expect(r.session).To(BeNil())
	g.Expect(r.err).To(MatchError(wierrors.ErrUnattestable))
	g.Expect(r.err.Error()).To(ContainSubstring("pod " + testSessionPodUID + " was deleted"))
	g.Expect(wierrors.IsRetryable(r.err)).To(BeFalse())
	g.Expect(h.cachedKey(testSessionPodUID)).To(BeEmpty(), "an exchange in flight at a deletion must not be cached")
	g.Expect(h.server.Calls()).To(Equal(1))
}

// TestSessionProvider_APodDeletedDuringARefreshStaysDropped proves a refresh in
// flight when its pod is deleted caches nothing, though the cache stores a
// renewal in flight at an Invalidate.
func TestSessionProvider_APodDeletedDuringARefreshStaysDropped(t *testing.T) {
	g := NewWithT(t)
	capture := captureLogs(t)
	h := newSessionFixture(t, sweeping, dueEverySecond)
	exchanges := map[int64]*heldExchange{2: {}}
	h.holdExchanges(t, exchanges, h.sessionFor)
	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())

	h.waitForCalls(t, 2)
	h.pods.Delete(testSessionPodUID)
	exchanges[2].release()

	capture.waitFor(t, testSessionPodUID, "Pod "+testSessionPodUID+" was deleted while its credentials refreshed", 1)
	g.Expect(h.cachedKey(testSessionPodUID)).To(BeEmpty(), "a renewal must not bring back a deleted pod's session")
	g.Expect(h.server.Calls()).To(Equal(2))
}

// TestSessionProvider_ARenewalRacingAnHTTPTokenCheckStillStores proves a
// refresh in flight while an HTTP caller's token passes local validation still
// stores. The HTTP retriever records the token on the entry while the refresh
// is parked, and the renewal is stored over it all the same.
func TestSessionProvider_ARenewalRacingAnHTTPTokenCheckStillStores(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t, sweeping, dueEverySecond, withValidator(&scriptedValidator{}))
	exchanges := map[int64]*heldExchange{2: {}}
	h.holdExchanges(t, exchanges, h.sessionFor)
	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())

	h.waitForCalls(t, 2)
	token := podToken(t, testSessionPodUID, 0)
	creds, err := h.httpCredentials(t.Context(), token)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(creds.AccessKeyId).To(Equal(exchangeKey(1)), "the validated token must be served the session")
	validated, _ := h.cache.Get(testSessionPodUID)
	g.Expect(validated.Request).NotTo(BeNil())
	g.Expect(validated.Request.ServiceAccountToken).To(Equal(token), "the validation hit must have recorded the token")
	exchanges[2].release()

	h.eventuallyCached(t, testSessionPodUID, exchangeKey(2))
	g.Expect(h.server.Calls()).To(Equal(2))
}

// TestSessionProvider_ExchangeErrorMapping proves how every way an exchange can
// fail reaches the caller: the taxonomy member, its metric label and retryable
// decision, and that the cause stays reachable. Nothing is cached in any case, and each failure is one
// failed exchange on the metric.
func TestSessionProvider_ExchangeErrorMapping(t *testing.T) {
	errMint := errors.New("api server unreachable")
	mintForbidden := wierrors.ErrTokenMintForbidden.Wrapf(nil, "CSIDriver does not declare the audience")
	mintFailed := wierrors.ErrTokenMintFailed.Wrapf(errMint, "TokenRequest failed")

	withSession := func(change func(*eksauthtest.Session)) func(h *sessionFixture) {
		return func(h *sessionFixture) {
			session := eksauthtest.EnrolledSession(h.clock.Now().Add(time.Hour))
			change(&session)
			h.server.SetSession(session)
		}
	}
	withAPIError := func(apiErr *eksauthtest.APIError) func(h *sessionFixture) {
		return func(h *sessionFixture) { h.server.SetError(apiErr) }
	}

	testCases := []struct {
		name          string
		minter        workloadidentity.TokenMinter
		setup         func(h *sessionFixture)
		wantKind      error
		wantRetryable bool
		wantIdentical error
		wantCause     error
		wantAPICode   string
		wantMessage   string
		wantCalls     int
	}{
		{
			name:          "mint refused with a taxonomy error passes through unchanged",
			minter:        &fake.TokenMinter{Err: mintForbidden},
			wantKind:      wierrors.ErrTokenMintForbidden,
			wantIdentical: mintForbidden,
		},
		{
			name:          "mint failed with a retryable taxonomy error passes through unchanged",
			minter:        &fake.TokenMinter{Err: mintFailed},
			wantKind:      wierrors.ErrTokenMintFailed,
			wantRetryable: true,
			wantIdentical: mintFailed,
		},
		{
			name:          "mint failed outside the taxonomy",
			minter:        &fake.TokenMinter{Err: errMint},
			wantKind:      wierrors.ErrTokenMintFailed,
			wantRetryable: true,
			wantCause:     errMint,
		},
		{
			name:          "mint returned no token",
			minter:        &fake.TokenMinter{},
			wantKind:      wierrors.ErrTokenMintFailed,
			wantRetryable: true,
		},
		{
			name:          "mint returned an empty token",
			minter:        &fake.TokenMinter{Result: &workloadidentity.ProjectedToken{}},
			wantKind:      wierrors.ErrTokenMintFailed,
			wantRetryable: true,
		},
		{
			name: "AccessDenied is a refusal", setup: withAPIError(eksauthtest.AccessDenied()),
			wantKind:    wierrors.ErrSessionRefused,
			wantAPICode: "AccessDeniedException", wantCalls: 1,
		},
		{
			name: "ExpiredToken", setup: withAPIError(eksauthtest.ExpiredToken()),
			wantKind: wierrors.ErrSessionUnavailable, wantRetryable: true,
			wantAPICode: "ExpiredTokenException", wantCalls: 1,
		},
		{
			name: "InvalidParameter", setup: withAPIError(eksauthtest.InvalidParameter()),
			wantKind: wierrors.ErrSessionUnavailable, wantRetryable: true,
			wantAPICode: "InvalidParameterException", wantCalls: 1,
		},
		{
			name: "InvalidRequest", setup: withAPIError(eksauthtest.InvalidRequest()),
			wantKind: wierrors.ErrSessionUnavailable, wantRetryable: true,
			wantAPICode: "InvalidRequestException", wantCalls: 1,
		},
		{
			name: "InvalidToken is a refusal", setup: withAPIError(eksauthtest.InvalidToken()),
			wantKind:    wierrors.ErrSessionRefused,
			wantAPICode: "InvalidTokenException", wantCalls: 1,
		},
		{
			// EKS Auth answers the same for a cluster it can't resolve, so the
			// message names the cluster.
			name: "ResourceNotFound is not enrolled", setup: withAPIError(eksauthtest.ResourceNotFound()),
			wantKind:    wierrors.ErrNotEnrolled,
			wantAPICode: "ResourceNotFoundException", wantCalls: 1,
			wantMessage: fmt.Sprintf("in cluster %q", testClusterName),
		},
		{
			name: "Throttling", setup: withAPIError(eksauthtest.Throttling()),
			wantKind: wierrors.ErrSessionUnavailable, wantRetryable: true,
			wantAPICode: "ThrottlingException", wantCalls: 1,
		},
		{
			name:     "InternalServer, which is also how EKS Auth reports STS throttling",
			setup:    withAPIError(eksauthtest.InternalServer()),
			wantKind: wierrors.ErrSessionUnavailable, wantRetryable: true,
			wantAPICode: "InternalServerException", wantCalls: 1,
		},
		{
			name: "ServiceUnavailable", setup: withAPIError(eksauthtest.ServiceUnavailable()),
			wantKind: wierrors.ErrSessionUnavailable, wantRetryable: true,
			wantAPICode: "ServiceUnavailableException", wantCalls: 1,
		},
		{
			name:     "a response EKS Auth sent that can't be used",
			setup:    func(h *sessionFixture) { h.server.SetRawResponse(200, []byte(`{}`)) },
			wantKind: wierrors.ErrSessionUnavailable, wantRetryable: true,
			wantMessage: "invalid response from server", wantCalls: 1,
		},
		{
			name:     "a session with no provider ARN is not enrolled",
			setup:    withSession(func(s *eksauthtest.Session) { s.ProviderArn = "" }),
			wantKind: wierrors.ErrNotEnrolled, wantCalls: 1,
			wantMessage: "no workload identity provider",
		},
		{
			name:     "a session without an access key ID",
			setup:    withSession(func(s *eksauthtest.Session) { s.AccessKeyID = "" }),
			wantKind: wierrors.ErrSessionUnavailable, wantRetryable: true, wantCalls: 1,
		},
		{
			name:     "a session without a secret access key",
			setup:    withSession(func(s *eksauthtest.Session) { s.SecretAccessKey = "" }),
			wantKind: wierrors.ErrSessionUnavailable, wantRetryable: true, wantCalls: 1,
		},
		{
			name:     "a session without a session token",
			setup:    withSession(func(s *eksauthtest.Session) { s.SessionToken = "" }),
			wantKind: wierrors.ErrSessionUnavailable, wantRetryable: true, wantCalls: 1,
		},
		{
			name: "credentials expiring within the floor",
			setup: withSession(func(s *eksauthtest.Session) {
				s.Expiration = s.Expiration.Add(-time.Hour + credcache.DefaultMinCredentialTtl/2)
			}),
			wantKind: wierrors.ErrSessionUnavailable, wantRetryable: true, wantCalls: 1,
			wantMessage: "will expire within the next",
		},
		{
			name:     "credentials already expired",
			setup:    withSession(func(s *eksauthtest.Session) { s.Expiration = s.Expiration.Add(-2 * time.Hour) }),
			wantKind: wierrors.ErrSessionUnavailable, wantRetryable: true, wantCalls: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			h := newSessionFixture(t, func(o *fixtureOpts) { o.minter = tc.minter })
			if tc.setup != nil {
				tc.setup(h)
			}

			got, err := h.session(testSessionPodUID)

			g.Expect(got).To(BeNil())
			g.Expect(err).To(MatchError(tc.wantKind))
			label := wierrors.MetricLabel(err)
			g.Expect(label).To(Equal(tc.wantKind.(*wierrors.WorkloadIdentityError).MetricLabel()))
			g.Expect(wierrors.IsRetryable(err)).To(Equal(tc.wantRetryable))
			if tc.wantIdentical != nil {
				g.Expect(err).To(BeIdenticalTo(tc.wantIdentical))
			}
			if tc.wantCause != nil {
				g.Expect(errors.Is(err, tc.wantCause)).To(BeTrue())
			}
			if tc.wantAPICode != "" {
				var apiErr smithy.APIError
				g.Expect(errors.As(err, &apiErr)).To(BeTrue(), "the SDK error must stay reachable")
				g.Expect(apiErr.ErrorCode()).To(Equal(tc.wantAPICode))
			}
			if tc.wantMessage != "" {
				g.Expect(err.Error()).To(ContainSubstring(tc.wantMessage))
			}
			g.Expect(h.server.Calls()).To(Equal(tc.wantCalls))
			g.Expect(h.cachedKey(testSessionPodUID)).To(BeEmpty(), "a failed exchange must cache nothing")
			g.Expect(h.exchangeCount(workloadidentity.OutcomeFailure, label)).To(Equal(1.0))
			g.Expect(h.exchangeCount(workloadidentity.OutcomeSuccess, wierrors.MetricLabelNone)).To(BeZero())
		})
	}
}

// TestSessionProvider_RefusesAnEmptyWorkload proves a workload with no pod UID
// is refused before anything is minted or exchanged.
func TestSessionProvider_RefusesAnEmptyWorkload(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)

	for _, w := range []*workloadidentity.Workload{nil, {}, {Namespace: "default", ServiceAccount: "example-sa"}} {
		got, err := h.provider.Session(t.Context(), w)
		g.Expect(got).To(BeNil())
		g.Expect(err).To(MatchError(wierrors.ErrSessionUnavailable))
	}
	g.Expect(h.minter.Calls()).To(Equal(0))
	g.Expect(h.server.Calls()).To(Equal(0))
}

// TestSessionProvider_ReturnsACopyOfTheSession proves a caller that changes the
// session it was handed changes nothing anyone else is handed, whether it was
// handed the exchange's session or a cache hit.
func TestSessionProvider_ReturnsACopyOfTheSession(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	tamper := func(s *workloadidentity.WorkloadSession) {
		s.ProviderArn = "tampered"
		s.Credentials.SecretAccessKey = "tampered"
		s.ExpiresAt = time.Time{}
	}
	exchanged, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	want := *exchanged
	tamper(exchanged)

	hit, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(hit).NotTo(BeIdenticalTo(exchanged))
	g.Expect(*hit).To(Equal(want))
	tamper(hit)

	again, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(again).NotTo(BeIdenticalTo(hit))
	g.Expect(*again).To(Equal(want), "a cache hit must be a copy too")
	g.Expect(h.server.Calls()).To(Equal(1))
}

// TestSessionProvider_CountsCacheLookups proves the cache metric counts hit,
// miss and expired on the read side, and nothing for an entry the cache pushes
// out, which credcache counts itself.
func TestSessionProvider_CountsCacheLookups(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t, func(o *fixtureOpts) { o.cache.MaxSize = 1 })
	count := func(result string) float64 { return h.cacheCount(result) }

	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	_, err = h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	h.clock.Advance(time.Hour)
	_, err = h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect([]float64{count("miss"), count("hit"), count("expired")}).To(Equal([]float64{1, 1, 1}))

	// A second pod in a cache of one pushes the first, still usable, out.
	_, err = h.session(otherSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(h.cachedKey(testSessionPodUID)).To(BeEmpty())
	g.Expect(count("miss")).To(Equal(2.0))
	g.Expect(count(workloadidentity.CacheResultEvicted)).To(BeZero())
}

// TestSessionProvider_ObservesEachExchangeOnce proves every exchange a Session
// caller starts is one observation, and neither a cache hit nor the cache's
// refresh of the session is one.
func TestSessionProvider_ObservesEachExchangeOnce(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t, sweeping)
	h.dueFirst()

	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	_, err = h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	h.eventuallyCached(t, testSessionPodUID, exchangeKey(2))
	h.server.SetError(eksauthtest.Throttling())
	h.provider.Invalidate(testSessionPodUID)
	_, err = h.session(testSessionPodUID)
	g.Expect(err).To(HaveOccurred())

	g.Expect(h.server.Calls()).To(Equal(3))
	g.Expect(h.exchangeCount(workloadidentity.OutcomeSuccess, wierrors.MetricLabelNone)).To(Equal(1.0))
	g.Expect(h.exchangeCount(workloadidentity.OutcomeFailure, wierrors.ErrSessionUnavailable.MetricLabel())).To(Equal(1.0))
	g.Expect(testutil.CollectAndCount(h.provider.metrics.latency)).To(Equal(2), "one latency series per outcome")
}

// TestRegisterCacheTotal proves the shared cache counter registers where it's
// absent, reuses the collector another tier registered, and never fails
// startup over a conflicting registration.
func TestRegisterCacheTotal(t *testing.T) {
	labels := []string{workloadidentity.LabelTier, workloadidentity.LabelResult}

	t.Run("registers where absent", func(t *testing.T) {
		g := NewWithT(t)
		reg := prometheus.NewRegistry()

		counter := registerCacheTotal(reg)
		counter.WithLabelValues(workloadidentity.CacheTierSession, workloadidentity.CacheResultHit).Inc()

		g.Expect(testutil.GatherAndCount(reg, workloadidentity.MetricCacheTotal)).To(Equal(1))
	})

	t.Run("reuses the collector the token minter registered", func(t *testing.T) {
		g := NewWithT(t)
		reg := prometheus.NewRegistry()
		// The token minter's registration, verbatim from internal/tokenminter/metrics.go.
		existing := promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: workloadidentity.MetricCacheTotal,
			Help: "Count of workload identity cache lookups, by tier and result.",
		}, labels)

		g.Expect(registerCacheTotal(reg)).To(BeIdenticalTo(existing))
	})

	t.Run("falls back to an unregistered counter on a conflict", func(t *testing.T) {
		g := NewWithT(t)
		reg := prometheus.NewRegistry()
		existing := promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: workloadidentity.MetricCacheTotal,
			Help: "Some other help text.",
		}, labels)

		var counter *prometheus.CounterVec
		g.Expect(func() { counter = registerCacheTotal(reg) }).NotTo(Panic())
		g.Expect(counter).NotTo(BeNil())
		g.Expect(counter).NotTo(BeIdenticalTo(existing))
		g.Expect(func() {
			counter.WithLabelValues(workloadidentity.CacheTierSession, workloadidentity.CacheResultHit).Inc()
		}).NotTo(Panic())
	})
}

// TestNew_RejectsAnInvalidConfiguration proves each missing field is an error
// rather than a panic or a provider that misbehaves, and that a missing cache
// names the flags that turn it off.
func TestNew_RejectsAnInvalidConfiguration(t *testing.T) {
	ctrl := gomock.NewController(t)
	// No expectations: validation must never reach EKS Auth.
	client := mockcreds.NewMockCredentialRetriever(ctrl)
	cache := credcache.New(credcache.Opts{Delegate: client, RenewalTtl: time.Hour, MaxSize: 10, CleanupInterval: time.Hour})
	valid := func() Opts {
		return Opts{ClusterName: testClusterName, Minter: &fake.TokenMinter{}, Cache: cache, EKSAuth: client,
			PodStore: &podstoretest.Store{}}
	}

	testCases := []struct {
		name    string
		change  func(o *Opts)
		wantErr []string
	}{
		{name: "no cluster name", change: func(o *Opts) { o.ClusterName = "" }, wantErr: []string{"cluster name"}},
		{name: "no minter", change: func(o *Opts) { o.Minter = nil }, wantErr: []string{"token minter"}},
		{
			name:   "no cache",
			change: func(o *Opts) { o.Cache = nil },
			wantErr: []string{
				"workload identity needs the credential cache",
				"--max-credential-retention-before-renewal",
				"--max-cache-size",
			},
		},
		{name: "no EKS Auth", change: func(o *Opts) { o.EKSAuth = nil }, wantErr: []string{"EKS Auth"}},
		{name: "no pod store", change: func(o *Opts) { o.PodStore = nil }, wantErr: []string{"pod store"}},
		{
			name:    "a pod store that refuses the callback",
			change:  func(o *Opts) { o.PodStore = &podstoretest.Store{RegisterErr: errors.New("no informer")} },
			wantErr: []string{"registering the pod deletion callback", "no informer"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			opts := valid()
			tc.change(&opts)

			p, err := New(opts)

			g.Expect(p).To(BeNil())
			g.Expect(err).To(HaveOccurred())
			for _, want := range tc.wantErr {
				g.Expect(err.Error()).To(ContainSubstring(want))
			}
		})
	}

	t.Run("every field set", func(t *testing.T) {
		g := NewWithT(t)
		opts := valid()
		p, err := New(opts)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(p.cache).To(BeIdenticalTo(cache))
		g.Expect(p.eksAuth).To(BeIdenticalTo(client))
		g.Expect(opts.PodStore.(*podstoretest.Store).Registered()).To(Equal(1), "New registers for pod deletions")
	})
}

// newMockedProvider builds a provider over a cache with its sweep an hour away, whose EKS
// Auth is client, minting "projected-token" for every exchange.
func newMockedProvider(t *testing.T, client credentials.CredentialRetriever) *Provider {
	t.Helper()
	cache := credcache.New(credcache.Opts{Delegate: client, RenewalTtl: 3 * time.Hour, MaxSize: 2000, CleanupInterval: time.Hour})
	p, err := New(Opts{
		ClusterName: testClusterName,
		Minter:      &fake.TokenMinter{Result: &workloadidentity.ProjectedToken{Token: "projected-token"}},
		Cache:       cache,
		EKSAuth:     client,
		PodStore:    &podstoretest.Store{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p.metrics = newTestSessionMetrics()
	return p
}

// TestSessionProvider_NilResponseIsSessionUnavailable proves a client that
// answers with neither a response nor an error, which only a broken client can,
// is a failed exchange rather than a panic.
func TestSessionProvider_NilResponseIsSessionUnavailable(t *testing.T) {
	g := NewWithT(t)
	ctrl := gomock.NewController(t)
	client := mockcreds.NewMockCredentialRetriever(ctrl)
	client.EXPECT().GetIamCredentials(gomock.Any(), &credentials.EksCredentialsRequest{
		ClusterName:         testClusterName,
		ServiceAccountToken: "projected-token",
	}).Return(nil, nil, nil)
	p := newMockedProvider(t, client)

	got, err := p.Session(t.Context(), sessionTestWorkload(testSessionPodUID))

	g.Expect(got).To(BeNil())
	g.Expect(err).To(MatchError(wierrors.ErrSessionUnavailable))
}

// TestSessionProvider_TakesTheAssociationFromTheResponseMetadata proves the
// entry keeps the metadata GetIamCredentials returns alongside the session, and
// its log context names that association. The provider ARN is in the metadata,
// so a client returning none yields ErrNotEnrolled.
func TestSessionProvider_TakesTheAssociationFromTheResponseMetadata(t *testing.T) {
	providerArn := eksauthtest.EnrolledSession(time.Time{}).ProviderArn
	for name, tc := range map[string]struct {
		metadata    credentials.ResponseMetadata
		wantErr     error
		wantAssocID string
	}{
		"metadata": {
			metadata: credentials.CredentialMetadata{
				Association: "a-mockedassoc0001", CredSource: credentials.SourceAuthService, Provider: providerArn,
			},
			wantAssocID: "a-mockedassoc0001",
		},
		"no metadata": {metadata: nil, wantErr: wierrors.ErrNotEnrolled},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			ctrl := gomock.NewController(t)
			client := mockcreds.NewMockCredentialRetriever(ctrl)
			client.EXPECT().GetIamCredentials(gomock.Any(), &credentials.EksCredentialsRequest{
				ClusterName:         testClusterName,
				ServiceAccountToken: "projected-token",
			}).Return(&credentials.EksCredentialsResponse{
				AccessKeyId:     "ASIAMOCKEDSESSION001",
				SecretAccessKey: "mocked-secret-access-key",
				Token:           "mocked-session-token",
				AccountId:       eksauthtest.AccountID,
				Expiration:      credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
			}, tc.metadata, nil)
			p := newMockedProvider(t, client)

			got, err := p.Session(t.Context(), sessionTestWorkload(testSessionPodUID))

			if tc.wantErr != nil {
				g.Expect(err).To(MatchError(tc.wantErr))
				return
			}
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(got.Credentials.AccessKeyID).To(Equal("ASIAMOCKEDSESSION001"))
			g.Expect(got.ProviderArn).To(Equal(providerArn))
			entry, ok := p.cache.Get(testSessionPodUID)
			g.Expect(ok).To(BeTrue())
			g.Expect(entry.Metadata == tc.metadata).To(BeTrue(), "the entry keeps the response metadata, whose source the cache reads")
			g.Expect(*entry.Request).To(Equal(credentials.EksCredentialsRequest{
				ClusterName: testClusterName, ServiceAccountToken: "projected-token",
			}), "the entry keeps the request it presented, for the cache's refreshes")
			g.Expect(logger.FromContext(entry.LogCtx).Data).To(SatisfyAll(
				HaveKeyWithValue("association-id", tc.wantAssocID),
				HaveKeyWithValue("pod-uid", testSessionPodUID),
			))
		})
	}
}

// TestSessionProvider_NeverLogsCredentialsOrTokens drives every line that logs,
// the client's and the cache's included, and proves no secret key, session
// token or projected token appears in any line.
func TestSessionProvider_NeverLogsCredentialsOrTokens(t *testing.T) {
	g := NewWithT(t)
	capture := captureLogs(t)
	h := newSessionFixture(t, sweeping)
	// The sweep refreshes the first session and its refresh at once, keeps it
	// over the third exchange's failure, and drops it over the fourth's.
	h.answerByExchange(func(n int64) (*eksauthtest.Session, *eksauthtest.APIError) {
		switch n {
		case 1, 2:
			return h.shortSessionFor(n), nil
		case 3:
			return nil, eksauthtest.InternalServer()
		case 4:
			return nil, eksauthtest.AccessDenied()
		}
		return h.sessionFor(n), nil
	})

	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	_, err = h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	capture.waitFor(t, testSessionPodUID, droppedLine(testSessionPodUID), 1)
	g.Expect(h.server.Calls()).To(Equal(4))

	_, err = h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	h.provider.Invalidate(testSessionPodUID)
	_, err = h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())

	lines := capture.all()
	g.Expect(lines).NotTo(BeEmpty())
	g.Expect(capture.fieldsAbout(testSessionPodUID, "Credentials still valid, keeping them")).NotTo(BeEmpty())
	secrets := []string{
		eksauthtest.EnrolledSession(time.Time{}).SecretAccessKey,
		eksauthtest.EnrolledSession(time.Time{}).SessionToken,
		"workload-session-token-",
		eksauthtest.NodeSecretAccessKey,
		eksauthtest.NodeSessionToken,
	}
	minted := h.mintedTokens()
	g.Expect(minted).NotTo(BeEmpty())
	for _, token := range minted {
		secrets = append(secrets, token, strings.Split(token, ".")[1])
	}
	for _, line := range lines {
		for _, secret := range secrets {
			g.Expect(strings.Contains(line, secret)).To(BeFalse(), "log line leaks %q: %s", secret, line)
		}
	}
}

// TestSessionProvider_LogsAboutAnEntryNameItsPodAndAssociation proves the lines
// logged about an entry away from any request, by a refresh, an invalidation
// and the cache's eviction, carry the pod UID and association ID the entry's
// LogCtx keeps, and that a refresh's lines say where they came from.
func TestSessionProvider_LogsAboutAnEntryNameItsPodAndAssociation(t *testing.T) {
	g := NewWithT(t)
	capture := captureLogs(t)
	h := newSessionFixture(t, sweeping, func(o *fixtureOpts) { o.cache.MaxSize = 1 })
	h.dueFirst()
	associationID := eksauthtest.EnrolledSession(time.Time{}).AssociationID
	namesTheEntry := SatisfyAll(
		HaveKeyWithValue("pod-uid", testSessionPodUID),
		HaveKeyWithValue("association-id", associationID),
	)

	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	h.eventuallyCached(t, testSessionPodUID, exchangeKey(2))
	h.provider.Invalidate(testSessionPodUID)
	_, err = h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	// A second pod in a cache of one pushes the first, still usable, out.
	_, err = h.session(otherSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())

	g.Expect(capture.fieldsOf("Storing creds in cache")).To(ContainElement(
		SatisfyAll(namesTheEntry, HaveKeyWithValue("from", "renewal-thread"))), "the refresh's store")
	g.Expect(capture.fieldsOf("Session invalidated, dropping its session")).To(ConsistOf(namesTheEntry))
	// The cache logs every removal: the invalidation's and the capacity
	// eviction's.
	g.Expect(capture.fieldsAbout(testSessionPodUID, "Credentials evicted from cache")).To(ConsistOf(namesTheEntry, namesTheEntry))
}

// TestSessionProvider_ARequestAndARefreshEachLogUnderTheirOwnContext proves a
// refresh builds its context from the entry's fields rather than from the
// request that first exchanged the session. The request's store line carries
// the request's fields and names the entry; the refresh's name the entry and
// where they came from, and carry none of the request's fields.
func TestSessionProvider_ARequestAndARefreshEachLogUnderTheirOwnContext(t *testing.T) {
	g := NewWithT(t)
	capture := captureLogs(t)
	h := newSessionFixture(t, sweeping)
	h.dueFirst()
	associationID := eksauthtest.EnrolledSession(time.Time{}).AssociationID
	const clientAddr = "192.0.2.10:40000"
	requestCtx := logger.ContextWithField(t.Context(), "client-addr", clientAddr)

	_, err := h.provider.Session(requestCtx, sessionTestWorkload(testSessionPodUID))
	g.Expect(err).NotTo(HaveOccurred())
	h.eventuallyCached(t, testSessionPodUID, exchangeKey(2))

	fromTheRequest := SatisfyAll(
		HaveKeyWithValue("client-addr", clientAddr),
		HaveKeyWithValue("association-id", associationID),
		Not(HaveKey("from")),
	)
	fromTheRefresh := SatisfyAll(
		HaveKeyWithValue("from", "renewal-thread"),
		HaveKeyWithValue("association-id", associationID),
		Not(HaveKey("client-addr")),
	)
	// The cache logs a refresh's store once, after it stores.
	capture.waitFor(t, testSessionPodUID, "Storing creds in cache", 2)
	g.Expect(capture.fieldsAbout(testSessionPodUID, "Storing creds in cache")).To(
		ConsistOf(fromTheRequest, fromTheRefresh))
}

// TestSessionProvider_AFailedRefreshsOwnLinesNameItsPodAndAssociation proves
// the lines the cache logs about a failed refresh name the entry: the context
// is built from the entry's LogCtx, which carries the pod UID and the
// association ID, plus where the lines come from.
func TestSessionProvider_AFailedRefreshsOwnLinesNameItsPodAndAssociation(t *testing.T) {
	g := NewWithT(t)
	capture := captureLogs(t)
	h := newSessionFixture(t, sweeping)
	h.answerByExchange(func(n int64) (*eksauthtest.Session, *eksauthtest.APIError) {
		if n == 1 {
			return h.shortSessionFor(n), nil
		}
		return nil, eksauthtest.InternalServer()
	})
	associationID := eksauthtest.EnrolledSession(time.Time{}).AssociationID
	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())

	capture.waitFor(t, testSessionPodUID, "Credentials still valid, keeping them", 1)

	fromTheRefresh := SatisfyAll(
		HaveKeyWithValue("from", "renewal-thread"),
		HaveKeyWithValue("association-id", associationID),
	)
	for _, prefix := range []string{"Background refresh failed for pod", "Credentials still valid, keeping them"} {
		lines := capture.fieldsAbout(testSessionPodUID, prefix)
		g.Expect(lines).NotTo(BeEmpty(), prefix)
		g.Expect(lines).To(HaveEach(fromTheRefresh), prefix)
	}
}

// TestSessionProvider_ARefreshedEntryLogsUnderTheAssociationOfItsSession proves
// the entry a refresh stores logs under the association of the session it holds
// when EKS Auth answers with another association, as it does once a pod
// identity association is recreated.
func TestSessionProvider_ARefreshedEntryLogsUnderTheAssociationOfItsSession(t *testing.T) {
	const renewedAssociation = "a-renewedassoc00002"
	g := NewWithT(t)
	capture := captureLogs(t)
	h := newSessionFixture(t, sweeping, func(o *fixtureOpts) { o.cache.MaxSize = 1 })
	h.answerByExchange(func(n int64) (*eksauthtest.Session, *eksauthtest.APIError) {
		if n == 1 {
			return h.shortSessionFor(n), nil
		}
		session := h.sessionFor(n)
		session.AssociationID = renewedAssociation
		return session, nil
	})

	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	h.eventuallyCached(t, testSessionPodUID, exchangeKey(2))
	renewed, _ := h.cache.Get(testSessionPodUID)
	g.Expect(logger.FromContext(renewed.LogCtx).Data).To(HaveKeyWithValue("association-id", renewedAssociation))

	// A second pod in a cache of one pushes the renewed entry out, which the
	// cache logs under the entry's own fields.
	_, err = h.session(otherSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(capture.fieldsAbout(testSessionPodUID, "Credentials evicted from cache")).To(ContainElement(SatisfyAll(
		HaveKeyWithValue("from", "renewal-thread"),
		HaveKeyWithValue("association-id", renewedAssociation),
	)))
}

// TestSessionProvider_AFailedRefreshIsRetriedAfterTheRetryIntervalPlusJitter
// proves the cache's schedule for a session kept over failed refreshes: each
// retry comes no sooner than the retry interval and no later than that plus the
// jitter and some slack, the jitter is added, and the kept session is still
// cached when a retry is due, since it's evicted only once it expires.
func TestSessionProvider_AFailedRefreshIsRetriedAfterTheRetryIntervalPlusJitter(t *testing.T) {
	const (
		retryInterval = 100 * time.Millisecond
		maxJitter     = time.Second
		failures      = 4
		slack         = 500 * time.Millisecond
	)
	g := NewWithT(t)
	h := newSessionFixture(t, sweeping, func(o *fixtureOpts) {
		// New allows a renewal TTL under a second only for a cache of one.
		o.cache.MaxSize = 1
		o.cache.RenewalTtl = retryInterval
		o.cache.RetryInterval = retryInterval
		o.cache.MaxRetryJitter = maxJitter
	})
	var mu sync.Mutex
	var exchanged []time.Time
	held := make(chan struct{})
	t.Cleanup(func() { close(held) })
	h.answerByExchange(func(n int64) (*eksauthtest.Session, *eksauthtest.APIError) {
		func() {
			mu.Lock()
			defer mu.Unlock()
			exchanged = append(exchanged, time.Now())
		}()
		switch {
		case n == 1:
			return h.sessionFor(n), nil
		case n <= 1+failures:
			return nil, eksauthtest.InternalServer()
		case n == 2+failures:
			<-held
		}
		return h.sessionFor(n), nil
	})
	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	picked, _ := h.cache.Get(testSessionPodUID)

	g.Eventually(h.server.Calls).WithTimeout(failures*(retryInterval+maxJitter+slack)).
		WithPolling(5*time.Millisecond).Should(Equal(2+failures), "waiting for the retry after the last failure")
	kept, ok := h.cache.Get(testSessionPodUID)
	g.Expect(ok).To(BeTrue(), "a kept session must stay cached past its retry")
	g.Expect(kept.Credentials).To(BeIdenticalTo(picked.Credentials))

	mu.Lock()
	defer mu.Unlock()
	// The first exchange is the request's; the refreshes' follow.
	g.Expect(exchanged).To(HaveLen(2 + failures))
	jittered := false
	for i := 2; i < len(exchanged); i++ {
		gap := exchanged[i].Sub(exchanged[i-1])
		g.Expect(gap).To(BeNumerically(">=", retryInterval), "retry %d came too soon", i-1)
		g.Expect(gap).To(BeNumerically("<=", retryInterval+maxJitter+slack), "retry %d came too late", i-1)
		jittered = jittered || gap > retryInterval+50*time.Millisecond
	}
	g.Expect(jittered).To(BeTrue(), "no retry was jittered")
}
