package session

// Tests of the HTTP retriever and the session tier sharing one credential
// cache: GetIamCredentials for the Pod Identity HTTP endpoint and Session for
// the workload identity socket. They run on sessionFixture, so both go through
// the real EKS Auth client to the fake. HTTP callers present a JWT naming their
// pod; Session mints its own.

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/eksauth/types"
	. "github.com/onsi/gomega"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/eksauth/eksauthtest"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/credcache"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/credsretriever"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// httpAccessKey is the access key ID of the session the fake answers an HTTP
// caller's token with in these tests, so a test can tell it from an exchanged one.
const httpAccessKey = "ASIAHTTPEXCHANGE0001"

// podToken is a JWT naming podUID, as a pod presents to the HTTP endpoint.
// Tokens for one pod with different n differ.
func podToken(t *testing.T, podUID string, n int) string {
	issued := time.Now().Add(time.Duration(n) * time.Second)
	return test.CreateToken(t, test.TokenConfig{Expiry: issued.Add(time.Hour), Iat: issued, Nbf: issued, PodUID: podUID})
}

// answerTokens makes the fake answer each token in sessions with its session,
// every exchange of a minted token as answerWithSessions does, and anything else
// with InvalidToken. The map must not change afterwards.
func (h *sessionFixture) answerTokens(sessions map[string]*eksauthtest.Session) {
	h.answerTokensOr(sessions, func(n int64) (*eksauthtest.Session, *eksauthtest.APIError) {
		return h.sessionFor(n), nil
	})
}

// answerTokensOr is answerTokens answering exchanges of minted tokens with
// minted.
func (h *sessionFixture) answerTokensOr(sessions map[string]*eksauthtest.Session,
	minted func(n int64) (*eksauthtest.Session, *eksauthtest.APIError)) {
	h.server.SetFunc(func(r eksauthtest.Request) (*eksauthtest.Session, *eksauthtest.APIError) {
		if session, ok := sessions[r.Token]; ok {
			return session, nil
		}
		n, ok := h.exchangeNumber(r.Token)
		if !ok {
			return nil, eksauthtest.InvalidToken()
		}
		return minted(n)
	})
}

// httpSession is an enrolled session, keyed httpAccessKey, expiring an hour
// after the test clock.
func (h *sessionFixture) httpSession() *eksauthtest.Session {
	session := eksauthtest.EnrolledSession(h.clock.Now().Add(time.Hour))
	session.AccessKeyID = httpAccessKey
	return &session
}

// httpCredentials asks the HTTP retriever for the credentials of the pod token
// names.
func (h *sessionFixture) httpCredentials(ctx context.Context, token string) (*credentials.EksCredentialsResponse, error) {
	creds, _, err := h.http.GetIamCredentials(ctx, &credentials.EksCredentialsRequest{
		ClusterName:         testClusterName,
		ServiceAccountToken: token,
	})
	return creds, err
}

type credentialsResult struct {
	creds *credentials.EksCredentialsResponse
	err   error
}

func (h *sessionFixture) httpCredentialsAsync(ctx context.Context, token string) <-chan credentialsResult {
	results := make(chan credentialsResult, 1)
	go func() {
		creds, err := h.httpCredentials(ctx, token)
		results <- credentialsResult{creds: creds, err: err}
	}()
	return results
}

func awaitCredentials(t *testing.T, results <-chan credentialsResult) credentialsResult {
	t.Helper()
	select {
	case r := <-results:
		return r
	case <-time.After(sessionTestTimeout):
		t.Fatalf("GetIamCredentials did not return within %s", sessionTestTimeout)
		return credentialsResult{}
	}
}

// withValidator gives the HTTP retriever v as its token validator.
func withValidator(v tokenValidator) func(*fixtureOpts) {
	return func(o *fixtureOpts) { o.validator = v }
}

// TestSharedCache_AnHTTPEntryForAnEnrolledPodServesSessionWithoutAMint proves
// Session serves a decorated entry the HTTP retriever stored, as a cache hit,
// with no mint and no exchange.
func TestSharedCache_AnHTTPEntryForAnEnrolledPodServesSessionWithoutAMint(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	token := podToken(t, testSessionPodUID, 0)
	h.answerTokens(map[string]*eksauthtest.Session{token: h.httpSession()})

	creds, err := h.httpCredentials(t.Context(), token)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(creds.AccessKeyId).To(Equal(httpAccessKey))
	g.Expect(h.exchangeCount(workloadidentity.OutcomeSuccess, wierrors.MetricLabelNone)).To(BeZero(),
		"an HTTP miss isn't a session exchange")

	got, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got.Credentials.AccessKeyID).To(Equal(httpAccessKey))
	g.Expect(got.ProviderArn).To(Equal(eksauthtest.EnrolledSession(time.Time{}).ProviderArn))
	g.Expect(h.minter.Calls()).To(BeZero())
	g.Expect(h.server.Calls()).To(Equal(1))
	g.Expect(h.cacheCount(workloadidentity.CacheResultHit)).To(Equal(1.0))
}

// TestSharedCache_ASessionEntryServesHTTPOnlyToAValidatedToken proves an entry
// Session stored, which keeps the minted token no pod holds, serves an HTTP
// caller only once the local validator accepts the caller's token. A rejected
// token exchanges on its own; an accepted one is served and recorded, and hits
// on token equality after.
func TestSharedCache_ASessionEntryServesHTTPOnlyToAValidatedToken(t *testing.T) {
	g := NewWithT(t)
	validator := &scriptedValidator{err: errors.New("signature mismatch")}
	h := newSessionFixture(t, withValidator(validator))
	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())

	rejected := podToken(t, testSessionPodUID, 0)
	var creds *credentials.EksCredentialsResponse
	g.Expect(func() { creds, err = h.httpCredentials(t.Context(), rejected) }).NotTo(Panic())
	g.Expect(creds).To(BeNil(), "a rejected token must not be served the session")
	g.Expect(err).To(HaveOccurred())
	g.Expect(validator.wasCalled()).To(BeTrue())
	g.Expect(h.server.Calls()).To(Equal(2), "a rejected token must exchange on its own")
	g.Expect(h.cachedKey(testSessionPodUID)).To(Equal(exchangeKey(1)), "the failed exchange must leave the session cached")

	validator.set(nil)
	accepted := podToken(t, testSessionPodUID, 1)
	creds, err = h.httpCredentials(t.Context(), accepted)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(creds.AccessKeyId).To(Equal(exchangeKey(1)))
	g.Expect(h.server.Calls()).To(Equal(2))
	entry, _ := h.cache.Get(testSessionPodUID)
	g.Expect(entry.Request.ServiceAccountToken).To(Equal(accepted))
	g.Expect(entry.Metadata.ProviderArn()).NotTo(BeEmpty(), "recording the token keeps the session decorated")

	validator.set(nil)
	_, err = h.httpCredentials(t.Context(), accepted)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(validator.wasCalled()).To(BeFalse(), "the recorded token must hit on equality")
}

// TestSharedCache_ASessionEntryRefreshesWithTheTokenAnHTTPHitRecorded proves
// the cache refreshes a Session entry by its one rule after an HTTP caller's
// validated token is recorded on it: through EKS Auth, presenting that token
// while it's outside the token floor, and minting nothing.
func TestSharedCache_ASessionEntryRefreshesWithTheTokenAnHTTPHitRecorded(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t, sweeping, dueEverySecond, withValidator(&scriptedValidator{}))
	token := podToken(t, testSessionPodUID, 0)
	h.answerTokens(map[string]*eksauthtest.Session{token: h.httpSession()})
	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	creds, err := h.httpCredentials(t.Context(), token)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(creds.AccessKeyId).To(Equal(exchangeKey(1)), "the validated token must be served the session")

	h.eventuallyCached(t, testSessionPodUID, httpAccessKey)

	requests := h.server.Requests()
	g.Expect(requests).To(HaveLen(2))
	g.Expect(requests[1].Token).To(Equal(token), "the refresh presents the token the hit recorded")
	g.Expect(h.minter.Calls()).To(Equal(1))
}

// TestSharedCache_ASessionEntryNeverServesHTTPWithoutAValidator proves an entry
// Session stored serves no HTTP caller while no local validator is loaded, and
// that the HTTP lookup of an entry recording another token falls through rather
// than panics. The pod UID in a token is only a claim until validated.
func TestSharedCache_ASessionEntryNeverServesHTTPWithoutAValidator(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())

	var creds *credentials.EksCredentialsResponse
	g.Expect(func() { creds, err = h.httpCredentials(t.Context(), podToken(t, testSessionPodUID, 0)) }).NotTo(Panic())

	g.Expect(creds).To(BeNil(), "an unvalidated token must not be served the session")
	g.Expect(err).To(HaveOccurred())
	g.Expect(h.server.Calls()).To(Equal(2), "the unvalidated token must exchange on its own")
}

// TestSharedCache_AForgedHTTPTokenNeverJoinsTheSessionExchange proves the HTTP
// retriever and the session tier never share a flight. While a Session exchange
// for a pod is parked at EKS Auth, an HTTP caller whose token claims that pod
// makes its own exchange and gets EKS Auth's refusal, never the session.
func TestSharedCache_AForgedHTTPTokenNeverJoinsTheSessionExchange(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	h.server.Block()
	pending := h.sessionAsync(t.Context(), testSessionPodUID)
	h.waitForBlocked(t, 1)

	forged := podToken(t, testSessionPodUID, 0)
	httpPending := h.httpCredentialsAsync(t.Context(), forged)
	h.waitForBlocked(t, 2)
	h.server.Release()

	forgedResult := awaitCredentials(t, httpPending)
	g.Expect(forgedResult.creds).To(BeNil())
	var invalidToken *types.InvalidTokenException
	g.Expect(errors.As(forgedResult.err, &invalidToken)).To(BeTrue(), "the forged token must get EKS Auth's own answer")
	sessionResult := awaitResult(t, pending)
	g.Expect(sessionResult.err).NotTo(HaveOccurred())
	g.Expect(sessionResult.session.Credentials.AccessKeyID).To(Equal(exchangeKey(1)))

	var tokens []string
	for _, r := range h.server.Requests() {
		tokens = append(tokens, r.Token)
	}
	g.Expect(tokens).To(ConsistOf(h.minted(1), forged))
}

// TestSharedCache_InvalidateForcesTheNextHTTPRequestToExchange proves Invalidate
// drops an entry the HTTP retriever stored, so that caller's next request
// exchanges again instead of hitting.
func TestSharedCache_InvalidateForcesTheNextHTTPRequestToExchange(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	token := podToken(t, testSessionPodUID, 0)
	h.answerTokens(map[string]*eksauthtest.Session{token: h.httpSession()})
	for range 2 {
		_, err := h.httpCredentials(t.Context(), token)
		g.Expect(err).NotTo(HaveOccurred())
	}
	g.Expect(h.server.Calls()).To(Equal(1))

	h.provider.Invalidate(testSessionPodUID)

	g.Expect(h.cachedKey(testSessionPodUID)).To(BeEmpty())
	_, err := h.httpCredentials(t.Context(), token)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(h.server.Calls()).To(Equal(2))
}

// TestSharedCache_ANotEnrolledHTTPEntryMakesSessionExchangeAndStaysCached proves
// Session treats an entry with no provider ARN as a miss: it exchanges, gets
// ErrNotEnrolled, stores nothing, and the HTTP entry goes on serving its caller.
func TestSharedCache_ANotEnrolledHTTPEntryMakesSessionExchangeAndStaysCached(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t)
	h.server.SetFunc(func(eksauthtest.Request) (*eksauthtest.Session, *eksauthtest.APIError) {
		session := eksauthtest.NotEnrolledSession(h.clock.Now().Add(time.Hour))
		return &session, nil
	})
	token := podToken(t, testSessionPodUID, 0)
	_, err := h.httpCredentials(t.Context(), token)
	g.Expect(err).NotTo(HaveOccurred())
	httpEntry, _ := h.cache.Get(testSessionPodUID)

	got, err := h.session(testSessionPodUID)

	g.Expect(got).To(BeNil())
	g.Expect(err).To(MatchError(wierrors.ErrNotEnrolled))
	g.Expect(h.minter.Calls()).To(Equal(1))
	g.Expect(h.server.Calls()).To(Equal(2))
	g.Expect(h.cacheCount(workloadidentity.CacheResultMiss)).To(Equal(1.0))
	g.Expect(h.cacheCount(workloadidentity.CacheResultExpired)).To(BeZero())
	g.Expect(h.provider.cached(testSessionPodUID, httpEntry)).To(BeTrue(), "ErrNotEnrolled must leave the HTTP entry in place")
	_, err = h.httpCredentials(t.Context(), token)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(h.server.Calls()).To(Equal(2))
}

// TestSharedCache_DecoratedEntriesRefreshThroughEKSAuthAndOthersThroughTheChain
// proves the cache's rule under an [imds, eksauth] chain whose IMDS source
// answers first. A Session entry and a decorated HTTP entry refresh through EKS
// Auth with their own tokens, never asking IMDS. An undecorated HTTP entry
// refreshes through the chain, and Session exchanges rather than serve its answer.
func TestSharedCache_DecoratedEntriesRefreshThroughEKSAuthAndOthersThroughTheChain(t *testing.T) {
	const refreshedHTTPKey = "ASIAHTTPREFRESHED001"
	g := NewWithT(t)
	imds := &imdsLikeRetriever{}
	h := newSessionFixture(t, sweeping, dueEverySecond, func(o *fixtureOpts) {
		o.delegate = func(eksAuth credentials.CredentialRetriever) credentials.CredentialRetriever {
			return credsretriever.NewChainedRetriever(imds, eksAuth)
		}
	})
	undecoratedToken := podToken(t, otherSessionPodUID, 0)
	decoratedToken := podToken(t, thirdSessionPodUID, 0)
	notEnrolled := eksauthtest.NotEnrolledSession(h.clock.Now().Add(time.Hour))
	notEnrolled.AccessKeyID = httpAccessKey
	var decoratedAnswers atomic.Int64
	h.server.SetFunc(func(r eksauthtest.Request) (*eksauthtest.Session, *eksauthtest.APIError) {
		switch r.Token {
		case undecoratedToken:
			return &notEnrolled, nil
		case decoratedToken:
			session := h.httpSession()
			if decoratedAnswers.Add(1) > 1 {
				session.AccessKeyID = refreshedHTTPKey
			}
			return session, nil
		}
		if n, ok := h.exchangeNumber(r.Token); ok {
			return h.sessionFor(n), nil
		}
		return nil, eksauthtest.InvalidToken()
	})
	enrolledArn := eksauthtest.EnrolledSession(time.Time{}).ProviderArn

	for _, token := range []string{undecoratedToken, decoratedToken} {
		_, err := h.httpCredentials(t.Context(), token)
		g.Expect(err).NotTo(HaveOccurred())
	}
	got, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got.Credentials.AccessKeyID).To(Equal(exchangeKey(1)))
	g.Expect(imds.calls.Load()).To(BeZero(), "no cache miss may ask IMDS")

	h.eventuallyCached(t, otherSessionPodUID, imdsAccessKey)
	h.eventuallyCached(t, thirdSessionPodUID, refreshedHTTPKey)
	h.eventuallyCached(t, testSessionPodUID, exchangeKey(2))

	undecorated, _ := h.cache.Get(otherSessionPodUID)
	g.Expect(undecorated.Metadata.Source()).To(Equal(credentials.SourceIMDS), "the undecorated entry refreshes through the chain")
	decorated, _ := h.cache.Get(thirdSessionPodUID)
	g.Expect(decorated.Request.ServiceAccountToken).To(Equal(decoratedToken), "the decorated HTTP entry presents its own token")
	g.Expect(decorated.Metadata.ProviderArn()).To(Equal(enrolledArn))
	sessionEntry, _ := h.cache.Get(testSessionPodUID)
	g.Expect(sessionEntry.Metadata.Source()).To(Equal(credentials.SourceAuthService))
	g.Expect(h.presentedBy(2)).To(Equal(h.minted(1)), "the Session entry presents its own token")
	g.Expect(imds.calls.Load()).To(Equal(int64(1)), "only the undecorated entry's refresh may ask IMDS")

	// The source metric is what an operator reads during the HOSM/WISE overlap to
	// confirm enrolled pods are skipping IMDS. It must agree with what the chain
	// was actually asked: two refreshes bypassed IMDS, one did not.
	g.Expect(h.sourceCount(workloadidentity.CredentialSourceEKSAuth)).To(Equal(2.0),
		"the Session entry and the decorated HTTP entry are both routed to EKS Auth")
	g.Expect(h.sourceCount(workloadidentity.CredentialSourceIMDSFirst)).To(Equal(1.0),
		"only the undecorated entry is routed to the IMDS-first chain")

	got, err = h.session(otherSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got.Credentials.AccessKeyID).To(HavePrefix("ASIAEXCHANGE"), "an IMDS entry must not serve Session")
	g.Expect(got.ProviderArn).To(Equal(enrolledArn))
	g.Expect(imds.calls.Load()).To(Equal(int64(1)))
	g.Expect(h.minter.Calls()).To(Equal(2), "only the two exchanges mint")
}

// imdsLikeRetriever answers every request as IMDS does: an unexpired credential
// with no provider ARN, sourced from IMDS. It counts the requests it answers and
// records the token each presented.
type imdsLikeRetriever struct {
	calls  atomic.Int64
	mu     sync.Mutex
	tokens []string
}

const imdsAccessKey = "ASIAIMDSUNDECORATED1"

func (r *imdsLikeRetriever) String() string                       { return "imds" }
func (r *imdsLikeRetriever) IsIrrecoverable(error) (string, bool) { return "Unknown", false }

func (r *imdsLikeRetriever) GetIamCredentials(_ context.Context, request *credentials.EksCredentialsRequest) (
	*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
	r.calls.Add(1)
	r.mu.Lock()
	r.tokens = append(r.tokens, request.ServiceAccountToken)
	r.mu.Unlock()
	return &credentials.EksCredentialsResponse{
		AccessKeyId:     imdsAccessKey,
		SecretAccessKey: "imds-secret-access-key",
		Token:           "imds-session-token",
		AccountId:       eksauthtest.AccountID,
		Expiration:      credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
	}, credentials.CredentialMetadata{CredSource: credentials.SourceIMDS}, nil
}

// presented returns the token of every request, in order.
func (r *imdsLikeRetriever) presented() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.tokens...)
}

// TestSharedCache_AnUndecoratedEntryRefreshesWithItsStoredTokenNearExpiry proves
// the token swap is only for decorated entries. An undecorated HTTP entry whose
// token expires within the cache's token floor, an IMDS-sourced one included,
// refreshes through the chain presenting that token, and nothing is minted.
func TestSharedCache_AnUndecoratedEntryRefreshesWithItsStoredTokenNearExpiry(t *testing.T) {
	for name, fromIMDS := range map[string]bool{"not enrolled": false, "from IMDS": true} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			imds := &imdsLikeRetriever{}
			h := newSessionFixture(t, sweeping, dueEverySecond, func(o *fixtureOpts) {
				o.delegate = func(eksAuth credentials.CredentialRetriever) credentials.CredentialRetriever {
					return credsretriever.NewChainedRetriever(imds, eksAuth)
				}
			})
			// It names the pod in full, so MinterTokens could mint for it. Number 0
			// is one the minter never mints.
			token := mintedToken(0, sessionTestWorkload(testSessionPodUID), h.clock.Now().Add(2*time.Minute))
			notEnrolled := eksauthtest.NotEnrolledSession(h.clock.Now().Add(time.Hour))
			notEnrolled.AccessKeyID = httpAccessKey
			h.answerTokens(map[string]*eksauthtest.Session{token: &notEnrolled})
			_, err := h.httpCredentials(t.Context(), token)
			g.Expect(err).NotTo(HaveOccurred())
			if fromIMDS {
				// An IMDS entry refreshes every 30 minutes, so relabel the stored
				// entry, keeping its refresh a second away, rather than wait.
				g.Expect(h.cache.Modify(testSessionPodUID, func(e *credcache.Entry) {
					e.Metadata = credentials.CredentialMetadata{CredSource: credentials.SourceIMDS}
				})).To(BeTrue())
			}

			h.eventuallyCached(t, testSessionPodUID, imdsAccessKey)
			g.Expect(imds.presented()).To(Equal([]string{token}), "the refresh presents the stored token")
			refreshed, _ := h.cache.Get(testSessionPodUID)
			g.Expect(refreshed.Request.ServiceAccountToken).To(Equal(token))
			g.Expect(h.attempts.Load()).To(BeZero(), "nothing is minted for an undecorated entry")
			g.Expect(h.server.Calls()).To(Equal(1), "only the HTTP miss goes to EKS Auth")
		})
	}
}

// TestSharedCache_APodEnrolledAfterItsEntryCameFromIMDSKeepsRefreshingThroughIMDS
// pins what happens when a pod's association gains a workload identity template
// while the pod already holds an undecorated entry sourced from IMDS.
//
// The fork rule reads enrollment off the entry, so an undecorated entry routes
// to the chain, IMDS answers it, and the renewal is undecorated too: the pod
// keeps refreshing through IMDS indefinitely, never learning it is now enrolled.
// Nothing breaks it out on its own, because an IMDS entry refreshes every 30
// minutes and never evicts.
//
// That is accepted rather than a defect, because the pod cannot use workload
// identity until it restarts anyway: the webhook injects SPIFFE_ENDPOINT_SOCKET
// and the socket volume at admission, so a running pod has no socket to ask for
// an SVID on, and an undecorated session harms nothing while it holds one. A
// pod-spec marker would read the same way for the same reason, so this is not a
// cost of resolving enrollment from the provider ARN. On restart the pod gets a
// new UID, misses the cache, and is served the decorated session, which the last
// phase here stands in for by dropping the entry.
func TestSharedCache_APodEnrolledAfterItsEntryCameFromIMDSKeepsRefreshingThroughIMDS(t *testing.T) {
	const enrolledHTTPKey = "ASIAHTTPENROLLED0001"
	g := NewWithT(t)
	imds := &imdsLikeRetriever{}
	h := newSessionFixture(t, sweeping, dueEverySecond, func(o *fixtureOpts) {
		o.delegate = func(eksAuth credentials.CredentialRetriever) credentials.CredentialRetriever {
			return credsretriever.NewChainedRetriever(imds, eksAuth)
		}
	})
	token := podToken(t, testSessionPodUID, 0)
	enrolledArn := eksauthtest.EnrolledSession(time.Time{}).ProviderArn

	// The association carries no workload identity template yet, so EKS Auth
	// answers undecorated. enrolled flips when the template is added.
	notEnrolled := eksauthtest.NotEnrolledSession(h.clock.Now().Add(time.Hour))
	notEnrolled.AccessKeyID = httpAccessKey
	var enrolled atomic.Bool
	h.server.SetFunc(func(r eksauthtest.Request) (*eksauthtest.Session, *eksauthtest.APIError) {
		if r.Token == token {
			if !enrolled.Load() {
				return &notEnrolled, nil
			}
			decorated := h.httpSession()
			decorated.AccessKeyID = enrolledHTTPKey
			return decorated, nil
		}
		if n, ok := h.exchangeNumber(r.Token); ok {
			return h.sessionFor(n), nil
		}
		return nil, eksauthtest.InvalidToken()
	})

	// 1. Not enrolled: the pod's first request is a miss, so EKS Auth serves it
	//    undecorated, as Mode 2's sync does.
	_, err := h.httpCredentials(t.Context(), token)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(h.cachedKey(testSessionPodUID)).To(Equal(httpAccessKey))

	// 2. A Mode 2 refresh has since served the pod from IMDS. Relabelling the
	//    stored entry is how an IMDS-sourced entry is reached without waiting out
	//    the 30 minute IMDS refresh, and Modify keeps the second-away schedule.
	g.Expect(h.cache.Modify(testSessionPodUID, func(e *credcache.Entry) {
		e.Metadata = credentials.CredentialMetadata{CredSource: credentials.SourceIMDS}
	})).To(BeTrue())

	// 3. The association gains the template, so EKS Auth would now decorate.
	enrolled.Store(true)

	// 4. The entry carries no provider ARN, so the refresh still routes to the
	//    chain and IMDS answers it. EKS Auth is never asked.
	h.eventuallyCached(t, testSessionPodUID, imdsAccessKey)
	g.Expect(h.server.Calls()).To(Equal(1), "EKS Auth must not be asked, though it would now decorate")
	g.Expect(imds.calls.Load()).To(Equal(int64(1)))
	stale, ok := h.cache.Get(testSessionPodUID)
	g.Expect(ok).To(BeTrue())
	g.Expect(stale.Metadata.ProviderArn()).To(BeEmpty(), "the renewal is undecorated too")
	g.Expect(stale.Metadata.Source()).To(Equal(credentials.SourceIMDS))
	g.Expect(h.sourceCount(workloadidentity.CredentialSourceIMDSFirst)).To(Equal(1.0))
	g.Expect(h.sourceCount(workloadidentity.CredentialSourceEKSAuth)).To(BeZero(),
		"enrollment the entry cannot see does not route it to EKS Auth")

	// 5. It heals on the next cache miss, which a pod restart or an agent restart
	//    produces: EKS Auth is asked again and decorates, so the entry the fork
	//    rule reads from then on carries the provider ARN.
	h.cache.Delete(testSessionPodUID)
	_, err = h.httpCredentials(t.Context(), token)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(h.server.Calls()).To(Equal(2))
	healed, ok := h.cache.Get(testSessionPodUID)
	g.Expect(ok).To(BeTrue())
	g.Expect(healed.Credentials.AccessKeyId).To(Equal(enrolledHTTPKey))
	g.Expect(healed.Metadata.ProviderArn()).To(Equal(enrolledArn))
	g.Expect(imds.calls.Load()).To(Equal(int64(1)), "a miss never asks IMDS")
}

// TestSharedCache_AMintForbiddenDropIsHealedByTheNextHTTPRequest proves a Session
// entry the sweep dropped because its refresh's mint was refused comes back
// through the HTTP retriever: the pod's next HTTP request exchanges and stores,
// and Session then serves that entry without minting.
func TestSharedCache_AMintForbiddenDropIsHealedByTheNextHTTPRequest(t *testing.T) {
	g := NewWithT(t)
	capture := captureLogs(t)
	h := newSessionFixture(t, sweeping, expiringTokens)
	token := podToken(t, testSessionPodUID, 0)
	h.answerTokensOr(map[string]*eksauthtest.Session{token: h.httpSession()},
		func(n int64) (*eksauthtest.Session, *eksauthtest.APIError) { return h.shortSessionFor(n), nil })
	h.failMintAttempts(func(attempt int64) error {
		if attempt > 1 {
			return wierrors.ErrTokenMintForbidden.Wrapf(nil, "CSIDriver does not declare the audience")
		}
		return nil
	})
	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	picked, _ := h.cache.Get(testSessionPodUID)

	capture.waitFor(t, testSessionPodUID, droppedLine(testSessionPodUID), 1)
	g.Expect(h.provider.cached(testSessionPodUID, picked)).To(BeFalse(), "a refused mint must drop the entry")

	creds, err := h.httpCredentials(t.Context(), token)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(creds.AccessKeyId).To(Equal(httpAccessKey))
	got, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got.Credentials.AccessKeyID).To(Equal(httpAccessKey))
	g.Expect(h.minter.Calls()).To(Equal(2), "the first exchange's mint and the refused refresh's")
	g.Expect(h.server.Calls()).To(Equal(2))
}

// TestSharedCache_AnHTTPEntryMissingACredentialMakesSessionExchange proves
// decorated checks each credential member: an HTTP entry with a provider ARN
// but no access key ID, secret access key or session token is a miss, and
// Session exchanges for a session of its own rather than serve it.
func TestSharedCache_AnHTTPEntryMissingACredentialMakesSessionExchange(t *testing.T) {
	for name, blank := range map[string]func(*eksauthtest.Session){
		"no access key ID":     func(s *eksauthtest.Session) { s.AccessKeyID = "" },
		"no secret access key": func(s *eksauthtest.Session) { s.SecretAccessKey = "" },
		"no session token":     func(s *eksauthtest.Session) { s.SessionToken = "" },
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			h := newSessionFixture(t)
			token := podToken(t, testSessionPodUID, 0)
			incomplete := h.httpSession()
			blank(incomplete)
			h.answerTokens(map[string]*eksauthtest.Session{token: incomplete})
			_, err := h.httpCredentials(t.Context(), token)
			g.Expect(err).NotTo(HaveOccurred())
			httpEntry, ok := h.cache.Get(testSessionPodUID)
			g.Expect(ok).To(BeTrue())
			g.Expect(httpEntry.Metadata.ProviderArn()).NotTo(BeEmpty())

			got, err := h.session(testSessionPodUID)

			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(got.Credentials.AccessKeyID).To(Equal(exchangeKey(1)), "the incomplete HTTP entry must not be served")
			g.Expect(h.minter.Calls()).To(Equal(1))
			g.Expect(h.server.Calls()).To(Equal(2))
			g.Expect(h.cacheCount(workloadidentity.CacheResultMiss)).To(Equal(1.0))
			g.Expect(h.cacheCount(workloadidentity.CacheResultHit)).To(BeZero())
		})
	}
}

// TestSharedCache_SessionNeverJoinsTheRefreshOfAnUndecoratedEntry proves Session
// shares no flight with a refresh presenting an HTTP entry's stored token. While
// the sweep refreshes a not-enrolled HTTP entry, Session for the pod makes its
// own exchange and gets a decorated session, never the refresh's answer.
func TestSharedCache_SessionNeverJoinsTheRefreshOfAnUndecoratedEntry(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t, sweeping, dueEverySecond)
	token := podToken(t, testSessionPodUID, 0)
	notEnrolled := eksauthtest.NotEnrolledSession(h.clock.Now().Add(time.Hour))
	notEnrolled.AccessKeyID = httpAccessKey
	h.answerTokens(map[string]*eksauthtest.Session{token: &notEnrolled})
	_, err := h.httpCredentials(t.Context(), token)
	g.Expect(err).NotTo(HaveOccurred())

	h.server.Block()
	h.waitForBlocked(t, 1)
	pending := h.sessionAsync(t.Context(), testSessionPodUID)
	h.waitForBlocked(t, 2)
	h.server.Release()

	r := awaitResult(t, pending)
	g.Expect(r.err).NotTo(HaveOccurred())
	// The refresh can store after the exchange, and Session then asks once more.
	g.Expect(r.session.Credentials.AccessKeyID).To(HavePrefix("ASIAEXCHANGE"))
	g.Expect(r.session.ProviderArn).NotTo(BeEmpty())
	g.Expect(h.server.Requests()[1].Token).To(Equal(token), "the parked call was the sweep's refresh")
}

// TestSharedCache_AValidationHitNeverHandsBackAnInvalidatedSession proves a
// validation hit keeps the entry's identity, which is its credentials. A Session
// request holds the cached session it found, an HTTP caller's validated token
// is recorded on that entry, and the pod is invalidated: a caller asking again
// must get a new session.
func TestSharedCache_AValidationHitNeverHandsBackAnInvalidatedSession(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t, withValidator(&scriptedValidator{}))
	ctxGate := newGate(t)
	held := h.sessionAsync(&gatedErrContext{Context: t.Context(), gate: ctxGate}, testSessionPodUID)
	ctxGate.waitUntilHeld(t)
	first, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(first.Credentials.AccessKeyID).To(Equal(exchangeKey(1)))

	// The held caller's request finds the first session and is held at the
	// clock read that decides whether it can be served.
	clockGate := h.gateNextCacheRead(t)
	ctxGate.open()
	clockGate.waitUntilHeld(t)
	creds, err := h.httpCredentials(t.Context(), podToken(t, testSessionPodUID, 0))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(creds.AccessKeyId).To(Equal(exchangeKey(1)), "the validated token must be served the session")
	h.provider.Invalidate(testSessionPodUID)
	again := h.sessionAsync(t.Context(), testSessionPodUID)
	h.waitForJoined(t, testSessionPodUID, 3)
	clockGate.open()

	g.Expect(awaitResult(t, held).err).NotTo(HaveOccurred())
	r := awaitResult(t, again)
	g.Expect(r.err).NotTo(HaveOccurred())
	g.Expect(r.session.Credentials.AccessKeyID).To(Equal(exchangeKey(2)),
		"a caller that invalidated a session must not be handed it back")
	g.Expect(h.server.Calls()).To(Equal(2))
}

// TestSharedCache_ValidationHitsOnASessionEntryAreRaceFree has HTTP callers with
// different tokens hit one Session entry at once, each validation hit recording
// its token as others read the entry. It finds nothing without the race
// detector, which the suite uses.
func TestSharedCache_ValidationHitsOnASessionEntryAreRaceFree(t *testing.T) {
	g := NewWithT(t)
	h := newSessionFixture(t, withValidator(&scriptedValidator{}))
	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())

	var wg sync.WaitGroup
	var served atomic.Int64
	for i := range 4 {
		token := podToken(t, testSessionPodUID, i)
		wg.Go(func() {
			for range 50 {
				if creds, err := h.httpCredentials(t.Context(), token); err == nil && creds.AccessKeyId == exchangeKey(1) {
					served.Add(1)
				}
			}
		})
	}
	wg.Wait()
	g.Expect(served.Load()).To(Equal(int64(200)))
	g.Expect(h.server.Calls()).To(Equal(1))
}

// TestSharedCache_SessionRefreshesCountOnThePodIdentityCacheMetrics proves the
// cache counts a Session entry's refreshes as it counts every entry's: a hit on
// success, a recoverable or non-recoverable error by EKS Auth error code on
// failure, and the drop as an eviction. Sweeps other tests left running can
// also count hits, drops and evictions, so those three are lower bounds.
func TestSharedCache_SessionRefreshesCountOnThePodIdentityCacheMetrics(t *testing.T) {
	g := NewWithT(t)
	capture := captureLogs(t)
	h := newSessionFixture(t, sweeping, expiringTokens)
	state := func(s string) float64 {
		return defaultCount(t, "pod_identity_cache_state", map[string]string{"state": s})
	}
	errorCount := func(kind, code string) float64 {
		return defaultCount(t, "pod_identity_cache_errors", map[string]string{"type": kind, "code": code})
	}
	hits, evictions := state("hit"), state("evicted")
	recoverable := errorCount("Recoverable", "ServiceUnavailableException")
	nonRecoverable := errorCount("NonRecoverable", "Unknown")
	// The sweep refreshes the first session and its refresh, keeps the second
	// over the third exchange's failure, and drops it when the fourth mint is
	// refused.
	h.answerByExchange(func(n int64) (*eksauthtest.Session, *eksauthtest.APIError) {
		if n == 3 {
			return nil, eksauthtest.ServiceUnavailable()
		}
		return h.shortSessionFor(n), nil
	})
	h.failMintAttempts(func(attempt int64) error {
		if attempt >= 4 {
			return wierrors.ErrTokenMintForbidden.Wrapf(nil, "the pod is gone")
		}
		return nil
	})
	_, err := h.session(testSessionPodUID)
	g.Expect(err).NotTo(HaveOccurred())

	capture.waitFor(t, testSessionPodUID, droppedLine(testSessionPodUID), 1)

	g.Expect(capture.fieldsAbout(testSessionPodUID, keptLine(testSessionPodUID))).To(HaveLen(1))
	g.Expect(state("hit")).To(BeNumerically(">=", hits+1))
	g.Expect(errorCount("Recoverable", "ServiceUnavailableException")).To(Equal(recoverable + 1))
	g.Expect(errorCount("NonRecoverable", "Unknown")).To(BeNumerically(">=", nonRecoverable+1),
		"a refused mint is a non-recoverable error")
	g.Expect(h.cachedKey(testSessionPodUID)).To(BeEmpty())
	g.Expect(state("evicted")).To(BeNumerically(">=", evictions+1), "the drop goes through the cache's eviction")
}
