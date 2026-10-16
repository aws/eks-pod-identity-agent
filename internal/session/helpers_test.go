package session

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eksauth/types"
	"github.com/golang-jwt/jwt/v5"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/eksauth"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/eksauth/eksauthtest"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/credcache"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/credsretriever"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity/fake"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

const (
	// sessionTestTimeout bounds every wait in this package's tests, so an
	// exchange that never finishes fails the test instead of hanging the suite.
	sessionTestTimeout = 5 * time.Second

	// dueSoon is the lifetime of a session a sweeping fixture refreshes: its
	// refresh and eviction both fall due this long after it's stored, so from
	// then on Get no longer finds it.
	dueSoon = 200 * time.Millisecond

	testClusterName    = "example-cluster"
	testSessionPodUID  = "9b3f2c1e-6a4d-4f7b-8e2a-1c5d7f9a0b3e"
	otherSessionPodUID = "0c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f"
	thirdSessionPodUID = "5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b"
)

// sessionTestWorkload is an attested workload whose namespace and
// ServiceAccount match the subject eksauthtest.EnrolledSession reports.
func sessionTestWorkload(podUID string) *workloadidentity.Workload {
	return &workloadidentity.Workload{
		PodUID:         podUID,
		PodName:        "example-" + podUID[:8],
		Namespace:      "default",
		ServiceAccount: "example-sa",
		NodeName:       "ip-10-0-1-23.us-west-2.compute.internal",
	}
}

// sessionClock is the cache's clock in these tests. It's safe to read from the
// exchange goroutines and the fake's handlers while a test moves it.
type sessionClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *sessionClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *sessionClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

func (c *sessionClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// tokenValidator is what the HTTP retriever validates tokens with.
type tokenValidator interface {
	ValidateToken(ctx context.Context, req *credentials.EksCredentialsRequest) error
}

// scriptedValidator answers every token with err and records that it was asked.
// Both are safe to change while HTTP callers are validating.
type scriptedValidator struct {
	mu     sync.Mutex
	err    error
	called bool
}

func (v *scriptedValidator) ValidateToken(context.Context, *credentials.EksCredentialsRequest) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.called = true
	return v.err
}

func (v *scriptedValidator) set(err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.err, v.called = err, false
}

func (v *scriptedValidator) wasCalled() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.called
}

// sessionFixture is a Provider and the HTTP retriever over one credcache.Cache,
// configured as the agent's with workload identity on. EKS Auth is the real
// client pointed at the fake EKS Auth, so every exchange goes through the SDK's
// serializer, deserializer and error types. The token minter numbers its JWTs,
// and the fake numbers each exchange presenting one, answering with a session
// whose access key ID carries that number, so a test can tell which exchange a
// session came from, a refresh included.
type sessionFixture struct {
	server   *eksauthtest.Server
	minter   *fake.TokenMinter
	clock    *sessionClock
	cache    *credcache.Cache
	http     credentials.CredentialRetriever
	provider *Provider
	// pods is the provider's pod store, which a test deletes pods from.
	pods *fake.PodStore
	// sourceBase is the credential source counts when the fixture was built. The
	// fork rule counts on the process-wide collector, which every other test in
	// the binary also increments, so sourceCount reports the delta since here.
	sourceBase map[string]float64
	// minTtl is the cache's floor.
	minTtl time.Duration
	// tokenLife is how long each minted token lives on the fixture's clock.
	tokenLife time.Duration
	// onCacheNow, when set, runs on every read of the cache's clock.
	onCacheNow atomic.Pointer[func()]

	mints     atomic.Int64
	attempts  atomic.Int64
	exchanges atomic.Int64
	mu        sync.Mutex
	mintErr   error
	// mintFail, when set, fails the mint attempt it returns an error for.
	mintFail func(attempt int64) error
	// joins counts, per pod, the Session callers that have started waiting on
	// an exchange since the fixture was built.
	joins map[string]int
	// tokens holds every minted token, the nth at n-1, and presented the token
	// each numbered exchange presented, by number.
	tokens    []string
	presented map[int64]string
}

// fixtureOpts is what newSessionFixture builds the cache, the HTTP retriever
// and the provider from.
type fixtureOpts struct {
	cache credcache.Opts
	// delegate builds the HTTP retriever's general delegate over the EKS Auth
	// client, which is the delegate when it's nil.
	delegate func(eksAuth credentials.CredentialRetriever) credentials.CredentialRetriever
	// validator is the HTTP retriever's token validator. When nil it tries to
	// load the real one, which fails off a cluster, so it validates nothing.
	validator tokenValidator
	// minter, when set, replaces the fixture's numbering minter, for the
	// provider and the cache's token source alike.
	minter workloadidentity.TokenMinter
	// tokenLife is how long each minted token lives, an hour when zero.
	tokenLife time.Duration
}

// sweeping runs the cache's sweep every 10ms, with a 10ms floor and no
// rate limit to speak of, so a session that lives dueSoon is refreshed within a
// sweep of falling due.
func sweeping(o *fixtureOpts) {
	o.cache.CleanupInterval = 10 * time.Millisecond
	o.cache.MinCredentialTtl = 10 * time.Millisecond
	// The cache charges its limiter twice a refresh, and these tests refresh
	// faster than the agent's 3 a second.
	o.cache.RefreshQPS = 1000
}

// dueEverySecond makes the cache refresh every entry a second after it stores
// it, so an hour-long session is due long before Get stops finding it.
func dueEverySecond(o *fixtureOpts) { o.cache.RenewalTtl = time.Second }

// newSessionFixture builds the cache with the agent's flag defaults, its clock
// the fixture's and its sweep an hour away unless sweeping is passed, refreshing as
// handlers.NewCredentialManager does with workload identity on. Then it builds
// the HTTP retriever and the provider over it, the provider with collectors of
// its own.
func newSessionFixture(t *testing.T, configure ...func(*fixtureOpts)) *sessionFixture {
	t.Helper()
	h := &sessionFixture{
		server:    eksauthtest.New(t),
		clock:     &sessionClock{now: time.Now()},
		joins:     map[string]int{},
		presented: map[int64]string{},
		pods:      &fake.PodStore{},
	}
	h.minter = &fake.TokenMinter{Func: h.mint}
	h.answerWithSessions()

	client := &closingRetriever{CredentialRetriever: eksauth.NewService(context.Background(), h.server.Config(), false)}
	opts := fixtureOpts{
		cache: credcache.Opts{
			RenewalTtl:      3 * time.Hour,
			MaxSize:         2000,
			RefreshQPS:      3,
			CleanupInterval: time.Hour,
			Now:             h.cacheNow,
		},
	}
	for _, c := range configure {
		c(&opts)
	}
	h.minTtl = cmp.Or(opts.cache.MinCredentialTtl, credcache.DefaultMinCredentialTtl)
	h.tokenLife = cmp.Or(opts.tokenLife, time.Hour)
	var delegate credentials.CredentialRetriever = client
	if opts.delegate != nil {
		delegate = opts.delegate(client)
	}
	var minter workloadidentity.TokenMinter = h.minter
	if opts.minter != nil {
		minter = opts.minter
	}
	opts.cache.Delegate = delegate
	h.sourceBase = currentSourceCounts()
	opts.cache.RefreshWith = RefreshWith(client, MinterTokens(minter))
	h.cache = credcache.New(opts.cache)
	h.http = credsretriever.NewCachedCredentialRetriever(credsretriever.CachedCredentialRetrieverOpts{
		Cache:                 h.cache,
		Delegate:              delegate,
		AuthoritativeDelegate: client,
		TokenValidator:        opts.validator,
	})
	provider, err := New(Opts{ClusterName: testClusterName, Minter: minter, Cache: h.cache, EKSAuth: client, PodStore: h.pods})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	provider.metrics = newTestSessionMetrics()
	provider.joined = h.countJoin
	h.provider = provider
	// A sweep can outlive the test, so leave it nothing to refresh, and drop
	// whatever it still finds without reaching the closed fake.
	t.Cleanup(func() {
		client.close()
		h.failMints(wierrors.ErrTokenMintForbidden.Wrapf(nil, "the test is over"))
		for _, podUID := range []string{testSessionPodUID, otherSessionPodUID, thirdSessionPodUID} {
			h.cache.Delete(podUID)
		}
	})
	return h
}

// closingRetriever is the fixture's EKS Auth client until close, then refuses
// every call, one in flight included, as AccessDenied. The cache stores every
// renewal, so this keeps a refresh that outlives the test from storing an entry
// whose own refreshes would retry against the closed fake.
type closingRetriever struct {
	credentials.CredentialRetriever
	closed atomic.Bool
}

func (r *closingRetriever) GetIamCredentials(ctx context.Context, request *credentials.EksCredentialsRequest) (
	*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
	if !r.closed.Load() {
		creds, metadata, err := r.CredentialRetriever.GetIamCredentials(ctx, request)
		if !r.closed.Load() {
			return creds, metadata, err
		}
	}
	return nil, nil, &types.AccessDeniedException{Message: aws.String("the test is over")}
}

func (r *closingRetriever) close() { r.closed.Store(true) }

// cacheNow is the cache's clock: the fixture's, after onCacheNow.
func (h *sessionFixture) cacheNow() time.Time {
	if hook := h.onCacheNow.Load(); hook != nil {
		(*hook)()
	}
	return h.clock.Now()
}

// countJoin is the provider's joined hook.
func (h *sessionFixture) countJoin(podUID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.joins[podUID]++
}

// joined reports how many Session callers have started waiting on an exchange
// for podUID since the fixture was built.
func (h *sessionFixture) joined(podUID string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.joins[podUID]
}

func (h *sessionFixture) mint(_ context.Context, w *workloadidentity.Workload) (*workloadidentity.ProjectedToken, error) {
	attempt := h.attempts.Add(1)
	fail, err := func() (func(int64) error, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.mintFail, h.mintErr
	}()
	if err == nil && fail != nil {
		err = fail(attempt)
	}
	if err != nil {
		return nil, err
	}
	expires := h.clock.Now().Add(h.tokenLife)
	token := func() string {
		h.mu.Lock()
		defer h.mu.Unlock()
		token := mintedToken(h.mints.Add(1), w, expires)
		h.tokens = append(h.tokens, token)
		return token
	}()
	return &workloadidentity.ProjectedToken{Token: token, ExpiresAt: expires}, nil
}

// withTokenLife makes every minted token live d, so with d within the cache's
// token floor every refresh mints first.
func withTokenLife(d time.Duration) func(*fixtureOpts) {
	return func(o *fixtureOpts) { o.tokenLife = d }
}

// expiringTokens makes every minted token live a minute, within the cache's
// 5-minute token floor, so every refresh of a Session entry mints first.
func expiringTokens(o *fixtureOpts) { withTokenLife(time.Minute)(o) }

// minted returns the nth minted token, or "" before it's minted.
func (h *sessionFixture) minted(n int64) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if n < 1 || int(n) > len(h.tokens) {
		return ""
	}
	return h.tokens[n-1]
}

// mintedTokens returns every token minted so far.
func (h *sessionFixture) mintedTokens() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.tokens...)
}

// presentedBy returns the token the nth exchange presented.
func (h *sessionFixture) presentedBy(n int64) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.presented[n]
}

// failMints makes every later mint fail with err, or succeed again for nil.
func (h *sessionFixture) failMints(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.mintErr = err
}

// failMintAttempts fails each mint attempt, counted from the fixture's first,
// that fail returns an error for.
func (h *sessionFixture) failMintAttempts(fail func(attempt int64) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.mintFail = fail
}

// mintedToken is the unsigned JWT the fixture mints nth for w: its
// kubernetes.io claims name w as the API server's do, and its mint claim is n.
func mintedToken(n int64, w *workloadidentity.Workload, expires time.Time) string {
	token, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"exp":  expires.Unix(),
		"mint": n,
		"kubernetes.io": map[string]any{
			"namespace":      w.Namespace,
			"pod":            map[string]any{"name": w.PodName, "uid": w.PodUID},
			"serviceaccount": map[string]any{"name": w.ServiceAccount},
		},
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		panic(err)
	}
	return token
}

// exchangeKey is the access key ID of the session the fake answers the nth
// exchange of a minted token with.
func exchangeKey(n int64) string {
	return fmt.Sprintf("ASIAEXCHANGE%04d", n)
}

// mintNumber is the n of a token the fixture's minter minted, and false for any
// other token.
func mintNumber(token string) (int64, bool) {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		return 0, false
	}
	n, ok := claims["mint"].(float64)
	return int64(n), ok
}

// tokenPod is the pod UID token's claims name, or "".
func tokenPod(token string) string {
	w, err := workloadFromToken(token)
	if err != nil {
		return ""
	}
	return w.PodUID
}

// exchangeNumber numbers an exchange presenting token, and is false for a token
// the fixture didn't mint.
func (h *sessionFixture) exchangeNumber(token string) (int64, bool) {
	if _, ok := mintNumber(token); !ok {
		return 0, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	n := h.exchanges.Add(1)
	h.presented[n] = token
	return n, true
}

// sessionFor is the fixture's usual answer to the nth minted token: an enrolled
// session expiring an hour after the test clock, keyed to that token.
func (h *sessionFixture) sessionFor(n int64) *eksauthtest.Session {
	session := eksauthtest.EnrolledSession(h.clock.Now().Add(time.Hour))
	session.AccessKeyID = exchangeKey(n)
	session.SessionToken = fmt.Sprintf("workload-session-token-%d", n)
	return &session
}

// shortSessionFor is sessionFor living dueSoon, so a sweeping fixture refreshes
// it at once.
func (h *sessionFixture) shortSessionFor(n int64) *eksauthtest.Session {
	return h.sessionLiving(n, dueSoon)
}

// sessionLiving is sessionFor living d. A sweeping fixture refreshes it once d
// has passed, and again d after keeping it over a failed refresh.
func (h *sessionFixture) sessionLiving(n int64, d time.Duration) *eksauthtest.Session {
	session := h.sessionFor(n)
	session.Expiration = h.clock.Now().Add(d)
	return session
}

// answerWithSessions restores the fixture's default answer, sessionFor each
// exchange's number.
func (h *sessionFixture) answerWithSessions() {
	h.answerByExchange(func(n int64) (*eksauthtest.Session, *eksauthtest.APIError) { return h.sessionFor(n), nil })
}

// answerByExchange answers each exchange presenting a minted token with what
// answer returns for its number, and any other token with InvalidToken.
func (h *sessionFixture) answerByExchange(answer func(n int64) (*eksauthtest.Session, *eksauthtest.APIError)) {
	h.server.SetFunc(func(r eksauthtest.Request) (*eksauthtest.Session, *eksauthtest.APIError) {
		n, ok := h.exchangeNumber(r.Token)
		if !ok {
			return nil, eksauthtest.InvalidToken()
		}
		return answer(n)
	})
}

// dueFirst answers the first exchange with a session the sweep refreshes at
// once, and every later one as answerWithSessions does.
func (h *sessionFixture) dueFirst() {
	h.answerByExchange(func(n int64) (*eksauthtest.Session, *eksauthtest.APIError) {
		if n == 1 {
			return h.shortSessionFor(n), nil
		}
		return h.sessionFor(n), nil
	})
}

// heldExchange is one exchange the fake holds until the test releases it.
type heldExchange struct {
	// fail is what the exchange is answered with once released, or nil for the
	// fixture's usual session.
	fail     *eksauthtest.APIError
	released chan struct{}
	once     sync.Once
}

func (e *heldExchange) release() {
	e.once.Do(func() { close(e.released) })
}

// holdExchanges makes the fake hold each numbered exchange in held until its
// release is called, then answer it with its fail or sessionFor, and answer
// every other exchange with answer. Every hold is released when the test ends,
// so a failed assertion can't leave a request parked.
func (h *sessionFixture) holdExchanges(t *testing.T, held map[int64]*heldExchange,
	answer func(n int64) *eksauthtest.Session) {
	t.Helper()
	for _, e := range held {
		e.released = make(chan struct{})
	}
	t.Cleanup(func() {
		for _, e := range held {
			e.release()
		}
	})
	h.answerByExchange(func(n int64) (*eksauthtest.Session, *eksauthtest.APIError) {
		e, isHeld := held[n]
		if !isHeld {
			return answer(n), nil
		}
		<-e.released
		if e.fail != nil {
			return nil, e.fail
		}
		return h.sessionFor(n), nil
	})
}

// cachedKey is the access key ID of the entry the cache holds for podUID, or ""
// when it holds none.
func (h *sessionFixture) cachedKey(podUID string) string {
	e, ok := h.cache.Get(podUID)
	if !ok {
		return ""
	}
	return e.Credentials.AccessKeyId
}

// eventuallyCached waits for the cache to hold the entry keyed key for podUID,
// or none for "".
func (h *sessionFixture) eventuallyCached(t *testing.T, podUID, key string) {
	t.Helper()
	NewWithT(t).Eventually(func() string { return h.cachedKey(podUID) }).
		WithTimeout(sessionTestTimeout).WithPolling(5*time.Millisecond).
		Should(Equal(key), "waiting for the cache to hold %q for pod %s", key, podUID)
}

func (h *sessionFixture) waitForBlocked(t *testing.T, n int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), sessionTestTimeout)
	defer cancel()
	if err := h.server.WaitForBlocked(ctx, n); err != nil {
		t.Fatalf("waiting for %d exchanges parked at the fake EKS Auth: %v", n, err)
	}
}

func (h *sessionFixture) waitForCalls(t *testing.T, n int) {
	t.Helper()
	NewWithT(t).Eventually(h.server.Calls).WithTimeout(sessionTestTimeout).WithPolling(time.Millisecond).
		Should(Equal(n), "waiting for %d exchanges to reach the fake EKS Auth", n)
}

// waitForJoined returns once n callers in all have started waiting on an
// exchange for podUID. Once every caller a test started is counted, releasing
// the fake can't let one of them find the cache instead.
func (h *sessionFixture) waitForJoined(t *testing.T, podUID string, n int) {
	t.Helper()
	NewWithT(t).Eventually(func() int { return h.joined(podUID) }).
		WithTimeout(sessionTestTimeout).WithPolling(time.Millisecond).
		Should(Equal(n), "waiting for %d callers in all to wait on an exchange for pod %s", n, podUID)
}

func (h *sessionFixture) session(podUID string) (*workloadidentity.WorkloadSession, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sessionTestTimeout)
	defer cancel()
	return h.provider.Session(ctx, sessionTestWorkload(podUID))
}

func (h *sessionFixture) cacheCount(result string) float64 {
	return testutil.ToFloat64(h.provider.metrics.cache.WithLabelValues(workloadidentity.CacheTierSession, result))
}

func (h *sessionFixture) exchangeCount(outcome, errLabel string) float64 {
	return testutil.ToFloat64(h.provider.metrics.exchanges.WithLabelValues(outcome, errLabel))
}

// currentSourceCounts reads the credential source counter for every source
// value, so a fixture can record a baseline and report deltas against it.
func currentSourceCounts() map[string]float64 {
	counts := map[string]float64{}
	for _, source := range []string{
		workloadidentity.CredentialSourceEKSAuth,
		workloadidentity.CredentialSourceIMDSFirst,
	} {
		counts[source] = testutil.ToFloat64(promCredentialSource.WithLabelValues(source))
	}
	return counts
}

// sourceCount returns how many refreshes have been routed to source since the
// fixture was built.
func (h *sessionFixture) sourceCount(source string) float64 {
	return testutil.ToFloat64(promCredentialSource.WithLabelValues(source)) - h.sourceBase[source]
}

// newTestSessionMetrics builds unregistered collectors with the production
// names and labels, so a test reads counts no other test has touched.
func newTestSessionMetrics() sessionMetrics {
	return sessionMetrics{
		exchanges: prometheus.NewCounterVec(sessionTotalOpts, sessionTotalLabels),
		latency:   prometheus.NewHistogramVec(sessionDurationOpts, sessionDurationLabels),
		cache:     prometheus.NewCounterVec(cacheTotalOpts, cacheTotalLabels),
	}
}

type sessionResult struct {
	session *workloadidentity.WorkloadSession
	err     error
}

func (h *sessionFixture) sessionAsync(ctx context.Context, podUID string) <-chan sessionResult {
	results := make(chan sessionResult, 1)
	go func() {
		session, err := h.provider.Session(ctx, sessionTestWorkload(podUID))
		results <- sessionResult{session: session, err: err}
	}()
	return results
}

func awaitResult(t *testing.T, results <-chan sessionResult) sessionResult {
	t.Helper()
	select {
	case r := <-results:
		return r
	case <-time.After(sessionTestTimeout):
		t.Fatalf("Session did not return within %s", sessionTestTimeout)
		return sessionResult{}
	}
}

// gate holds the first goroutine that reaches it until it's opened, and closes
// held once it holds one. It's opened when the test ends as well, so a failed
// assertion can't leave a goroutine held.
type gate struct {
	held     chan struct{}
	opened   chan struct{}
	holdOnce sync.Once
	openOnce sync.Once
}

func newGate(t *testing.T) *gate {
	gt := &gate{held: make(chan struct{}), opened: make(chan struct{})}
	t.Cleanup(gt.open)
	return gt
}

func (gt *gate) pass() {
	gt.holdOnce.Do(func() {
		close(gt.held)
		<-gt.opened
	})
}

func (gt *gate) open() { gt.openOnce.Do(func() { close(gt.opened) }) }

func (gt *gate) waitUntilHeld(t *testing.T) {
	t.Helper()
	select {
	case <-gt.held:
	case <-time.After(sessionTestTimeout):
		t.Fatalf("nothing reached the gate within %s", sessionTestTimeout)
	}
}

// gatedErrContext holds the first caller of Err at its gate. Session calls Err
// once it has missed the cache and before it joins an exchange, so a caller on
// this context is held there.
type gatedErrContext struct {
	context.Context
	gate *gate
}

func (c *gatedErrContext) Err() error {
	c.gate.pass()
	return c.Context.Err()
}

// gateNextCacheRead holds the next read of the cache's clock at a new gate. The
// flight of a caller that finds a cached entry reads it to decide whether it can
// serve the entry.
func (h *sessionFixture) gateNextCacheRead(t *testing.T) *gate {
	gt := newGate(t)
	var armed atomic.Bool
	armed.Store(true)
	hook := func() {
		if armed.CompareAndSwap(true, false) {
			gt.pass()
		}
	}
	h.onCacheNow.Store(&hook)
	t.Cleanup(func() { h.onCacheNow.Store(nil) })
	return gt
}

// keptLine and droppedLine start the lines the cache logs about podUID when it
// keeps an entry over a failed refresh and when it drops one.
func keptLine(podUID string) string {
	return "Background refresh failed for pod " + podUID + ": keeping existing credentials in cache (recoverable)"
}

func droppedLine(podUID string) string {
	return "Background refresh failed for pod " + podUID + ": removing credentials from cache (irrecoverable)"
}

// logPause holds the first goroutine that logs a line about podUID starting
// with prefix until resume is called, and closes paused once it holds it. The
// pod is matched as well as the message because sweeps other tests left
// running log lines of their own.
type logPause struct {
	prefix     string
	podUID     string
	paused     chan struct{}
	resumed    chan struct{}
	holdOnce   sync.Once
	resumeOnce sync.Once
}

func (l *logPause) Levels() []logrus.Level { return logrus.AllLevels }

func (l *logPause) Fire(entry *logrus.Entry) error {
	if !strings.HasPrefix(entry.Message, l.prefix) || entry.Data["pod-uid"] != l.podUID {
		return nil
	}
	hold := false
	l.holdOnce.Do(func() { hold = true })
	if hold {
		close(l.paused)
		<-l.resumed
	}
	return nil
}

func (l *logPause) resume() {
	l.resumeOnce.Do(func() { close(l.resumed) })
}

func (l *logPause) waitUntilPaused(t *testing.T) {
	t.Helper()
	select {
	case <-l.paused:
	case <-time.After(sessionTestTimeout):
		t.Fatalf("nothing logged %q for pod %s within %s", l.prefix, l.podUID, sessionTestTimeout)
	}
}

// pauseAtLog installs a logPause on the agent's logger for the rest of the
// test. It's resumed when the test ends, so a failed assertion can't leave a
// goroutine held.
func pauseAtLog(t *testing.T, podUID, prefix string) *logPause {
	t.Helper()
	base := logger.FromContext(context.Background()).Logger
	pause := &logPause{prefix: prefix, podUID: podUID, paused: make(chan struct{}), resumed: make(chan struct{})}
	hooks := make(logrus.LevelHooks)
	hooks.Add(pause)
	previous := base.ReplaceHooks(hooks)
	t.Cleanup(func() {
		pause.resume()
		base.ReplaceHooks(previous)
	})
	return pause
}

// logCapture records every log line emitted while it's installed.
type logCapture struct {
	mu      sync.Mutex
	lines   []string
	records []logRecord
}

// logRecord is one captured line's message and fields.
type logRecord struct {
	message string
	fields  logrus.Fields
}

func (c *logCapture) Levels() []logrus.Level { return logrus.AllLevels }

func (c *logCapture) Fire(entry *logrus.Entry) error {
	line := entry.Message + " " + fmt.Sprint(entry.Data)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, line)
	c.records = append(c.records, logRecord{message: entry.Message, fields: maps.Clone(entry.Data)})
	return nil
}

func (c *logCapture) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.lines...)
}

// fieldsOf returns the fields of every captured line whose message is message.
func (c *logCapture) fieldsOf(message string) []logrus.Fields {
	c.mu.Lock()
	defer c.mu.Unlock()
	var fields []logrus.Fields
	for _, r := range c.records {
		if r.message == message {
			fields = append(fields, r.fields)
		}
	}
	return fields
}

// fieldsAbout returns the fields of every captured line about podUID whose
// message starts with prefix.
func (c *logCapture) fieldsAbout(podUID, prefix string) []logrus.Fields {
	c.mu.Lock()
	defer c.mu.Unlock()
	var fields []logrus.Fields
	for _, r := range c.records {
		if strings.HasPrefix(r.message, prefix) && r.fields["pod-uid"] == podUID {
			fields = append(fields, r.fields)
		}
	}
	return fields
}

// waitFor returns once n lines about podUID starting with prefix are captured.
func (c *logCapture) waitFor(t *testing.T, podUID, prefix string, n int) {
	t.Helper()
	NewWithT(t).Eventually(func() int { return len(c.fieldsAbout(podUID, prefix)) }).
		WithTimeout(sessionTestTimeout).WithPolling(5*time.Millisecond).
		Should(BeNumerically(">=", n), "waiting for %d lines %q about pod %s", n, prefix, podUID)
}

// captureLogs hooks the agent's logger for the rest of the test.
func captureLogs(t *testing.T) *logCapture {
	t.Helper()
	base := logger.FromContext(context.Background()).Logger
	capture := &logCapture{}
	hooks := make(logrus.LevelHooks)
	hooks.Add(capture)
	previous := base.ReplaceHooks(hooks)
	t.Cleanup(func() { base.ReplaceHooks(previous) })
	return capture
}

// defaultCount reads a counter of the default registry, such as credcache's,
// which this package can't reach, by name and labels. It's zero when absent.
func defaultCount(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gathering the default registry: %v", err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, m := range family.GetMetric() {
			got := map[string]string{}
			for _, l := range m.GetLabel() {
				got[l.GetName()] = l.GetValue()
			}
			if maps.Equal(got, labels) {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}
