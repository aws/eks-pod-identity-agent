package bundle

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity/fake"
)

const otherProviderArn = "arn:aws:iam::444455556666:workload-identity-provider/other"

// providerFetcher is a fake GetTrustBundles that answers per provider ARN and
// records the credentials each call was signed with.
type providerFetcher struct {
	mu        sync.Mutex
	responses map[string]func(call int) ([]sts.TrustBundle, error)
	calls     map[string]int
	signers   map[string][]string
}

func newProviderFetcher(responses map[string]func(int) ([]sts.TrustBundle, error)) *providerFetcher {
	return &providerFetcher{responses: responses, calls: map[string]int{}, signers: map[string][]string{}}
}

func (f *providerFetcher) GetTrustBundles(_ context.Context, creds aws.Credentials, providerArn string) ([]sts.TrustBundle, error) {
	call, respond, ok := func() (int, func(int) ([]sts.TrustBundle, error), bool) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls[providerArn]++
		f.signers[providerArn] = append(f.signers[providerArn], creds.AccessKeyID)
		respond, ok := f.responses[providerArn]
		return f.calls[providerArn], respond, ok
	}()
	if !ok {
		return nil, fmt.Errorf("no canned response for %s", providerArn)
	}
	return respond(call)
}

func (f *providerFetcher) Calls(providerArn string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[providerArn]
}

// Signers returns the access key IDs the provider's fetches were signed with.
func (f *providerFetcher) Signers(providerArn string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.signers[providerArn]...)
}

func (f *providerFetcher) TotalCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	total := 0
	for _, calls := range f.calls {
		total += calls
	}
	return total
}

// testSessions is a SessionProvider that gives each pod a session naming the
// provider the test assigned it, signed by a key ID derived from the pod.
type testSessions struct {
	mu       sync.Mutex
	provider map[string]string
	err      map[string]error
	calls    int
}

func newTestSessions() *testSessions {
	return &testSessions{
		provider: map[string]string{"own-pod": testProviderArn, "other-pod": otherProviderArn},
		err:      map[string]error{},
	}
}

func (s *testSessions) Session(_ context.Context, w *workloadidentity.Workload) (*workloadidentity.WorkloadSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if err := s.err[w.PodUID]; err != nil {
		return nil, err
	}
	return &workloadidentity.WorkloadSession{
		Credentials: aws.Credentials{AccessKeyID: "AKID-" + w.PodUID, SecretAccessKey: "secret", SessionToken: "token"},
		ProviderArn: s.provider[w.PodUID],
	}, nil
}

func (s *testSessions) Invalidate(string) {}

func (s *testSessions) assign(pod, providerArn string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.provider[pod] = providerArn
	delete(s.err, pod)
}

func (s *testSessions) fail(pod string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err[pod] = err
}

func (s *testSessions) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func pod(uid string) *workloadidentity.Workload {
	return &workloadidentity.Workload{PodUID: uid, Namespace: "default", ServiceAccount: "sa"}
}

var (
	ownPod   = pod("own-pod")
	otherPod = pod("other-pod")
)

// sessionOpts wires the tier as launch does: the provider and the signing
// credentials both come from the workload's session.
func sessionOpts(fetcher Fetcher, notifier workloadidentity.BundleNotifier, sessions workloadidentity.SessionProvider) Opts {
	return Opts{
		Fetcher:   fetcher,
		Notifier:  notifier,
		Providers: workloadidentity.SessionProviderArns(sessions),
		Signer:    WorkloadSessionSigner(sessions),
	}
}

func newTestRegistry(t *testing.T, fetcher Fetcher) (*Registry, *fake.Subscriber, *testSessions) {
	t.Helper()
	notifier := &fake.Subscriber{}
	sessions := newTestSessions()
	registry, err := New(sessionOpts(fetcher, notifier, sessions))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return registry, notifier, sessions
}

// leaseClock is a clock a test moves by hand.
type leaseClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *leaseClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *leaseClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// newClockedRegistry builds a registry over providers that always answer, with
// the registry and every source on one hand-moved clock and no jitter.
func newClockedRegistry(t *testing.T, providers ...string) (*Registry, *providerFetcher, *testSessions, *leaseClock) {
	t.Helper()
	responses := map[string]func(int) ([]sts.TrustBundle, error){}
	for _, arn := range providers {
		responses[arn] = fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, jwtECKey(t, "k1", newECKey(t)))})
	}
	fetcher := newProviderFetcher(responses)
	registry, _, sessions := newTestRegistry(t, fetcher)
	clock := &leaseClock{now: time.Now()}
	registry.now = clock.Now
	registry.configure = func(source *providerSource) {
		source.now = clock.Now
		source.jitter = func() float64 { return 0 }
	}
	return registry, fetcher, sessions, clock
}

func (r *Registry) entryFor(providerArn string) *providerEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.entries[providerArn]
}

func (r *Registry) leasesFor(providerArn string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[providerArn]
	if !ok {
		return -1
	}
	total := 0
	for _, holder := range entry.holders {
		total += holder.leases
	}
	return total
}

func (r *Registry) entryCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

func TestNew_FetchesNothingUntilAWorkloadReads(t *testing.T) {
	g := NewWithT(t)
	fetcher := &fakeFetcher{respond: fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca")))})}
	sessions := newTestSessions()

	registry, err := New(sessionOpts(fetcher, &fake.Subscriber{}, sessions))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(fetcher.Calls()).To(BeZero())
	g.Expect(sessions.Calls()).To(BeZero())

	_, err = registry.X509Bundles(context.Background(), ownPod)

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(fetcher.arns).To(Equal([]string{testProviderArn}), "the provider comes from the reader's session")
	g.Expect(fetcher.creds[0].AccessKeyID).To(Equal("AKID-own-pod"), "the fetch is signed with the reader's session")
}

func TestNew_MissingInputs_AreEachReported(t *testing.T) {
	g := NewWithT(t)

	_, err := New(Opts{})

	g.Expect(err).To(MatchError(ContainSubstring("fetcher")))
	g.Expect(err).To(MatchError(ContainSubstring("notifier")))
	g.Expect(err).To(MatchError(ContainSubstring("provider ARN resolver")))
	g.Expect(err).To(MatchError(ContainSubstring("signer")))
}

func TestRegistry_TwoProviders_AreFetchedAndServedApart(t *testing.T) {
	g := NewWithT(t)
	ownCA, otherCA := newAuthority(t, "own"), newAuthority(t, "other")
	fetcher := newProviderFetcher(map[string]func(int) ([]sts.TrustBundle, error){
		testProviderArn:  fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, ownCA), jwtECKey(t, "own-1", newECKey(t)))}),
		otherProviderArn: fixed(sts.TrustBundle{TrustDomain: peerDomain, Bundle: bundleDoc(t, 0, x509Key(t, otherCA), jwtECKey(t, "other-1", newECKey(t)))}),
	})
	registry, _, _ := newTestRegistry(t, fetcher)
	ctx := context.Background()

	ownX509, err := registry.X509Bundles(ctx, ownPod)
	g.Expect(err).ToNot(HaveOccurred())
	otherX509, err := registry.X509Bundles(ctx, otherPod)
	g.Expect(err).ToNot(HaveOccurred())
	own, err := registry.OwnTrustDomain(ctx, ownPod)
	g.Expect(err).ToNot(HaveOccurred())
	other, err := registry.OwnTrustDomain(ctx, otherPod)
	g.Expect(err).ToNot(HaveOccurred())
	ownSource, err := registry.JWTSource(ctx, ownPod)
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(ownX509).To(Equal(map[string][][]byte{testDomain: {ownCA.der}}))
	g.Expect(otherX509).To(Equal(map[string][][]byte{peerDomain: {otherCA.der}}))
	g.Expect(own).To(Equal(testDomain))
	g.Expect(other).To(Equal(peerDomain))
	_, err = ownSource.GetJWTBundleForTrustDomain(spiffeid.RequireTrustDomainFromString(peerDomain))
	g.Expect(err).To(HaveOccurred(), "one provider's bundles never answer for another's")
	g.Expect(fetcher.Signers(testProviderArn)).To(Equal([]string{"AKID-own-pod"}))
	g.Expect(fetcher.Signers(otherProviderArn)).To(Equal([]string{"AKID-other-pod"}))
}

func TestRegistry_OneProvider_OneFetchBacksEveryRead(t *testing.T) {
	g := NewWithT(t)
	registry, fetcher, sessions, _ := newClockedRegistry(t, testProviderArn)
	sessions.assign("second-pod", testProviderArn)
	ctx := context.Background()

	_, x509Err := registry.X509Bundles(ctx, ownPod)
	_, jwtErr := registry.JWTBundles(ctx, pod("second-pod"))
	_, sourceErr := registry.JWTSource(ctx, ownPod)
	_, ownErr := registry.OwnTrustDomain(ctx, pod("second-pod"))

	g.Expect([]error{x509Err, jwtErr, sourceErr, ownErr}).To(HaveEach(BeNil()))
	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(1), "workloads of one provider share its cache")
}

func TestRegistry_BadCallers_AreRefusedWithoutFetching(t *testing.T) {
	ctx := context.Background()
	reads := map[string]func(*Registry, *workloadidentity.Workload) error{
		"Lease":          func(r *Registry, w *workloadidentity.Workload) error { _, err := r.Lease(ctx, w); return err },
		"OwnTrustDomain": func(r *Registry, w *workloadidentity.Workload) error { _, err := r.OwnTrustDomain(ctx, w); return err },
		"X509Bundles":    func(r *Registry, w *workloadidentity.Workload) error { _, err := r.X509Bundles(ctx, w); return err },
		"JWTBundles":     func(r *Registry, w *workloadidentity.Workload) error { _, err := r.JWTBundles(ctx, w); return err },
		"JWTSource":      func(r *Registry, w *workloadidentity.Workload) error { _, err := r.JWTSource(ctx, w); return err },
	}
	for name, call := range reads {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			registry, fetcher, sessions, _ := newClockedRegistry(t, testProviderArn)
			sessions.assign("unenrolled", "")
			sessions.fail("no-session", wierrors.ErrSessionUnavailable)

			g.Expect(call(registry, nil)).To(MatchError(wierrors.ErrUnattestable))
			g.Expect(call(registry, pod("unenrolled"))).To(MatchError(wierrors.ErrNotEnrolled), "a session naming no provider")
			g.Expect(call(registry, pod("no-session"))).To(MatchError(wierrors.ErrSessionUnavailable), "a session error passes through")

			g.Expect(fetcher.TotalCalls()).To(BeZero())
			g.Expect(registry.entryCount()).To(BeZero())
		})
	}
}

func TestRegistry_JWTSource_ValidatesAJWTSVIDWithNothingReparsed(t *testing.T) {
	g := NewWithT(t)
	key := newECKey(t)
	fetcher := newProviderFetcher(map[string]func(int) ([]sts.TrustBundle, error){
		testProviderArn: fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, jwtECKey(t, "k1", key))}),
	})
	registry, _, _ := newTestRegistry(t, fetcher)
	sign := func(signingKey any, kid string) string {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: signingKey},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), kid))
		g.Expect(err).ToNot(HaveOccurred())
		token, err := jwt.Signed(signer).Claims(jwt.Claims{
			Subject:  "spiffe://" + testDomain + "/ns/default/sa/peer",
			Audience: jwt.Audience{"verifier"},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}).Serialize()
		g.Expect(err).ToNot(HaveOccurred())
		return token
	}

	source, err := registry.JWTSource(context.Background(), ownPod)
	g.Expect(err).ToNot(HaveOccurred())

	svid, err := jwtsvid.ParseAndValidate(sign(key, "k1"), source, []string{"verifier"})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(svid.ID.String()).To(Equal("spiffe://" + testDomain + "/ns/default/sa/peer"))
	_, err = jwtsvid.ParseAndValidate(sign(newECKey(t), "k1"), source, []string{"verifier"})
	g.Expect(err).To(HaveOccurred(), "a token signed by a key outside the bundle fails")
	_, err = jwtsvid.ParseAndValidate(sign(key, "unknown"), source, []string{"verifier"})
	g.Expect(err).To(HaveOccurred(), "a key ID outside the bundle fails")
}

func TestRegistry_JWTSource_HandsOutClones(t *testing.T) {
	g := NewWithT(t)
	registry, _, _, _ := newClockedRegistry(t, testProviderArn)
	trustDomain := spiffeid.RequireTrustDomainFromString(testDomain)
	source, err := registry.JWTSource(context.Background(), ownPod)
	g.Expect(err).ToNot(HaveOccurred())

	bundle, err := source.GetJWTBundleForTrustDomain(trustDomain)
	g.Expect(err).ToNot(HaveOccurred())
	bundle.RemoveJWTAuthority("k1")

	again, err := source.GetJWTBundleForTrustDomain(trustDomain)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(again.HasJWTAuthority("k1")).To(BeTrue())
}

func TestRegistry_ProvidersBeyondTheSoftCap_AreServedWithAWarning(t *testing.T) {
	g := NewWithT(t)
	responses := map[string]func(int) ([]sts.TrustBundle, error){}
	arn := func(i int) string {
		return fmt.Sprintf("arn:aws:iam::111122223333:workload-identity-provider/p%02d", i)
	}
	for i := 0; i <= softProviderCap+1; i++ {
		responses[arn(i)] = fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, jwtECKey(t, "k1", newECKey(t)))})
	}
	fetcher := newProviderFetcher(responses)
	registry, _, sessions := newTestRegistry(t, fetcher)
	workloadFor := func(i int) *workloadidentity.Workload {
		sessions.assign(fmt.Sprintf("pod-%02d", i), arn(i))
		return pod(fmt.Sprintf("pod-%02d", i))
	}
	hook := logtest.NewLocal(logger.FromContext(context.Background()).Logger)
	defer hook.Reset()
	ctx := context.Background()
	for i := 0; i < softProviderCap; i++ {
		_, err := registry.JWTBundles(ctx, workloadFor(i))
		g.Expect(err).ToNot(HaveOccurred())
	}
	g.Expect(capWarnings(hook)).To(BeZero())

	_, err := registry.JWTBundles(ctx, workloadFor(softProviderCap))
	g.Expect(err).ToNot(HaveOccurred(), "the cap only warns")
	release, err := registry.Lease(ctx, workloadFor(softProviderCap+1))
	g.Expect(err).ToNot(HaveOccurred(), "a lease past the cap is not refused either")
	defer release()

	g.Expect(registry.entryCount()).To(Equal(softProviderCap + 2))
	g.Expect(capWarnings(hook)).To(Equal(2), "one warning per newly learned provider")
	for i := 0; i <= softProviderCap+1; i++ {
		_, _ = registry.JWTBundles(ctx, workloadFor(i))
	}
	g.Expect(capWarnings(hook)).To(Equal(2), "reading a known provider does not warn again")
}

// capWarnings counts the soft cap warnings hook has seen.
func capWarnings(hook *logtest.Hook) int {
	count := 0
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, "workload identity providers, more than the") {
			count++
		}
	}
	return count
}

// evictionLogs returns the provider of every eviction hook has seen, in order.
func evictionLogs(hook *logtest.Hook) []string {
	var arns []string
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.InfoLevel && strings.HasPrefix(entry.Message, "Evicted trust bundles") {
			arns = append(arns, fmt.Sprint(entry.Data["provider_arn"]))
		}
	}
	return arns
}

func TestRegistry_AChange_NotifiesOnlyThatProvidersStreams(t *testing.T) {
	g := NewWithT(t)
	k1 := jwtECKey(t, "k1", newECKey(t))
	fetcher := newProviderFetcher(map[string]func(int) ([]sts.TrustBundle, error){
		testProviderArn: fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, k1)}),
		otherProviderArn: sequence(
			ok(sts.TrustBundle{TrustDomain: peerDomain, Bundle: bundleDoc(t, 0, k1)}),
			ok(sts.TrustBundle{TrustDomain: peerDomain, Bundle: bundleDoc(t, 0, k1, jwtECKey(t, "k2", newECKey(t)))}),
		),
	})
	registry, notifier, sessions := newTestRegistry(t, fetcher)
	// the streams resolve their providers as the tier does
	notifier.Providers = workloadidentity.SessionProviderArns(sessions)
	ctx := context.Background()
	ownStream, releaseOwn, err := notifier.SubscribeToJWTBundles(ctx, ownPod)
	g.Expect(err).ToNot(HaveOccurred())
	defer releaseOwn()
	otherStream, releaseOther, err := notifier.SubscribeToJWTBundles(ctx, otherPod)
	g.Expect(err).ToNot(HaveOccurred())
	defer releaseOther()
	<-ownStream
	<-otherStream
	_, err = registry.JWTBundles(ctx, ownPod)
	g.Expect(err).ToNot(HaveOccurred())
	_, err = registry.JWTBundles(ctx, otherPod)
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(refreshOnce(registry.entryFor(otherProviderArn).source, ctx)).To(Succeed())

	g.Expect(otherStream).To(Receive(), "the provider whose JWT key rolled")
	g.Expect(ownStream).ToNot(Receive(), "another provider's rotation is not news here")
	g.Expect(notifier.CertBundleCalls()).To(BeZero(), "the X.509 set did not change")
	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(1), "the other provider's refresh does not touch this one")
}

func TestRegistry_RefreshDue_RefreshesOnlyProvidersWhoseTimeHasCome(t *testing.T) {
	g := NewWithT(t)
	registry, fetcher, _, clock := newClockedRegistry(t, testProviderArn, otherProviderArn)
	ctx := context.Background()
	_, err := registry.JWTBundles(ctx, ownPod)
	g.Expect(err).ToNot(HaveOccurred())
	clock.Advance(time.Minute)
	_, err = registry.JWTBundles(ctx, otherPod)
	g.Expect(err).ToNot(HaveOccurred())

	clock.Advance(defaultRefreshInterval - time.Minute)
	registry.refreshDue(ctx)
	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(2), "due five minutes after its fetch")
	g.Expect(fetcher.Calls(otherProviderArn)).To(Equal(1), "not due for another minute")

	clock.Advance(time.Minute)
	registry.refreshDue(ctx)
	g.Expect(fetcher.Calls(otherProviderArn)).To(Equal(2))
	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(2))
}

func TestRegistry_Refresh_SignsWithALeaseholdersSession(t *testing.T) {
	g := NewWithT(t)
	registry, fetcher, sessions, clock := newClockedRegistry(t, testProviderArn)
	sessions.assign("holder", testProviderArn)
	sessions.assign("reader", testProviderArn)
	ctx := context.Background()
	release, err := registry.Lease(ctx, pod("holder"))
	g.Expect(err).ToNot(HaveOccurred())
	defer release()
	_, err = registry.JWTBundles(ctx, pod("reader"))
	g.Expect(err).ToNot(HaveOccurred())

	clock.Advance(defaultRefreshInterval)
	registry.refreshDue(ctx)

	g.Expect(fetcher.Signers(testProviderArn)).To(Equal([]string{"AKID-reader", "AKID-holder"}),
		"the reader's own read fetched with its session; the refresh signs with the leaseholder's")
}

func TestRegistry_Refresh_WithNoLease_SignsWithTheLatestReader(t *testing.T) {
	g := NewWithT(t)
	registry, fetcher, sessions, clock := newClockedRegistry(t, testProviderArn)
	sessions.assign("first", testProviderArn)
	sessions.assign("latest", testProviderArn)
	ctx := context.Background()
	_, err := registry.JWTBundles(ctx, pod("first"))
	g.Expect(err).ToNot(HaveOccurred())
	_, err = registry.JWTSource(ctx, pod("latest"))
	g.Expect(err).ToNot(HaveOccurred())

	clock.Advance(defaultRefreshInterval)
	registry.refreshDue(ctx)

	g.Expect(fetcher.Signers(testProviderArn)).To(Equal([]string{"AKID-first", "AKID-latest"}))
}

func TestRegistry_Refresh_SkipsALeaseholderWhoseSessionCannotSign(t *testing.T) {
	for name, spoil := range map[string]func(*testSessions){
		"its session names another provider": func(s *testSessions) { s.assign("holder", otherProviderArn) },
		"its session fails":                  func(s *testSessions) { s.fail("holder", wierrors.ErrSessionUnavailable) },
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			registry, fetcher, sessions, clock := newClockedRegistry(t, testProviderArn, otherProviderArn)
			sessions.assign("holder", testProviderArn)
			sessions.assign("reader", testProviderArn)
			ctx := context.Background()
			release, err := registry.Lease(ctx, pod("holder"))
			g.Expect(err).ToNot(HaveOccurred())
			defer release()
			_, err = registry.JWTBundles(ctx, pod("reader"))
			g.Expect(err).ToNot(HaveOccurred())

			spoil(sessions)
			clock.Advance(defaultRefreshInterval)
			registry.refreshDue(ctx)

			g.Expect(fetcher.Signers(testProviderArn)).To(Equal([]string{"AKID-reader", "AKID-reader"}))
		})
	}
}

func TestRegistry_Signer_IsAskedOnlyWhenAFetchRuns(t *testing.T) {
	g := NewWithT(t)
	registry, fetcher, sessions, clock := newClockedRegistry(t, testProviderArn)
	signer := &recordingSigner{}
	registry.opts.Signer = signer
	sessions.assign("holder", testProviderArn)
	sessions.assign("reader", testProviderArn)
	ctx := context.Background()
	release, err := registry.Lease(ctx, pod("holder"))
	g.Expect(err).ToNot(HaveOccurred())
	defer release()

	_, err = registry.JWTBundles(ctx, pod("reader"))
	g.Expect(err).ToNot(HaveOccurred())
	_, err = registry.X509Bundles(ctx, pod("reader"))
	g.Expect(err).ToNot(HaveOccurred())
	clock.Advance(defaultRefreshInterval)
	registry.refreshDue(ctx)

	g.Expect(signer.Calls()).To(Equal([][]string{{"reader"}, {"holder", "reader"}}),
		"the first read for its reader, nothing for a cached read, the refresh for the leaseholder then the latest reader")
	g.Expect(fetcher.Signers(testProviderArn)).To(Equal([]string{"AKID-signer", "AKID-signer"}))

	// the latest reader is now a leaseholder, and is offered once
	_, err = registry.JWTSource(ctx, pod("holder"))
	g.Expect(err).ToNot(HaveOccurred())
	clock.Advance(defaultRefreshInterval)
	registry.refreshDue(ctx)
	g.Expect(signer.Calls()[2]).To(Equal([]string{"holder"}))
}

// resolverFunc is a ProviderArnResolver backed by a function.
type resolverFunc func(context.Context, *workloadidentity.Workload) (string, error)

func (f resolverFunc) ProviderArn(ctx context.Context, w *workloadidentity.Workload) (string, error) {
	return f(ctx, w)
}

func TestRegistry_WithoutWorkloadSessions_ServesFromTheResolverAndTheSigner(t *testing.T) {
	g := NewWithT(t)
	fetcher := &fakeFetcher{respond: fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca")))})}
	registry, err := New(Opts{
		Fetcher:   fetcher,
		Notifier:  &fake.Subscriber{},
		Providers: resolverFunc(func(context.Context, *workloadidentity.Workload) (string, error) { return testProviderArn, nil }),
		Signer:    &recordingSigner{},
	})
	g.Expect(err).ToNot(HaveOccurred())

	bundles, err := registry.X509Bundles(context.Background(), ownPod)

	g.Expect(err).ToNot(HaveOccurred(), "nothing in the tier needs a workload session")
	g.Expect(bundles).To(HaveKey(testDomain))
	g.Expect(fetcher.arns).To(Equal([]string{testProviderArn}))
	g.Expect(fetcher.creds[0].AccessKeyID).To(Equal("AKID-signer"))
}

func TestRegistry_FirstRead_SignsWithTheReadersSession(t *testing.T) {
	for name, read := range map[string]func(*Registry, *workloadidentity.Workload) error{
		"OwnTrustDomain": func(r *Registry, w *workloadidentity.Workload) error {
			_, err := r.OwnTrustDomain(context.Background(), w)
			return err
		},
		"X509Bundles": func(r *Registry, w *workloadidentity.Workload) error {
			_, err := r.X509Bundles(context.Background(), w)
			return err
		},
		"JWTBundles": func(r *Registry, w *workloadidentity.Workload) error {
			_, err := r.JWTBundles(context.Background(), w)
			return err
		},
		"JWTSource": func(r *Registry, w *workloadidentity.Workload) error {
			_, err := r.JWTSource(context.Background(), w)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			registry, fetcher, _, _ := newClockedRegistry(t, testProviderArn)

			g.Expect(read(registry, ownPod)).To(Succeed())

			g.Expect(fetcher.Signers(testProviderArn)).To(Equal([]string{"AKID-own-pod"}))
		})
	}
}

func TestRegistry_Refresh_WithNoUsableSession_IsARetryableFailureForReaders(t *testing.T) {
	g := NewWithT(t)
	registry, fetcher, sessions, _ := newClockedRegistry(t, testProviderArn)
	sessions.assign("holder", testProviderArn)
	sessions.assign("reader", testProviderArn)
	ctx := context.Background()
	release, err := registry.Lease(ctx, pod("holder"))
	g.Expect(err).ToNot(HaveOccurred())
	defer release()

	sessions.fail("holder", wierrors.ErrSessionUnavailable)
	registry.refreshDue(ctx)
	_, err = registry.X509Bundles(ctx, pod("reader"))

	g.Expect(err).To(MatchError(wierrors.ErrBundleUnavailable), "inside the backoff a read gets the recorded failure")
	g.Expect(wierrors.IsRetryable(err)).To(BeTrue())
	g.Expect(fetcher.TotalCalls()).To(BeZero())
}

func TestRegistry_Refresh_WithNoUsableSession_BacksOffWithoutCallingSTS(t *testing.T) {
	g := NewWithT(t)
	registry, fetcher, sessions, clock := newClockedRegistry(t, testProviderArn)
	ctx := context.Background()
	_, err := registry.JWTBundles(ctx, ownPod)
	g.Expect(err).ToNot(HaveOccurred())

	sessions.fail("own-pod", wierrors.ErrSessionUnavailable)
	clock.Advance(defaultRefreshInterval)
	registry.refreshDue(ctx)

	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(1), "nothing to sign with, so STS is not called")
	g.Expect(registry.entryFor(testProviderArn).source.dueAt()).To(BeTemporally("==", clock.Now().Add(retryBaseDelay)), "the refresh backs off")
	served, err := registry.entryFor(testProviderArn).source.JWTBundles(ctx, signTest)
	g.Expect(err).ToNot(HaveOccurred(), "the last good bundle keeps serving")
	g.Expect(served).To(HaveKey(testDomain))

	sessions.assign("own-pod", testProviderArn)
	clock.Advance(retryBaseDelay)
	registry.refreshDue(ctx)
	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(2), "the next refresh after the backoff fetches")
}

func TestRegistry_Run_TicksEveryThirtySecondsAndSweepsEveryFiveMinutes(t *testing.T) {
	g := NewWithT(t)
	registry, fetcher, _, clock := newClockedRegistry(t, testProviderArn)
	ticks := make(chan time.Duration, 8)
	fire := make(chan time.Time)
	registry.after = func(d time.Duration) <-chan time.Time {
		ticks <- d
		return fire
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		registry.Run(ctx)
	}()
	g.Eventually(ticks).Should(Receive(Equal(30 * time.Second)))

	// a lease learns the provider, and the next tick prefetches it with the
	// leaseholder's session
	release, err := registry.Lease(ctx, ownPod)
	g.Expect(err).ToNot(HaveOccurred())
	fire <- clock.Now()
	g.Eventually(ticks).Should(Receive())
	g.Expect(fetcher.Signers(testProviderArn)).To(Equal([]string{"AKID-own-pod"}))

	// once released and idle past the TTL, the sweep five minutes on evicts it
	release()
	clock.Advance(providerIdleTTL + sweepInterval)
	fire <- clock.Now()
	g.Eventually(ticks).Should(Receive())
	g.Expect(registry.entryCount()).To(BeZero())

	g.Consistently(done, 50*time.Millisecond).ShouldNot(BeClosed(), "Run holds until its context ends")
	cancel()
	g.Eventually(done).Should(BeClosed())
}

func TestRegistry_ReadAfterRunHasStopped_IsStillServed(t *testing.T) {
	g := NewWithT(t)
	registry, fetcher, _, _ := newClockedRegistry(t, testProviderArn)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		registry.Run(ctx)
	}()
	cancel()
	g.Eventually(done).Should(BeClosed())

	bundles, err := registry.JWTBundles(context.Background(), ownPod)

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(bundles).To(HaveKey(testDomain))
	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(1))
}

func TestRegistry_FailingProvider_IsKeptAndBacksOff(t *testing.T) {
	g := NewWithT(t)
	fetcher := newProviderFetcher(map[string]func(int) ([]sts.TrustBundle, error){
		testProviderArn: sequence(fail(errors.New("boom"))),
	})
	registry, _, _ := newTestRegistry(t, fetcher)
	ctx := context.Background()

	for range 5 {
		_, err := registry.X509Bundles(ctx, ownPod)
		g.Expect(err).To(MatchError(wierrors.ErrBundleUnavailable))
		_, err = registry.JWTSource(ctx, ownPod)
		g.Expect(err).To(MatchError(wierrors.ErrBundleUnavailable))
	}

	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(1), "reads inside the provider's backoff do not call STS")
	g.Expect(registry.entryFor(testProviderArn)).ToNot(BeNil(), "a failed first fetch does not drop the provider")
}

func TestRegistry_Lease_LearnsTheProviderWithoutFetching(t *testing.T) {
	g := NewWithT(t)
	fetcher := newProviderFetcher(map[string]func(int) ([]sts.TrustBundle, error){
		testProviderArn: sequence(fail(errors.New("STS is down"))),
	})
	registry, _, _ := newTestRegistry(t, fetcher)

	release, err := registry.Lease(context.Background(), ownPod)

	g.Expect(err).ToNot(HaveOccurred(), "an STS outage does not stop a stream opening")
	defer release()
	g.Expect(registry.leasesFor(testProviderArn)).To(Equal(1))
	g.Expect(fetcher.Calls(testProviderArn)).To(BeZero(), "the refresher fetches a leased provider, not the lease")
}

func TestRegistry_Sweep_EvictsOnlyProvidersWithNoLeaseAndAnExpiredTTL(t *testing.T) {
	g := NewWithT(t)
	idle, leased, readLater := testProviderArn, otherProviderArn, "arn:aws:iam::111122223333:workload-identity-provider/later"
	registry, _, sessions, clock := newClockedRegistry(t, idle, leased, readLater)
	sessions.assign("later-pod", readLater)
	hook := logtest.NewLocal(logger.FromContext(context.Background()).Logger)
	defer hook.Reset()
	ctx := context.Background()
	_, err := registry.JWTBundles(ctx, ownPod)
	g.Expect(err).ToNot(HaveOccurred())
	release, err := registry.Lease(ctx, otherPod)
	g.Expect(err).ToNot(HaveOccurred())
	defer release()
	_, err = registry.JWTBundles(ctx, pod("later-pod"))
	g.Expect(err).ToNot(HaveOccurred())

	clock.Advance(50 * time.Minute)
	_, _ = registry.OwnTrustDomain(ctx, pod("later-pod"))
	clock.Advance(11 * time.Minute)
	registry.sweep(ctx)

	g.Expect(registry.entryFor(idle)).To(BeNil(), "unread and unleased for over providerIdleTTL")
	g.Expect(registry.entryFor(leased)).ToNot(BeNil(), "a lease keeps a provider however long it is unread")
	g.Expect(registry.entryFor(readLater)).ToNot(BeNil(), "read 11 minutes ago")
	g.Expect(evictionLogs(hook)).To(Equal([]string{idle}), "each eviction is logged with its provider")

	clock.Advance(providerIdleTTL)
	registry.sweep(ctx)
	g.Expect(registry.entryFor(readLater)).To(BeNil())
	g.Expect(registry.entryFor(leased)).ToNot(BeNil())
}

func TestRegistry_ReleasingTheLastLease_RestartsTheTTL(t *testing.T) {
	g := NewWithT(t)
	registry, _, _, clock := newClockedRegistry(t, testProviderArn)
	ctx := context.Background()
	first, err := registry.Lease(ctx, ownPod)
	g.Expect(err).ToNot(HaveOccurred())
	second, err := registry.Lease(ctx, ownPod)
	g.Expect(err).ToNot(HaveOccurred())

	clock.Advance(2 * time.Hour)
	first()
	registry.sweep(ctx)
	g.Expect(registry.entryFor(testProviderArn)).ToNot(BeNil(), "one lease is still open")
	clock.Advance(time.Hour)
	second()
	clock.Advance(providerIdleTTL - time.Minute)
	registry.sweep(ctx)
	g.Expect(registry.entryFor(testProviderArn)).ToNot(BeNil(), "the TTL runs from the last lease ending")

	clock.Advance(time.Minute)
	registry.sweep(ctx)
	g.Expect(registry.entryFor(testProviderArn)).To(BeNil())
}

func TestRegistry_Lease_EndsWithItsContextAndReleasesOnce(t *testing.T) {
	g := NewWithT(t)
	registry, _, _, _ := newClockedRegistry(t, testProviderArn)
	leaseCtx, cancel := context.WithCancel(context.Background())
	release, err := registry.Lease(leaseCtx, ownPod)
	g.Expect(err).ToNot(HaveOccurred())
	other, err := registry.Lease(context.Background(), ownPod)
	g.Expect(err).ToNot(HaveOccurred())
	defer other()

	cancel()
	g.Eventually(func() int { return registry.leasesFor(testProviderArn) }).Should(Equal(1))
	release()
	release()

	g.Expect(registry.leasesFor(testProviderArn)).To(Equal(1), "a lease ends once however it ends")
}

func TestRegistry_EvictedProvider_IsNotRefreshedAndIsRelearnedOnTheNextRead(t *testing.T) {
	g := NewWithT(t)
	registry, fetcher, _, clock := newClockedRegistry(t, testProviderArn)
	ctx := context.Background()
	_, err := registry.JWTBundles(ctx, ownPod)
	g.Expect(err).ToNot(HaveOccurred())

	clock.Advance(providerIdleTTL)
	registry.sweep(ctx)
	registry.refreshDue(ctx)
	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(1), "an evicted provider is not refreshed")

	_, err = registry.JWTBundles(ctx, ownPod)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(2), "relearning the provider fetches it again")
}

func TestRegistry_EveryRead_RestartsTheTTL(t *testing.T) {
	ctx := context.Background()
	for name, read := range map[string]func(*Registry){
		"X509Bundles":    func(r *Registry) { _, _ = r.X509Bundles(ctx, ownPod) },
		"JWTBundles":     func(r *Registry) { _, _ = r.JWTBundles(ctx, ownPod) },
		"JWTSource":      func(r *Registry) { _, _ = r.JWTSource(ctx, ownPod) },
		"OwnTrustDomain": func(r *Registry) { _, _ = r.OwnTrustDomain(ctx, ownPod) },
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			registry, _, _, clock := newClockedRegistry(t, testProviderArn)
			_, err := registry.JWTBundles(ctx, ownPod)
			g.Expect(err).ToNot(HaveOccurred())

			clock.Advance(50 * time.Minute)
			read(registry)
			clock.Advance(11 * time.Minute)
			registry.sweep(ctx)
			g.Expect(registry.entryFor(testProviderArn)).ToNot(BeNil(), "read 11 minutes ago")

			clock.Advance(providerIdleTTL)
			registry.sweep(ctx)
			g.Expect(registry.entryFor(testProviderArn)).To(BeNil())
		})
	}
}

func TestRegistry_ProviderIdleTTL_IsOneHourToTheMinute(t *testing.T) {
	g := NewWithT(t)
	registry, _, _, clock := newClockedRegistry(t, testProviderArn)
	ctx := context.Background()
	_, err := registry.JWTBundles(ctx, ownPod)
	g.Expect(err).ToNot(HaveOccurred())

	clock.Advance(59 * time.Minute)
	registry.sweep(ctx)
	g.Expect(registry.entryFor(testProviderArn)).ToNot(BeNil())
	clock.Advance(time.Minute)
	registry.sweep(ctx)
	g.Expect(registry.entryFor(testProviderArn)).To(BeNil(), "idle for exactly an hour is evicted")
}

func TestRegistry_ConcurrentLeasesReadsRefreshesAndSweeps_AreRaceFree(t *testing.T) {
	g := NewWithT(t)
	registry, _, _, clock := newClockedRegistry(t, testProviderArn, otherProviderArn)
	workloads := []*workloadidentity.Workload{ownPod, otherPod}
	ctx := context.Background()

	var wg sync.WaitGroup
	for worker := range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 50 {
				w := workloads[(worker+i)%len(workloads)]
				switch i % 5 {
				case 0:
					if release, err := registry.Lease(ctx, w); err == nil {
						release()
					}
				case 1:
					_, _ = registry.JWTBundles(ctx, w)
				case 2:
					clock.Advance(providerIdleTTL)
					registry.sweep(ctx)
				case 3:
					registry.refreshDue(ctx)
				default:
					_, _ = registry.OwnTrustDomain(ctx, w)
				}
			}
		}()
	}
	wg.Wait()

	for _, arn := range []string{testProviderArn, otherProviderArn} {
		leases := registry.leasesFor(arn)
		g.Expect(leases == -1 || leases == 0).To(BeTrue(), "every lease was released: %s has %d", arn, leases)
	}
}
