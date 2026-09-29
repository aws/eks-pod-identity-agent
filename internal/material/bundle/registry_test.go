package bundle

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity/fake"
)

const otherProviderArn = "arn:aws:iam::444455556666:workload-identity-provider/other"

// providerFetcher is a fake GetTrustBundles that answers per provider ARN and
// counts calls per provider.
type providerFetcher struct {
	mu        sync.Mutex
	responses map[string]func(call int) ([]sts.TrustBundle, error)
	calls     map[string]int
}

func newProviderFetcher(responses map[string]func(int) ([]sts.TrustBundle, error)) *providerFetcher {
	return &providerFetcher{responses: responses, calls: map[string]int{}}
}

func (f *providerFetcher) GetTrustBundles(_ context.Context, providerArn string) ([]sts.TrustBundle, error) {
	f.mu.Lock()
	f.calls[providerArn]++
	call := f.calls[providerArn]
	respond, ok := f.responses[providerArn]
	f.mu.Unlock()
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

func (f *providerFetcher) TotalCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	total := 0
	for _, calls := range f.calls {
		total += calls
	}
	return total
}

func newTestRegistry(t *testing.T, fetcher Fetcher) (*Registry, *fake.Subscriber) {
	t.Helper()
	notifier := &fake.Subscriber{}
	registry, err := New(Opts{Fetcher: fetcher, Notifier: notifier})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return registry, notifier
}

func TestNew_NeedsNoWorkloadSession(t *testing.T) {
	g := NewWithT(t)
	fetcher := &fakeFetcher{respond: fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca")))})}

	// Opts has no session provider, no workload and no provider ARN: a fetcher
	// built from the node's configuration and a notifier are all the tier is given.
	registry, err := New(Opts{Fetcher: fetcher, Notifier: &fake.Subscriber{}})
	g.Expect(err).ToNot(HaveOccurred())

	_, err = registry.X509Bundles(context.Background(), testProviderArn)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(fetcher.arns).To(Equal([]string{testProviderArn}), "the provider the caller names goes out as the request input")
}

func TestNew_MissingInputs_AreEachReported(t *testing.T) {
	g := NewWithT(t)

	_, err := New(Opts{})

	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("fetcher"))
	g.Expect(err.Error()).To(ContainSubstring("notifier"))
}

func TestRegistry_TwoProviders_AreFetchedAndServedApart(t *testing.T) {
	g := NewWithT(t)
	ownCA, otherCA := newAuthority(t, "own"), newAuthority(t, "other")
	ownKey, otherKey := newECKey(t), newECKey(t)
	fetcher := newProviderFetcher(map[string]func(int) ([]sts.TrustBundle, error){
		testProviderArn:  fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, ownCA), jwtECKey(t, "own-1", ownKey))}),
		otherProviderArn: fixed(sts.TrustBundle{TrustDomain: peerDomain, Bundle: bundleDoc(t, 0, x509Key(t, otherCA), jwtECKey(t, "other-1", otherKey))}),
	})
	registry, _ := newTestRegistry(t, fetcher)
	ctx := context.Background()

	ownX509, err := registry.X509Bundles(ctx, testProviderArn)
	g.Expect(err).ToNot(HaveOccurred())
	otherX509, err := registry.X509Bundles(ctx, otherProviderArn)
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(ownX509).To(Equal(map[string][][]byte{testDomain: {ownCA.der}}))
	g.Expect(otherX509).To(Equal(map[string][][]byte{peerDomain: {otherCA.der}}))
	g.Expect(registry.OwnTrustDomain(testProviderArn)).To(Equal(testDomain))
	g.Expect(registry.OwnTrustDomain(otherProviderArn)).To(Equal(peerDomain))
	authority, err := registry.JWTAuthority(otherProviderArn, peerDomain, "other-1")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(otherKey.PublicKey.Equal(authority)).To(BeTrue())
	_, err = registry.JWTAuthority(testProviderArn, peerDomain, "other-1")
	g.Expect(err).To(MatchError(wierrors.ErrUnknownTrustDomain), "one provider's bundles never answer for another's")
	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(1))
	g.Expect(fetcher.Calls(otherProviderArn)).To(Equal(1))
}

func TestRegistry_OneProvider_OneFetchBacksAllFourMethods(t *testing.T) {
	g := NewWithT(t)
	fetcher := newProviderFetcher(map[string]func(int) ([]sts.TrustBundle, error){
		testProviderArn: fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca")), jwtECKey(t, "k1", newECKey(t)))}),
	})
	registry, _ := newTestRegistry(t, fetcher)
	ctx := context.Background()

	_, x509Err := registry.X509Bundles(ctx, testProviderArn)
	_, jwtErr := registry.JWTBundles(ctx, testProviderArn)
	_, authorityErr := registry.JWTAuthority(testProviderArn, testDomain, "k1")
	own := registry.OwnTrustDomain(testProviderArn)

	g.Expect(x509Err).ToNot(HaveOccurred())
	g.Expect(jwtErr).ToNot(HaveOccurred())
	g.Expect(authorityErr).ToNot(HaveOccurred())
	g.Expect(own).To(Equal(testDomain))
	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(1))
}

func TestRegistry_NoProvider_IsNotEnrolled(t *testing.T) {
	g := NewWithT(t)
	fetcher := newProviderFetcher(nil)
	registry, _ := newTestRegistry(t, fetcher)
	ctx := context.Background()

	_, x509Err := registry.X509Bundles(ctx, "")
	_, jwtErr := registry.JWTBundles(ctx, "")
	_, authorityErr := registry.JWTAuthority("", testDomain, "k1")

	g.Expect(x509Err).To(MatchError(wierrors.ErrNotEnrolled))
	g.Expect(jwtErr).To(MatchError(wierrors.ErrNotEnrolled))
	g.Expect(authorityErr).To(MatchError(wierrors.ErrNotEnrolled))
	g.Expect(registry.OwnTrustDomain("")).To(BeEmpty())
	g.Expect(fetcher.TotalCalls()).To(BeZero())
	g.Expect(registry.entries).To(BeEmpty())
}

func TestRegistry_ContextFreeMethods_NeverLearnAProvider(t *testing.T) {
	g := NewWithT(t)
	fetcher := newProviderFetcher(map[string]func(int) ([]sts.TrustBundle, error){
		testProviderArn: fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca")))}),
	})
	registry, _ := newTestRegistry(t, fetcher)

	g.Expect(registry.OwnTrustDomain(testProviderArn)).To(BeEmpty())
	_, err := registry.JWTAuthority(testProviderArn, testDomain, "k1")

	g.Expect(err).To(MatchError(wierrors.ErrBundleUnavailable))
	g.Expect(fetcher.TotalCalls()).To(BeZero())
	g.Expect(registry.entries).To(BeEmpty(), "only a read that can fetch learns a provider")
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
	registry, _ := newTestRegistry(t, fetcher)
	hook := logtest.NewLocal(logger.FromContext(context.Background()).Logger)
	defer hook.Reset()
	ctx := context.Background()
	for i := 0; i < softProviderCap; i++ {
		_, err := registry.JWTBundles(ctx, arn(i))
		g.Expect(err).ToNot(HaveOccurred())
	}
	g.Expect(capWarnings(hook)).To(BeZero())

	_, err := registry.JWTBundles(ctx, arn(softProviderCap))
	g.Expect(err).ToNot(HaveOccurred(), "the cap only warns")
	release, err := registry.Lease(ctx, arn(softProviderCap+1))
	g.Expect(err).ToNot(HaveOccurred(), "a lease past the cap is not refused either")
	defer release()

	g.Expect(fetcher.Calls(arn(softProviderCap))).To(Equal(1))
	g.Expect(registry.entries).To(HaveLen(softProviderCap + 2))
	g.Expect(capWarnings(hook)).To(Equal(2), "one warning per newly learned provider")
	for i := 0; i <= softProviderCap+1; i++ {
		_, _ = registry.JWTBundles(ctx, arn(i))
		_ = registry.OwnTrustDomain(arn(i))
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

func TestRegistry_AChangeInAnyProvider_BroadcastsToTheNode(t *testing.T) {
	g := NewWithT(t)
	k1 := jwtECKey(t, "k1", newECKey(t))
	fetcher := newProviderFetcher(map[string]func(int) ([]sts.TrustBundle, error){
		testProviderArn: fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, k1)}),
		otherProviderArn: sequence(
			ok(sts.TrustBundle{TrustDomain: peerDomain, Bundle: bundleDoc(t, 0, k1)}),
			ok(sts.TrustBundle{TrustDomain: peerDomain, Bundle: bundleDoc(t, 0, k1, jwtECKey(t, "k2", newECKey(t)))}),
		),
	})
	registry, notifier := newTestRegistry(t, fetcher)
	ctx := context.Background()
	_, err := registry.JWTBundles(ctx, testProviderArn)
	g.Expect(err).ToNot(HaveOccurred())
	_, err = registry.JWTBundles(ctx, otherProviderArn)
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(refreshOnce(registry.known(otherProviderArn), ctx)).To(Succeed())

	g.Expect(notifier.BroadcastCalls()).To(Equal(1))
	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(1), "the other provider's refresh does not touch this one")
}

func TestRegistry_Run_RefreshesProvidersLearnedBeforeAndAfterItStarts(t *testing.T) {
	g := NewWithT(t)
	fetcher := newProviderFetcher(map[string]func(int) ([]sts.TrustBundle, error){
		testProviderArn:  fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "own")))}),
		otherProviderArn: fixed(sts.TrustBundle{TrustDomain: peerDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "other")))}),
	})
	registry, _ := newTestRegistry(t, fetcher)

	// every refresh loop reports each wait it asks for, and waits until the test
	// releases that provider's loop
	waits := map[string]chan time.Duration{testProviderArn: make(chan time.Duration, 4), otherProviderArn: make(chan time.Duration, 4)}
	fire := map[string]chan time.Time{testProviderArn: make(chan time.Time), otherProviderArn: make(chan time.Time)}
	registry.configure = func(source *providerSource) {
		source.jitter = func() float64 { return 0 }
		source.after = func(d time.Duration) <-chan time.Time {
			waits[source.providerArn] <- d
			return fire[source.providerArn]
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// learned before Run: fetched by the read, and its loop starts with Run
	_, err := registry.X509Bundles(ctx, testProviderArn)
	g.Expect(err).ToNot(HaveOccurred())
	done := make(chan struct{})
	go func() {
		defer close(done)
		registry.Run(ctx)
	}()
	g.Eventually(waits[testProviderArn]).Should(Receive(BeZero()))

	// the loop's first wake finds the read's snapshot and waits a full interval
	// rather than fetching again
	fire[testProviderArn] <- time.Now()
	g.Eventually(waits[testProviderArn]).Should(Receive(Equal(defaultRefreshInterval)))
	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(1))

	// learned after Run: its loop starts at once, and likewise does not refetch
	_, err = registry.X509Bundles(ctx, otherProviderArn)
	g.Expect(err).ToNot(HaveOccurred())
	g.Eventually(waits[otherProviderArn]).Should(Receive(BeZero()))
	fire[otherProviderArn] <- time.Now()
	g.Eventually(waits[otherProviderArn]).Should(Receive(Equal(defaultRefreshInterval)))
	g.Expect(fetcher.Calls(otherProviderArn)).To(Equal(1))

	// after the interval each loop refreshes its own provider
	fire[testProviderArn] <- time.Now()
	fire[otherProviderArn] <- time.Now()
	g.Eventually(func() int { return fetcher.Calls(testProviderArn) }).Should(Equal(2))
	g.Eventually(func() int { return fetcher.Calls(otherProviderArn) }).Should(Equal(2))
	g.Eventually(waits[testProviderArn]).Should(Receive())
	g.Eventually(waits[otherProviderArn]).Should(Receive())

	// Run holds until its context ends, and no loop outlives it
	g.Consistently(done, 100*time.Millisecond).ShouldNot(BeClosed())
	cancel()
	g.Eventually(done).Should(BeClosed())
	for arn, release := range fire {
		select {
		case release <- time.Now():
			t.Fatalf("the refresh loop for %s outlived Run's context", arn)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func TestRegistry_ReadAfterRunHasStopped_IsStillServed(t *testing.T) {
	g := NewWithT(t)
	fetcher := newProviderFetcher(map[string]func(int) ([]sts.TrustBundle, error){
		testProviderArn: fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca")))}),
	})
	registry, _ := newTestRegistry(t, fetcher)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		registry.Run(ctx)
	}()
	cancel()
	g.Eventually(done).Should(BeClosed())

	bundles, err := registry.X509Bundles(context.Background(), testProviderArn)

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(bundles).To(HaveKey(testDomain))
	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(1), "no refresh loop starts under a finished Run")
}

func TestRegistry_ReReadingAKnownProvider_StartsNoSecondLoop(t *testing.T) {
	g := NewWithT(t)
	fetcher := newProviderFetcher(map[string]func(int) ([]sts.TrustBundle, error){
		testProviderArn: fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca")), jwtECKey(t, "k1", newECKey(t)))}),
	})
	registry, _ := newTestRegistry(t, fetcher)
	waits := make(chan time.Duration, 8)
	registry.configure = func(source *providerSource) {
		source.after = func(d time.Duration) <-chan time.Time {
			waits <- d
			return make(chan time.Time)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go registry.Run(ctx)

	_, err := registry.X509Bundles(ctx, testProviderArn)
	g.Expect(err).ToNot(HaveOccurred())
	g.Eventually(waits).Should(Receive())
	for range 5 {
		_, err = registry.X509Bundles(ctx, testProviderArn)
		g.Expect(err).ToNot(HaveOccurred())
		_, err = registry.JWTBundles(ctx, testProviderArn)
		g.Expect(err).ToNot(HaveOccurred())
	}

	g.Consistently(waits, 200*time.Millisecond).ShouldNot(Receive(), "one provider has one refresh loop")
}

func TestRegistry_FailingProvider_IsKeptAndBacksOff(t *testing.T) {
	g := NewWithT(t)
	fetcher := newProviderFetcher(map[string]func(int) ([]sts.TrustBundle, error){
		testProviderArn: sequence(fail(errors.New("boom"))),
	})
	registry, _ := newTestRegistry(t, fetcher)
	ctx := context.Background()

	for range 5 {
		_, err := registry.X509Bundles(ctx, testProviderArn)
		g.Expect(err).To(MatchError(wierrors.ErrBundleUnavailable))
		_, err = registry.JWTBundles(ctx, testProviderArn)
		g.Expect(err).To(MatchError(wierrors.ErrBundleUnavailable))
	}

	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(1), "reads inside the provider's backoff do not call STS")
	g.Expect(registry.known(testProviderArn)).ToNot(BeNil(), "a failed first fetch does not drop the provider")
}

func TestRegistry_ConcurrentLearningAndLookups_AreRaceFree(t *testing.T) {
	g := NewWithT(t)
	responses := map[string]func(int) ([]sts.TrustBundle, error){}
	arns := []string{testProviderArn, otherProviderArn,
		"arn:aws:iam::111122223333:workload-identity-provider/third",
		"arn:aws:iam::111122223333:workload-identity-provider/fourth"}
	for _, arn := range arns {
		responses[arn] = fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, jwtECKey(t, "k1", newECKey(t)))})
	}
	fetcher := newProviderFetcher(responses)
	registry, _ := newTestRegistry(t, fetcher)
	ctx := context.Background()

	// lookups run in goroutines that never learn a provider themselves, so the
	// only thing ordering their reads against the learners' writes is the
	// registry's own lock
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for worker := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				arn := arns[(worker+i)%len(arns)]
				_ = registry.OwnTrustDomain(arn)
				_, _ = registry.JWTAuthority(arn, testDomain, "k1")
			}
		}()
	}
	var learners sync.WaitGroup
	for worker := range 4 {
		learners.Add(1)
		go func() {
			defer learners.Done()
			for i := range 20 {
				arn := arns[(worker+i)%len(arns)]
				if i%2 == 0 {
					_, _ = registry.X509Bundles(ctx, arn)
				} else {
					_, _ = registry.JWTBundles(ctx, arn)
				}
			}
		}()
	}
	learners.Wait()
	close(stop)
	wg.Wait()

	for _, arn := range arns {
		g.Expect(registry.known(arn)).ToNot(BeNil())
		g.Expect(fetcher.Calls(arn)).To(Equal(1), "concurrent first reads of %s share one fetch", arn)
	}
}

// leaseClock is a registry clock a test moves by hand.
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

// newLeaseTestRegistry builds a registry over providers that always answer, on a
// hand-moved clock.
func newLeaseTestRegistry(t *testing.T, arns ...string) (*Registry, *providerFetcher, *leaseClock) {
	t.Helper()
	responses := map[string]func(int) ([]sts.TrustBundle, error){}
	for _, arn := range arns {
		responses[arn] = fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, jwtECKey(t, "k1", newECKey(t)))})
	}
	fetcher := newProviderFetcher(responses)
	registry, _ := newTestRegistry(t, fetcher)
	clock := &leaseClock{now: time.Now()}
	registry.now = clock.Now
	return registry, fetcher, clock
}

func (r *Registry) leasesFor(providerArn string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, ok := r.entries[providerArn]; ok {
		return entry.leases
	}
	return -1
}

func TestRegistry_Lease_NoProvider_IsNotEnrolled(t *testing.T) {
	g := NewWithT(t)
	registry, fetcher, _ := newLeaseTestRegistry(t)

	release, err := registry.Lease(context.Background(), "")

	g.Expect(err).To(MatchError(wierrors.ErrNotEnrolled))
	g.Expect(release).To(BeNil())
	g.Expect(registry.entries).To(BeEmpty())
	g.Expect(fetcher.TotalCalls()).To(BeZero())
}

func TestRegistry_Lease_LearnsTheProviderAndItsLoopFetches(t *testing.T) {
	g := NewWithT(t)
	registry, fetcher, _ := newLeaseTestRegistry(t, testProviderArn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go registry.Run(ctx)
	g.Eventually(func() bool { registry.mu.Lock(); defer registry.mu.Unlock(); return registry.runCtx != nil }).Should(BeTrue())

	release, err := registry.Lease(ctx, testProviderArn)
	g.Expect(err).ToNot(HaveOccurred())
	defer release()

	g.Expect(registry.leasesFor(testProviderArn)).To(Equal(1))
	g.Eventually(func() int { return fetcher.Calls(testProviderArn) }).Should(Equal(1),
		"the new provider's loop fetches, since no read has stored anything")
}

func TestRegistry_Sweep_EvictsOnlyProvidersWithNoLeaseAndAnExpiredTTL(t *testing.T) {
	g := NewWithT(t)
	idle, leased, readLater := testProviderArn, otherProviderArn, "arn:aws:iam::111122223333:workload-identity-provider/later"
	registry, _, clock := newLeaseTestRegistry(t, idle, leased, readLater)
	hook := logtest.NewLocal(logger.FromContext(context.Background()).Logger)
	defer hook.Reset()
	ctx := context.Background()
	_, err := registry.JWTBundles(ctx, idle)
	g.Expect(err).ToNot(HaveOccurred())
	release, err := registry.Lease(ctx, leased)
	g.Expect(err).ToNot(HaveOccurred())
	defer release()
	_, err = registry.JWTBundles(ctx, readLater)
	g.Expect(err).ToNot(HaveOccurred())

	clock.Advance(50 * time.Minute)
	_ = registry.OwnTrustDomain(readLater) // any read restarts the TTL
	clock.Advance(11 * time.Minute)
	registry.sweep(ctx)

	g.Expect(registry.entries).ToNot(HaveKey(idle), "unread and unleased for over idleTTL")
	g.Expect(registry.entries).To(HaveKey(leased), "a lease keeps a provider however long it is unread")
	g.Expect(registry.entries).To(HaveKey(readLater), "read 11 minutes ago")
	g.Expect(evictionLogs(hook)).To(Equal([]string{idle}), "each eviction is logged with its provider")

	clock.Advance(idleTTL)
	registry.sweep(ctx)
	g.Expect(registry.entries).ToNot(HaveKey(readLater))
	g.Expect(registry.entries).To(HaveKey(leased))
}

func TestRegistry_ReleasingTheLastLease_RestartsTheTTL(t *testing.T) {
	g := NewWithT(t)
	registry, _, clock := newLeaseTestRegistry(t, testProviderArn)
	ctx := context.Background()
	first, err := registry.Lease(ctx, testProviderArn)
	g.Expect(err).ToNot(HaveOccurred())
	second, err := registry.Lease(ctx, testProviderArn)
	g.Expect(err).ToNot(HaveOccurred())

	clock.Advance(2 * time.Hour)
	first()
	registry.sweep(ctx)
	g.Expect(registry.entries).To(HaveKey(testProviderArn), "one lease is still open")
	clock.Advance(time.Hour)
	second()
	clock.Advance(idleTTL - time.Minute)
	registry.sweep(ctx)
	g.Expect(registry.entries).To(HaveKey(testProviderArn), "the TTL runs from the last lease ending")

	clock.Advance(time.Minute)
	registry.sweep(ctx)
	g.Expect(registry.entries).ToNot(HaveKey(testProviderArn))
}

func TestRegistry_Lease_EndsWithItsContextAndReleasesOnce(t *testing.T) {
	g := NewWithT(t)
	registry, _, _ := newLeaseTestRegistry(t, testProviderArn)
	leaseCtx, cancel := context.WithCancel(context.Background())
	release, err := registry.Lease(leaseCtx, testProviderArn)
	g.Expect(err).ToNot(HaveOccurred())
	other, err := registry.Lease(context.Background(), testProviderArn)
	g.Expect(err).ToNot(HaveOccurred())
	defer other()

	cancel()
	g.Eventually(func() int { return registry.leasesFor(testProviderArn) }).Should(Equal(1))
	release()
	release()

	g.Expect(registry.leasesFor(testProviderArn)).To(Equal(1), "a lease ends once however it ends")
}

func TestRegistry_EvictedProvider_StopsRefreshingAndIsRelearnedOnTheNextRead(t *testing.T) {
	g := NewWithT(t)
	registry, fetcher, clock := newLeaseTestRegistry(t, testProviderArn)
	waits := make(chan time.Duration, 8)
	fire := make(chan time.Time)
	registry.configure = func(source *providerSource) {
		source.jitter = func() float64 { return 0 }
		source.after = func(d time.Duration) <-chan time.Time {
			waits <- d
			return fire
		}
	}
	sweeps := make(chan time.Time)
	registry.after = func(time.Duration) <-chan time.Time { return sweeps }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go registry.Run(ctx)
	g.Eventually(func() bool { registry.mu.Lock(); defer registry.mu.Unlock(); return registry.runCtx != nil }).Should(BeTrue())

	_, err := registry.JWTBundles(ctx, testProviderArn)
	g.Expect(err).ToNot(HaveOccurred())
	g.Eventually(waits).Should(Receive(BeZero()))
	fire <- time.Now()
	g.Eventually(waits).Should(Receive(Equal(defaultRefreshInterval)))

	// the sweep Run schedules evicts the idle provider and stops its loop
	clock.Advance(idleTTL)
	sweeps <- time.Now()
	g.Eventually(func() int { registry.mu.Lock(); defer registry.mu.Unlock(); return len(registry.entries) }).Should(BeZero())
	select {
	case fire <- time.Now():
		t.Fatal("the evicted provider's refresh loop is still running")
	case <-time.After(200 * time.Millisecond):
	}

	_, err = registry.JWTBundles(ctx, testProviderArn)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(fetcher.Calls(testProviderArn)).To(Equal(2), "relearning the provider fetches it again")
}

func TestRegistry_ConcurrentLeasesReadsAndSweeps_AreRaceFree(t *testing.T) {
	g := NewWithT(t)
	arns := []string{testProviderArn, otherProviderArn}
	registry, _, clock := newLeaseTestRegistry(t, arns...)
	ctx := context.Background()

	var wg sync.WaitGroup
	for worker := range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 50 {
				arn := arns[(worker+i)%len(arns)]
				switch i % 4 {
				case 0:
					if release, err := registry.Lease(ctx, arn); err == nil {
						release()
					}
				case 1:
					_, _ = registry.JWTBundles(ctx, arn)
				case 2:
					clock.Advance(idleTTL)
					registry.sweep(ctx)
				default:
					_ = registry.OwnTrustDomain(arn)
				}
			}
		}()
	}
	wg.Wait()

	for _, arn := range arns {
		leases := registry.leasesFor(arn)
		g.Expect(leases == -1 || leases == 0).To(BeTrue(), "every lease was released: %s has %d", arn, leases)
	}
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

func TestRegistry_EveryRead_RestartsTheTTL(t *testing.T) {
	ctx := context.Background()
	for name, read := range map[string]func(*Registry){
		"X509Bundles":    func(r *Registry) { _, _ = r.X509Bundles(ctx, testProviderArn) },
		"JWTBundles":     func(r *Registry) { _, _ = r.JWTBundles(ctx, testProviderArn) },
		"OwnTrustDomain": func(r *Registry) { _ = r.OwnTrustDomain(testProviderArn) },
		"JWTAuthority":   func(r *Registry) { _, _ = r.JWTAuthority(testProviderArn, testDomain, "k1") },
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			registry, _, clock := newLeaseTestRegistry(t, testProviderArn)
			_, err := registry.JWTBundles(ctx, testProviderArn)
			g.Expect(err).ToNot(HaveOccurred())

			clock.Advance(50 * time.Minute)
			read(registry)
			clock.Advance(11 * time.Minute)
			registry.sweep(ctx)
			g.Expect(registry.entries).To(HaveKey(testProviderArn), "read 11 minutes ago")

			clock.Advance(idleTTL)
			registry.sweep(ctx)
			g.Expect(registry.entries).ToNot(HaveKey(testProviderArn))
		})
	}
}

func TestRegistry_IdleTTL_IsOneHourToTheMinute(t *testing.T) {
	g := NewWithT(t)
	registry, _, clock := newLeaseTestRegistry(t, testProviderArn)
	ctx := context.Background()
	_, err := registry.JWTBundles(ctx, testProviderArn)
	g.Expect(err).ToNot(HaveOccurred())

	clock.Advance(59 * time.Minute)
	registry.sweep(ctx)
	g.Expect(registry.entries).To(HaveKey(testProviderArn))
	clock.Advance(time.Minute)
	registry.sweep(ctx)
	g.Expect(registry.entries).ToNot(HaveKey(testProviderArn), "idle for exactly an hour is evicted")
}

func TestRegistry_Run_SweepsEveryFiveMinutes(t *testing.T) {
	g := NewWithT(t)
	registry, _, _ := newLeaseTestRegistry(t)
	requested := make(chan time.Duration, 4)
	registry.after = func(d time.Duration) <-chan time.Time {
		requested <- d
		return make(chan time.Time)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go registry.Run(ctx)

	g.Eventually(requested).Should(Receive(Equal(5 * time.Minute)))
}

func TestRegistry_Lease_NeverFetchesOrFailsForANamedProvider(t *testing.T) {
	g := NewWithT(t)
	fetcher := newProviderFetcher(map[string]func(int) ([]sts.TrustBundle, error){
		testProviderArn: sequence(fail(errors.New("STS is down"))),
	})
	registry, _ := newTestRegistry(t, fetcher)

	release, err := registry.Lease(context.Background(), testProviderArn)

	g.Expect(err).ToNot(HaveOccurred(), "an STS outage does not stop a stream opening")
	g.Expect(release).ToNot(BeNil())
	defer release()
	g.Consistently(func() int { return fetcher.Calls(testProviderArn) }, 100*time.Millisecond).Should(BeZero(),
		"a lease leaves fetching to the provider's loop and its reads")
}
