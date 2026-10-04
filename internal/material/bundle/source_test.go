package bundle

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity/fake"
)

// newTestSource builds one provider's source over fetcher with a fake Subscriber
// as its notifier, which is the T9 contract the tier signals through.
func newTestSource(t *testing.T, fetcher Fetcher) (*providerSource, *fake.Subscriber) {
	t.Helper()
	notifier := &fake.Subscriber{}
	return newProviderSource(testProviderArn, Opts{Fetcher: fetcher, Notifier: notifier}), notifier
}

// notifications is how many times each authority set's change was published.
type notifications struct{ x509, jwt int }

func notified(n *fake.Subscriber) notifications {
	return notifications{x509: n.CertBundleCalls(), jwt: n.JWTBundleCalls()}
}

// served decodes what JWTBundles returned for one domain.
func served(t *testing.T, jwks []byte) []map[string]any {
	t.Helper()
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		t.Fatalf("JWTBundles did not return a JWK Set: %v", err)
	}
	return set.Keys
}

func TestSource_Fetch_ReturnsAuthoritiesKeyedByTrustDomain(t *testing.T) {
	g := NewWithT(t)
	own, peer := newAuthority(t, "own"), newAuthority(t, "peer")
	ownJWT, peerJWT := newECKey(t), newECKey(t)
	fetcher := &fakeFetcher{respond: fixed(
		sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, own), jwtECKey(t, "own-1", ownJWT))},
		sts.TrustBundle{TrustDomain: peerDomain, Bundle: bundleDoc(t, 0, x509Key(t, peer), jwtECKey(t, "peer-1", peerJWT))},
	)}
	source, _ := newTestSource(t, fetcher)

	x509Bundles, err := source.X509Bundles(context.Background(), signTest)
	g.Expect(err).ToNot(HaveOccurred())
	jwtBundles, err := source.JWTBundles(context.Background(), signTest)
	g.Expect(err).ToNot(HaveOccurred())

	// every entry passes through under its own domain, and neither domain's
	// authorities are visible under the other
	g.Expect(rawBundles(x509Bundles)).To(Equal(map[string][][]byte{testDomain: {own.der}, peerDomain: {peer.der}}))
	g.Expect(jwtBundles).To(HaveLen(2))
	g.Expect(served(t, jwtBundles[testDomain])).To(ConsistOf(HaveKeyWithValue("kid", "own-1")))
	g.Expect(served(t, jwtBundles[peerDomain])).To(ConsistOf(HaveKeyWithValue("kid", "peer-1")))
	g.Expect(ownDomain(t, source)).To(Equal(testTrustDomain), "the first entry is the provider's own domain")
	g.Expect(jwtAuthority(t, source, peerDomain, "own-1")).To(BeNil(), "neither domain's keys answer for the other")
}

// ownDomain reads the source's own trust domain, failing the test on an error.
func ownDomain(t *testing.T, source *providerSource) spiffeid.TrustDomain {
	t.Helper()
	domain, err := source.OwnTrustDomain(context.Background(), signTest)
	if err != nil {
		t.Fatalf("OwnTrustDomain: %v", err)
	}
	return domain
}

// jwtAuthority looks a key up through the source's JWTSource, nil when the domain
// or the key is unknown.
func jwtAuthority(t *testing.T, source *providerSource, trustDomain, keyID string) crypto.PublicKey {
	t.Helper()
	jwt, err := source.JWTSource(context.Background(), signTest)
	if err != nil {
		t.Fatalf("JWTSource: %v", err)
	}
	bundle, err := jwt.GetJWTBundleForTrustDomain(spiffeid.RequireTrustDomainFromString(trustDomain))
	if err != nil {
		return nil
	}
	key, ok := bundle.FindJWTAuthority(keyID)
	if !ok {
		return nil
	}
	return key
}

func TestSource_OneFetch_BacksAllFourMethods(t *testing.T) {
	g := NewWithT(t)
	jwtKey := newECKey(t)
	fetcher := &fakeFetcher{respond: fixed(sts.TrustBundle{
		TrustDomain: testDomain,
		Bundle:      bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca")), jwtECKey(t, "k1", jwtKey)),
	})}
	source, _ := newTestSource(t, fetcher)
	ctx := context.Background()

	_, x509Err := source.X509Bundles(ctx, signTest)
	_, jwtErr := source.JWTBundles(ctx, signTest)
	_, sourceErr := source.JWTSource(ctx, signTest)
	own, ownErr := source.OwnTrustDomain(ctx, signTest)

	g.Expect([]error{x509Err, jwtErr, sourceErr, ownErr}).To(HaveEach(BeNil()))
	g.Expect(own).To(Equal(testTrustDomain))
	g.Expect(fetcher.Calls()).To(Equal(1))
	g.Expect(fetcher.creds).To(Equal([]aws.Credentials{testCreds}), "the fetch is signed with the reader's credentials")
}

func TestSource_DocumentWithBothKinds_RoutesEachKeyByUse(t *testing.T) {
	g := NewWithT(t)
	ca := newAuthority(t, "ca")
	ecKey, rsaKey := newECKey(t), newRSAKey(t)
	unknownUse := jwtECKey(t, "wit-1", newECKey(t))
	unknownUse["use"] = "wit-svid"
	doc := bundleDoc(t, 300, x509Key(t, ca), jwtECKey(t, "ec-1", ecKey), jwtRSAKey("rsa-1", rsaKey), unknownUse)
	source, _ := newTestSource(t, &fakeFetcher{respond: fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: doc})})
	ctx := context.Background()

	x509Bundles, err := source.X509Bundles(ctx, signTest)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(rawBundles(x509Bundles)[testDomain]).To(Equal([][]byte{ca.der}), "the x509-svid key's x5c certificate")

	jwtBundles, err := source.JWTBundles(ctx, signTest)
	g.Expect(err).ToNot(HaveOccurred())
	keys := served(t, jwtBundles[testDomain])
	g.Expect(keys).To(HaveLen(2), "only jwt-svid keys are served as JWT authorities")
	g.Expect(keys).To(ContainElement(HaveKeyWithValue("kid", "ec-1")))
	g.Expect(keys).To(ContainElement(HaveKeyWithValue("kid", "rsa-1")))
	for _, key := range keys {
		g.Expect(key).ToNot(HaveKey("use"), "jwt-svid is not an RFC 7517 use value, so it is not served")
		g.Expect(key).ToNot(HaveKey("x5c"))
	}
	g.Expect(string(jwtBundles[testDomain])).ToNot(ContainSubstring("spiffe_refresh_hint"))

	g.Expect(ecKey.PublicKey.Equal(jwtAuthority(t, source, testDomain, "ec-1"))).To(BeTrue())
	g.Expect(rsaKey.PublicKey.Equal(jwtAuthority(t, source, testDomain, "rsa-1"))).To(BeTrue())
	g.Expect(jwtAuthority(t, source, testDomain, "wit-1")).To(BeNil(), "a key with an unknown use is ignored")

	// the hint is kept for the refresh loop and is not on the interface
	g.Expect(source.current.Load().refreshHint).To(Equal(300 * time.Second))
	g.Expect(source.refreshInterval()).To(Equal(300 * time.Second))
}

func TestSource_JWTSource_DomainWithOnlyX509Authorities_IsUnknownToIt(t *testing.T) {
	g := NewWithT(t)
	source, _ := newTestSource(t, &fakeFetcher{respond: fixed(
		sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, jwtECKey(t, "k1", newECKey(t)))},
		sts.TrustBundle{TrustDomain: peerDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "peer")))},
	)})
	jwtBundles, err := source.JWTBundles(context.Background(), signTest)
	g.Expect(err).ToNot(HaveOccurred())
	jwt, err := source.JWTSource(context.Background(), signTest)
	g.Expect(err).ToNot(HaveOccurred())

	_, err = jwt.GetJWTBundleForTrustDomain(spiffeid.RequireTrustDomainFromString(peerDomain))

	g.Expect(jwtBundles).ToNot(HaveKey(peerDomain))
	g.Expect(err).To(HaveOccurred(), "JWTSource and JWTBundles agree on which JWT domains exist")
}

func TestSource_Refresh_ReorderedOrReformattedAuthorities_DoNotSignal(t *testing.T) {
	g := NewWithT(t)
	caA, caB := newAuthority(t, "a"), newAuthority(t, "b")
	k1, k2 := jwtECKey(t, "k1", newECKey(t)), jwtRSAKey("k2", newRSAKey(t))
	first := sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 300, x509Key(t, caA), x509Key(t, caB), k1, k2)}
	reordered := sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 120, k2, x509Key(t, caB), k1, x509Key(t, caA))}
	reformatted := sts.TrustBundle{TrustDomain: testDomain, Bundle: indentedBundleDoc(t, 600, x509Key(t, caA), x509Key(t, caB), k1, k2)}
	fetcher := &fakeFetcher{respond: sequence(ok(first), ok(reformatted), ok(reordered))}
	source, notifier := newTestSource(t, fetcher)
	ctx := context.Background()
	changesBefore := testutil.ToFloat64(promBundleChangeTotal)

	g.Expect(refreshOnce(source, ctx)).To(Succeed())
	servedBefore, _ := source.JWTBundles(ctx, signTest)
	x509Before, _ := source.X509Bundles(ctx, signTest)
	g.Expect(rawBundles(x509Before)[testDomain]).To(Equal(sortedDER(caA.der, caB.der)), "every authority is served, not only the newest, sorted by DER")
	x509Again, _ := source.X509Bundles(ctx, signTest)
	g.Expect(rawBundles(x509Again)).To(Equal(rawBundles(x509Before)), "every read serves the same order")
	g.Expect(refreshOnce(source, ctx)).To(Succeed())
	g.Expect(refreshOnce(source, ctx)).To(Succeed())
	x509After, _ := source.X509Bundles(ctx, signTest)
	g.Expect(rawBundles(x509After)).To(Equal(rawBundles(x509Before)), "an unchanged set keeps serving the order it already served")

	g.Expect(fetcher.Calls()).To(Equal(3))
	g.Expect(notified(notifier)).To(Equal(notifications{}))
	g.Expect(testutil.ToFloat64(promBundleChangeTotal)).To(Equal(changesBefore))
	servedAfter, _ := source.JWTBundles(ctx, signTest)
	g.Expect(servedAfter).To(Equal(servedBefore), "the JWT set is unchanged")
	g.Expect(source.refreshInterval()).To(Equal(120*time.Second), "the hint still follows the latest document")
}

func TestSource_Refresh_ChangedAuthorities_NotifyEachChangedSetOnce(t *testing.T) {
	ca := newAuthority(t, "ca")
	k1 := jwtECKey(t, "k1", newECKey(t))
	base := sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, ca), k1)}

	for name, tc := range map[string]struct {
		changed sts.TrustBundle
		want    notifications
	}{
		"a jwt-svid key added":   {sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, ca), k1, jwtECKey(t, "k2", newECKey(t)))}, notifications{jwt: 1}},
		"a jwt-svid key rotated": {sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, ca), jwtECKey(t, "k1", newECKey(t)))}, notifications{jwt: 1}},
		"an x509-svid key added": {sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, ca), x509Key(t, newAuthority(t, "next")), k1)}, notifications{x509: 1}},
		"an x509-svid key gone":  {sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, k1)}, notifications{x509: 1}},
		"both sets rotated":      {sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "next")), jwtECKey(t, "k2", newECKey(t)))}, notifications{x509: 1, jwt: 1}},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			fetcher := &fakeFetcher{respond: sequence(ok(base), ok(tc.changed), ok(tc.changed))}
			source, notifier := newTestSource(t, fetcher)
			ctx := context.Background()
			changesBefore := testutil.ToFloat64(promBundleChangeTotal)

			g.Expect(refreshOnce(source, ctx)).To(Succeed())
			g.Expect(notified(notifier)).To(Equal(notifications{}), "the first bundle is not a change")
			g.Expect(refreshOnce(source, ctx)).To(Succeed())
			g.Expect(refreshOnce(source, ctx)).To(Succeed())

			g.Expect(notified(notifier)).To(Equal(tc.want))
			g.Expect(testutil.ToFloat64(promBundleChangeTotal)).To(Equal(changesBefore + 1))
		})
	}
}

func TestSource_Refresh_ChangedDomainSet_Signals(t *testing.T) {
	g := NewWithT(t)
	k1 := jwtECKey(t, "k1", newECKey(t))
	own := sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, k1)}
	peer := sts.TrustBundle{TrustDomain: peerDomain, Bundle: bundleDoc(t, 0, k1)}
	fetcher := &fakeFetcher{respond: sequence(ok(own), ok(own, peer), ok(peer, own))}
	source, notifier := newTestSource(t, fetcher)
	ctx := context.Background()

	g.Expect(refreshOnce(source, ctx)).To(Succeed())
	g.Expect(refreshOnce(source, ctx)).To(Succeed())
	g.Expect(notified(notifier)).To(Equal(notifications{jwt: 1}), "a new trust domain with only jwt-svid keys is a JWT change")

	// the same authorities with the other domain first changes which one is the
	// workload's own, which only the X.509 streams split on
	g.Expect(refreshOnce(source, ctx)).To(Succeed())
	g.Expect(notified(notifier)).To(Equal(notifications{x509: 1, jwt: 1}))
	g.Expect(ownDomain(t, source)).To(Equal(peerTrustDomain))
}

func TestSource_FailedRefresh_KeepsServingTheLastGoodBundle(t *testing.T) {
	ca := newAuthority(t, "ca")
	key := newECKey(t)
	good := sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, ca), jwtECKey(t, "k1", key))}

	for name, failure := range map[string]func() ([]sts.TrustBundle, error){
		"STS error":                  fail(errors.New("throttled")),
		"no entries":                 ok(),
		"empty document":             ok(sts.TrustBundle{TrustDomain: testDomain, Bundle: ""}),
		"unparseable document":       ok(sts.TrustBundle{TrustDomain: testDomain, Bundle: "{not json"}),
		"document with no authority": ok(sts.TrustBundle{TrustDomain: testDomain, Bundle: `{"keys":[]}`}),
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			fetcher := &fakeFetcher{respond: sequence(ok(good), failure)}
			source, notifier := newTestSource(t, fetcher)
			ctx := context.Background()
			g.Expect(refreshOnce(source, ctx)).To(Succeed())
			failuresBefore := testutil.ToFloat64(promBundleFetchTotal.WithLabelValues(workloadidentity.OutcomeFailure, "bundle_unavailable"))

			err := refreshOnce(source, ctx)

			g.Expect(err).To(MatchError(wierrors.ErrBundleUnavailable))
			g.Expect(wierrors.IsRetryable(err)).To(BeTrue())
			g.Expect(testutil.ToFloat64(promBundleFetchTotal.WithLabelValues(workloadidentity.OutcomeFailure, "bundle_unavailable"))).
				To(Equal(failuresBefore + 1))
			x509Bundles, err := source.X509Bundles(ctx, signTest)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(rawBundles(x509Bundles)).To(Equal(map[string][][]byte{testDomain: {ca.der}}))
			g.Expect(key.PublicKey.Equal(jwtAuthority(t, source, testDomain, "k1"))).To(BeTrue())
			g.Expect(ownDomain(t, source)).To(Equal(testTrustDomain))
			g.Expect(notified(notifier)).To(Equal(notifications{}))
			g.Expect(fetcher.Calls()).To(Equal(2), "the served value came from the cache, not a new fetch")
		})
	}
}

func TestSource_FirstReadFailure_IsAnErrorNotAnEmptyBundle(t *testing.T) {
	for name, tc := range map[string]struct {
		response func() ([]sts.TrustBundle, error)
		reason   string
	}{
		"STS error":                  {fail(errors.New("unavailable")), "unavailable"},
		"no entries":                 {ok(), "holds no trust bundle"},
		"document with no authority": {ok(sts.TrustBundle{TrustDomain: testDomain, Bundle: `{"keys":[]}`}), "no x509-svid or jwt-svid authority"},
		"malformed x509-svid key":    {ok(sts.TrustBundle{TrustDomain: testDomain, Bundle: `{"keys":[{"use":"x509-svid"}]}`}), "will not serve"},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			fetcher := &fakeFetcher{respond: sequence(tc.response, ok(sts.TrustBundle{
				TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca"))),
			}))}
			source, _ := newTestSource(t, fetcher)
			clock := time.Now()
			source.now = func() time.Time { return clock }

			bundles, err := source.X509Bundles(context.Background(), signTest)
			g.Expect(err).To(MatchError(wierrors.ErrBundleUnavailable))
			g.Expect(err).To(MatchError(ContainSubstring(tc.reason)))
			g.Expect(bundles).To(BeNil())
			_, err = source.OwnTrustDomain(context.Background(), signTest)
			g.Expect(err).To(MatchError(ContainSubstring(tc.reason)))

			// inside the backoff a read gets the same failure without calling STS
			_, err = source.JWTBundles(context.Background(), signTest)
			g.Expect(err).To(MatchError(ContainSubstring(tc.reason)))
			g.Expect(fetcher.Calls()).To(Equal(1))

			// nothing was cached, so once the backoff has passed a read fetches
			// again and succeeds
			clock = clock.Add(retryMaxDelay)
			bundles, err = source.X509Bundles(context.Background(), signTest)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(rawBundles(bundles)).To(HaveKey(testDomain))
			g.Expect(fetcher.Calls()).To(Equal(2))
		})
	}
}

func TestSource_FirstReadBackoff_FollowsConsecutiveFailures(t *testing.T) {
	g := NewWithT(t)
	fetcher := &fakeFetcher{respond: fixed()}
	source, _ := newTestSource(t, fetcher)
	source.jitter = func() float64 { return 0 }
	clock := time.Now()
	source.now = func() time.Time { return clock }
	ctx := context.Background()

	// each failure pushes the next permitted fetch out along the backoff
	for _, wait := range []time.Duration{
		10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second,
		160 * time.Second, 320 * time.Second, 10 * time.Minute, 10 * time.Minute,
	} {
		calls := fetcher.Calls()
		_, err := source.X509Bundles(ctx, signTest)
		g.Expect(err).To(HaveOccurred())
		g.Expect(fetcher.Calls()).To(Equal(calls + 1))

		clock = clock.Add(wait - time.Millisecond)
		_, err = source.X509Bundles(ctx, signTest)
		g.Expect(err).To(HaveOccurred())
		g.Expect(fetcher.Calls()).To(Equal(calls+1), "still inside the %s backoff", wait)
		clock = clock.Add(time.Millisecond)
	}
}

func TestSource_RefreshLoopFailure_AlsoHoldsOffFirstReads(t *testing.T) {
	g := NewWithT(t)
	fetcher := &fakeFetcher{respond: fixed()}
	source, _ := newTestSource(t, fetcher)
	clock := time.Now()
	source.now = func() time.Time { return clock }

	g.Expect(refreshOnce(source, context.Background())).ToNot(Succeed())
	_, err := source.X509Bundles(context.Background(), signTest)

	g.Expect(err).To(MatchError(wierrors.ErrBundleUnavailable))
	g.Expect(fetcher.Calls()).To(Equal(1), "a first read inside the loop's backoff does not call STS")
}

func TestSource_ConcurrentFailingFirstReads_ShareOneFetch(t *testing.T) {
	g := NewWithT(t)
	fetcher := &fakeFetcher{
		respond: fixed(),
		gate:    make(chan struct{}),
		entered: make(chan struct{}, 16),
	}
	source, _ := newTestSource(t, fetcher)

	const readers = 8
	var wg sync.WaitGroup
	errs := make(chan error, readers)
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := source.X509Bundles(context.Background(), signTest)
			errs <- err
		}()
	}
	<-fetcher.entered
	close(fetcher.gate)
	wg.Wait()
	close(errs)

	for err := range errs {
		g.Expect(err).To(MatchError(wierrors.ErrBundleUnavailable))
	}
	g.Expect(fetcher.Calls()).To(Equal(1))
}

func TestSource_SharedFirstFetch_SurvivesTheReaderThatStartedIt(t *testing.T) {
	g := NewWithT(t)
	fetcher := &fakeFetcher{
		respond: fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca")))}),
		gate:    make(chan struct{}),
		entered: make(chan struct{}, 2),
	}
	source, _ := newTestSource(t, fetcher)
	failure := promBundleFetchTotal.WithLabelValues(workloadidentity.OutcomeFailure, "bundle_unavailable")
	failuresBefore := testutil.ToFloat64(failure)

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() {
		_, err := source.X509Bundles(firstCtx, signTest)
		firstDone <- err
	}()
	<-fetcher.entered
	secondDone := make(chan error, 1)
	go func() {
		_, err := source.JWTBundles(context.Background(), signTest)
		secondDone <- err
	}()

	// the reader holding the fetch goes away while the call is in flight
	cancelFirst()
	close(fetcher.gate)

	g.Expect(<-firstDone).ToNot(HaveOccurred())
	g.Expect(<-secondDone).ToNot(HaveOccurred())
	g.Expect(fetcher.Calls()).To(Equal(1))
	g.Expect(testutil.ToFloat64(failure)).To(Equal(failuresBefore))
}

func TestSource_ReaderWhoseContextIsDone_NeverFetches(t *testing.T) {
	g := NewWithT(t)
	fetcher := &fakeFetcher{respond: fixed()}
	source, _ := newTestSource(t, fetcher)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for range 100 {
		_, err := source.X509Bundles(ctx, signTest)
		g.Expect(err).To(MatchError(context.Canceled))
	}

	g.Expect(fetcher.Calls()).To(BeZero())
}

func TestSource_Refusal_IsNotRetryableAndLabelledApart(t *testing.T) {
	for code, expected := range map[string]*wierrors.WorkloadIdentityError{
		"ResourceNotFoundException": wierrors.ErrBundleRefused,
		"AccessDenied":              wierrors.ErrBundleRefused,
		"AccessDeniedException":     wierrors.ErrBundleRefused,
		"ValidationError":           wierrors.ErrBundleRefused,
		"InvalidAction":             wierrors.ErrBundleRefused,
		"Throttling":                wierrors.ErrBundleUnavailable,
		"ExpiredToken":              wierrors.ErrBundleUnavailable,
		"InternalFailure":           wierrors.ErrBundleUnavailable,
	} {
		t.Run(code, func(t *testing.T) {
			g := NewWithT(t)
			apiErr := &smithy.GenericAPIError{Code: code, Message: "no", Fault: smithy.FaultClient}
			fetcher := &fakeFetcher{respond: sequence(fail(&smithy.OperationError{ServiceID: "STS", OperationName: "GetTrustBundles", Err: apiErr}))}
			source, _ := newTestSource(t, fetcher)
			counter := promBundleFetchTotal.WithLabelValues(workloadidentity.OutcomeFailure, expected.MetricLabel())
			before := testutil.ToFloat64(counter)

			err := refreshOnce(source, context.Background())

			g.Expect(err).To(MatchError(expected))
			g.Expect(wierrors.IsRetryable(err)).To(Equal(expected.Retryable()))
			g.Expect(testutil.ToFloat64(counter)).To(Equal(before + 1))
			var unwrapped smithy.APIError
			g.Expect(errors.As(err, &unwrapped)).To(BeTrue(), "the STS error stays in the chain")
		})
	}
}

func TestSource_ConcurrentFirstReads_ShareOneFetch(t *testing.T) {
	g := NewWithT(t)
	fetcher := &fakeFetcher{
		respond: fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca")))}),
		gate:    make(chan struct{}),
		entered: make(chan struct{}, 16),
	}
	source, _ := newTestSource(t, fetcher)

	const readers = 8
	var wg sync.WaitGroup
	errs := make(chan error, readers)
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := source.X509Bundles(context.Background(), signTest)
			errs <- err
		}()
	}
	<-fetcher.entered
	close(fetcher.gate)
	wg.Wait()
	close(errs)

	for err := range errs {
		g.Expect(err).ToNot(HaveOccurred())
	}
	g.Expect(fetcher.Calls()).To(Equal(1))
}

func TestSource_ReaderWaitingOnAFetch_GivesUpWithItsContext(t *testing.T) {
	g := NewWithT(t)
	fetcher := &fakeFetcher{
		respond: fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca")))}),
		gate:    make(chan struct{}),
		entered: make(chan struct{}, 1),
	}
	source, _ := newTestSource(t, fetcher)
	go func() { _, _ = source.X509Bundles(context.Background(), signTest) }()
	<-fetcher.entered

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := source.JWTBundles(ctx, signTest)

	g.Expect(err).To(MatchError(wierrors.ErrBundleUnavailable))
	g.Expect(err).To(MatchError(context.Canceled))
	close(fetcher.gate)
}

func TestSource_ReturnedValues_AreCopies(t *testing.T) {
	g := NewWithT(t)
	ca, other := newAuthority(t, "ca"), newAuthority(t, "other")
	source, _ := newTestSource(t, &fakeFetcher{respond: fixed(sts.TrustBundle{
		TrustDomain: testDomain,
		Bundle:      bundleDoc(t, 0, x509Key(t, ca), jwtECKey(t, "k1", newECKey(t))),
	})})
	ctx := context.Background()
	expected := map[string][][]byte{testDomain: {ca.der}}
	own := func(set *x509bundle.Set) *x509bundle.Bundle {
		bundle, found := set.Get(testTrustDomain)
		g.Expect(found).To(BeTrue())
		return bundle
	}

	// every change a caller can make to the set or a bundle in it
	for name, mutate := range map[string]func(*x509bundle.Set){
		"bundle added": func(set *x509bundle.Set) {
			set.Add(x509bundle.FromX509Authorities(peerTrustDomain, []*x509.Certificate{other.cert}))
		},
		"bundle replaced":      func(set *x509bundle.Set) { set.Add(x509bundle.New(testTrustDomain)) },
		"bundle removed":       func(set *x509bundle.Set) { set.Remove(testTrustDomain) },
		"authority added":      func(set *x509bundle.Set) { own(set).AddX509Authority(other.cert) },
		"authority removed":    func(set *x509bundle.Set) { own(set).RemoveX509Authority(ca.cert) },
		"authorities replaced": func(set *x509bundle.Set) { own(set).SetX509Authorities([]*x509.Certificate{other.cert}) },
	} {
		x509Bundles, err := source.X509Bundles(ctx, signTest)
		g.Expect(err).ToNot(HaveOccurred())
		mutate(x509Bundles)
		g.Expect(rawBundles(x509Bundles)).ToNot(Equal(expected), "%s changed what the caller got", name)

		again, err := source.X509Bundles(ctx, signTest)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(rawBundles(again)).To(Equal(expected), "%s did not reach the tier", name)
	}

	jwtBundles, _ := source.JWTBundles(ctx, signTest)
	jwtBundles[testDomain][0] = 'X'
	jwtAgain, _ := source.JWTBundles(ctx, signTest)
	g.Expect(served(t, jwtAgain[testDomain])).To(HaveLen(1))
}

func TestSource_Fetch_RecordsOutcomeMetrics(t *testing.T) {
	g := NewWithT(t)
	fetcher := &fakeFetcher{respond: sequence(
		ok(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca")))}),
		fail(errors.New("boom")),
	)}
	source, _ := newTestSource(t, fetcher)
	success := promBundleFetchTotal.WithLabelValues(workloadidentity.OutcomeSuccess, wierrors.MetricLabelNone)
	failure := promBundleFetchTotal.WithLabelValues(workloadidentity.OutcomeFailure, "bundle_unavailable")
	successBefore, failureBefore := testutil.ToFloat64(success), testutil.ToFloat64(failure)

	g.Expect(refreshOnce(source, context.Background())).To(Succeed())
	g.Expect(refreshOnce(source, context.Background())).ToNot(Succeed())

	g.Expect(testutil.ToFloat64(success)).To(Equal(successBefore + 1))
	g.Expect(testutil.ToFloat64(failure)).To(Equal(failureBefore + 1))
	g.Expect(testutil.CollectAndCount(promBundleFetchDuration, workloadidentity.MetricBundleFetchDuration)).To(Equal(2),
		"one latency series per outcome")
}

func TestSource_RefreshInterval_FollowsTheHintWithinBounds(t *testing.T) {
	for name, tc := range map[string]struct {
		hintSeconds int
		expected    time.Duration
	}{
		"hint":                   {hintSeconds: 300, expected: 300 * time.Second},
		"no hint":                {expected: defaultRefreshInterval},
		"hint below the floor":   {hintSeconds: 1, expected: minRefreshInterval},
		"hint above the ceiling": {hintSeconds: 7 * 24 * 3600, expected: maxRefreshInterval},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			source := newProviderSource(testProviderArn, Opts{
				Fetcher: &fakeFetcher{respond: fixed(sts.TrustBundle{
					TrustDomain: testDomain,
					Bundle:      bundleDoc(t, tc.hintSeconds, x509Key(t, newAuthority(t, "ca"))),
				})},
				Notifier: &fake.Subscriber{},
			})
			g.Expect(refreshOnce(source, context.Background())).To(Succeed())

			g.Expect(source.refreshInterval()).To(Equal(tc.expected))
		})
	}
}

func TestSource_RefreshInterval_TakesTheShortestHintAcrossDomains(t *testing.T) {
	g := NewWithT(t)
	source, _ := newTestSource(t, &fakeFetcher{respond: fixed(
		sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 900, x509Key(t, newAuthority(t, "a")))},
		sts.TrustBundle{TrustDomain: peerDomain, Bundle: bundleDoc(t, 120, x509Key(t, newAuthority(t, "b")))},
	)})

	g.Expect(refreshOnce(source, context.Background())).To(Succeed())

	g.Expect(source.refreshInterval()).To(Equal(120 * time.Second))
}

func TestSource_RefreshInterval_ADomainWithoutAHint_DoesNotShortenIt(t *testing.T) {
	hinted := sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 900, x509Key(t, newAuthority(t, "a")))}
	hintless := sts.TrustBundle{TrustDomain: peerDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "b")))}
	for name, entries := range map[string][]sts.TrustBundle{
		"hintless first": {hintless, hinted},
		"hintless last":  {hinted, hintless},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			source, _ := newTestSource(t, &fakeFetcher{respond: fixed(entries...)})

			g.Expect(refreshOnce(source, context.Background())).To(Succeed())

			g.Expect(source.refreshInterval()).To(Equal(900 * time.Second))
		})
	}
}

func TestSource_Delays_AreJitteredShorterAndBackOff(t *testing.T) {
	g := NewWithT(t)
	source, _ := newTestSource(t, &fakeFetcher{respond: fixed()})

	source.jitter = func() float64 { return 0 }
	g.Expect(source.refreshDelay()).To(Equal(defaultRefreshInterval))
	g.Expect([]time.Duration{
		source.retryDelay(1), source.retryDelay(2), source.retryDelay(3), source.retryDelay(4),
		source.retryDelay(5), source.retryDelay(6), source.retryDelay(7), source.retryDelay(50),
	}).To(Equal([]time.Duration{
		10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second,
		160 * time.Second, 320 * time.Second, 10 * time.Minute, 10 * time.Minute,
	}))

	// jitter only ever shortens, so the tier never polls later than asked
	source.jitter = func() float64 { return 0.999999 }
	g.Expect(source.refreshDelay()).To(BeNumerically("<", defaultRefreshInterval))
	g.Expect(source.retryDelay(1)).To(BeNumerically("<", retryBaseDelay))
	g.Expect(source.retryDelay(1)).To(BeNumerically(">=", time.Duration(float64(retryBaseDelay)*(1-refreshJitter))))
	g.Expect(source.refreshDelay()).To(BeNumerically(">=", time.Duration(float64(defaultRefreshInterval)*(1-refreshJitter))))
}

func TestSource_Fetch_IsBoundedByTheFetchTimeout(t *testing.T) {
	g := NewWithT(t)
	fetcher := &fakeFetcher{respond: fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca")))})}
	source, _ := newTestSource(t, fetcher)

	before := time.Now()
	_, err := source.X509Bundles(context.Background(), signTest)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(refreshOnce(source, context.Background())).To(Succeed())

	// the first read's fetch is detached from its caller, so this deadline is the
	// only thing that bounds it
	for _, deadline := range fetcher.deadlines {
		g.Expect(deadline).ToNot(BeZero())
		g.Expect(deadline).To(BeTemporally("<=", time.Now().Add(fetchTimeout)))
		g.Expect(deadline).To(BeTemporally(">=", before.Add(fetchTimeout)))
	}
	g.Expect(fetcher.deadlines).To(HaveLen(2))
}

func TestSource_ReaderCancelledWhileWaiting_GivesUp(t *testing.T) {
	g := NewWithT(t)
	fetcher := &fakeFetcher{
		respond: fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca")))}),
		gate:    make(chan struct{}),
		entered: make(chan struct{}, 1),
	}
	source, _ := newTestSource(t, fetcher)
	go func() { _, _ = source.X509Bundles(context.Background(), signTest) }()
	<-fetcher.entered

	ctx, cancel := context.WithCancel(context.Background())
	waiting := make(chan error, 1)
	go func() {
		_, err := source.JWTBundles(ctx, signTest)
		waiting <- err
	}()
	g.Consistently(waiting, 50*time.Millisecond).ShouldNot(Receive(), "the reader is queued behind the fetch in flight")
	cancel()

	g.Eventually(waiting).Should(Receive(MatchError(context.Canceled)))
	close(fetcher.gate)
}

func TestSource_X509Bundles_OmitsADomainWithNoX509Authority(t *testing.T) {
	g := NewWithT(t)
	source, _ := newTestSource(t, &fakeFetcher{respond: fixed(
		sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca")))},
		sts.TrustBundle{TrustDomain: peerDomain, Bundle: bundleDoc(t, 0, jwtECKey(t, "k1", newECKey(t)))},
	)})

	x509Bundles, err := source.X509Bundles(context.Background(), signTest)
	g.Expect(err).ToNot(HaveOccurred())
	jwtBundles, err := source.JWTBundles(context.Background(), signTest)
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(rawBundles(x509Bundles)).To(HaveKey(testDomain))
	g.Expect(rawBundles(x509Bundles)).ToNot(HaveKey(peerDomain))
	g.Expect(jwtBundles).To(HaveKey(peerDomain))
	g.Expect(jwtBundles).ToNot(HaveKey(testDomain))
}

func TestSource_DueAt_FollowsTheIntervalAfterASuccessAndTheBackoffAfterAFailure(t *testing.T) {
	g := NewWithT(t)
	fetcher := &fakeFetcher{respond: sequence(
		ok(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 120, x509Key(t, newAuthority(t, "ca")))}),
		fail(errors.New("unavailable")),
		fail(errors.New("unavailable")),
		ok(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 120, x509Key(t, newAuthority(t, "ca")))}),
		fail(errors.New("unavailable")),
	)}
	source, _ := newTestSource(t, fetcher)
	clock := time.Now()
	source.now = func() time.Time { return clock }
	source.jitter = func() float64 { return 0 }
	ctx := context.Background()

	g.Expect(source.dueAt().After(clock)).To(BeFalse(), "a source nothing has fetched for is due at once")
	g.Expect(refreshOnce(source, ctx)).To(Succeed())
	g.Expect(source.dueAt()).To(BeTemporally("==", clock.Add(120*time.Second)), "a success waits for the hint")

	clock = clock.Add(120 * time.Second)
	g.Expect(refreshOnce(source, ctx)).ToNot(Succeed())
	g.Expect(source.dueAt()).To(BeTemporally("==", clock.Add(retryBaseDelay)), "a failure retries on the backoff")
	clock = clock.Add(retryBaseDelay)
	g.Expect(refreshOnce(source, ctx)).ToNot(Succeed())
	g.Expect(source.dueAt()).To(BeTemporally("==", clock.Add(2*retryBaseDelay)), "consecutive failures back off further")

	clock = clock.Add(2 * retryBaseDelay)
	g.Expect(refreshOnce(source, ctx)).To(Succeed())
	g.Expect(source.dueAt()).To(BeTemporally("==", clock.Add(120*time.Second)))

	clock = clock.Add(120 * time.Second)
	g.Expect(refreshOnce(source, ctx)).ToNot(Succeed())
	g.Expect(source.dueAt()).To(BeTemporally("==", clock.Add(retryBaseDelay)), "a success resets the backoff")
}

func TestSource_ReaderThatCannotSign_GetsItsOwnErrorAndStartsNoBackoff(t *testing.T) {
	g := NewWithT(t)
	fetcher := &fakeFetcher{respond: fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca")))})}
	source, _ := newTestSource(t, fetcher)
	ctx := context.Background()
	cannotSign := func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{}, wierrors.ErrSessionUnavailable
	}

	_, err := source.X509Bundles(ctx, cannotSign)
	g.Expect(err).To(MatchError(wierrors.ErrSessionUnavailable))
	g.Expect(fetcher.Calls()).To(BeZero())

	_, err = source.X509Bundles(ctx, signTest)
	g.Expect(err).ToNot(HaveOccurred(), "the next reader is not held off")
	g.Expect(fetcher.Calls()).To(Equal(1))
}

func TestSource_RefreshAndRecordFailure_OvertakenByAnotherFetch_DoNothing(t *testing.T) {
	g := NewWithT(t)
	fetcher := &fakeFetcher{respond: fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca")))})}
	source, _ := newTestSource(t, fetcher)
	ctx := context.Background()
	// the refresher sees the new source due, and a first read fetches before it runs
	seen := source.dueAt()
	_, err := source.X509Bundles(ctx, signTest)
	g.Expect(err).ToNot(HaveOccurred())
	scheduled := source.dueAt()

	g.Expect(source.refresh(ctx, testCreds, seen)).To(Succeed())
	source.recordFailure(ctx, errors.New("no session to sign with"), seen)

	g.Expect(fetcher.Calls()).To(Equal(1), "learning a provider costs one call")
	g.Expect(source.dueAt()).To(BeTemporally("==", scheduled), "a stale failure does not pull the schedule in")
	_, err = source.X509Bundles(ctx, signTest)
	g.Expect(err).ToNot(HaveOccurred())
}

// notifyFunc is a BundleNotifier that runs a function on either change.
type notifyFunc func()

func (f notifyFunc) NotifyCertBundleChange(string) { f() }
func (f notifyFunc) NotifyJWTBundleChange(string)  { f() }

func TestSource_Broadcast_ComesAfterTheNewBundleIsServed(t *testing.T) {
	g := NewWithT(t)
	k1 := jwtECKey(t, "k1", newECKey(t))
	fetcher := &fakeFetcher{respond: sequence(
		ok(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, k1)}),
		ok(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, k1, jwtECKey(t, "k2", newECKey(t)))}),
	)}
	source, _ := newTestSource(t, fetcher)
	var keysOnWake []int
	// a stream woken by the signal reads the bundle again
	source.notifier = notifyFunc(func() {
		jwks, err := source.JWTBundles(context.Background(), signTest)
		g.Expect(err).ToNot(HaveOccurred())
		keysOnWake = append(keysOnWake, len(served(t, jwks[testDomain])))
	})
	ctx := context.Background()

	g.Expect(refreshOnce(source, ctx)).To(Succeed())
	g.Expect(refreshOnce(source, ctx)).To(Succeed())

	g.Expect(keysOnWake).To(Equal([]int{2}), "the woken stream reads the new set, not the one it replaced")
}

func TestSource_Refresh_InsideAReadsBackoff_DoesNotFetch(t *testing.T) {
	g := NewWithT(t)
	fetcher := &fakeFetcher{respond: fixed()}
	source, _ := newTestSource(t, fetcher)
	clock := time.Now()
	source.now = func() time.Time { return clock }
	_, err := source.JWTBundles(context.Background(), signTest)
	g.Expect(err).To(HaveOccurred())

	err = refreshOnce(source, context.Background())

	g.Expect(err).To(MatchError(wierrors.ErrBundleUnavailable))
	g.Expect(fetcher.Calls()).To(Equal(1), "the refresher and reads share one backoff")
}

func TestSource_Refresh_ItsOwnCancellation_IsNotServedToALiveReader(t *testing.T) {
	g := NewWithT(t)
	fetcher := &fakeFetcher{
		respond: sequence(
			fail(errors.New("unreachable")),
			ok(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca")))}),
		),
		gate:    make(chan struct{}),
		entered: make(chan struct{}, 2),
	}
	source, _ := newTestSource(t, fetcher)
	refreshCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- source.refresh(refreshCtx, testCreds, source.dueAt()) }()
	<-fetcher.entered

	// the refresher stops while its fetch is in flight
	cancel()
	g.Eventually(done).Should(Receive(HaveOccurred()))
	close(fetcher.gate)

	bundles, err := source.X509Bundles(context.Background(), signTest)

	g.Expect(err).ToNot(HaveOccurred(), "a live reader fetches for itself rather than being handed the cancellation")
	g.Expect(rawBundles(bundles)).To(HaveKey(testDomain))
	g.Expect(fetcher.Calls()).To(Equal(2))
}
