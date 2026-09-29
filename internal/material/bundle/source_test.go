package bundle

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aws/smithy-go"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"

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

	x509Bundles, err := source.X509Bundles(context.Background())
	g.Expect(err).ToNot(HaveOccurred())
	jwtBundles, err := source.JWTBundles(context.Background())
	g.Expect(err).ToNot(HaveOccurred())

	// every entry passes through under its own domain, and neither domain's
	// authorities are visible under the other
	g.Expect(x509Bundles).To(Equal(map[string][][]byte{testDomain: {own.der}, peerDomain: {peer.der}}))
	g.Expect(jwtBundles).To(HaveLen(2))
	g.Expect(served(t, jwtBundles[testDomain])).To(ConsistOf(HaveKeyWithValue("kid", "own-1")))
	g.Expect(served(t, jwtBundles[peerDomain])).To(ConsistOf(HaveKeyWithValue("kid", "peer-1")))
	g.Expect(source.OwnTrustDomain()).To(Equal(testDomain), "the first entry is the provider's own domain")
	_, err = source.JWTAuthority(peerDomain, "own-1")
	g.Expect(err).To(MatchError(wierrors.ErrUnknownKeyID))
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

	_, x509Err := source.X509Bundles(ctx)
	_, jwtErr := source.JWTBundles(ctx)
	_, authorityErr := source.JWTAuthority(testDomain, "k1")
	own := source.OwnTrustDomain()

	g.Expect(x509Err).ToNot(HaveOccurred())
	g.Expect(jwtErr).ToNot(HaveOccurred())
	g.Expect(authorityErr).ToNot(HaveOccurred())
	g.Expect(own).To(Equal(testDomain))
	g.Expect(fetcher.Calls()).To(Equal(1))
}

func TestSource_ContextFreeMethods_NeverFetch(t *testing.T) {
	g := NewWithT(t)
	fetcher := &fakeFetcher{respond: fixed()}
	source, _ := newTestSource(t, fetcher)

	g.Expect(source.OwnTrustDomain()).To(BeEmpty())
	_, err := source.JWTAuthority(testDomain, "k1")

	g.Expect(err).To(MatchError(wierrors.ErrBundleUnavailable))
	g.Expect(fetcher.Calls()).To(BeZero())
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

	x509Bundles, err := source.X509Bundles(ctx)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(x509Bundles[testDomain]).To(Equal([][]byte{ca.der}), "the x509-svid key's x5c, decoded to DER")

	jwtBundles, err := source.JWTBundles(ctx)
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

	ecAuthority, err := source.JWTAuthority(testDomain, "ec-1")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(ecKey.PublicKey.Equal(ecAuthority)).To(BeTrue())
	rsaAuthority, err := source.JWTAuthority(testDomain, "rsa-1")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(rsaKey.PublicKey.Equal(rsaAuthority)).To(BeTrue())
	_, err = source.JWTAuthority(testDomain, "wit-1")
	g.Expect(err).To(MatchError(wierrors.ErrUnknownKeyID), "a key with an unknown use is ignored")

	// the hint is kept for the refresh loop and is not on the interface
	g.Expect(source.current.Load().refreshHint).To(Equal(300 * time.Second))
	g.Expect(source.refreshInterval()).To(Equal(300 * time.Second))
}

func TestSource_JWTAuthority_UnknownDomainAndUnknownKeyID_AreDistinguishable(t *testing.T) {
	g := NewWithT(t)
	source, _ := newTestSource(t, &fakeFetcher{respond: fixed(sts.TrustBundle{
		TrustDomain: testDomain,
		Bundle:      bundleDoc(t, 0, jwtECKey(t, "k1", newECKey(t))),
	})})
	_, err := source.JWTBundles(context.Background())
	g.Expect(err).ToNot(HaveOccurred())

	_, unknownDomain := source.JWTAuthority("other.example.org", "k1")
	_, unknownKey := source.JWTAuthority(testDomain, "k2")

	g.Expect(unknownDomain).To(MatchError(wierrors.ErrUnknownTrustDomain))
	g.Expect(errors.Is(unknownDomain, wierrors.ErrUnknownKeyID)).To(BeFalse())
	g.Expect(unknownKey).To(MatchError(wierrors.ErrUnknownKeyID))
	g.Expect(errors.Is(unknownKey, wierrors.ErrUnknownTrustDomain)).To(BeFalse())
	g.Expect(wierrors.MetricLabel(unknownDomain)).ToNot(Equal(wierrors.MetricLabel(unknownKey)))
}

func TestSource_JWTAuthority_DomainWithOnlyX509Authorities_IsAnUnknownJWTDomain(t *testing.T) {
	g := NewWithT(t)
	source, _ := newTestSource(t, &fakeFetcher{respond: fixed(
		sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, jwtECKey(t, "k1", newECKey(t)))},
		sts.TrustBundle{TrustDomain: peerDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "peer")))},
	)})
	jwtBundles, err := source.JWTBundles(context.Background())
	g.Expect(err).ToNot(HaveOccurred())

	_, err = source.JWTAuthority(peerDomain, "k1")

	g.Expect(jwtBundles).ToNot(HaveKey(peerDomain))
	g.Expect(err).To(MatchError(wierrors.ErrUnknownTrustDomain), "JWTAuthority and JWTBundles agree on which JWT domains exist")
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
	servedBefore, _ := source.JWTBundles(ctx)
	x509Before, _ := source.X509Bundles(ctx)
	g.Expect(x509Before[testDomain]).To(Equal(sortedDER(caA.der, caB.der)), "every authority is served, not only the newest")
	g.Expect(refreshOnce(source, ctx)).To(Succeed())
	g.Expect(refreshOnce(source, ctx)).To(Succeed())
	x509After, _ := source.X509Bundles(ctx)
	g.Expect(x509After[testDomain]).To(Equal(x509Before[testDomain]), "an unchanged set keeps serving the bytes it already served")

	g.Expect(fetcher.Calls()).To(Equal(3))
	g.Expect(notifier.BroadcastCalls()).To(BeZero())
	g.Expect(testutil.ToFloat64(promBundleChangeTotal)).To(Equal(changesBefore))
	servedAfter, _ := source.JWTBundles(ctx)
	g.Expect(servedAfter).To(Equal(servedBefore), "the JWT set is unchanged")
	g.Expect(source.refreshInterval()).To(Equal(120*time.Second), "the hint still follows the latest document")
}

func TestSource_Refresh_ChangedAuthorities_SignalExactlyOnce(t *testing.T) {
	ca := newAuthority(t, "ca")
	k1 := jwtECKey(t, "k1", newECKey(t))
	base := sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, ca), k1)}

	for name, changed := range map[string]sts.TrustBundle{
		"a jwt-svid key added":   {TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, ca), k1, jwtECKey(t, "k2", newECKey(t)))},
		"a jwt-svid key rotated": {TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, ca), jwtECKey(t, "k1", newECKey(t)))},
		"an x509-svid key added": {TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, ca), x509Key(t, newAuthority(t, "next")), k1)},
		"an x509-svid key gone":  {TrustDomain: testDomain, Bundle: bundleDoc(t, 0, k1)},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			fetcher := &fakeFetcher{respond: sequence(ok(base), ok(changed), ok(changed))}
			source, notifier := newTestSource(t, fetcher)
			ctx := context.Background()
			changesBefore := testutil.ToFloat64(promBundleChangeTotal)

			g.Expect(refreshOnce(source, ctx)).To(Succeed())
			g.Expect(notifier.BroadcastCalls()).To(BeZero(), "the first bundle is not a change")
			g.Expect(refreshOnce(source, ctx)).To(Succeed())
			g.Expect(refreshOnce(source, ctx)).To(Succeed())

			g.Expect(notifier.BroadcastCalls()).To(Equal(1))
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
	g.Expect(notifier.BroadcastCalls()).To(Equal(1), "a new trust domain is a change")

	// the same authorities with the other domain first changes which one is the
	// workload's own, and the handlers split on that
	g.Expect(refreshOnce(source, ctx)).To(Succeed())
	g.Expect(notifier.BroadcastCalls()).To(Equal(2))
	g.Expect(source.OwnTrustDomain()).To(Equal(peerDomain))
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
			x509Bundles, err := source.X509Bundles(ctx)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(x509Bundles).To(Equal(map[string][][]byte{testDomain: {ca.der}}))
			authority, err := source.JWTAuthority(testDomain, "k1")
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(key.PublicKey.Equal(authority)).To(BeTrue())
			g.Expect(source.OwnTrustDomain()).To(Equal(testDomain))
			g.Expect(notifier.BroadcastCalls()).To(BeZero())
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

			bundles, err := source.X509Bundles(context.Background())
			g.Expect(err).To(MatchError(wierrors.ErrBundleUnavailable))
			g.Expect(err).To(MatchError(ContainSubstring(tc.reason)))
			g.Expect(bundles).To(BeNil())
			g.Expect(source.OwnTrustDomain()).To(BeEmpty())

			// inside the backoff a read gets the same failure without calling STS
			_, err = source.JWTBundles(context.Background())
			g.Expect(err).To(MatchError(ContainSubstring(tc.reason)))
			g.Expect(fetcher.Calls()).To(Equal(1))

			// nothing was cached, so once the backoff has passed a read fetches
			// again and succeeds
			clock = clock.Add(retryMaxDelay)
			bundles, err = source.X509Bundles(context.Background())
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(bundles).To(HaveKey(testDomain))
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
		_, err := source.X509Bundles(ctx)
		g.Expect(err).To(HaveOccurred())
		g.Expect(fetcher.Calls()).To(Equal(calls + 1))

		clock = clock.Add(wait - time.Millisecond)
		_, err = source.X509Bundles(ctx)
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
	_, err := source.X509Bundles(context.Background())

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
			_, err := source.X509Bundles(context.Background())
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
		_, err := source.X509Bundles(firstCtx)
		firstDone <- err
	}()
	<-fetcher.entered
	secondDone := make(chan error, 1)
	go func() {
		_, err := source.JWTBundles(context.Background())
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
		_, err := source.X509Bundles(ctx)
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
			_, err := source.X509Bundles(context.Background())
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
	go func() { _, _ = source.X509Bundles(context.Background()) }()
	<-fetcher.entered

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := source.JWTBundles(ctx)

	g.Expect(err).To(MatchError(wierrors.ErrBundleUnavailable))
	g.Expect(err).To(MatchError(context.Canceled))
	close(fetcher.gate)
}

func TestSource_ReturnedValues_AreCopies(t *testing.T) {
	g := NewWithT(t)
	ca := newAuthority(t, "ca")
	source, _ := newTestSource(t, &fakeFetcher{respond: fixed(sts.TrustBundle{
		TrustDomain: testDomain,
		Bundle:      bundleDoc(t, 0, x509Key(t, ca), jwtECKey(t, "k1", newECKey(t))),
	})})
	ctx := context.Background()

	x509Bundles, _ := source.X509Bundles(ctx)
	x509Bundles[testDomain][0][0] ^= 0xff
	x509Bundles[peerDomain] = nil
	jwtBundles, _ := source.JWTBundles(ctx)
	jwtBundles[testDomain][0] = 'X'

	again, _ := source.X509Bundles(ctx)
	g.Expect(again).To(Equal(map[string][][]byte{testDomain: {ca.der}}))
	jwtAgain, _ := source.JWTBundles(ctx)
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

func TestSource_RefreshInterval_FollowsHintWithinBoundsUnlessOverridden(t *testing.T) {
	for name, tc := range map[string]struct {
		hintSeconds int
		override    time.Duration
		expected    time.Duration
	}{
		"hint":                       {hintSeconds: 300, expected: 300 * time.Second},
		"no hint":                    {expected: defaultRefreshInterval},
		"hint below the floor":       {hintSeconds: 1, expected: minRefreshInterval},
		"hint above the ceiling":     {hintSeconds: 7 * 24 * 3600, expected: maxRefreshInterval},
		"override wins over hint":    {hintSeconds: 300, override: 10 * time.Minute, expected: 10 * time.Minute},
		"override below the floor":   {hintSeconds: 300, override: time.Second, expected: minRefreshInterval},
		"override above the ceiling": {hintSeconds: 300, override: 3 * time.Hour, expected: 3 * time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			source := newProviderSource(testProviderArn, Opts{
				Fetcher: &fakeFetcher{respond: fixed(sts.TrustBundle{
					TrustDomain: testDomain,
					Bundle:      bundleDoc(t, tc.hintSeconds, x509Key(t, newAuthority(t, "ca"))),
				})},
				Notifier:        &fake.Subscriber{},
				RefreshInterval: tc.override,
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
	g := NewWithT(t)
	source, _ := newTestSource(t, &fakeFetcher{respond: fixed(
		sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "a")))},
		sts.TrustBundle{TrustDomain: peerDomain, Bundle: bundleDoc(t, 900, x509Key(t, newAuthority(t, "b")))},
	)})

	g.Expect(refreshOnce(source, context.Background())).To(Succeed())

	g.Expect(source.refreshInterval()).To(Equal(900 * time.Second))
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

// runHarness drives Run with a fake clock: each wait the loop asks for is
// recorded, and the test releases it, advancing the clock by that wait.
type runHarness struct {
	waits  chan time.Duration
	fire   chan time.Time
	clock  time.Time
	mu     sync.Mutex
	done   chan struct{}
	cancel context.CancelFunc
}

func startRun(t *testing.T, source *providerSource) *runHarness {
	t.Helper()
	h := &runHarness{waits: make(chan time.Duration, 16), fire: make(chan time.Time), clock: time.Now(), done: make(chan struct{})}
	source.jitter = func() float64 { return 0 }
	source.now = h.now
	source.after = func(d time.Duration) <-chan time.Time {
		h.waits <- d
		return h.fire
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() {
		defer close(h.done)
		source.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-h.done
	})
	return h
}

func (h *runHarness) now() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.clock
}

func (h *runHarness) advance(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clock = h.clock.Add(d)
}

// release lets the loop's current wait elapse.
func (h *runHarness) release(wait time.Duration) {
	h.advance(wait)
	h.fire <- h.now()
}

func TestSource_Run_FetchesAtOnceThenBacksOffAndRefreshes(t *testing.T) {
	g := NewWithT(t)
	ca := newAuthority(t, "ca")
	next := newAuthority(t, "next")
	fetcher := &fakeFetcher{respond: sequence(
		fail(errors.New("unavailable")),
		fail(errors.New("unavailable")),
		ok(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 120, x509Key(t, ca))}),
		ok(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 120, x509Key(t, ca), x509Key(t, next))}),
	)}
	source, notifier := newTestSource(t, fetcher)
	h := startRun(t, source)

	wait := <-h.waits
	g.Expect(wait).To(BeZero(), "the first fetch is immediate")
	h.release(wait)
	wait = <-h.waits
	g.Expect(wait).To(Equal(retryBaseDelay), "a failure retries on the backoff")
	h.release(wait)
	wait = <-h.waits
	g.Expect(wait).To(Equal(2*retryBaseDelay), "consecutive failures back off further")
	h.release(wait)
	wait = <-h.waits
	g.Expect(wait).To(Equal(120*time.Second), "a success waits for the hint")
	g.Expect(source.OwnTrustDomain()).To(Equal(testDomain))
	h.release(wait)
	wait = <-h.waits
	g.Expect(wait).To(Equal(120 * time.Second))
	g.Expect(notifier.BroadcastCalls()).To(Equal(1))
	x509Bundles, err := source.X509Bundles(context.Background())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(x509Bundles[testDomain]).To(ConsistOf(ca.der, next.der), "the published authority is served beside the signing one")

	h.cancel()
	g.Eventually(h.done).Should(BeClosed())
	g.Expect(fetcher.Calls()).To(Equal(4))
}

func TestSource_Run_WakingInsideAFirstReadsBackoff_WaitsOutTheRest(t *testing.T) {
	g := NewWithT(t)
	fetcher := &fakeFetcher{respond: fixed()}
	source, _ := newTestSource(t, fetcher)
	h := startRun(t, source)

	h.release(<-h.waits)
	g.Expect(<-h.waits).To(Equal(retryBaseDelay))
	g.Expect(fetcher.Calls()).To(Equal(1))

	// a first read fetches as soon as the loop's backoff ends, fails, and moves
	// the schedule on before the loop's own timer fires
	h.advance(retryBaseDelay)
	_, err := source.X509Bundles(context.Background())
	g.Expect(err).To(MatchError(wierrors.ErrBundleUnavailable))
	g.Expect(fetcher.Calls()).To(Equal(2))

	// the loop wakes inside the backoff that read started, and waits out the
	// rest of it rather than making a second call back to back
	h.fire <- h.now()
	g.Expect(<-h.waits).To(Equal(2 * retryBaseDelay))
	g.Expect(fetcher.Calls()).To(Equal(2))
}

func TestSource_Run_ItsOwnCancellation_IsNotServedToALiveReader(t *testing.T) {
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
	h := startRun(t, source)
	h.release(<-h.waits)
	<-fetcher.entered

	// the loop stops while its first fetch is in flight
	h.cancel()
	g.Eventually(h.done).Should(BeClosed())
	close(fetcher.gate)

	bundles, err := source.X509Bundles(context.Background())

	g.Expect(err).ToNot(HaveOccurred(), "a live reader fetches for itself rather than being handed the loop's cancellation")
	g.Expect(bundles).To(HaveKey(testDomain))
	g.Expect(fetcher.Calls()).To(Equal(2))
}

func TestSource_Fetch_IsBoundedByTheFetchTimeout(t *testing.T) {
	g := NewWithT(t)
	fetcher := &fakeFetcher{respond: fixed(sts.TrustBundle{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca")))})}
	source, _ := newTestSource(t, fetcher)

	before := time.Now()
	_, err := source.X509Bundles(context.Background())
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
	go func() { _, _ = source.X509Bundles(context.Background()) }()
	<-fetcher.entered

	ctx, cancel := context.WithCancel(context.Background())
	waiting := make(chan error, 1)
	go func() {
		_, err := source.JWTBundles(ctx)
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

	x509Bundles, err := source.X509Bundles(context.Background())
	g.Expect(err).ToNot(HaveOccurred())
	jwtBundles, err := source.JWTBundles(context.Background())
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(x509Bundles).To(HaveKey(testDomain))
	g.Expect(x509Bundles).ToNot(HaveKey(peerDomain))
	g.Expect(jwtBundles).To(HaveKey(peerDomain))
	g.Expect(jwtBundles).ToNot(HaveKey(testDomain))
}

func TestSource_Run_WaitsTheJitteredInterval(t *testing.T) {
	g := NewWithT(t)
	source, _ := newTestSource(t, &fakeFetcher{respond: fixed(sts.TrustBundle{
		TrustDomain: testDomain, Bundle: bundleDoc(t, 300, x509Key(t, newAuthority(t, "ca"))),
	})})
	h := startRun(t, source)
	source.jitter = func() float64 { return 0.5 }

	h.release(<-h.waits)

	g.Expect(<-h.waits).To(Equal(shorten(300*time.Second, 0.5)))
}
