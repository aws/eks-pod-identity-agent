package notify

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// The metric collectors are package-level and shared by every Subscriber, so a test
// that asserts on them has to own its rpc label. Each test below passes its own
// label to ForRPC, which gives it its own gauge and its own pair of counters and
// keeps the assertions independent of test order and of -count greater than one.
//
// The labels are test-only strings rather than the workloadidentity RPC constants
// for the same reason. The constants are asserted to be the right shape by that
// package's own contract tests; what matters here is isolation.

// hubTestTimeout bounds every wait, so a hub that fails to deliver fails the test
// instead of hanging the suite.
const hubTestTimeout = 2 * time.Second

const (
	// hubTestProvider is the identity provider most tests subscribe against.
	hubTestProvider = "arn:aws:iam::111122223333:workload-identity-provider/provider-a"
	// hubOtherProvider is a second provider on the same node, for the tests that
	// prove a rotation is scoped to one.
	hubOtherProvider = "arn:aws:iam::111122223333:workload-identity-provider/provider-b"
)

// hubWorkload builds an attested caller for one pod UID.
func hubWorkload(podUID string) *workloadidentity.Workload {
	return &workloadidentity.Workload{
		PodUID:         podUID,
		PodName:        podUID + "-pod",
		Namespace:      "my-namespace",
		ServiceAccount: "my-service-account",
		NodeName:       "my-node",
	}
}

// hubSignals drains and counts the signals pending in ch.
func hubSignals(ch <-chan struct{}) int {
	signals := 0
	for {
		select {
		case <-ch:
			signals++
		default:
			return signals
		}
	}
}

// hubDrainPrimes asserts every channel came back with exactly the prime pending
// and consumes it, so the assertions after it count real publishes only.
//
// It doubles as the test that a live subscribe is primed: a channel that is empty
// here would leave a wait-then-send handler with nothing to send until the first
// real change.
func hubDrainPrimes(t *testing.T, channels ...<-chan struct{}) {
	t.Helper()
	for i, ch := range channels {
		if signals := hubSignals(ch); signals != 1 {
			t.Fatalf("subscription %d came back with %d pending signals, want the prime only", i, signals)
		}
	}
}

// hubDo runs fn in another goroutine and fails the test if it has not returned
// before the timeout. Every publish is supposed to be non-blocking, so a publish
// that blocks has to fail rather than hang.
func hubDo(t *testing.T, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(hubTestTimeout):
		t.Fatalf("call did not return within %v", hubTestTimeout)
	}
}

// hubSnapshot is one Subscriber's three metric values at a point in time.
type hubSnapshot struct {
	active    float64
	signalled float64
	coalesced float64
}

// hubCounts reads one Subscriber's metrics, so a test can assert on the gauge and
// the two delivery counters without naming the collectors.
func hubCounts(stream *Subscriber) hubSnapshot {
	return hubSnapshot{
		active:    testutil.ToFloat64(stream.metrics.active),
		signalled: testutil.ToFloat64(stream.metrics.signalled),
		coalesced: testutil.ToFloat64(stream.metrics.coalesced),
	}
}

// since returns what this snapshot gained over base.
//
// Every assertion here is on a difference rather than an absolute, because the
// collectors live in the process-wide default registry: a counter is never reset,
// so the same test run twice under -count would otherwise see the first run's
// values. Taking a baseline at the top of each test makes the assertions say what
// they mean, which is what this publish did.
func (s hubSnapshot) since(base hubSnapshot) hubSnapshot {
	return hubSnapshot{
		active:    s.active - base.active,
		signalled: s.signalled - base.signalled,
		coalesced: s.coalesced - base.coalesced,
	}
}

// hubActiveSince returns the live gauge's movement since base, for an Eventually
// or Consistently that waits on a release.
func hubActiveSince(stream *Subscriber, base hubSnapshot) func() float64 {
	return func() float64 {
		return hubCounts(stream).since(base).active
	}
}

func TestHubForRPC_EmptyLabel_Panics(t *testing.T) {
	g := NewWithT(t)

	// An unlabelled series is one no dashboard and no alarm looks at, and the only
	// way to get one is a wiring mistake, so it fails at wiring time.
	g.Expect(func() { NewHub().ForRPC("") }).To(Panic())
}

func TestHubSubscribeToWorkloadMaterial_PodRenewal_SignalsOnlyThatPod(t *testing.T) {
	g := NewWithT(t)

	hub := NewHub()
	stream := hub.ForRPC("test_pod_scope")

	firstCh, _ := stream.SubscribeToWorkloadMaterial(context.Background(), hubWorkload("pod-a"), hubTestProvider)
	// A second stream for the same pod, which is what a library holding an SVID
	// stream beside a bundle stream looks like.
	secondCh, _ := stream.SubscribeToWorkloadMaterial(context.Background(), hubWorkload("pod-a"), hubTestProvider)
	otherCh, _ := stream.SubscribeToWorkloadMaterial(context.Background(), hubWorkload("pod-b"), hubTestProvider)
	hubDrainPrimes(t, firstCh, secondCh, otherCh)

	hubDo(t, func() { hub.NotifyWorkloadChange("pod-a") })

	g.Expect(hubSignals(firstCh)).To(Equal(1))
	g.Expect(hubSignals(secondCh)).To(Equal(1))
	g.Expect(hubSignals(otherCh)).To(Equal(0))

	hubDo(t, func() { hub.NotifyWorkloadChange("pod-b") })
	g.Expect(hubSignals(otherCh)).To(Equal(1))

	// A pod with no open stream is ordinary, not an error, and so is an empty UID.
	hubDo(t, func() { hub.NotifyWorkloadChange("pod-unknown") })
	hubDo(t, func() { hub.NotifyWorkloadChange("") })
	g.Expect(hubSignals(firstCh)).To(Equal(0))
}

func TestHubNotifyBundleChange_CertAndJWT_ReachDisjointAudiences(t *testing.T) {
	g := NewWithT(t)

	hub := NewHub()
	stream := hub.ForRPC("test_bundle_kinds")

	materialCh, _ := stream.SubscribeToWorkloadMaterial(context.Background(), hubWorkload("pod-a"), hubTestProvider)
	certCh, _ := stream.SubscribeToCertBundles(context.Background(), hubTestProvider)
	jwtCh, _ := stream.SubscribeToJWTBundles(context.Background(), hubTestProvider)
	hubDrainPrimes(t, materialCh, certCh, jwtCh)

	// The X.509 authorities verify the peers of a stream serving an SVID, so the
	// workload material subscription takes that change too.
	hubDo(t, func() { hub.NotifyCertBundleChange(hubTestProvider) })
	g.Expect(hubSignals(materialCh)).To(Equal(1))
	g.Expect(hubSignals(certCh)).To(Equal(1))
	g.Expect(hubSignals(jwtCh)).To(Equal(0))

	// A JWT key roll reaches only the JWT bundle stream. This is the whole reason
	// the two are separate publishes.
	hubDo(t, func() { hub.NotifyJWTBundleChange(hubTestProvider) })
	g.Expect(hubSignals(jwtCh)).To(Equal(1))
	g.Expect(hubSignals(materialCh)).To(Equal(0))
	g.Expect(hubSignals(certCh)).To(Equal(0))

	// A renewal reaches neither bundle stream, since neither carries a pod.
	hubDo(t, func() { hub.NotifyWorkloadChange("pod-a") })
	g.Expect(hubSignals(materialCh)).To(Equal(1))
	g.Expect(hubSignals(certCh)).To(Equal(0))
	g.Expect(hubSignals(jwtCh)).To(Equal(0))
}

func TestHubNotifyBundleChange_OtherProvider_SignalsNothing(t *testing.T) {
	g := NewWithT(t)

	hub := NewHub()
	stream := hub.ForRPC("test_provider_scope")

	materialCh, _ := stream.SubscribeToWorkloadMaterial(context.Background(), hubWorkload("pod-a"), hubTestProvider)
	certCh, _ := stream.SubscribeToCertBundles(context.Background(), hubTestProvider)
	otherCh, _ := stream.SubscribeToCertBundles(context.Background(), hubOtherProvider)
	hubDrainPrimes(t, materialCh, certCh, otherCh)

	// A node hosts the pods of however many providers its associations name. A
	// rotation in one is not news to the others.
	hubDo(t, func() { hub.NotifyCertBundleChange(hubOtherProvider) })
	g.Expect(hubSignals(otherCh)).To(Equal(1))
	g.Expect(hubSignals(materialCh)).To(Equal(0))
	g.Expect(hubSignals(certCh)).To(Equal(0))

	hubDo(t, func() { hub.NotifyCertBundleChange(hubTestProvider) })
	g.Expect(hubSignals(materialCh)).To(Equal(1))
	g.Expect(hubSignals(certCh)).To(Equal(1))
	g.Expect(hubSignals(otherCh)).To(Equal(0))

	// An empty ARN is a caller that should have been refused ErrNotEnrolled before
	// it subscribed. It reaches nothing rather than reaching everything.
	hubDo(t, func() { hub.NotifyCertBundleChange("") })
	hubDo(t, func() { hub.NotifyJWTBundleChange("") })
	g.Expect(hubSignals(materialCh)).To(Equal(0))
	g.Expect(hubSignals(certCh)).To(Equal(0))
	g.Expect(hubSignals(otherCh)).To(Equal(0))
}

func TestHubSubscribe_EmptyKeys_AreNeverSignalled(t *testing.T) {
	g := NewWithT(t)

	hub := NewHub()
	stream := hub.ForRPC("test_empty_keys")

	// A nil workload and an empty provider: both degenerate, neither a panic.
	nilWorkloadCh, _ := stream.SubscribeToWorkloadMaterial(context.Background(), nil, hubTestProvider)
	noProviderCh, _ := stream.SubscribeToWorkloadMaterial(context.Background(), hubWorkload("pod-a"), "")
	hubDrainPrimes(t, nilWorkloadCh, noProviderCh)

	hubDo(t, func() { hub.NotifyWorkloadChange("pod-a") })
	// The one with no provider still has a pod, so a renewal reaches it.
	g.Expect(hubSignals(noProviderCh)).To(Equal(1))
	// The one with no pod cannot be named by a renewal.
	g.Expect(hubSignals(nilWorkloadCh)).To(Equal(0))

	hubDo(t, func() { hub.NotifyCertBundleChange(hubTestProvider) })
	g.Expect(hubSignals(nilWorkloadCh)).To(Equal(1))
	g.Expect(hubSignals(noProviderCh)).To(Equal(0))

	// Neither index kept an empty key, so nothing is left behind to leak.
	hub.mu.Lock()
	defer hub.mu.Unlock()
	g.Expect(hub.byPod).To(HaveLen(1))
	g.Expect(hub.byProviderCert).To(HaveLen(1))
	g.Expect(hub.byProviderJWT).To(BeEmpty())
}

func TestHubSignal_SubscriberNotReading_CoalescesToOnePending(t *testing.T) {
	g := NewWithT(t)

	hub := NewHub()
	stream := hub.ForRPC("test_coalesce")
	base := hubCounts(stream)
	ch, _ := stream.SubscribeToCertBundles(context.Background(), hubTestProvider)
	hubDrainPrimes(t, ch)

	// Publishing repeatedly while nobody reads must neither block nor queue. A
	// queue would hand this stream a superseded bundle after a fresh one.
	hubDo(t, func() {
		for range 100 {
			hub.NotifyCertBundleChange(hubTestProvider)
		}
	})

	g.Expect(hubSignals(ch)).To(Equal(1))

	got := hubCounts(stream).since(base)
	g.Expect(got.signalled).To(Equal(float64(1)), "only the first publish found an empty channel")
	g.Expect(got.coalesced).To(Equal(float64(99)), "every later publish replaced an unread signal")

	// Once the pending signal is read the next publish lands again.
	hubDo(t, func() { hub.NotifyCertBundleChange(hubTestProvider) })
	g.Expect(hubSignals(ch)).To(Equal(1))

	got = hubCounts(stream).since(base)
	g.Expect(got.signalled).To(Equal(float64(2)))
	g.Expect(got.coalesced).To(Equal(float64(99)))
}

func TestHubSignal_SlowSubscriber_ObservesTheNewestStateThroughOnePending(t *testing.T) {
	g := NewWithT(t)

	hub := NewHub()
	stream := hub.ForRPC("test_latest_wins")
	ch, _ := stream.SubscribeToCertBundles(context.Background(), hubTestProvider)

	// The source the subscriber re-reads on waking. Each publish moves it, which is
	// what a sequence of rotations looks like to a handler.
	var (
		mu      sync.Mutex
		version int
	)
	publish := func() {
		mu.Lock()
		version++
		mu.Unlock()
		hub.NotifyCertBundleChange(hubTestProvider)
	}

	// Several changes arrive while the subscriber is not reading.
	hubDo(t, func() {
		for range 5 {
			publish()
		}
	})

	// It wakes once and reads the newest version, not the first of five.
	select {
	case <-ch:
	case <-time.After(hubTestTimeout):
		t.Fatal("the subscriber was never signalled")
	}

	mu.Lock()
	seen := version
	mu.Unlock()
	g.Expect(seen).To(Equal(5), "the signal has no payload, so what is read is whatever is current")

	// And there is nothing queued behind it.
	g.Expect(hubSignals(ch)).To(Equal(0))
}

func TestHubSignal_SlowSubscriber_ReceiveIsOrderedAfterTheLatestPublish(t *testing.T) {
	// raceDetectorEnabled is a build-tagged const; see race_test.go.
	if !raceDetectorEnabled {
		t.Skip("this test proves a happens-before edge and only fails under -race")
	}

	g := NewWithT(t)

	hub := NewHub()
	stream := hub.ForRPC("test_ordering")
	ch, _ := stream.SubscribeToCertBundles(context.Background(), hubTestProvider)
	hubDrainPrimes(t, ch)

	// An unlocked source, read by the subscriber and written by the publisher. The
	// only thing making this safe is the hub: the publisher writes before it takes
	// the mutex, and the subscriber's receive is ordered after the send that
	// happened under it.
	//
	// Drain before write is what makes that true of the *latest* publish. A plain
	// non-blocking send would leave the first publish's signal in place, so the
	// receive would only be ordered after that one and the later writes would be a
	// data race the detector reports.
	version := 0

	const publishes = 20
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range publishes {
			version++
			hub.NotifyCertBundleChange(hubTestProvider)
		}
	}()

	select {
	case <-done:
	case <-time.After(hubTestTimeout):
		t.Fatal("the publisher did not finish")
	}

	select {
	case <-ch:
	case <-time.After(hubTestTimeout):
		t.Fatal("the subscriber was never signalled")
	}

	g.Expect(version).To(Equal(publishes))
}

func TestHubBundleChange_ManySubscribers_AllWoken(t *testing.T) {
	g := NewWithT(t)

	const subscriptions = 500

	hub := NewHub()
	stream := hub.ForRPC("test_fan_out")
	base := hubCounts(stream)

	channels := make([]<-chan struct{}, 0, subscriptions)
	for range subscriptions {
		ch, _ := stream.SubscribeToCertBundles(context.Background(), hubTestProvider)
		channels = append(channels, ch)
	}
	hubDrainPrimes(t, channels...)

	// One rotation is one fan-out across every stream of that provider on the node.
	hubDo(t, func() { hub.NotifyCertBundleChange(hubTestProvider) })

	for i, ch := range channels {
		g.Expect(hubSignals(ch)).To(Equal(1), "subscription %d was not signalled", i)
	}

	got := hubCounts(stream).since(base)
	g.Expect(got.active).To(Equal(float64(subscriptions)))
	g.Expect(got.signalled).To(Equal(float64(subscriptions)))
}

func TestHubRelease_CalledTwice_IsSafeAndStopsDelivery(t *testing.T) {
	g := NewWithT(t)

	hub := NewHub()
	stream := hub.ForRPC("test_release_twice")
	base := hubCounts(stream)
	ch, release := stream.SubscribeToWorkloadMaterial(context.Background(), hubWorkload("pod-a"), hubTestProvider)
	hubDrainPrimes(t, ch)

	hubDo(t, func() { hub.NotifyWorkloadChange("pod-a") })
	g.Expect(hubSignals(ch)).To(Equal(1))

	release()
	release()

	// The gauge moves once however many times release is called.
	g.Expect(hubCounts(stream).since(base).active).To(Equal(float64(0)))

	hubDo(t, func() { hub.NotifyWorkloadChange("pod-a") })
	hubDo(t, func() { hub.NotifyCertBundleChange(hubTestProvider) })
	g.Expect(hubSignals(ch)).To(Equal(0))

	// Both indexes dropped their now-empty entries rather than keeping a key per
	// pod and provider the node has ever seen.
	hub.mu.Lock()
	defer hub.mu.Unlock()
	g.Expect(hub.all).To(BeEmpty())
	g.Expect(hub.byPod).To(BeEmpty())
	g.Expect(hub.byProviderCert).To(BeEmpty())
}

func TestHubRelease_ChannelIsNotClosed(t *testing.T) {
	g := NewWithT(t)

	hub := NewHub()
	stream := hub.ForRPC("test_no_close")
	ch, release := stream.SubscribeToCertBundles(context.Background(), hubTestProvider)
	hubDrainPrimes(t, ch)

	release()

	// A closed channel receives forever, which would spin a handler racing its own
	// teardown instead of letting its context end the loop. So release removes the
	// subscription and leaves the channel open and empty.
	select {
	case <-ch:
		t.Fatal("release closed or signalled the subscription channel")
	default:
	}
	g.Expect(ch).To(Not(BeNil()))
}

func TestHubSubscribe_ContextCancelled_ReleasesWithoutAnExplicitRelease(t *testing.T) {
	g := NewWithT(t)

	hub := NewHub()
	stream := hub.ForRPC("test_ctx_release")
	base := hubCounts(stream)
	ctx, cancel := context.WithCancel(context.Background())

	ch, _ := stream.SubscribeToWorkloadMaterial(ctx, hubWorkload("pod-a"), hubTestProvider)
	hubDrainPrimes(t, ch)

	hubDo(t, func() { hub.NotifyWorkloadChange("pod-a") })
	g.Expect(hubSignals(ch)).To(Equal(1))

	// A handler that returns without calling release must not leak. The context
	// hook is what covers it.
	cancel()

	g.Eventually(func() int {
		hub.mu.Lock()
		defer hub.mu.Unlock()
		return len(hub.all)
	}, hubTestTimeout, time.Millisecond).Should(Equal(0))

	g.Expect(hubCounts(stream).since(base).active).To(Equal(float64(0)))

	hubDo(t, func() { hub.NotifyWorkloadChange("pod-a") })
	g.Expect(hubSignals(ch)).To(Equal(0))
}

func TestHubSubscribe_ContextAlreadyDone_RegistersNothingAndIsNotPrimed(t *testing.T) {
	g := NewWithT(t)

	hub := NewHub()
	stream := hub.ForRPC("test_ctx_done")
	base := hubCounts(stream)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ch, release := stream.SubscribeToCertBundles(ctx, hubTestProvider)

	// The stream is already over, so there is nobody to wake. Registering would
	// put an entry in the indexes for every publish to walk until the context hook
	// got to it, and priming would hand a handler an initial send for a stream
	// that cannot send.
	hub.mu.Lock()
	g.Expect(hub.all).To(BeEmpty())
	g.Expect(hub.byProviderCert).To(BeEmpty())
	hub.mu.Unlock()

	g.Expect(ch).To(Not(BeNil()), "a handler still selects on the channel beside its own context")
	g.Expect(hubSignals(ch)).To(Equal(0), "an already done subscribe is not primed")
	g.Expect(hubCounts(stream).since(base).active).To(Equal(float64(0)))

	hubDo(t, func() { hub.NotifyCertBundleChange(hubTestProvider) })
	g.Expect(hubSignals(ch)).To(Equal(0))

	// The release func is still safe to call, so a handler needs no special case.
	g.Expect(release).To(Not(BeNil()))
	release()
	release()
}

func TestHubSubscribe_ManyOpenSubscriptions_HoldNoGoroutine(t *testing.T) {
	g := NewWithT(t)

	const subscriptions = 1000

	hub := NewHub()
	stream := hub.ForRPC("test_open_goroutines")

	// An open subscription has to cost a channel and two map entries and nothing
	// else. A goroutine parked on each stream's context would be a goroutine per
	// open stream, which is what context.AfterFunc avoids: it registers a hook and
	// runs nothing until the context is actually done.
	before := runtime.NumGoroutine()

	releases := make([]func(), 0, subscriptions)
	for range subscriptions {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		_, release := stream.SubscribeToWorkloadMaterial(ctx, hubWorkload("pod-a"), hubTestProvider)
		releases = append(releases, release)
	}

	hub.mu.Lock()
	g.Expect(hub.all).To(HaveLen(subscriptions), "every subscription is live")
	hub.mu.Unlock()

	g.Expect(runtime.NumGoroutine()).To(BeNumerically("<=", before+5))

	for _, release := range releases {
		release()
	}
}

func TestHubPublish_DoesNotAllocate(t *testing.T) {
	const subscriptions = 200

	hub := NewHub()
	stream := hub.ForRPC("test_allocations")

	channels := make([]<-chan struct{}, 0, subscriptions)
	for range subscriptions {
		ch, _ := stream.SubscribeToWorkloadMaterial(context.Background(), hubWorkload("pod-a"), hubTestProvider)
		channels = append(channels, ch)
	}
	hubDrainPrimes(t, channels...)

	// A publish walks an index under the lock and does a drain, a non-blocking send
	// and a counter increment per subscription. None of that may allocate, because
	// one rotation touches every stream of a provider at once and a copy of the
	// index would put that allocation on the path a renewal loop waits behind.
	//
	// The signals are drained inside the measured function, which is also
	// allocation-free, so each publish finds the same state the last one left.
	testCases := []struct {
		name    string
		publish func()
	}{
		{name: "workload change", publish: func() { hub.NotifyWorkloadChange("pod-a") }},
		{name: "cert bundle change", publish: func() { hub.NotifyCertBundleChange(hubTestProvider) }},
		{name: "jwt bundle change", publish: func() { hub.NotifyJWTBundleChange(hubTestProvider) }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			allocations := testing.AllocsPerRun(10, func() {
				tc.publish()
				for _, ch := range channels {
					select {
					case <-ch:
					default:
					}
				}
			})

			g.Expect(allocations).To(Equal(float64(0)))
		})
	}
}

func TestHubRelease_ExplicitThenContext_MovesTheGaugeOnce(t *testing.T) {
	g := NewWithT(t)

	hub := NewHub()
	stream := hub.ForRPC("test_double_path_release")
	base := hubCounts(stream)
	ctx, cancel := context.WithCancel(context.Background())

	_, release := stream.SubscribeToCertBundles(ctx, hubTestProvider)

	g.Expect(hubCounts(stream).since(base).active).To(Equal(float64(1)))

	// Releasing explicitly and then cancelling exercises both teardown paths for
	// one subscription. Only the first one to remove it may touch the gauge, so
	// the level has to settle at zero and stay there rather than going negative.
	release()
	cancel()

	g.Consistently(hubActiveSince(stream, base), 100*time.Millisecond, 10*time.Millisecond).
		Should(Equal(float64(0)))
}

func TestHubSubscribe_ManyCycles_LeaksNoGoroutines(t *testing.T) {
	g := NewWithT(t)

	hub := NewHub()
	stream := hub.ForRPC("test_goroutines")

	// A released subscription must cost nothing afterwards. context.AfterFunc is
	// what makes that true without a goroutine parked on every stream's context,
	// and the release func deregisters the hook.
	before := runtime.NumGoroutine()

	for range 1000 {
		ctx, cancel := context.WithCancel(context.Background())
		_, release := stream.SubscribeToWorkloadMaterial(ctx, hubWorkload("pod-a"), hubTestProvider)
		release()
		cancel()
	}

	g.Eventually(runtime.NumGoroutine, hubTestTimeout, 10*time.Millisecond).
		Should(BeNumerically("<=", before+5))

	hub.mu.Lock()
	defer hub.mu.Unlock()
	g.Expect(hub.all).To(BeEmpty())
	g.Expect(hub.byPod).To(BeEmpty())
	g.Expect(hub.byProviderCert).To(BeEmpty())
}

func TestHub_ConcurrentSubscribePublishRelease_IsRaceFree(t *testing.T) {
	g := NewWithT(t)

	const workers = 24

	hub := NewHub()
	stream := hub.ForRPC("test_concurrency")
	base := hubCounts(stream)

	var wg sync.WaitGroup
	for worker := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				ctx, cancel := context.WithCancel(context.Background())
				ch, release := stream.SubscribeToWorkloadMaterial(ctx, hubWorkload("pod-a"), hubTestProvider)
				_ = hubSignals(ch)
				// Half release explicitly and half leave it to the context, so both
				// teardown paths run against a live fan-out.
				if worker%2 == 0 {
					release()
				}
				cancel()
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				hub.NotifyWorkloadChange("pod-a")
				hub.NotifyCertBundleChange(hubTestProvider)
				hub.NotifyJWTBundleChange(hubTestProvider)
			}
		}()
	}

	hubDo(t, wg.Wait)

	// Every subscription is gone whichever way it was torn down, so both indexes
	// and the live set drain back to empty.
	g.Eventually(func() int {
		hub.mu.Lock()
		defer hub.mu.Unlock()
		return len(hub.all) + len(hub.byPod) + len(hub.byProviderCert) + len(hub.byProviderJWT)
	}, hubTestTimeout, time.Millisecond).Should(Equal(0))

	g.Eventually(hubActiveSince(stream, base), hubTestTimeout, time.Millisecond).
		Should(Equal(float64(0)))
}

func TestHubForRPC_SeparateLabels_CountIndependently(t *testing.T) {
	g := NewWithT(t)

	hub := NewHub()
	first := hub.ForRPC("test_label_first")
	second := hub.ForRPC("test_label_second")
	firstBase, secondBase := hubCounts(first), hubCounts(second)

	firstCh, _ := first.SubscribeToCertBundles(context.Background(), hubTestProvider)
	secondCh, _ := second.SubscribeToCertBundles(context.Background(), hubTestProvider)
	hubDrainPrimes(t, firstCh, secondCh)

	// One hub, one publish, two RPCs: the fan-out reaches both, and each RPC's
	// metrics account for its own streams only.
	hubDo(t, func() { hub.NotifyCertBundleChange(hubTestProvider) })

	g.Expect(hubSignals(firstCh)).To(Equal(1))
	g.Expect(hubSignals(secondCh)).To(Equal(1))

	gotFirst := hubCounts(first).since(firstBase)
	g.Expect(gotFirst.active).To(Equal(float64(1)))
	g.Expect(gotFirst.signalled).To(Equal(float64(1)))

	gotSecond := hubCounts(second).since(secondBase)
	g.Expect(gotSecond.active).To(Equal(float64(1)))
	g.Expect(gotSecond.signalled).To(Equal(float64(1)))
}
