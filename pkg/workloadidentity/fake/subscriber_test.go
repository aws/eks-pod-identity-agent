package fake

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// subscriberTestTimeout bounds every wait in this file, so a fake that never
// releases a parked call, or that blocks on delivery, fails the test instead of
// hanging the suite.
const subscriberTestTimeout = 2 * time.Second

// subscriberTestProviderArn is the provider subscriberProviders names for every
// pod, so a bundle change has a provider to be scoped to.
const subscriberTestProviderArn = "arn:aws:iam::111122223333:workload-identity-provider/provider-a"

// subscriberOtherProviderArn is a second provider on the same node, for the
// tests that prove a rotation reaches one provider's subscriptions and not the
// other's.
const subscriberOtherProviderArn = "arn:aws:iam::111122223333:workload-identity-provider/provider-b"

// subscriberTestWorkload is the attested caller the default subscription is for.
var subscriberTestWorkload = &workloadidentity.Workload{
	PodUID:         "pod-uid-1",
	PodName:        "my-pod",
	Namespace:      "my-namespace",
	ServiceAccount: "my-service-account",
	NodeName:       "my-node",
}

// subscriberSubscribeResult is what a subscribe call running in another goroutine
// hands back to the test.
type subscriberSubscribeResult struct {
	ch     <-chan struct{}
	cancel func()
	err    error
}

// subscriberProviders names every pod's provider subscriberTestProviderArn.
func subscriberProviders() *ProviderArnResolver {
	return &ProviderArnResolver{Arn: subscriberTestProviderArn}
}

// subscriberMust takes a subscribe's results and fails loudly on an error, for
// the tests whose subscribe has no reason to fail.
func subscriberMust(ch <-chan struct{}, release func(), err error) (<-chan struct{}, func()) {
	if err != nil {
		panic(fmt.Sprintf("subscribe failed: %v", err))
	}
	return ch, release
}

// subscriberWorkload builds a workload for one pod UID, so a test can hold
// several subscriptions apart.
func subscriberWorkload(podUID string) *workloadidentity.Workload {
	return &workloadidentity.Workload{
		PodUID:         podUID,
		PodName:        podUID + "-pod",
		Namespace:      "my-namespace",
		ServiceAccount: "my-service-account",
		NodeName:       "my-node",
	}
}

// subscriberSignals drains and counts the signals pending in ch. It must not be
// used on a channel the fake has closed, which a closed channel test asserts
// directly instead.
func subscriberSignals(ch <-chan struct{}) int {
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

// subscriberDrainPrimes asserts every channel came back with exactly the prime
// pending and consumes it, so the assertions after it count real publishes only.
//
// It doubles as the test that a live subscribe is primed, which is the part of T9
// a handler can observe: a wait-then-send loop has nothing to send without it.
func subscriberDrainPrimes(t *testing.T, channels ...<-chan struct{}) {
	t.Helper()
	for i, ch := range channels {
		if signals := subscriberSignals(ch); signals != 1 {
			t.Fatalf("subscription %d came back with %d pending signals, want the prime only", i, signals)
		}
	}
}

// subscriberDo runs fn in another goroutine and fails the test if it has not
// returned before the timeout, so a fake that blocks fails instead of hanging.
func subscriberDo(t *testing.T, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(subscriberTestTimeout):
		t.Fatalf("call did not return within %v", subscriberTestTimeout)
	}
}

func TestSubscriptionLive_ZeroValue_IsLiveAndReceivesNothing(t *testing.T) {
	g := NewWithT(t)

	// Subscription is exported, so a consumer can build one the fake never handed
	// out. It carries no ctx and no channel, and every accessor has to answer for
	// it rather than dereference what is not there.
	sub := &Subscription{}

	g.Expect(sub.Live()).To(BeTrue())
	g.Expect(sub.Chan()).To(BeNil())
	g.Expect(sub.Notified()).To(Equal(0))

	// A delivery attempt finds no channel for the signal to land in, so it reports
	// no signal and counts none, exactly as a full buffer does.
	g.Expect(sub.notify()).To(BeFalse())
	g.Expect(sub.Notified()).To(Equal(0))
	g.Expect(sub.Live()).To(BeTrue())
}

func TestSubscriberSubscribeToWorkloadMaterial_Called_ReturnsChannelAndReleaseFunc(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{Providers: subscriberProviders()}

	ch, release := subscriberMust(subscriber.SubscribeToWorkloadMaterial(context.Background(), subscriberTestWorkload))
	subscriberDrainPrimes(t, ch)

	g.Expect(ch).To(Not(BeNil()))
	g.Expect(release).To(Not(BeNil()))
	g.Expect(subscriber.SubscribeCalls()).To(Equal(1))
	g.Expect(subscriber.CertBundleCalls()).To(Equal(0))
	g.Expect(subscriber.JWTBundleCalls()).To(Equal(0))
	g.Expect(subscriber.WorkloadChanges()).To(BeEmpty())
	g.Expect(subscriber.CancelCalls()).To(Equal(0))
	g.Expect(subscriber.LiveSubscriptions()).To(Equal(1))

	subs := subscriber.Subscriptions()
	g.Expect(subs).To(HaveLen(1))
	g.Expect(subs[0].Kind).To(Equal(KindWorkloadMaterial))
	g.Expect(subs[0].Workload).To(BeIdenticalTo(subscriberTestWorkload))
	g.Expect(*subs[0].Workload).To(Equal(*subscriberTestWorkload))
	g.Expect(subs[0].ProviderArn).To(Equal(subscriberTestProviderArn))
	g.Expect(subs[0].Chan()).To(BeIdenticalTo(ch))
	g.Expect(subs[0].Live()).To(BeTrue())
	g.Expect(subs[0].Notified()).To(Equal(0))
	g.Expect(subscriberSignals(ch)).To(Equal(0))
}

func TestSubscriberSubscribeToBundles_Called_RecordsKindAndWorkloadButNotPerPod(t *testing.T) {
	testCases := []struct {
		name      string
		subscribe func(*Subscriber) (<-chan struct{}, func())
		wantKind  SubscriptionKind
	}{
		{
			name: "cert bundles",
			subscribe: func(s *Subscriber) (<-chan struct{}, func()) {
				return subscriberMust(s.SubscribeToCertBundles(context.Background(), subscriberTestWorkload))
			},
			wantKind: KindCertBundles,
		},
		{
			name: "jwt bundles",
			subscribe: func(s *Subscriber) (<-chan struct{}, func()) {
				return subscriberMust(s.SubscribeToJWTBundles(context.Background(), subscriberTestWorkload))
			},
			wantKind: KindJWTBundles,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			subscriber := &Subscriber{Providers: subscriberProviders()}
			ch, release := tc.subscribe(subscriber)

			g.Expect(ch).To(Not(BeNil()))
			g.Expect(release).To(Not(BeNil()))
			g.Expect(subscriber.SubscribeCalls()).To(Equal(1))

			subs := subscriber.Subscriptions()
			g.Expect(subs).To(HaveLen(1))
			g.Expect(subs[0].Kind).To(Equal(tc.wantKind))
			// The workload only names the provider: a renewal it cannot act on
			// still never reaches a bundle subscription.
			g.Expect(subs[0].Workload).To(BeIdenticalTo(subscriberTestWorkload))
			g.Expect(subs[0].ProviderArn).To(Equal(subscriberTestProviderArn))
			g.Expect(subscriber.NotifyWorkload(subscriberTestWorkload.PodUID)).To(Equal(0))
		})
	}
}

func TestSubscriberSubscribe_CalledRepeatedly_RecordsSubscriptionsInOrder(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{Providers: subscriberProviders()}
	first := subscriberWorkload("pod-a")
	second := subscriberWorkload("pod-b")

	firstCh, firstRelease := subscriberMust(subscriber.SubscribeToWorkloadMaterial(context.Background(), first))
	secondCh, _ := subscriberMust(subscriber.SubscribeToWorkloadMaterial(context.Background(), second))

	g.Expect(subscriber.SubscribeCalls()).To(Equal(2))
	subs := subscriber.Subscriptions()
	g.Expect(subs).To(HaveLen(2))
	g.Expect(subs[0].Workload).To(BeIdenticalTo(first))
	g.Expect(subs[0].Chan()).To(BeIdenticalTo(firstCh))
	g.Expect(subs[1].Workload).To(BeIdenticalTo(second))
	g.Expect(subs[1].Chan()).To(BeIdenticalTo(secondCh))

	// Subscriptions keeps released subscriptions, in subscribe order, and hands
	// back a copy of the slice.
	firstRelease()
	kept := subscriber.Subscriptions()
	g.Expect(kept).To(HaveLen(2))
	g.Expect(kept[0]).To(BeIdenticalTo(subs[0]))
	g.Expect(kept[0].Live()).To(BeFalse())
	g.Expect(kept[1].Live()).To(BeTrue())
	kept[0] = nil
	g.Expect(subscriber.Subscriptions()[0]).To(BeIdenticalTo(subs[0]))
	g.Expect(subscriber.LiveSubscriptions()).To(Equal(1))
}

func TestSubscriberNotifyCertBundles_Called_SignalsLiveSubscriptionsOfThatProvider(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{Providers: subscriberProviders()}
	liveCtx, cancelLive := context.WithCancel(context.Background())
	t.Cleanup(cancelLive)
	doneCtx, cancelDone := context.WithCancel(context.Background())

	firstCh, _ := subscriberMust(subscriber.SubscribeToWorkloadMaterial(liveCtx, subscriberWorkload("pod-a")))
	secondCh, _ := subscriberMust(subscriber.SubscribeToCertBundles(liveCtx, subscriberTestWorkload))
	releasedCh, releaseThird := subscriberMust(subscriber.SubscribeToWorkloadMaterial(liveCtx, subscriberWorkload("pod-c")))
	doneCh, _ := subscriberMust(subscriber.SubscribeToWorkloadMaterial(doneCtx, subscriberWorkload("pod-d")))
	// All four were live at subscribe, so all four are primed. The two that stop
	// being live do so afterwards.
	subscriberDrainPrimes(t, firstCh, secondCh, releasedCh, doneCh)
	releaseThird()
	cancelDone()

	g.Expect(subscriber.LiveSubscriptions()).To(Equal(2))

	subscriberDo(t, func() { subscriber.NotifyCertBundleChange(subscriberTestProviderArn) })

	g.Expect(subscriber.CertBundleCalls()).To(Equal(1))
	g.Expect(subscriberSignals(firstCh)).To(Equal(1))
	g.Expect(subscriberSignals(secondCh)).To(Equal(1))
	g.Expect(subscriberSignals(releasedCh)).To(Equal(0))
	g.Expect(subscriberSignals(doneCh)).To(Equal(0))

	subs := subscriber.Subscriptions()
	g.Expect(subs).To(HaveLen(4))
	g.Expect(subs[0].Notified()).To(Equal(1))
	g.Expect(subs[1].Notified()).To(Equal(1))
	g.Expect(subs[2].Notified()).To(Equal(0))
	g.Expect(subs[3].Notified()).To(Equal(0))
}

func TestSubscriberNotifyBundles_CertAndJWT_ReachOnlyTheirOwnSubscriptions(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{Providers: subscriberProviders()}
	materialCh, _ := subscriberMust(subscriber.SubscribeToWorkloadMaterial(context.Background(), subscriberTestWorkload))
	certCh, _ := subscriberMust(subscriber.SubscribeToCertBundles(context.Background(), subscriberTestWorkload))
	jwtCh, _ := subscriberMust(subscriber.SubscribeToJWTBundles(context.Background(), subscriberTestWorkload))
	subscriberDrainPrimes(t, materialCh, certCh, jwtCh)

	// The X.509 authorities verify the peers of a stream serving an SVID, so a
	// workload material subscription takes that change as well as its own pod's.
	g.Expect(subscriber.NotifyCertBundles(subscriberTestProviderArn)).To(Equal(2))
	g.Expect(subscriberSignals(materialCh)).To(Equal(1))
	g.Expect(subscriberSignals(certCh)).To(Equal(1))
	g.Expect(subscriberSignals(jwtCh)).To(Equal(0))

	// A JWT key roll reaches only the JWT bundle stream. That is the whole point
	// of splitting the two: the SVID streams cannot observe it.
	g.Expect(subscriber.NotifyJWTBundles(subscriberTestProviderArn)).To(Equal(1))
	g.Expect(subscriberSignals(jwtCh)).To(Equal(1))
	g.Expect(subscriberSignals(materialCh)).To(Equal(0))
	g.Expect(subscriberSignals(certCh)).To(Equal(0))

	g.Expect(subscriber.CertBundleCalls()).To(Equal(1))
	g.Expect(subscriber.JWTBundleCalls()).To(Equal(1))
}

func TestSubscriberNotifyBundles_OtherProvider_SignalsNothing(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{Providers: subscriberProviders()}
	materialCh, _ := subscriberMust(subscriber.SubscribeToWorkloadMaterial(context.Background(), subscriberTestWorkload))
	jwtCh, _ := subscriberMust(subscriber.SubscribeToJWTBundles(context.Background(), subscriberTestWorkload))
	subscriberDrainPrimes(t, materialCh, jwtCh)

	// A node hosts the pods of however many providers its associations name, and a
	// rotation in one of them is not news to the others.
	g.Expect(subscriber.NotifyCertBundles(subscriberOtherProviderArn)).To(Equal(0))
	g.Expect(subscriber.NotifyJWTBundles(subscriberOtherProviderArn)).To(Equal(0))
	g.Expect(subscriberSignals(materialCh)).To(Equal(0))
	g.Expect(subscriberSignals(jwtCh)).To(Equal(0))

	g.Expect(subscriber.NotifyCertBundles(subscriberTestProviderArn)).To(Equal(1))
	g.Expect(subscriberSignals(materialCh)).To(Equal(1))
}

func TestSubscriberNotifyWorkload_MatchingPodUID_SignalsOnlyThatPodsSubscriptions(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{Providers: subscriberProviders()}
	firstCh, _ := subscriberMust(subscriber.SubscribeToWorkloadMaterial(context.Background(), subscriberWorkload("pod-a")))
	secondCh, _ := subscriberMust(subscriber.SubscribeToWorkloadMaterial(context.Background(), subscriberWorkload("pod-a")))
	otherCh, _ := subscriberMust(subscriber.SubscribeToWorkloadMaterial(context.Background(), subscriberWorkload("pod-b")))
	bundleCh, _ := subscriberMust(subscriber.SubscribeToCertBundles(context.Background(), subscriberTestWorkload))
	subscriberDrainPrimes(t, firstCh, secondCh, otherCh, bundleCh)

	// Two streams for one pod both wake, which is what a library holding an SVID
	// stream beside a bundle stream looks like.
	g.Expect(subscriber.NotifyWorkload("pod-a")).To(Equal(2))
	g.Expect(subscriberSignals(firstCh)).To(Equal(1))
	g.Expect(subscriberSignals(secondCh)).To(Equal(1))
	g.Expect(subscriberSignals(otherCh)).To(Equal(0))
	// A bundle subscription carries no pod, so no renewal can reach it.
	g.Expect(subscriberSignals(bundleCh)).To(Equal(0))

	g.Expect(subscriber.NotifyWorkload("pod-b")).To(Equal(1))
	g.Expect(subscriberSignals(otherCh)).To(Equal(1))

	g.Expect(subscriber.NotifyWorkload("pod-unknown")).To(Equal(0))
	g.Expect(subscriber.NotifyWorkload("")).To(Equal(0))
	g.Expect(subscriber.CertBundleCalls()).To(Equal(0))
	// Every publish is recorded with the UID it named, in call order, which is what
	// a material tier is asserted on rather than a bare count.
	g.Expect(subscriber.WorkloadChanges()).To(Equal([]string{"pod-a", "pod-b", "pod-unknown", ""}))
}

func TestSubscriberNotifyWorkload_BufferAlreadyFull_CoalescesAndReportsNoSignal(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{Providers: subscriberProviders()}
	ch, _ := subscriberMust(subscriber.SubscribeToWorkloadMaterial(context.Background(), subscriberTestWorkload))
	subscriberDrainPrimes(t, ch)

	g.Expect(subscriber.NotifyWorkload("pod-uid-1")).To(Equal(1))
	g.Expect(subscriber.NotifyWorkload("pod-uid-1")).To(Equal(0))
	g.Expect(subscriberSignals(ch)).To(Equal(1))

	// Once the pending signal is read the next one lands again.
	g.Expect(subscriber.NotifyWorkload("pod-uid-1")).To(Equal(1))
	g.Expect(subscriberSignals(ch)).To(Equal(1))
	g.Expect(subscriber.Subscriptions()[0].Notified()).To(Equal(2))
}

func TestSubscriberNotifyCertBundles_NoReader_CoalescesWithoutBlocking(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{Providers: subscriberProviders()}
	ch, _ := subscriberMust(subscriber.SubscribeToCertBundles(context.Background(), subscriberTestWorkload))
	subscriberDrainPrimes(t, ch)

	subscriberDo(t, func() {
		for range 5 {
			subscriber.NotifyCertBundleChange(subscriberTestProviderArn)
		}
	})

	g.Expect(subscriber.CertBundleCalls()).To(Equal(5))
	g.Expect(subscriber.Subscriptions()[0].Notified()).To(Equal(1))
	g.Expect(subscriberSignals(ch)).To(Equal(1))
}

func TestSubscriberSubscribe_BufferSet_AcceptsThatManyPendingSignals(t *testing.T) {
	testCases := []struct {
		name     string
		buffer   int
		expected int
	}{
		{name: "zero buffer defaults to one", buffer: 0, expected: 1},
		{name: "negative buffer defaults to one", buffer: -3, expected: 1},
		{name: "explicit buffer of one", buffer: 1, expected: 1},
		{name: "explicit buffer of three", buffer: 3, expected: 3},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			subscriber := &Subscriber{Providers: subscriberProviders(), Buffer: tc.buffer}
			ch, _ := subscriberMust(subscriber.SubscribeToCertBundles(context.Background(), subscriberTestWorkload))
			// The prime occupies one slot of whatever buffer was asked for, so
			// draining it leaves the buffer empty for the publishes below.
			subscriberDrainPrimes(t, ch)

			subscriberDo(t, func() {
				for range 5 {
					subscriber.NotifyCertBundleChange(subscriberTestProviderArn)
				}
			})

			g.Expect(subscriber.Subscriptions()[0].Notified()).To(Equal(tc.expected))
			g.Expect(subscriberSignals(ch)).To(Equal(tc.expected))
		})
	}
}

func TestSubscriberRelease_CalledTwice_CountsOnceAndStopsDelivery(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{Providers: subscriberProviders()}
	ch, release := subscriberMust(subscriber.SubscribeToWorkloadMaterial(context.Background(), subscriberTestWorkload))
	subscriberDrainPrimes(t, ch)

	g.Expect(subscriber.NotifyWorkload("pod-uid-1")).To(Equal(1))
	g.Expect(subscriberSignals(ch)).To(Equal(1))

	release()
	release()

	g.Expect(subscriber.CancelCalls()).To(Equal(1))
	g.Expect(subscriber.LiveSubscriptions()).To(Equal(0))

	sub := subscriber.Subscriptions()[0]
	g.Expect(sub.Live()).To(BeFalse())

	g.Expect(subscriber.NotifyWorkload("pod-uid-1")).To(Equal(0))
	subscriberDo(t, func() { subscriber.NotifyCertBundleChange(subscriberTestProviderArn) })

	g.Expect(sub.Notified()).To(Equal(1))
	g.Expect(subscriberSignals(ch)).To(Equal(0))
}

func TestSubscriberRelease_CloseOnCancelSet_ClosesChannel(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{Providers: subscriberProviders(), CloseOnCancel: true}
	ch, release := subscriberMust(subscriber.SubscribeToWorkloadMaterial(context.Background(), subscriberTestWorkload))
	subscriberDrainPrimes(t, ch)

	select {
	case <-ch:
		t.Fatal("channel was signalled or closed before release")
	default:
	}

	release()
	release()

	g.Expect(subscriber.CancelCalls()).To(Equal(1))
	select {
	case _, ok := <-ch:
		g.Expect(ok).To(BeFalse())
	default:
		t.Fatal("channel was not closed by release")
	}

	// Delivery to a closed channel would panic, so a publish after release has to
	// stay a no-op.
	subscriberDo(t, func() { subscriber.NotifyCertBundleChange(subscriberTestProviderArn) })
	g.Expect(subscriber.NotifyWorkload("pod-uid-1")).To(Equal(0))
	g.Expect(subscriber.Subscriptions()[0].Notified()).To(Equal(0))
}

func TestSubscriberRelease_CloseOnCancelUnset_LeavesChannelOpen(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{Providers: subscriberProviders()}
	ch, release := subscriberMust(subscriber.SubscribeToWorkloadMaterial(context.Background(), subscriberTestWorkload))
	subscriberDrainPrimes(t, ch)

	release()

	select {
	case <-ch:
		t.Fatal("channel was signalled or closed by release")
	default:
	}
	g.Expect(subscriber.CancelCalls()).To(Equal(1))
}

func TestSubscriberSubscribe_ContextAlreadyDone_FailsAndRecordsNothing(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{Providers: subscriberProviders()}
	ctx, cancelCtx := context.WithCancel(context.Background())
	cancelCtx()

	ch, release, err := subscriber.SubscribeToWorkloadMaterial(ctx, subscriberTestWorkload)

	g.Expect(err).To(MatchError(context.Canceled))
	g.Expect(ch).To(BeNil())
	g.Expect(release).To(BeNil())
	g.Expect(subscriber.SubscribeCalls()).To(BeZero(), "the Gate turned the call away")
	g.Expect(subscriber.Subscriptions()).To(BeEmpty())
}

func TestSubscriberSubscribe_ContextCancelledAfterSubscribe_StopsReceiving(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{Providers: subscriberProviders()}
	ctx, cancelCtx := context.WithCancel(context.Background())
	t.Cleanup(cancelCtx)

	ch, _ := subscriberMust(subscriber.SubscribeToWorkloadMaterial(ctx, subscriberTestWorkload))
	subscriberDrainPrimes(t, ch)

	g.Expect(subscriber.NotifyWorkload("pod-uid-1")).To(Equal(1))
	g.Expect(subscriberSignals(ch)).To(Equal(1))

	cancelCtx()

	g.Expect(subscriber.LiveSubscriptions()).To(Equal(0))
	g.Expect(subscriber.NotifyWorkload("pod-uid-1")).To(Equal(0))
	subscriberDo(t, func() { subscriber.NotifyCertBundleChange(subscriberTestProviderArn) })

	sub := subscriber.Subscriptions()[0]
	g.Expect(sub.Live()).To(BeFalse())
	g.Expect(sub.Notified()).To(Equal(1))
	g.Expect(subscriberSignals(ch)).To(Equal(0))
	// The subscription's ctx being done does not count as a release.
	g.Expect(subscriber.CancelCalls()).To(Equal(0))
}

func TestSubscriberSubscribe_GateBlocked_ReturnsUsableSubscriptionAfterRelease(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{Providers: subscriberProviders()}
	subscriber.Block()

	ctx, cancel := context.WithTimeout(context.Background(), subscriberTestTimeout)
	t.Cleanup(cancel)

	done := make(chan subscriberSubscribeResult, 1)
	go func() {
		ch, releaseSub := subscriberMust(subscriber.SubscribeToWorkloadMaterial(ctx, subscriberTestWorkload))
		done <- subscriberSubscribeResult{ch: ch, cancel: releaseSub}
	}()

	g.Expect(subscriber.WaitForBlocked(ctx, 1)).To(Succeed())
	g.Expect(subscriber.Blocked()).To(Equal(1))
	g.Expect(done).To(Not(Receive()))
	g.Expect(subscriber.SubscribeCalls()).To(Equal(0))
	g.Expect(subscriber.Subscriptions()).To(BeEmpty())

	subscriber.Release()

	var got subscriberSubscribeResult
	select {
	case got = <-done:
	case <-ctx.Done():
		t.Fatalf("the subscribe did not return after Release: %v", ctx.Err())
	}

	g.Expect(got.ch).To(Not(BeNil()))
	g.Expect(got.cancel).To(Not(BeNil()))
	g.Expect(subscriber.SubscribeCalls()).To(Equal(1))
	g.Expect(subscriber.Blocked()).To(Equal(0))

	subs := subscriber.Subscriptions()
	g.Expect(subs).To(HaveLen(1))
	g.Expect(subs[0].Workload).To(BeIdenticalTo(subscriberTestWorkload))
	g.Expect(subs[0].Chan()).To(BeIdenticalTo(got.ch))
	g.Expect(subs[0].Live()).To(BeTrue())

	subscriberDrainPrimes(t, got.ch)
	g.Expect(subscriber.NotifyWorkload("pod-uid-1")).To(Equal(1))
	g.Expect(subscriberSignals(got.ch)).To(Equal(1))

	got.cancel()
	g.Expect(subscriber.CancelCalls()).To(Equal(1))
	g.Expect(subscriber.LiveSubscriptions()).To(Equal(0))
}

func TestSubscriberSubscribe_ParkedCallContextCancelled_ReturnsTheGateError(t *testing.T) {
	g := NewWithT(t)

	subscriber := &Subscriber{Providers: subscriberProviders()}
	subscriber.Block()
	t.Cleanup(subscriber.Release)

	waitCtx, cancelWait := context.WithTimeout(context.Background(), subscriberTestTimeout)
	t.Cleanup(cancelWait)
	callCtx, cancelCall := context.WithCancel(context.Background())
	t.Cleanup(cancelCall)

	done := make(chan subscriberSubscribeResult, 1)
	go func() {
		ch, releaseSub, err := subscriber.SubscribeToWorkloadMaterial(callCtx, subscriberTestWorkload)
		done <- subscriberSubscribeResult{ch: ch, cancel: releaseSub, err: err}
	}()

	g.Expect(subscriber.WaitForBlocked(waitCtx, 1)).To(Succeed())
	cancelCall()

	var got subscriberSubscribeResult
	select {
	case got = <-done:
	case <-waitCtx.Done():
		t.Fatalf("the subscribe did not return after its context was cancelled: %v", waitCtx.Err())
	}

	g.Expect(got.err).To(MatchError(context.Canceled))
	g.Expect(got.ch).To(BeNil())
	g.Expect(subscriber.SubscribeCalls()).To(BeZero())
	g.Expect(subscriber.Subscriptions()).To(BeEmpty())
	g.Expect(subscriber.Blocked()).To(Equal(0))
}

func TestSubscriberSubscribe_FuncSet_ReturnsItsChannelAndRecordsNoSubscription(t *testing.T) {
	g := NewWithT(t)

	canned := make(chan struct{}, 1)
	releases := 0
	var gotKinds []SubscriptionKind
	subscriber := &Subscriber{
		Func: func(_ context.Context, kind SubscriptionKind, _ *workloadidentity.Workload) (<-chan struct{}, func(), error) {
			gotKinds = append(gotKinds, kind)
			return canned, func() { releases++ }, nil
		},
	}

	ch, release := subscriberMust(subscriber.SubscribeToWorkloadMaterial(context.Background(), subscriberTestWorkload))

	g.Expect(ch).To(BeIdenticalTo((<-chan struct{})(canned)))
	g.Expect(subscriber.SubscribeCalls()).To(Equal(1))
	g.Expect(subscriber.Subscriptions()).To(BeEmpty())
	g.Expect(subscriber.LiveSubscriptions()).To(Equal(0))

	// One Func serves all three methods and is told which one it is answering.
	_, _ = subscriberMust(subscriber.SubscribeToJWTBundles(context.Background(), subscriberTestWorkload))
	g.Expect(gotKinds).To(Equal([]SubscriptionKind{KindWorkloadMaterial, KindJWTBundles}))

	// The release func is returned unwrapped, so it is neither counted nor made
	// idempotent by the fake.
	release()
	release()
	g.Expect(releases).To(Equal(2))
	g.Expect(subscriber.CancelCalls()).To(Equal(0))

	// Nothing was recorded, so no delivery path reaches the canned channel.
	g.Expect(subscriber.NotifyWorkload("pod-uid-1")).To(Equal(0))
	subscriberDo(t, func() { subscriber.NotifyCertBundleChange(subscriberTestProviderArn) })
	g.Expect(subscriber.CertBundleCalls()).To(Equal(1))
	g.Expect(subscriberSignals(ch)).To(Equal(0))
}

func TestSubscriberNotify_ConcurrentWithRelease_DeliversWithoutRacing(t *testing.T) {
	g := NewWithT(t)

	const subscriptions = 5
	subscriber := &Subscriber{Providers: subscriberProviders(), CloseOnCancel: true}

	releases := make([]func(), 0, subscriptions)
	for range subscriptions {
		_, release := subscriberMust(subscriber.SubscribeToWorkloadMaterial(context.Background(), subscriberWorkload("pod-a")))
		releases = append(releases, release)
	}

	var wg sync.WaitGroup
	for _, release := range releases {
		wg.Add(2)
		go func() {
			defer wg.Done()
			release()
			release()
		}()
		go func() {
			defer wg.Done()
			subscriber.NotifyCertBundleChange(subscriberTestProviderArn)
			subscriber.NotifyWorkloadChange("pod-a")
		}()
	}

	subscriberDo(t, wg.Wait)

	g.Expect(subscriber.SubscribeCalls()).To(Equal(subscriptions))
	g.Expect(subscriber.CertBundleCalls()).To(Equal(subscriptions))
	g.Expect(subscriber.WorkloadChanges()).To(HaveLen(subscriptions))
	g.Expect(subscriber.CancelCalls()).To(Equal(subscriptions))
	g.Expect(subscriber.LiveSubscriptions()).To(Equal(0))

	for _, sub := range subscriber.Subscriptions() {
		g.Expect(sub.Live()).To(BeFalse())
		g.Expect(sub.Notified()).To(BeNumerically("<=", 1))
		select {
		case _, ok := <-sub.Chan():
			// Either the signal that landed before the release, or the close.
			_ = ok
		default:
			t.Fatal("a released subscription's channel was neither signalled nor closed")
		}
	}
}

func TestSubscriberSubscribe_ProvidersNameTheProvider(t *testing.T) {
	g := NewWithT(t)
	subscriber := &Subscriber{Providers: &ProviderArnResolver{
		Arn:  subscriberTestProviderArn,
		Arns: map[string]string{"pod-other": subscriberOtherProviderArn},
	}}

	ownCh, _ := subscriberMust(subscriber.SubscribeToCertBundles(context.Background(), subscriberWorkload("pod-a")))
	otherCh, _ := subscriberMust(subscriber.SubscribeToCertBundles(context.Background(), subscriberWorkload("pod-other")))
	subscriberSignals(ownCh)
	subscriberSignals(otherCh)

	g.Expect(subscriber.Subscriptions()[1].ProviderArn).To(Equal(subscriberOtherProviderArn))
	g.Expect(subscriber.NotifyCertBundles(subscriberOtherProviderArn)).To(Equal(1))
	g.Expect(subscriberSignals(otherCh)).To(Equal(1))
	g.Expect(subscriberSignals(ownCh)).To(Equal(0))
}

func TestSubscriberSubscribe_ProvidersCannotName_FailsCountedWithNoSubscription(t *testing.T) {
	errUnavailable := errors.New("session unavailable")
	for name, tc := range map[string]struct {
		providers *ProviderArnResolver
		expected  error
	}{
		"the resolver fails":             {providers: &ProviderArnResolver{Err: errUnavailable}, expected: errUnavailable},
		"the resolver names no provider": {providers: &ProviderArnResolver{}, expected: wierrors.ErrNotEnrolled},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			subscriber := &Subscriber{Providers: tc.providers}

			ch, release, err := subscriber.SubscribeToJWTBundles(context.Background(), subscriberTestWorkload)

			g.Expect(err).To(MatchError(tc.expected))
			g.Expect(ch).To(BeNil())
			g.Expect(release).To(BeNil())
			g.Expect(subscriber.SubscribeCalls()).To(Equal(1))
			g.Expect(subscriber.Subscriptions()).To(BeEmpty())
		})
	}
}

func TestSubscriberSubscribe_NoProviders_SucceedsWithAnEmptyProviderArn(t *testing.T) {
	g := NewWithT(t)
	subscriber := &Subscriber{}

	_, _ = subscriberMust(subscriber.SubscribeToCertBundles(context.Background(), subscriberTestWorkload))

	g.Expect(subscriber.Subscriptions()[0].ProviderArn).To(BeEmpty())
}
