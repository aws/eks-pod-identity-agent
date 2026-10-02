package fake

import (
	"context"
	"slices"
	"sync"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// SubscriptionKind is which of the three Subscriber methods handed out a
// Subscription, so a test can tell them apart in Subscriptions().
type SubscriptionKind string

const (
	// KindWorkloadMaterial is a subscription from SubscribeToWorkloadMaterial.
	// It receives NotifyWorkloadChange for its pod and NotifyCertBundleChange
	// for its provider.
	KindWorkloadMaterial SubscriptionKind = "workload_material"
	// KindCertBundles is a subscription from SubscribeToCertBundles. It receives
	// NotifyCertBundleChange for its provider only.
	KindCertBundles SubscriptionKind = "cert_bundles"
	// KindJWTBundles is a subscription from SubscribeToJWTBundles. It receives
	// NotifyJWTBundleChange for its provider only.
	KindJWTBundles SubscriptionKind = "jwt_bundles"
)

// Subscription is one subscription the fake handed out. A test reaches it through
// Subscriber.Subscriptions.
//
// The channel is behind Chan rather than an exported field because the fake writes
// to it from whichever goroutine publishes while a test reads it, and because
// CloseOnCancel may close it. Chan returns the same channel the subscriber got.
type Subscription struct {
	// Kind is which Subscribe method produced this subscription.
	Kind SubscriptionKind
	// Workload is the workload SubscribeToWorkloadMaterial was called with, nil
	// for a bundle subscription, which has no workload to pass.
	Workload *workloadidentity.Workload
	// ProviderArn is the provider ARN the subscribe was called with.
	ProviderArn string

	mu            sync.Mutex
	ch            chan struct{}
	ctx           context.Context
	cancelled     bool
	closeOnCancel bool
	notified      int
}

// Chan is the channel Subscribe handed to the subscriber.
func (s *Subscription) Chan() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ch
}

// Live reports whether the subscription still receives signals. It stops being
// live once its release func has run or its subscribe ctx is done.
//
// A zero-valued Subscription carries no ctx and no channel. It reports live and
// every accessor answers rather than panicking, but nothing is delivered to it.
func (s *Subscription) Live() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.liveLocked()
}

// Notified reports how many signals landed in the subscription's channel. A
// signal dropped because the buffer was already full is not counted, since the
// pending signal it coalesced into is still there to be read.
func (s *Subscription) Notified() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.notified
}

// liveLocked reports whether the subscription still receives signals. The caller
// must hold s.mu.
func (s *Subscription) liveLocked() bool {
	if s.cancelled {
		return false
	}
	if s.ctx == nil {
		return true
	}
	select {
	case <-s.ctx.Done():
		return false
	default:
		return true
	}
}

// notify performs one non-blocking send and reports whether the signal landed.
func (s *Subscription) notify() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.liveLocked() {
		return false
	}
	select {
	case s.ch <- struct{}{}:
		s.notified++
		return true
	default:
		return false
	}
}

// cancel marks the subscription dead and reports whether this call is the one
// that did it, so a repeated release is a no-op.
func (s *Subscription) cancel() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancelled {
		return false
	}
	s.cancelled = true
	if s.closeOnCancel {
		close(s.ch)
	}
	return true
}

// wantsCertBundle reports whether a change in a provider's X.509 authorities
// reaches this subscription, which is true for the two kinds that serve them.
func (s *Subscription) wantsCertBundle() bool {
	return s.Kind == KindWorkloadMaterial || s.Kind == KindCertBundles
}

// Subscriber is a fake workloadidentity.Subscriber, WorkloadNotifier and
// BundleNotifier, so one value stands in for whichever side a test is driving.
//
// Set the fields before use; they are not safe to write once a call can be in
// flight. There are no setters because there is no canned return value to change:
// a subscribe cannot fail, and delivery is driven by the Notify methods.
type Subscriber struct {
	Gate

	// Buffer sizes each subscription's channel. Defaults to 1 when zero, which
	// is the coalescing shape the notification tier uses.
	Buffer int
	// CloseOnCancel closes a subscription's channel on release. Off by default
	// and not production behaviour: the real tier never closes the channel, since
	// a closed channel receives forever and would spin a handler racing its own
	// teardown. Here for a test that wants to prove its loop does not depend on it.
	CloseOnCancel bool
	// Func, when non-nil, wins: every subscribe returns whatever it returns and
	// records no Subscription, so Subscriptions, the Notify methods and
	// CancelCalls see nothing of that call. SubscribeCalls still counts it.
	//
	// It is handed the kind, so one Func serves all three methods.
	Func func(ctx context.Context, kind SubscriptionKind, w *workloadidentity.Workload, providerArn string) (<-chan struct{}, func())

	mu              sync.Mutex
	subscribeCalls  int
	certBundleCalls int
	jwtBundleCalls  int
	workloadChanges []string
	cancelCalls     int
	subs            []*Subscription
}

// SubscribeToWorkloadMaterial records a KindWorkloadMaterial Subscription for w
// and the provider, and returns its channel and a release func.
func (s *Subscriber) SubscribeToWorkloadMaterial(ctx context.Context, w *workloadidentity.Workload, providerArn string) (<-chan struct{}, func()) {
	return s.subscribe(ctx, KindWorkloadMaterial, w, providerArn)
}

// SubscribeToCertBundles records a KindCertBundles Subscription for the
// provider. Its Workload is nil, which is what tells it apart from a workload
// material subscription in Subscriptions().
func (s *Subscriber) SubscribeToCertBundles(ctx context.Context, providerArn string) (<-chan struct{}, func()) {
	return s.subscribe(ctx, KindCertBundles, nil, providerArn)
}

// SubscribeToJWTBundles records a KindJWTBundles Subscription for the provider.
func (s *Subscriber) SubscribeToJWTBundles(ctx context.Context, providerArn string) (<-chan struct{}, func()) {
	return s.subscribe(ctx, KindJWTBundles, nil, providerArn)
}

// subscribe is what all three Subscribe methods record through.
//
// It parks at the Gate first, so a test can hold a subscribe open. A subscribe has
// no error return, so a Gate error is discarded: the call still gets a usable
// channel and release func, and a done ctx simply means it never receives a signal.
//
// The call is counted and recorded under one lock, so a test polling SubscribeCalls
// as a synchronisation point cannot see the count move before Subscriptions knows
// of the call. Func runs after the lock is dropped, so a Func that calls back into
// the fake does not deadlock.
func (s *Subscriber) subscribe(ctx context.Context, kind SubscriptionKind, w *workloadidentity.Workload, providerArn string) (<-chan struct{}, func()) {
	// The Gate error is deliberately ignored; see the doc comment.
	_ = s.enter(ctx)

	s.mu.Lock()
	s.subscribeCalls++
	fn, buffer, closeOnCancel := s.Func, s.Buffer, s.CloseOnCancel
	var sub *Subscription
	if fn == nil {
		if buffer <= 0 {
			buffer = 1
		}
		sub = &Subscription{
			Kind:          kind,
			Workload:      w,
			ProviderArn:   providerArn,
			ch:            make(chan struct{}, buffer),
			ctx:           ctx,
			closeOnCancel: closeOnCancel,
		}
		// A live subscribe comes back primed, as the real tier does, so a
		// wait-then-send handler produces its initial response. The prime is not
		// a notification: it does not count on Notified, and a done ctx is not
		// primed because its stream is already over.
		if ctx == nil || ctx.Err() == nil {
			sub.ch <- struct{}{}
		}
		s.subs = append(s.subs, sub)
	}
	s.mu.Unlock()

	if fn != nil {
		return fn(ctx, kind, w, providerArn)
	}
	return sub.ch, func() { s.cancelSubscription(sub) }
}

// NotifyWorkloadChange signals the live workload material subscriptions for the
// pod, so the fake satisfies workloadidentity.WorkloadNotifier. A test asserting
// on delivery calls NotifyWorkload, which reports how many received the signal.
func (s *Subscriber) NotifyWorkloadChange(podUID string) {
	_ = s.NotifyWorkload(podUID)
}

// NotifyCertBundleChange signals the live subscriptions of the provider that take
// X.509 authorities. A test asserting on delivery calls NotifyCertBundles.
func (s *Subscriber) NotifyCertBundleChange(providerArn string) {
	_ = s.NotifyCertBundles(providerArn)
}

// NotifyJWTBundleChange signals the live JWT bundle subscriptions of the
// provider. A test asserting on delivery calls NotifyJWTBundles.
func (s *Subscriber) NotifyJWTBundleChange(providerArn string) {
	_ = s.NotifyJWTBundles(providerArn)
}

// NotifyWorkload signals the live workload material subscriptions for the pod and
// returns how many received the signal. A bundle subscription never matches, since
// it carries no workload.
//
// Delivery is a non-blocking send, so it coalesces: a subscription whose buffer is
// already full is not counted, and the signal it coalesced into is still pending.
func (s *Subscriber) NotifyWorkload(podUID string) int {
	s.mu.Lock()
	s.workloadChanges = append(s.workloadChanges, podUID)
	subs := slices.Clone(s.subs)
	s.mu.Unlock()

	return notifyMatching(subs, func(sub *Subscription) bool {
		return sub.Kind == KindWorkloadMaterial && sub.Workload != nil && sub.Workload.PodUID == podUID
	})
}

// NotifyCertBundles signals the provider's live subscriptions that take X.509
// authorities, workload material and cert bundle alike, and returns how many
// received the signal. A JWT bundle subscription never matches, nor does another
// provider's.
func (s *Subscriber) NotifyCertBundles(providerArn string) int {
	s.mu.Lock()
	s.certBundleCalls++
	subs := slices.Clone(s.subs)
	s.mu.Unlock()

	return notifyMatching(subs, func(sub *Subscription) bool {
		return sub.wantsCertBundle() && sub.ProviderArn == providerArn
	})
}

// NotifyJWTBundles signals the live JWT bundle subscriptions of the provider and
// returns how many received the signal. No other kind matches, which is what
// makes a JWT key roll invisible to the streams serving SVIDs.
func (s *Subscriber) NotifyJWTBundles(providerArn string) int {
	s.mu.Lock()
	s.jwtBundleCalls++
	subs := slices.Clone(s.subs)
	s.mu.Unlock()

	return notifyMatching(subs, func(sub *Subscription) bool {
		return sub.Kind == KindJWTBundles && sub.ProviderArn == providerArn
	})
}

// notifyMatching signals every subscription match reports true for and returns
// how many took the signal.
func notifyMatching(subs []*Subscription, match func(*Subscription) bool) int {
	notified := 0
	for _, sub := range subs {
		if !match(sub) {
			continue
		}
		if sub.notify() {
			notified++
		}
	}
	return notified
}

// Subscriptions returns a copy of the subscriptions handed out so far, in
// subscribe order and including released ones, so it is safe to read while
// another goroutine is calling the fake. The Subscription values themselves are
// shared and safe to use concurrently.
func (s *Subscriber) Subscriptions() []*Subscription {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.subs)
}

// SubscribeCalls reports how many times any of the three Subscribe methods has
// been called, Func included. A call woken by Release is counted when it is next
// scheduled, and by then its Subscription is already recorded.
func (s *Subscriber) SubscribeCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.subscribeCalls
}

// WorkloadChanges reports the pod UID of every per-pod publish, in call order.
//
// It records UIDs rather than counting calls because that is what the material
// tiers are asserted on: T7 publishes once per successful store with the pod's own
// UID and not at all on a failed renewal, which a count cannot tell apart.
func (s *Subscriber) WorkloadChanges() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.workloadChanges)
}

// CertBundleCalls reports how many times the X.509 authority publish has been
// called, by either NotifyCertBundleChange or NotifyCertBundles.
func (s *Subscriber) CertBundleCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.certBundleCalls
}

// JWTBundleCalls reports how many times the JWT authority publish has been
// called, by either NotifyJWTBundleChange or NotifyJWTBundles.
func (s *Subscriber) JWTBundleCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jwtBundleCalls
}

// CancelCalls reports how many subscriptions have been released. The release func
// is idempotent, so releasing the same subscription twice counts once.
func (s *Subscriber) CancelCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cancelCalls
}

// LiveSubscriptions reports how many subscriptions still receive signals, that
// is, how many are neither released nor carrying a done ctx.
func (s *Subscriber) LiveSubscriptions() int {
	s.mu.Lock()
	subs := slices.Clone(s.subs)
	s.mu.Unlock()

	live := 0
	for _, sub := range subs {
		if sub.Live() {
			live++
		}
	}
	return live
}

// cancelSubscription is what the release func runs. Idempotent, stops all further
// delivery, and safe to call concurrently with the Notify methods. The
// subscription's lock is released before the fake's, so the two never nest.
func (s *Subscriber) cancelSubscription(sub *Subscription) {
	if !sub.cancel() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancelCalls++
}

// The fake serves all three sides of the notification tier, so one value can
// stand in for the read side a handler holds and for either publishing side a
// material tier holds.
var (
	_ workloadidentity.Subscriber       = &Subscriber{}
	_ workloadidentity.BundleNotifier   = &Subscriber{}
	_ workloadidentity.WorkloadNotifier = &Subscriber{}
)
