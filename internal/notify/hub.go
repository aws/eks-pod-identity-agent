// Package notify lets an open stream learn that the material it serves has
// changed, without polling and without the producing tier knowing which streams
// exist. The handlers would otherwise each write their own fan-out.
//
// Delivery semantics:
//
//   - Latest value wins. Depth-one channel, drained before each write, so a slow
//     subscriber sees the newest state and never a queue of superseded ones.
//   - No payload. The subscriber wakes and re-reads its source.
//   - Publishing never blocks and allocates nothing.
//   - Release is idempotent and also happens with the context.
//   - Nothing is required to observe a signal.
//
// One hub serves the node, indexed by pod for a workload's own material and by
// provider for each authority set. One hub per provider was rejected: a stream
// serving SVIDs needs its pod's renewals and its provider's anchors on one
// channel, the per-pod publish would have to resolve a pod to a provider to find
// the right hub, and a per-provider hub's lifetime would follow cache eviction
// rather than the streams it serves.
//
// Out of scope: keeping a provider cached while a stream waits, which is the
// BundleSource lease a stream takes beside its subscription, and deduplication,
// which belongs to the handler that knows what it last sent.
package notify

import (
	"context"
	"sync"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// Hub holds every live subscription on the node and is the publishing side of
// the tier. The material tiers hold it as a workloadidentity.BundleNotifier or
// WorkloadNotifier; handlers hold only the Subscriber that ForRPC returns.
//
// One index per publish method, so a publish walks exactly its audience and
// tests nothing as it goes.
type Hub struct {
	mu sync.Mutex
	// all is every live subscription. Membership is the liveness flag, which is
	// what makes release idempotent without a second piece of state. Nothing
	// publishes to it.
	all map[*subscription]struct{}
	// byPod is the audience of NotifyWorkloadChange.
	byPod map[string]map[*subscription]struct{}
	// byProviderCert is the audience of NotifyCertBundleChange: workload
	// material and cert bundle subscriptions.
	byProviderCert map[string]map[*subscription]struct{}
	// byProviderJWT is the audience of NotifyJWTBundleChange. Separate from
	// byProviderCert rather than filtered out of it, so a JWT key roll never
	// reaches the streams serving SVIDs.
	byProviderJWT map[string]map[*subscription]struct{}
}

// NewHub returns an empty Hub. It owns no goroutine and needs no shutdown.
func NewHub() *Hub {
	return &Hub{
		all:            make(map[*subscription]struct{}),
		byPod:          make(map[string]map[*subscription]struct{}),
		byProviderCert: make(map[string]map[*subscription]struct{}),
		byProviderJWT:  make(map[string]map[*subscription]struct{}),
	}
}

// subscription is one open stream's registration.
//
// podUID and providerArn exist only so release can find it in the indexes it was
// added to. Being in an index is what decides whether it is signalled.
type subscription struct {
	// podUID is empty for a bundle-only subscription.
	podUID string
	// providerArn comes from the caller's session.
	providerArn string
	// ch is depth one and never closed: a closed channel receives forever, which
	// would spin a handler racing its own teardown. Build it with
	// newSubscription rather than here, so the depth stays in one place.
	ch chan struct{}
	// metrics is shared by every subscription of this RPC.
	metrics *rpcMetrics
}

// newSubscription is the only way a subscription is built, so the channel depth
// that latest-value-wins depends on is set in one place rather than at each call
// site. It does not prime the channel; subscribe does, where the ordering against
// registration and a done context is visible.
func newSubscription(podUID, providerArn string, metrics *rpcMetrics) *subscription {
	return &subscription{
		podUID:      podUID,
		providerArn: providerArn,
		// Depth one. A deeper buffer would queue superseded signals behind fresh
		// ones, which is the one thing this tier promises not to do.
		ch:      make(chan struct{}, 1),
		metrics: metrics,
	}
}

// signalLocked delivers one notification. The caller must hold Hub.mu, which
// makes the drain and the write one step against other publishers so the channel
// cannot end up holding two signals.
//
// A concurrent reader is harmless: it takes either the drained signal or the one
// written here, and wakes to re-read the newest state either way.
func (s *subscription) signalLocked() {
	// The drain is also what tells the two delivery labels apart.
	select {
	case <-s.ch:
		s.metrics.coalesced.Inc()
	default:
		s.metrics.signalled.Inc()
	}

	// The drain above left room, so this send always lands. The default arm is
	// only there to keep the send non-blocking; it is not permission to call this
	// without Hub.mu, which the Locked suffix requires.
	select {
	case s.ch <- struct{}{}:
	default:
	}
}

// Subscriber is the view of a Hub one RPC's handler subscribes through. It
// carries no publishing method, so a handler cannot wake another pod's stream or
// another provider's.
type Subscriber struct {
	hub     *Hub
	metrics *rpcMetrics
}

// ForRPC returns the Subscriber for one RPC, where rpc is that RPC's
// workloadidentity LabelRPC value.
//
// Binding the label here rather than on every Subscribe keeps it off the
// Subscriber interface and makes it impossible to get right on one call path and
// wrong on another. Call it once per RPC at wiring time; an empty rpc is a wiring
// bug and panics rather than producing an unlabelled series.
func (h *Hub) ForRPC(rpc string) *Subscriber {
	if rpc == "" {
		panic("notify: ForRPC called with an empty rpc label")
	}
	return &Subscriber{hub: h, metrics: metricsForRPC(rpc)}
}

// SubscribeToWorkloadMaterial is woken by the workload's own credential changes
// and by its provider's X.509 rotations, the two things a stream serving an SVID
// beside its peers' anchors has to react to.
//
// A nil workload or an empty pod UID gets no per-pod signal. Every caller
// attests before subscribing, so that is degenerate rather than supported.
func (s *Subscriber) SubscribeToWorkloadMaterial(ctx context.Context, w *workloadidentity.Workload, providerArn string) (<-chan struct{}, func()) {
	podUID := ""
	if w != nil {
		podUID = w.PodUID
	}
	return s.hub.subscribe(ctx, s.metrics, podUID, providerArn, func(h *Hub, sub *subscription) {
		addLocked(h.byPod, podUID, sub)
		addLocked(h.byProviderCert, providerArn, sub)
	})
}

// SubscribeToCertBundles is woken only by the provider's X.509 rotations.
func (s *Subscriber) SubscribeToCertBundles(ctx context.Context, providerArn string) (<-chan struct{}, func()) {
	return s.hub.subscribe(ctx, s.metrics, "", providerArn, func(h *Hub, sub *subscription) {
		addLocked(h.byProviderCert, providerArn, sub)
	})
}

// SubscribeToJWTBundles is woken only by the provider's JWT rotations.
func (s *Subscriber) SubscribeToJWTBundles(ctx context.Context, providerArn string) (<-chan struct{}, func()) {
	return s.hub.subscribe(ctx, s.metrics, "", providerArn, func(h *Hub, sub *subscription) {
		addLocked(h.byProviderJWT, providerArn, sub)
	})
}

// subscribe registers one subscription in the audiences index puts it in and
// returns its channel and release func. The index func is the only thing that
// differs between the three Subscribe methods.
//
// Nothing is rejected here. A subscribe that cannot fail keeps the handler's
// error mapping at the call that produced a missing value, which for a missing
// provider is the session read returning ErrNotEnrolled.
func (h *Hub) subscribe(ctx context.Context, metrics *rpcMetrics, podUID, providerArn string, index func(*Hub, *subscription)) (<-chan struct{}, func()) {
	sub := newSubscription(podUID, providerArn, metrics)

	// Under a done context there is nobody to wake, so register nothing rather
	// than leave an entry for every publish to walk until the ctx hook runs. The
	// channel is still returned and never signalled; the handler's own context
	// ends its loop.
	if ctx.Err() != nil {
		return sub.ch, func() {}
	}

	// Prime the channel, so a handler's wait-then-send loop produces the initial
	// response instead of serving nothing until the first real change. The send
	// is safe unguarded because no publish can reach the subscription yet, and a
	// publish arriving later replaces this signal rather than queueing behind it.
	//
	// Deliberately not counted: the prime is not a change, and counting it would
	// put one signalled per stream open into a rate-of-change counter.
	sub.ch <- struct{}{}

	// index is supplied by the caller, so the unlock is deferred: a panic in it
	// would otherwise leave the mutex held and deadlock every later publish.
	func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.all[sub] = struct{}{}
		index(h, sub)
	}()

	metrics.active.Inc()

	// context.AfterFunc rather than a goroutine parked on ctx.Done(), which would
	// be a goroutine per open stream. stop deregisters the hook so an explicit
	// release does not leave it on a long-lived context.
	stop := context.AfterFunc(ctx, func() { h.release(sub) })
	release := func() {
		stop()
		h.release(sub)
	}
	return sub.ch, release
}

// release ends one subscription. Idempotent, and safe concurrently with a
// publish, because membership in h.all decides whether there is anything to
// remove. Only the call that removed it touches the gauge, so an explicit release
// racing the ctx hook moves it once.
func (h *Hub) release(sub *subscription) {
	var live bool
	func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if _, live = h.all[sub]; !live {
			return
		}
		delete(h.all, sub)
		// A subscription is in at most one provider index and removeLocked
		// tolerates an absent entry, so release need not remember which.
		removeLocked(h.byPod, sub.podUID, sub)
		removeLocked(h.byProviderCert, sub.providerArn, sub)
		removeLocked(h.byProviderJWT, sub.providerArn, sub)
	}()

	if !live {
		return
	}

	sub.metrics.active.Dec()

	// Drain what was pending. Nothing can refill it now, so a handler racing its
	// own teardown waits on its context instead of being woken to re-read a
	// stream it is already returning from.
	select {
	case <-sub.ch:
	default:
	}
}

// NotifyWorkloadChange signals the pod's workload material subscriptions. A pod
// with no open stream costs one map lookup and is not an error.
func (h *Hub) NotifyWorkloadChange(podUID string) {
	if podUID == "" {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	for sub := range h.byPod[podUID] {
		sub.signalLocked()
	}
}

// NotifyCertBundleChange signals the provider's subscriptions that take X.509
// authorities: workload material and cert bundle streams.
func (h *Hub) NotifyCertBundleChange(providerArn string) {
	h.notifyProvider(h.byProviderCert, providerArn)
}

// NotifyJWTBundleChange signals the provider's JWT bundle subscriptions.
//
// Separate from NotifyCertBundleChange because the two sets rotate
// independently, so a JWT key roll does not wake every SVID stream on the node.
// A fetch that changed both calls each once, and no subscription is in both
// audiences.
func (h *Hub) NotifyJWTBundleChange(providerArn string) {
	h.notifyProvider(h.byProviderJWT, providerArn)
}

// notifyProvider signals every subscription index holds for the provider.
//
// One lock across the fan-out serialises it against subscribes and releases.
// Each signal is a drain, a non-blocking send and an atomic increment, and the
// walk allocates nothing, which matters because a rotation can touch every stream
// of a provider at once. If the lock becomes the bottleneck, shard the hub rather
// than copying the index, which would allocate here.
func (h *Hub) notifyProvider(index map[string]map[*subscription]struct{}, providerArn string) {
	if providerArn == "" {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	for sub := range index[providerArn] {
		sub.signalLocked()
	}
}

// addLocked records sub under key, creating the key's set on first use. An empty
// key is dropped: no publish accepts one, so indexing it would leave an entry
// nothing reads and removeLocked never clears. The caller holds Hub.mu.
func addLocked(index map[string]map[*subscription]struct{}, key string, sub *subscription) {
	if key == "" {
		return
	}
	subs := index[key]
	if subs == nil {
		subs = make(map[*subscription]struct{})
		index[key] = subs
	}
	subs[sub] = struct{}{}
}

// removeLocked drops sub from under key, and drops the key with its last
// subscription so the index does not grow with churn. An empty key, or a sub that
// was never here, is a no-op. The caller holds Hub.mu.
func removeLocked(index map[string]map[*subscription]struct{}, key string, sub *subscription) {
	if key == "" {
		return
	}
	subs := index[key]
	if subs == nil {
		return
	}
	delete(subs, sub)
	if len(subs) == 0 {
		delete(index, key)
	}
}

// The hub implements all three sides: the publishing interfaces directly, the
// read side through ForRPC.
var (
	_ workloadidentity.BundleNotifier   = (*Hub)(nil)
	_ workloadidentity.WorkloadNotifier = (*Hub)(nil)
	_ workloadidentity.Subscriber       = (*Subscriber)(nil)
)
