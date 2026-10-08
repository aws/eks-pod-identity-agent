package session

// Collectors for the session metric names declared in
// pkg/workloadidentity/metrics.go. Names, labels and values are taken from that
// package so a rename there is a compile error here. No label carries a pod,
// namespace or ServiceAccount, per the cardinality rule declared there.

import (
	"context"
	"errors"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// cacheTotalHelp is the help text of the shared workload_identity_cache_total
// counter. It must be byte-for-byte what every other tier registers it with,
// T4's included: the registry treats the same name with a different help string
// as a conflicting collector, not as the one already registered, so reusing it
// would fail.
const cacheTotalHelp = "Count of workload identity cache lookups, by tier and result."

var (
	sessionTotalOpts = prometheus.CounterOpts{
		Name: workloadidentity.MetricSessionTotal,
		Help: "Count of workload identity session exchanges with EKS Auth, by outcome and error label.",
	}
	sessionTotalLabels = []string{workloadidentity.LabelOutcome, workloadidentity.LabelError}

	sessionDurationOpts = prometheus.HistogramOpts{
		Name:    workloadidentity.MetricSessionDuration,
		Help:    "Latency of workload identity session exchanges with EKS Auth, by outcome.",
		Buckets: prometheus.DefBuckets,
	}
	sessionDurationLabels = []string{workloadidentity.LabelOutcome}

	cacheTotalOpts = prometheus.CounterOpts{
		Name: workloadidentity.MetricCacheTotal,
		Help: cacheTotalHelp,
	}
	cacheTotalLabels = []string{workloadidentity.LabelTier, workloadidentity.LabelResult}

	credentialSourceOpts = prometheus.CounterOpts{
		Name: workloadidentity.MetricCredentialSourceTotal,
		Help: "Count of credential refreshes by the source the pod's enrollment routed them to.",
	}
	credentialSourceLabels = []string{workloadidentity.LabelSource}
)

var (
	// promSessionTotal counts exchanges by outcome and taxonomy error label. An
	// exchange the tier refuses to cache, such as one for a pod that isn't
	// enrolled, counts as a failure, since it yields no session either.
	promSessionTotal = promauto.NewCounterVec(sessionTotalOpts, sessionTotalLabels)

	// promSessionDuration observes exchange latency by outcome, from the token
	// mint to the EKS Auth answer. A cache hit isn't an exchange and isn't
	// observed.
	promSessionDuration = promauto.NewHistogramVec(sessionDurationOpts, sessionDurationLabels)

	// promCredentialSource counts each refresh by the source RefreshWith routed
	// it to. It is owned here rather than by credcache because the enrollment
	// fork rule lives here, and it is the only place both outcomes of that rule
	// are visible.
	promCredentialSource = promauto.NewCounterVec(credentialSourceOpts, credentialSourceLabels)

	// promCacheTotal is the shared workload_identity_cache_total counter, which
	// other tiers register too. sessionCacheTotal registers it lazily, after
	// every package's init, and reuses a registration that came first. A promauto
	// call here would run before tokenminter's and make that one panic.
	promCacheTotalOnce sync.Once
	promCacheTotal     *prometheus.CounterVec
)

// sessionMetrics is the set of collectors a Provider emits on. A
// provider carries its own set so a test can give it unregistered collectors and
// read them without sharing the process-wide ones with any other test.
type sessionMetrics struct {
	exchanges *prometheus.CounterVec
	latency   *prometheus.HistogramVec
	cache     *prometheus.CounterVec
}

// defaultSessionMetrics returns the process-wide collectors, registering the
// shared cache counter on first use.
func defaultSessionMetrics() sessionMetrics {
	return sessionMetrics{
		exchanges: promSessionTotal,
		latency:   promSessionDuration,
		cache:     sessionCacheTotal(),
	}
}

// sessionCacheTotal returns the shared cache counter, registering it with the
// default registry the first time it's asked for.
func sessionCacheTotal() *prometheus.CounterVec {
	promCacheTotalOnce.Do(func() {
		promCacheTotal = registerCacheTotal(prometheus.DefaultRegisterer)
	})
	return promCacheTotal
}

// registerCacheTotal registers the shared cache counter with reg, or returns the
// one another tier already registered there. Any other failure, such as
// different help text, is logged and answered with an unregistered counter:
// losing a metric beats losing the workload identity socket.
func registerCacheTotal(reg prometheus.Registerer) *prometheus.CounterVec {
	counter := prometheus.NewCounterVec(cacheTotalOpts, cacheTotalLabels)
	err := reg.Register(counter)
	if err == nil {
		return counter
	}
	var already prometheus.AlreadyRegisteredError
	if errors.As(err, &already) {
		if existing, ok := already.ExistingCollector.(*prometheus.CounterVec); ok {
			return existing
		}
	}
	logger.FromContext(context.Background()).Errorf("Could not register %s, session cache lookups will not be exported: %v",
		workloadidentity.MetricCacheTotal, err)
	return counter
}

// observeExchange records one exchange on both exchange metrics.
func (m sessionMetrics) observeExchange(err error, seconds float64) {
	outcome := workloadidentity.OutcomeSuccess
	if err != nil {
		outcome = workloadidentity.OutcomeFailure
	}
	m.exchanges.WithLabelValues(outcome, wierrors.MetricLabel(err)).Inc()
	m.latency.WithLabelValues(outcome).Observe(seconds)
}

// observeCache records one session cache lookup's result: hit, miss or
// expired.
func (m sessionMetrics) observeCache(result string) {
	m.cache.WithLabelValues(workloadidentity.CacheTierSession, result).Inc()
}

// sourceMetrics is the collector the enrollment fork rule emits on. It is
// separate from sessionMetrics because RefreshWith is a package function the
// cache calls, not a method on a Provider, and a test needs to read its own
// counter rather than the process-wide one every other test also increments.
type sourceMetrics struct {
	sources *prometheus.CounterVec
}

// defaultSourceMetrics returns the process-wide credential source collector.
func defaultSourceMetrics() sourceMetrics {
	return sourceMetrics{sources: promCredentialSource}
}

// observeSource records one refresh routed to source, which is one of the
// workloadidentity.CredentialSource values.
func (m sourceMetrics) observeSource(source string) {
	m.sources.WithLabelValues(source).Inc()
}
