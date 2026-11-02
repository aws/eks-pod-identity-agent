package bundle

// workload_identity_cache_total is not registered here: every tier shares it,
// and a second promauto registration of the same name panics at init. This
// tier's snapshot is either there or not, so a hit ratio would say nothing the
// fetch metrics do not.

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

var (
	// promBundleFetchTotal counts GetTrustBundles fetches by outcome and
	// taxonomy error label. A response the tier refuses to serve counts as a
	// failed fetch, since it yields no new trust material either.
	promBundleFetchTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: workloadidentity.MetricBundleFetchTotal,
		Help: "Count of trust bundle fetches, by outcome and error label.",
	}, []string{workloadidentity.LabelOutcome, workloadidentity.LabelError})

	// promBundleFetchDuration observes fetch latency by outcome.
	promBundleFetchDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    workloadidentity.MetricBundleFetchDuration,
		Help:    "Latency of trust bundle fetches, by outcome.",
		Buckets: prometheus.DefBuckets,
	}, []string{workloadidentity.LabelOutcome})

	// promBundleChangeTotal counts changes in the authority set, which is also
	// the number of broadcasts the tier has sent. A reordered or reformatted
	// document is not a change and does not count.
	promBundleChangeTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: workloadidentity.MetricBundleChangeTotal,
		Help: "Count of detected trust bundle authority changes.",
	})
)

// observeFetch records one fetch on both fetch metrics.
func observeFetch(err error, seconds float64) {
	outcome := workloadidentity.OutcomeSuccess
	if err != nil {
		outcome = workloadidentity.OutcomeFailure
	}
	promBundleFetchTotal.WithLabelValues(outcome, wierrors.MetricLabel(err)).Inc()
	promBundleFetchDuration.WithLabelValues(outcome).Observe(seconds)
}

// observeChange records one authority set change.
func observeChange() {
	promBundleChangeTotal.Inc()
}
