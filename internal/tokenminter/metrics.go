package tokenminter

// T4 collectors for the token-mint and token-cache metric names declared in
// pkg/workloadidentity/metrics.go. Names, labels and values are taken from that
// package so a rename there is a compile error here.

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

var (
	// promTokenMintTotal counts mints by outcome and, on failure, taxonomy error
	// label. A spike in token_mint_forbidden means the CSIDriver declaration is
	// missing.
	promTokenMintTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: workloadidentity.MetricTokenMintTotal,
		Help: "Count of ServiceAccount token mints, by outcome and error label.",
	}, []string{workloadidentity.LabelOutcome, workloadidentity.LabelError})

	// promTokenMintDuration observes mint latency by outcome; a cache hit is not
	// a mint and is not observed.
	promTokenMintDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    workloadidentity.MetricTokenMintDuration,
		Help:    "Latency of ServiceAccount token mints, by outcome.",
		Buckets: prometheus.DefBuckets,
	}, []string{workloadidentity.LabelOutcome})

	// promCacheTotal counts cache lookups, labelled to the token tier here.
	promCacheTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: workloadidentity.MetricCacheTotal,
		Help: "Count of workload identity cache lookups, by tier and result.",
	}, []string{workloadidentity.LabelTier, workloadidentity.LabelResult})
)

// observeMint records one mint attempt on both mint metrics.
func observeMint(err error, seconds float64) {
	outcome := workloadidentity.OutcomeSuccess
	if err != nil {
		outcome = workloadidentity.OutcomeFailure
	}
	promTokenMintTotal.WithLabelValues(outcome, wierrors.MetricLabel(err)).Inc()
	promTokenMintDuration.WithLabelValues(outcome).Observe(seconds)
}

// observeCache records one token cache lookup result.
func observeCache(result string) {
	promCacheTotal.WithLabelValues(workloadidentity.CacheTierToken, result).Inc()
}
