package x509

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

var (
	// promIssuanceTotal counts every certificate we ask STS for, including
	// replacements.
	promIssuanceTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: workloadidentity.MetricSvidIssuanceTotal,
		Help: "Count of SVID issuances, by credential format, outcome and error label.",
	}, []string{workloadidentity.LabelFormat, workloadidentity.LabelOutcome, workloadidentity.LabelError})

	// promIssuanceDuration is mostly the customer's certificate authority signing, not
	// agent time.
	promIssuanceDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    workloadidentity.MetricSvidIssuanceDuration,
		Help:    "Latency of SVID issuances, by credential format and outcome.",
		Buckets: prometheus.DefBuckets,
	}, []string{workloadidentity.LabelFormat, workloadidentity.LabelOutcome})

	// promRenewalTotal counts replacements separately from first-time requests.
	//
	// Only a replacement has an existing certificate to fall back on. A graph that
	// lumps them together cannot show replacements failing while every workload is
	// still being served, which is the case an operator wants to catch early.
	promRenewalTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: workloadidentity.MetricSvidRenewalTotal,
		Help: "Count of SVID renewals, by credential format, outcome and error label.",
	}, []string{workloadidentity.LabelFormat, workloadidentity.LabelOutcome, workloadidentity.LabelError})
)

// workload_identity_cache_total, the shared metric for cache hits and misses, is not
// registered here. The trust bundle tier does not register it either.
//
// It has a label for which cache a number came from, so every per-pod cache reports
// into the one metric, which means no single tier can set it up. The token cache
// already registers it, and registering the same metric twice is an error that crashes
// the agent at startup. Fixing that means changing more than this package.

// observeIssuance records one attempt. When it was a replacement it is counted on the
// renewal metric too, so a failing replacement does not look like a workload that
// never got a certificate in the first place.
func observeIssuance(err error, seconds float64, renewal bool) {
	outcome := workloadidentity.OutcomeSuccess
	if err != nil {
		outcome = workloadidentity.OutcomeFailure
	}
	label := wierrors.MetricLabel(err)

	promIssuanceTotal.WithLabelValues(workloadidentity.FormatX509SVID, outcome, label).Inc()
	promIssuanceDuration.WithLabelValues(workloadidentity.FormatX509SVID, outcome).Observe(seconds)
	if renewal {
		promRenewalTotal.WithLabelValues(workloadidentity.FormatX509SVID, outcome, label).Inc()
	}
}
