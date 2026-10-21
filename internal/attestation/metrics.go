package attestation

// Attestation metrics. T3 owns the collectors for the two attestation metric
// names declared in pkg/workloadidentity/metrics.go and registers them against
// those names here. The names and label names are taken from that package rather
// than written out again, so a rename there is a compile error here rather than a
// silent divergence.

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// reasonNone is the LabelReason value on a successful attestation. The reason
// label only ever carries a failure mode, so a success needs a distinct value
// rather than an empty string, mirroring how errors.MetricLabel uses "none" for
// a nil error.
const reasonNone = "none"

var (
	// promAttestationTotal counts attestation attempts by outcome and, on
	// failure, by the reason it was refused. The two security-relevant reasons,
	// pod_not_in_store and pod_node_mismatch, are what an operator alarms on.
	promAttestationTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: workloadidentity.MetricAttestationTotal,
		Help: "Count of workload attestation attempts, by outcome and failure reason.",
	}, []string{workloadidentity.LabelOutcome, workloadidentity.LabelReason})

	// promAttestationDuration observes attestation latency by outcome.
	promAttestationDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    workloadidentity.MetricAttestationDuration,
		Help:    "Latency of workload attestation, by outcome.",
		Buckets: prometheus.DefBuckets,
	}, []string{workloadidentity.LabelOutcome})
)
