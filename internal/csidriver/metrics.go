package csidriver

// Collectors for the metric names declared in pkg/workloadidentity/metrics.go. The
// library serves the Node service and exports nothing, so every series here is ours.

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

var (
	// promVolumeMountTotal counts publishes and unpublishes. No pod label, per the
	// cardinality rule; the pod is in the log line beside it. The kubelet retries, so
	// failures read as a rate.
	promVolumeMountTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: workloadidentity.MetricVolumeMountTotal,
		Help: "Count of CSI publishes and unpublishes of the workload identity socket directory, by operation and outcome.",
	}, []string{workloadidentity.LabelOperation, workloadidentity.LabelOutcome})

	// promRegistrationTotal counts the kubelet's decision about this plugin.
	promRegistrationTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: workloadidentity.MetricRegistrationTotal,
		Help: "Count of kubelet plugin registration results for the workload identity CSI driver, by outcome.",
	}, []string{workloadidentity.LabelOutcome})
)

// recordRegistration emits what the kubelet reported. Taken from RegistrationStatus
// rather than an error, since the kubelet reports a refusal in a successful RPC.
func recordRegistration(registered bool) {
	promRegistrationTotal.WithLabelValues(outcome(registered)).Inc()
}

// recordMount emits the outcome of one publish or unpublish. The error becomes an
// outcome rather than a label: these are gRPC statuses, not members of the pkg/errors
// taxonomy, so an error label would read "unknown" every time.
func recordMount(operation string, err error) {
	promVolumeMountTotal.WithLabelValues(operation, outcome(err == nil)).Inc()
}

func outcome(ok bool) string {
	if ok {
		return workloadidentity.OutcomeSuccess
	}
	return workloadidentity.OutcomeFailure
}
