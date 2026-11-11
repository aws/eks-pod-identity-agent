package handlers

// Collectors for the RPC metric names declared in pkg/workloadidentity. They live
// here, beside the status mapping, because the Workload API and SDS
// handlers both emit them and a second promauto registration of a name panics.

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/grpc/status"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

var (
	// promRPCTotal counts answered RPCs. Its error label is unknown only for a
	// failure nobody classified, which is one answered Internal, so an unexpected
	// error is visible apart from the denials.
	promRPCTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: workloadidentity.MetricRPCTotal,
		Help: "Count of answered workload identity RPCs, by RPC, outcome and error label.",
	}, []string{workloadidentity.LabelRPC, workloadidentity.LabelOutcome, workloadidentity.LabelError})

	// promRPCDuration observes how long a caller waited for its answer: the whole
	// call for a unary RPC, the time to the first response for a stream.
	promRPCDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    workloadidentity.MetricRPCDuration,
		Help:    "Latency of workload identity RPCs to their answer, by RPC and outcome.",
		Buckets: prometheus.DefBuckets,
	}, []string{workloadidentity.LabelRPC, workloadidentity.LabelOutcome})

	// promRPCRetryTotal counts each retry of a step that failed retryably, by the
	// error that caused it, so a stream blocked waiting for its identity is
	// visible while it waits and after its client gives up.
	promRPCRetryTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: workloadidentity.MetricRPCRetryTotal,
		Help: "Count of retries of a workload identity RPC step after a retryable error, by RPC and error label.",
	}, []string{workloadidentity.LabelRPC, workloadidentity.LabelError})
)

// observeRetry records one retry of an RPC step that failed with err.
func observeRetry(rpc string, err error) {
	promRPCRetryTotal.WithLabelValues(rpc, rpcErrorLabel(err)).Inc()
}

// ObserveRPC records one answer on both RPC metrics: a unary call's result, or a
// stream's first response or the error that ended it before one. err is the
// error before status mapping, and elapsed is how long the caller waited for it.
func ObserveRPC(rpc string, err error, elapsed time.Duration) {
	outcome := workloadidentity.OutcomeSuccess
	if err != nil {
		outcome = workloadidentity.OutcomeFailure
	}
	promRPCTotal.WithLabelValues(rpc, outcome, rpcErrorLabel(err)).Inc()
	promRPCDuration.WithLabelValues(rpc, outcome).Observe(elapsed.Seconds())
}

// rpcErrorLabel is errors.MetricLabel, except that a status a handler built for a
// refusal the taxonomy has no member for is MetricLabelNone, since counting it
// unknown would hide the unexpected errors. The Workload API handler builds none.
func rpcErrorLabel(err error) string {
	if _, ok := errors.AsWorkloadIdentityError(err); !ok && err != nil {
		if _, isStatus := status.FromError(err); isStatus {
			return errors.MetricLabelNone
		}
	}
	return errors.MetricLabel(err)
}
