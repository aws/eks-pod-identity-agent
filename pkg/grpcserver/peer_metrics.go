package grpcserver

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// promPeerPinTotal counts handshakes by whether the peer was pinned and, if not,
// why. peer_pid_zero is the one to alarm on: the agent is missing hostPID.
var promPeerPinTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: workloadidentity.MetricPeerPinTotal,
	Help: "Count of workload identity connections by whether their peer process was pinned, and why not.",
}, []string{workloadidentity.LabelOutcome, workloadidentity.LabelReason})

func countPin(err error) {
	if err == nil {
		promPeerPinTotal.WithLabelValues(workloadidentity.OutcomeSuccess, "none").Inc()
		return
	}
	promPeerPinTotal.WithLabelValues(workloadidentity.OutcomeFailure, pinReason(err)).Inc()
}

func pinReason(err error) string {
	switch {
	case errors.Is(err, errNotUnixSocket):
		return workloadidentity.ReasonNotUnixSocket
	case errors.Is(err, errPeerPIDZero):
		return workloadidentity.ReasonPeerPIDZero
	case errors.Is(err, errPeerGone):
		return workloadidentity.ReasonPeerGone
	case errors.Is(err, errLivenessRecheckFailed):
		return workloadidentity.ReasonLivenessRecheckFailed
	default:
		return workloadidentity.ReasonPeerCredFailed
	}
}
