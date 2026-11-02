package notify

// Collectors for the subscription and notification metric names declared in
// pkg/workloadidentity/metrics.go. Names, labels and values are taken from that
// package so a rename there is a compile error here.

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

var (
	// promSubscriptionsActive gauges open subscriptions by RPC. A value climbing
	// without bound is a handler not releasing on client disconnect.
	promSubscriptionsActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: workloadidentity.MetricSubscriptionsActive,
		Help: "Open workload identity stream subscriptions, by RPC.",
	}, []string{workloadidentity.LabelRPC})

	// promNotificationTotal counts notifications by RPC and delivery. Both
	// delivery values are normal; a sustained coalesced rate means that RPC's
	// streams read slower than the material changes.
	promNotificationTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: workloadidentity.MetricNotificationTotal,
		Help: "Count of change notifications delivered to workload identity streams, by RPC and delivery.",
	}, []string{workloadidentity.LabelRPC, workloadidentity.LabelDelivery})
)

// rpcMetrics holds one RPC's collectors with the label already applied, resolved
// once at wiring time so the publish path does no map lookup and no allocation
// per subscription. Safe to use concurrently.
type rpcMetrics struct {
	// active is the subscription gauge.
	active prometheus.Gauge
	// signalled counts notifications that landed in an empty channel.
	signalled prometheus.Counter
	// coalesced counts notifications that replaced an unread one.
	coalesced prometheus.Counter
}

// metricsForRPC binds the collectors for one RPC label value.
func metricsForRPC(rpc string) *rpcMetrics {
	return &rpcMetrics{
		active:    promSubscriptionsActive.WithLabelValues(rpc),
		signalled: promNotificationTotal.WithLabelValues(rpc, workloadidentity.DeliverySignalled),
		coalesced: promNotificationTotal.WithLabelValues(rpc, workloadidentity.DeliveryCoalesced),
	}
}
