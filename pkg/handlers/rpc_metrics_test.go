package handlers

import (
	"context"
	stderrors "errors"
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// The collectors are process-wide, so every assertion here is a delta taken
// around one ObserveRPC call rather than an absolute value.

// rpcTotal reads one series of promRPCTotal.
func rpcTotal(rpc, outcome, errLabel string) float64 {
	return testutil.ToFloat64(promRPCTotal.WithLabelValues(rpc, outcome, errLabel))
}

// rpcDurationSample is one promRPCDuration series as the default registry
// exposes it: its sample count and sum, and the label names it carries.
type rpcDurationSample struct {
	count  uint64
	sum    float64
	labels []string
}

// rpcDuration gathers the promRPCDuration series for rpc and outcome from the
// default registry, which is also where promauto registered it, so a collector
// registered anywhere else fails here.
func rpcDuration(g Gomega, rpc, outcome string) rpcDurationSample {
	families, err := prometheus.DefaultGatherer.Gather()
	g.Expect(err).ToNot(HaveOccurred())
	for _, family := range families {
		if family.GetName() != workloadidentity.MetricRPCDuration {
			continue
		}
		for _, metric := range family.GetMetric() {
			values := map[string]string{}
			var names []string
			for _, pair := range metric.GetLabel() {
				values[pair.GetName()] = pair.GetValue()
				names = append(names, pair.GetName())
			}
			if values[workloadidentity.LabelRPC] == rpc && values[workloadidentity.LabelOutcome] == outcome {
				h := metric.GetHistogram()
				return rpcDurationSample{count: h.GetSampleCount(), sum: h.GetSampleSum(), labels: names}
			}
		}
	}
	return rpcDurationSample{}
}

// TestObserveRPC_SuccessIsLabelledNone pins a success as outcome success and
// error none, so it is distinguishable from a failure nobody classified.
func TestObserveRPC_SuccessIsLabelledNone(t *testing.T) {
	g := NewWithT(t)
	rpc := workloadidentity.RPCFetchJWTSVID

	success := rpcTotal(rpc, workloadidentity.OutcomeSuccess, errors.MetricLabelNone)
	unknown := rpcTotal(rpc, workloadidentity.OutcomeSuccess, errors.MetricLabelUnknown)

	ObserveRPC(rpc, nil, time.Millisecond)

	g.Expect(rpcTotal(rpc, workloadidentity.OutcomeSuccess, errors.MetricLabelNone) - success).To(Equal(1.0))
	g.Expect(rpcTotal(rpc, workloadidentity.OutcomeSuccess, errors.MetricLabelUnknown)).To(Equal(unknown))
}

// TestObserveRPC_TaxonomyErrorTakesItsMetricLabel pins that a failure is counted
// under the member's own label, annotated and wrapped as the tiers return it, so
// a dashboard can split refusals from outages by kind.
func TestObserveRPC_TaxonomyErrorTakesItsMetricLabel(t *testing.T) {
	rpc := workloadidentity.RPCFetchX509SVID

	for _, member := range errors.WorkloadIdentityTaxonomy() {
		t.Run(member.MetricLabel(), func(t *testing.T) {
			for _, err := range []error{
				member,
				member.Wrapf(stderrors.New("remote said no"), "serving %s", "uid-a"),
				fmt.Errorf("building a response: %w", member.Wrapf(nil, "annotated")),
			} {
				g := NewWithT(t)

				before := rpcTotal(rpc, workloadidentity.OutcomeFailure, member.MetricLabel())
				unknown := rpcTotal(rpc, workloadidentity.OutcomeFailure, errors.MetricLabelUnknown)

				ObserveRPC(rpc, err, time.Millisecond)

				g.Expect(rpcTotal(rpc, workloadidentity.OutcomeFailure, member.MetricLabel())-before).To(Equal(1.0), "%v", err)
				g.Expect(rpcTotal(rpc, workloadidentity.OutcomeFailure, errors.MetricLabelUnknown)).To(Equal(unknown), "%v", err)
			}
		})
	}
}

// TestObserveRPC_HandlerBuiltStatusIsLabelledNone pins the fallback for a refusal
// a handler builds as a status with no taxonomy member, such as SDS answering
// NotFound for a resource it does not serve: a failure labelled none, since
// counting it unknown would hide the errors that are unexpected.
func TestObserveRPC_HandlerBuiltStatusIsLabelledNone(t *testing.T) {
	rpc := workloadidentity.RPCStreamSecrets

	for name, err := range map[string]error{
		"bare":    status.Error(codes.NotFound, "no such resource"),
		"wrapped": fmt.Errorf("sending: %w", status.Error(codes.NotFound, "no such resource")),
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)

			none := rpcTotal(rpc, workloadidentity.OutcomeFailure, errors.MetricLabelNone)
			unknown := rpcTotal(rpc, workloadidentity.OutcomeFailure, errors.MetricLabelUnknown)

			ObserveRPC(rpc, err, time.Millisecond)

			g.Expect(rpcTotal(rpc, workloadidentity.OutcomeFailure, errors.MetricLabelNone) - none).To(Equal(1.0))
			g.Expect(rpcTotal(rpc, workloadidentity.OutcomeFailure, errors.MetricLabelUnknown)).To(Equal(unknown))
		})
	}
}

// TestObserveRPC_UnclassifiedErrorIsLabelledUnknown pins the one label that means
// a bug: an error outside the taxonomy and not built by a handler, which is the
// failure answered Internal.
func TestObserveRPC_UnclassifiedErrorIsLabelledUnknown(t *testing.T) {
	rpc := workloadidentity.RPCFetchJWTBundles

	for name, err := range map[string]error{
		"bare":     stderrors.New("something nobody classified"),
		"wrapped":  fmt.Errorf("marshalling: %w", stderrors.New("bad key")),
		"deadline": context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)

			unknown := rpcTotal(rpc, workloadidentity.OutcomeFailure, errors.MetricLabelUnknown)
			none := rpcTotal(rpc, workloadidentity.OutcomeFailure, errors.MetricLabelNone)

			ObserveRPC(rpc, err, time.Millisecond)

			g.Expect(rpcTotal(rpc, workloadidentity.OutcomeFailure, errors.MetricLabelUnknown) - unknown).To(Equal(1.0))
			g.Expect(rpcTotal(rpc, workloadidentity.OutcomeFailure, errors.MetricLabelNone)).To(Equal(none))
		})
	}
}

// TestObserveRPC_DurationObservedUnderRPCAndOutcome pins the histogram: one sample
// of elapsed in seconds per call, under the rpc and outcome labels pkg/workloadidentity
// declares for it and no error label.
func TestObserveRPC_DurationObservedUnderRPCAndOutcome(t *testing.T) {
	g := NewWithT(t)
	rpc := workloadidentity.RPCFetchX509Bundles

	ObserveRPC(rpc, nil, 0)
	ObserveRPC(rpc, errors.ErrBundleRefused, 0)
	success := rpcDuration(g, rpc, workloadidentity.OutcomeSuccess)
	failure := rpcDuration(g, rpc, workloadidentity.OutcomeFailure)

	ObserveRPC(rpc, nil, 1500*time.Millisecond)

	afterSuccess := rpcDuration(g, rpc, workloadidentity.OutcomeSuccess)
	g.Expect(afterSuccess.count - success.count).To(Equal(uint64(1)))
	g.Expect(afterSuccess.sum - success.sum).To(BeNumerically("~", 1.5, 1e-9))
	g.Expect(rpcDuration(g, rpc, workloadidentity.OutcomeFailure).count).To(Equal(failure.count))
	g.Expect(afterSuccess.labels).To(ConsistOf(workloadidentity.LabelRPC, workloadidentity.LabelOutcome))

	ObserveRPC(rpc, errors.ErrBundleRefused, 250*time.Millisecond)

	afterFailure := rpcDuration(g, rpc, workloadidentity.OutcomeFailure)
	g.Expect(afterFailure.count - failure.count).To(Equal(uint64(1)))
	g.Expect(afterFailure.sum - failure.sum).To(BeNumerically("~", 0.25, 1e-9))
	g.Expect(rpcDuration(g, rpc, workloadidentity.OutcomeSuccess).count).To(Equal(afterSuccess.count))
}

// TestObserveRPC_CountsUnderTheDeclaredNames pins that the counter is registered
// under MetricRPCTotal with the rpc, outcome and error labels, so T9's
// subscription metrics and these spell the dimensions alike.
func TestObserveRPC_CountsUnderTheDeclaredNames(t *testing.T) {
	g := NewWithT(t)

	ObserveRPC(workloadidentity.RPCStreamSecrets, errors.ErrNotEnrolled, time.Millisecond)

	families, err := prometheus.DefaultGatherer.Gather()
	g.Expect(err).ToNot(HaveOccurred())
	var found bool
	for _, family := range families {
		if family.GetName() != workloadidentity.MetricRPCTotal {
			continue
		}
		for _, metric := range family.GetMetric() {
			values := map[string]string{}
			for _, pair := range metric.GetLabel() {
				values[pair.GetName()] = pair.GetValue()
			}
			if values[workloadidentity.LabelRPC] != workloadidentity.RPCStreamSecrets {
				continue
			}
			g.Expect(values).To(HaveLen(3))
			g.Expect(values).To(HaveKey(workloadidentity.LabelOutcome))
			g.Expect(values).To(HaveKey(workloadidentity.LabelError))
			if values[workloadidentity.LabelError] == errors.ErrNotEnrolled.MetricLabel() {
				found = true
			}
		}
	}
	g.Expect(found).To(BeTrue(), "no %s series for %s", workloadidentity.MetricRPCTotal, workloadidentity.RPCStreamSecrets)
}
