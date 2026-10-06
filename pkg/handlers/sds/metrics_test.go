package sds

import (
	"context"
	"testing"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	pkgerrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// rpcTotal reads one series of workload_identity_rpc_total off the default
// registry, where promauto registered it, returning zero for a series that does
// not exist yet.
//
// Read by name through the gatherer rather than through the collector, because the
// collector is unexported in pkg/handlers and this package is deliberately not
// given a second registration of the same metric name, which would panic.
func rpcTotal(t *testing.T, rpc, outcome, errLabel string) float64 {
	t.Helper()

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gathering metrics: %v", err)
	}

	for _, family := range families {
		if family.GetName() != workloadidentity.MetricRPCTotal {
			continue
		}
		for _, metric := range family.GetMetric() {
			labels := map[string]string{}
			for _, pair := range metric.GetLabel() {
				labels[pair.GetName()] = pair.GetValue()
			}
			if labels[workloadidentity.LabelRPC] == rpc &&
				labels[workloadidentity.LabelOutcome] == outcome &&
				labels[workloadidentity.LabelError] == errLabel {
				return metric.GetCounter().GetValue()
			}
		}
	}

	return 0
}

// The collectors are process-wide and every test in this package shares them, so
// each assertion below takes a before and after reading of its own series rather
// than expecting an absolute count.

// TestStreamSecrets_CountsOneRPCAtItsFirstResponse is the accounting that matters
// for the shared metric: a stream is one RPC however many responses it sends, so
// the counter stays a stream count here as it is on the Workload API. Counting per
// send would make the same series mean two different things depending on which
// interface produced it.
func TestStreamSecrets_CountsOneRPCAtItsFirstResponse(t *testing.T) {
	g := NewWithT(t)

	before := rpcTotal(t, workloadidentity.RPCStreamSecrets, workloadidentity.OutcomeSuccess, pkgerrors.MetricLabelNone)

	h := newHarness(t)
	ts := h.open(t)

	// Two resources, so two responses, Envoy's SdsApi taking one each.
	ts.request(t, []string{ResourceNameTLSCertificate, ResourceNameOwnValidationContext}, "")
	_ = ts.nextResponse(t)
	_ = ts.nextResponse(t)

	g.Expect(rpcTotal(t, workloadidentity.RPCStreamSecrets, workloadidentity.OutcomeSuccess, pkgerrors.MetricLabelNone)-before).
		To(Equal(1.0), "two responses on one stream must count once")

	// A renewal pushed later is still the same RPC.
	h.certs.SetResult([]*x509svid.SVID{newTestSVID(t, "spiffe://example.org/workload")}, nil)
	g.Eventually(func() int {
		return h.subs.NotifyWorkload("pod-one")
	}).Should(Equal(1))
	_ = ts.nextResponse(t)

	g.Expect(rpcTotal(t, workloadidentity.RPCStreamSecrets, workloadidentity.OutcomeSuccess, pkgerrors.MetricLabelNone)-before).
		To(Equal(1.0), "a pushed rotation must not count a second RPC")
}

// TestStreamSecrets_RefusalCarriesTheTaxonomyErrorLabel is why the handler returns
// tier errors unmapped and lets one place map them: a status built at the point of
// failure would reach ObserveRPC with its taxonomy member already erased, and
// every refusal would be labelled the same.
func TestStreamSecrets_RefusalCarriesTheTaxonomyErrorLabel(t *testing.T) {
	g := NewWithT(t)

	label := pkgerrors.ErrNotEnrolled.MetricLabel()
	before := rpcTotal(t, workloadidentity.RPCStreamSecrets, workloadidentity.OutcomeFailure, label)

	h := newHarness(t)
	h.providers.Err = pkgerrors.ErrNotEnrolled

	ts := h.open(t)
	ts.request(t, []string{ResourceNameOwnValidationContext}, "")
	_ = ts.streamError(t)

	g.Expect(rpcTotal(t, workloadidentity.RPCStreamSecrets, workloadidentity.OutcomeFailure, label) - before).
		To(Equal(1.0))
}

// TestStreamSecrets_DisconnectCountsNoFailure pins that a sidecar going away is
// not an agent failure. The stream was already counted at its first response, and
// the context ending must not add a second observation.
func TestStreamSecrets_DisconnectCountsNoFailure(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	ts := h.open(t)
	ts.request(t, []string{ResourceNameOwnValidationContext}, "")
	_ = ts.nextResponse(t)

	// Every failure series for this RPC, so the assertion does not depend on
	// which error a disconnect might have been mistaken for.
	failuresBefore := streamSecretsFailures(t)

	ts.cancel()
	g.Eventually(h.subs.LiveSubscriptions).Should(BeZero())

	g.Expect(streamSecretsFailures(t)).To(Equal(failuresBefore))
}

// TestFetchSecrets_CountsItsOwnRPC pins that the unary method reports under its
// own label rather than borrowing the stream's, which is what makes the two
// legible apart on a dashboard.
func TestFetchSecrets_CountsItsOwnRPC(t *testing.T) {
	g := NewWithT(t)

	before := rpcTotal(t, workloadidentity.RPCFetchSecrets, workloadidentity.OutcomeSuccess, pkgerrors.MetricLabelNone)
	streamBefore := rpcTotal(t, workloadidentity.RPCStreamSecrets, workloadidentity.OutcomeSuccess, pkgerrors.MetricLabelNone)

	h := newHarness(t)

	_, err := h.client.FetchSecrets(context.Background(), &discoveryv3.DiscoveryRequest{
		TypeUrl:       SecretTypeURL,
		ResourceNames: []string{ResourceNameOwnValidationContext},
	})
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(rpcTotal(t, workloadidentity.RPCFetchSecrets, workloadidentity.OutcomeSuccess, pkgerrors.MetricLabelNone) - before).
		To(Equal(1.0))
	g.Expect(rpcTotal(t, workloadidentity.RPCStreamSecrets, workloadidentity.OutcomeSuccess, pkgerrors.MetricLabelNone)).
		To(Equal(streamBefore), "a unary call must not count against the stream")
}

// TestFetchSecrets_HandlerBuiltRefusalIsLabelledNone pins the other half of the
// error label. A bad resource name is refused by this handler rather than by a
// tier, so there is no taxonomy member to name, and rpcErrorLabel answers "none"
// rather than "unknown" so that the unexpected errors stay visible on their own.
func TestFetchSecrets_HandlerBuiltRefusalIsLabelledNone(t *testing.T) {
	g := NewWithT(t)

	before := rpcTotal(t, workloadidentity.RPCFetchSecrets, workloadidentity.OutcomeFailure, pkgerrors.MetricLabelNone)
	unknownBefore := rpcTotal(t, workloadidentity.RPCFetchSecrets, workloadidentity.OutcomeFailure, pkgerrors.MetricLabelUnknown)

	h := newHarness(t)

	_, err := h.client.FetchSecrets(context.Background(), &discoveryv3.DiscoveryRequest{
		TypeUrl:       SecretTypeURL,
		ResourceNames: []string{"ALL"},
	})
	g.Expect(err).To(HaveOccurred())

	g.Expect(rpcTotal(t, workloadidentity.RPCFetchSecrets, workloadidentity.OutcomeFailure, pkgerrors.MetricLabelNone) - before).
		To(Equal(1.0))
	g.Expect(rpcTotal(t, workloadidentity.RPCFetchSecrets, workloadidentity.OutcomeFailure, pkgerrors.MetricLabelUnknown)).
		To(Equal(unknownBefore), "a deliberate refusal must not read as an unclassified failure")
}

// streamSecretsFailures totals every failure series for StreamSecrets, whatever
// its error label: every taxonomy member's, plus the two labels for a refusal
// with no member and a failure nobody classified.
func streamSecretsFailures(t *testing.T) float64 {
	t.Helper()

	labels := []string{pkgerrors.MetricLabelNone, pkgerrors.MetricLabelUnknown}
	for _, member := range pkgerrors.WorkloadIdentityTaxonomy() {
		labels = append(labels, member.MetricLabel())
	}

	var total float64
	for _, label := range labels {
		total += rpcTotal(t, workloadidentity.RPCStreamSecrets, workloadidentity.OutcomeFailure, label)
	}
	return total
}
