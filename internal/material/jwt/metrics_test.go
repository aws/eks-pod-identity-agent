package jwt

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

func TestRegisterSVIDMetricsReusesExistingCollectors(t *testing.T) {
	registry := prometheus.NewRegistry()
	first := registerSVIDMetrics(registry)
	second := registerSVIDMetrics(registry)

	require.Same(t, first.issuance, second.issuance)
	require.Same(t, first.latency, second.latency)
	require.Same(t, first.renewal, second.renewal)
}

func TestSVIDMetricsSeparateRenewalsFromInitialIssuance(t *testing.T) {
	metrics := registerSVIDMetrics(prometheus.NewRegistry())
	metrics.observeIssuance(nil, 0.1, false)
	metrics.observeIssuance(errors.New("failed"), 0.2, true)

	require.Equal(t, float64(1), testutil.ToFloat64(metrics.issuance.WithLabelValues(
		workloadidentity.FormatJWTSVID,
		workloadidentity.OutcomeSuccess,
		"none",
	)))
	require.Equal(t, float64(1), testutil.ToFloat64(metrics.renewal.WithLabelValues(
		workloadidentity.FormatJWTSVID,
		workloadidentity.OutcomeFailure,
		"unknown",
	)))
}
