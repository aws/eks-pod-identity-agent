package jwt

import (
	"context"
	"errors"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

var (
	issuanceTotalOpts = prometheus.CounterOpts{
		Name: workloadidentity.MetricSvidIssuanceTotal,
		Help: "Count of SVID issuances, by credential format, outcome and error label.",
	}
	issuanceTotalLabels = []string{
		workloadidentity.LabelFormat,
		workloadidentity.LabelOutcome,
		workloadidentity.LabelError,
	}
	issuanceDurationOpts = prometheus.HistogramOpts{
		Name:    workloadidentity.MetricSvidIssuanceDuration,
		Help:    "Latency of SVID issuances, by credential format and outcome.",
		Buckets: prometheus.DefBuckets,
	}
	issuanceDurationLabels = []string{
		workloadidentity.LabelFormat,
		workloadidentity.LabelOutcome,
	}
	renewalTotalOpts = prometheus.CounterOpts{
		Name: workloadidentity.MetricSvidRenewalTotal,
		Help: "Count of SVID renewals, by credential format, outcome and error label.",
	}
	renewalTotalLabels = issuanceTotalLabels

	defaultMetricsOnce sync.Once
	defaultMetrics     svidMetrics
)

type svidMetrics struct {
	issuance *prometheus.CounterVec
	latency  *prometheus.HistogramVec
	renewal  *prometheus.CounterVec
}

func defaultSVIDMetrics() svidMetrics {
	defaultMetricsOnce.Do(func() {
		defaultMetrics = registerSVIDMetrics(prometheus.DefaultRegisterer)
	})
	return defaultMetrics
}

func registerSVIDMetrics(reg prometheus.Registerer) svidMetrics {
	return svidMetrics{
		issuance: registerCounter(reg, issuanceTotalOpts, issuanceTotalLabels),
		latency:  registerHistogram(reg, issuanceDurationOpts, issuanceDurationLabels),
		renewal:  registerCounter(reg, renewalTotalOpts, renewalTotalLabels),
	}
}

func registerCounter(
	reg prometheus.Registerer,
	opts prometheus.CounterOpts,
	labels []string,
) *prometheus.CounterVec {
	counter := prometheus.NewCounterVec(opts, labels)
	if err := reg.Register(counter); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(*prometheus.CounterVec); ok {
				return existing
			}
		}
		logger.FromContext(context.Background()).Errorf("Could not register %s: %v", opts.Name, err)
	}
	return counter
}

func registerHistogram(
	reg prometheus.Registerer,
	opts prometheus.HistogramOpts,
	labels []string,
) *prometheus.HistogramVec {
	histogram := prometheus.NewHistogramVec(opts, labels)
	if err := reg.Register(histogram); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(*prometheus.HistogramVec); ok {
				return existing
			}
		}
		logger.FromContext(context.Background()).Errorf("Could not register %s: %v", opts.Name, err)
	}
	return histogram
}

func (m svidMetrics) observeIssuance(err error, seconds float64, renewal bool) {
	outcome := workloadidentity.OutcomeSuccess
	if err != nil {
		outcome = workloadidentity.OutcomeFailure
	}
	errorLabel := wierrors.MetricLabel(err)
	m.issuance.WithLabelValues(workloadidentity.FormatJWTSVID, outcome, errorLabel).Inc()
	m.latency.WithLabelValues(workloadidentity.FormatJWTSVID, outcome).Observe(seconds)
	if renewal {
		m.renewal.WithLabelValues(workloadidentity.FormatJWTSVID, outcome, errorLabel).Inc()
	}
}
