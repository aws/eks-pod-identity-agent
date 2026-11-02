package csidriver

import (
	"errors"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// The collectors are process-wide, so each assertion reads its own series before and
// after rather than expecting an absolute count.

// TestRecordRegistration_SeparatesTheKubeletsDecision covers the metric an operator
// alarms on: a refusal is terminal, so every enrolled pod on the node fails and no
// publish follows to show it.
func TestRecordRegistration_SeparatesTheKubeletsDecision(t *testing.T) {
	for name, tc := range map[string]struct {
		registered  bool
		wantOutcome string
	}{
		"registered": {registered: true, wantOutcome: workloadidentity.OutcomeSuccess},
		"refused":    {registered: false, wantOutcome: workloadidentity.OutcomeFailure},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			counter := promRegistrationTotal.WithLabelValues(tc.wantOutcome)
			before := testutil.ToFloat64(counter)

			recordRegistration(tc.registered)

			g.Expect(testutil.ToFloat64(counter)).To(Equal(before + 1))
		})
	}
}

// TestRecordMount_CountsEachOperationByOutcome pins the four series the mount metric can
// produce. The library serves the publish, so this is the only place it is counted.
func TestRecordMount_CountsEachOperationByOutcome(t *testing.T) {
	for name, tc := range map[string]struct {
		operation   string
		err         error
		wantOutcome string
	}{
		"publish succeeded":   {operation: workloadidentity.OperationPublish, wantOutcome: workloadidentity.OutcomeSuccess},
		"publish failed":      {operation: workloadidentity.OperationPublish, err: errors.New("mount failed"), wantOutcome: workloadidentity.OutcomeFailure},
		"unpublish succeeded": {operation: workloadidentity.OperationUnpublish, wantOutcome: workloadidentity.OutcomeSuccess},
		"unpublish failed":    {operation: workloadidentity.OperationUnpublish, err: errors.New("unmount failed"), wantOutcome: workloadidentity.OutcomeFailure},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			counter := promVolumeMountTotal.WithLabelValues(tc.operation, tc.wantOutcome)
			before := testutil.ToFloat64(counter)

			recordMount(tc.operation, tc.err)

			g.Expect(testutil.ToFloat64(counter)).To(Equal(before + 1))
		})
	}
}
