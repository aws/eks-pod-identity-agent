package handlers

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"k8s.io/apimachinery/pkg/util/wait"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
)

var testRetryBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 1 << 30, Cap: time.Millisecond}

// captureLogs installs a hook on the shared logger and raises its level so
// Debug lines are captured too, restoring both after the test.
func captureLogs(t *testing.T) *logtest.Hook {
	t.Helper()
	base := logger.FromContext(context.Background()).Logger
	level := base.GetLevel()
	base.SetLevel(logrus.DebugLevel)
	hook := logtest.NewLocal(base)
	t.Cleanup(func() {
		hook.Reset()
		base.SetLevel(level)
	})
	return hook
}

func entriesFor(hook *logtest.Hook, rpc string, level logrus.Level) []*logrus.Entry {
	var out []*logrus.Entry
	for _, e := range hook.AllEntries() {
		if e.Data["rpc"] == rpc && e.Level == level {
			out = append(out, e)
		}
	}
	return out
}

func setRetryWarnAfter(t *testing.T, d time.Duration) {
	t.Helper()
	old := retryWarnAfter
	retryWarnAfter = d
	t.Cleanup(func() { retryWarnAfter = old })
}

// A step that keeps failing retryably is retried until its caller gives up.
// Every retry is counted on the retry metric by its error, and once the RPC has
// waited retryWarnAfter each retry is logged at Warn with the error that holds
// it, so a stuck workload is visible at the default log level.
func TestAwait_RetryableFailure_IsCountedAndLoggedAtWarnAfterThreshold(t *testing.T) {
	g := NewWithT(t)
	hook := captureLogs(t)
	setRetryWarnAfter(t, 0)

	const rpc = "test_rpc_warn"
	cause := wierrors.ErrSessionUnavailable.Wrapf(nil, "EKS Auth answered InternalServerException")
	before := testutil.ToFloat64(promRPCRetryTotal.WithLabelValues(rpc, cause.MetricLabel()))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	calls := 0
	err := NewRPCState(rpc, testRetryBackoff).Await(ctx, nil, func() error { calls++; return cause })

	g.Expect(err).To(HaveOccurred())
	g.Expect(calls).To(BeNumerically(">=", 3))
	retries := testutil.ToFloat64(promRPCRetryTotal.WithLabelValues(rpc, cause.MetricLabel())) - before
	g.Expect(retries).To(BeNumerically(">=", 2), "retries were not counted by error")

	warns := entriesFor(hook, rpc, logrus.WarnLevel)
	g.Expect(warns).ToNot(BeEmpty(), "a stuck RPC was never logged at Warn")
	g.Expect(warns[0].Message).To(ContainSubstring("EKS Auth answered InternalServerException"))
	g.Expect(warns[0].Data).To(HaveKeyWithValue("error-label", cause.MetricLabel()))
	g.Expect(warns[0].Data).To(HaveKeyWithValue("attempt", 1))
	g.Expect(warns[0].Data).To(HaveKey("waiting-for"))
}

// Before the threshold a retry is Debug, so a cold start that retries briefly
// adds nothing at the default log level.
func TestAwait_RetryableFailure_BeforeThreshold_IsDebugOnly(t *testing.T) {
	g := NewWithT(t)
	hook := captureLogs(t)
	setRetryWarnAfter(t, time.Hour)

	const rpc = "test_rpc_debug"
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_ = NewRPCState(rpc, testRetryBackoff).Await(ctx, nil, func() error {
		return wierrors.ErrSessionUnavailable.Wrapf(nil, "not yet")
	})

	g.Expect(entriesFor(hook, rpc, logrus.WarnLevel)).To(BeEmpty())
	g.Expect(entriesFor(hook, rpc, logrus.DebugLevel)).ToNot(BeEmpty())
}

// A step that succeeds first time is neither counted as a retry nor logged.
func TestAwait_Success_IsNotARetry(t *testing.T) {
	g := NewWithT(t)
	hook := captureLogs(t)
	setRetryWarnAfter(t, 0)

	const rpc = "test_rpc_ok"
	g.Expect(NewRPCState(rpc, testRetryBackoff).Await(context.Background(), nil, func() error { return nil })).To(Succeed())
	g.Expect(entriesFor(hook, rpc, logrus.WarnLevel)).To(BeEmpty())
	g.Expect(entriesFor(hook, rpc, logrus.DebugLevel)).To(BeEmpty())
}

// LogFailure picks the level from the status the error maps to.
func TestLogFailure_LevelFollowsMappedCode(t *testing.T) {
	testCases := []struct {
		name  string
		err   error
		level logrus.Level
	}{
		{name: "unattestable is a refusal the operator acts on", err: wierrors.ErrUnattestable.Wrapf(nil, "x"), level: logrus.WarnLevel},
		{name: "refused session is a refusal the operator acts on", err: wierrors.ErrSessionRefused.Wrapf(nil, "x"), level: logrus.WarnLevel},
		{name: "unclassified error is unexpected", err: context.DeadlineExceeded, level: logrus.ErrorLevel},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			hook := captureLogs(t)
			rpc := "test_rpc_" + tc.name
			LogFailure(context.Background(), rpc, tc.err)
			g.Expect(entriesFor(hook, rpc, tc.level)).To(HaveLen(1), "%s logged at %v", tc.name, hook.AllEntries())
		})
	}
}
