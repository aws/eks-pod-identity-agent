package handlers

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"k8s.io/apimachinery/pkg/util/wait"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
)

var testRetryBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 1 << 30, Cap: time.Millisecond}

// captureLogs captures Debug and up on the shared logger for one test.
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

// After retryWarnAfter, each retry logs at Warn with the error and the pod.
func TestAwait_RetryableFailure_IsLoggedAtWarnAfterThreshold(t *testing.T) {
	g := NewWithT(t)
	hook := captureLogs(t)
	setRetryWarnAfter(t, 0)

	const rpc = "test_rpc_warn"
	cause := wierrors.ErrSessionUnavailable.Wrapf(nil, "EKS Auth answered InternalServerException")

	// The context Attest returns: the pod and its UID are on its logger.
	attested := logger.ContextWithField(context.Background(), "pod", "ns-1/pod-1", "pod-uid", "uid-1")
	ctx, cancel := context.WithTimeout(attested, 50*time.Millisecond)
	defer cancel()
	calls := 0
	err := NewRPCState(rpc, testRetryBackoff).Await(ctx, nil, func() error { calls++; return cause })

	g.Expect(err).To(HaveOccurred())
	g.Expect(calls).To(BeNumerically(">=", 3))

	warns := entriesFor(hook, rpc, logrus.WarnLevel)
	g.Expect(warns).ToNot(BeEmpty(), "a stuck RPC was never logged at Warn")
	g.Expect(warns[0].Message).To(ContainSubstring("EKS Auth answered InternalServerException"))
	g.Expect(warns[0].Data).To(HaveKeyWithValue("pod", "ns-1/pod-1"))
	g.Expect(warns[0].Data).To(HaveKeyWithValue("pod-uid", "uid-1"))
	g.Expect(warns[0].Data).To(HaveKeyWithValue("error-label", cause.MetricLabel()))
	g.Expect(warns[0].Data).To(HaveKeyWithValue("attempt", 1))
	g.Expect(warns[0].Data).To(HaveKey("waiting-for"))
}

// Before retryWarnAfter, retries log at Debug only.
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

// A step that succeeds first time is not logged as a retry.
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
