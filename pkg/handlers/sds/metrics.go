package sds

import (
	"context"
	goerrors "errors"
	"time"

	"google.golang.org/grpc/codes"
	"k8s.io/apimachinery/pkg/util/wait"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/handlers"
)

// RPC metrics and retry for the SDS handlers, accounted the same way
// workloadapi's stream engine does: one RPC counts once, at the answer it gave or
// at the error that ended it before one, and a caller that left counts neither.
// Both interfaces share the collectors in pkg/handlers/rpc_metrics.go, so a
// series meaning "per stream" on one and "per response" on the other would make
// the metric unreadable.
//
// Duplicated rather than imported: workloadapi's streamState is unexported, and
// SDS cannot use its stream engine anyway, which builds one response per wake and
// never reads from the client.

// rpcState is one RPC's progress: when it started, whether it has answered, and
// how long its next retry waits.
type rpcState struct {
	// rpc is the LabelRPC value, which is this RPC's constant.
	rpc string

	// start is when the caller began waiting, which is what the duration
	// histogram observes: the whole call for FetchSecrets, the time to the first
	// response for StreamSecrets.
	start time.Time

	// answeredOnce is set by the first answer. A stream that then sends a hundred
	// rotations is still one RPC, and counting each send would make the counter a
	// response count on this interface and a stream count on the other.
	answeredOnce bool

	// backoff is this RPC's own retry pace and initial what it resets to after a
	// step that succeeds. Each RPC carries its own copy, so one stream's failures
	// never slow another's retries.
	backoff wait.Backoff
	initial wait.Backoff
}

// newRPCState starts the clock for one RPC.
func newRPCState(rpc string, backoff wait.Backoff) *rpcState {
	return &rpcState{rpc: rpc, start: time.Now(), backoff: backoff, initial: backoff}
}

// await runs op until it succeeds, fails in a way no retry can fix, or ctx ends.
// Between retryable failures it waits out the backoff, cut short by a signal,
// which means there is something new to read anyway. Returned errors are the
// tiers' own, unmapped, for the entry point to record and map.
//
// Same shape as workloadapi's streamState.await: the agent knows a failure is
// transient and the client would only learn its stream broke, so a retryable one
// blocks here. Envoy reconnects for the rest.
//
// Consequence worth knowing: a retryable error never reaches the caller. The
// stream stays open with no response until the tier comes good, the error turns
// non-retryable, or the workload goes away.
func (s *rpcState) await(ctx context.Context, signals <-chan struct{}, op func() error) error {
	for {
		err := op()
		switch {
		case ctx.Err() != nil:
			// Checked before err, so a failure caused by the shutdown or the
			// disconnect is reported as what it was rather than as a tier fault.
			return ctx.Err()
		case err == nil:
			s.backoff = s.initial
			return nil
		case !errors.IsRetryable(err):
			return err
		}

		delay := s.backoff.Step()
		logger.FromContext(ctx).WithField("rpc", s.rpc).
			Debugf("Retrying the SDS stream in %s: %v", delay, err)

		if !s.wait(ctx, signals, delay) {
			return ctx.Err()
		}
	}
}

// wait blocks for delay, or until a signal arrives, and reports false if ctx ended
// first. The timer is stopped on every path, so nothing outlives the RPC.
func (s *rpcState) wait(ctx context.Context, signals <-chan struct{}, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-signals:
	case <-timer.C:
	}

	return true
}

// answered records the RPC's first answer and ignores every later one.
func (s *rpcState) answered() {
	if s.answeredOnce {
		return
	}
	s.answeredOnce = true
	handlers.ObserveRPC(s.rpc, nil, time.Since(s.start))
}

// failed ends the RPC with err: it records the failure, logs it, and maps err onto
// the status the caller sees. err is the error before mapping, which is what makes
// the metric's error label the taxonomy's own.
//
// Two things are deliberately not counted. A caller whose context ended got no
// answer from the agent, and the error in flight would only say its wait was cut
// short, so that case returns the context's status and records nothing, exactly as
// workloadapi's failUnary does. And a stream that already answered is not counted
// again, since the RPC it is ending was counted at its first response.
func (s *rpcState) failed(ctx context.Context, err error) error {
	if err == nil {
		// A stream that ended without an error, which is Envoy half-closing
		// while the context is still live. It was counted at its first response,
		// if it got one, and there is nothing here to report.
		return nil
	}

	if ctx.Err() != nil {
		return handlers.StatusErrorFromContext(ctx)
	}

	// A failed write to the client is the client going away mid-send, not the
	// agent failing to produce an answer. Upstream's stream engine returns one
	// unwrapped and counts nothing, so this does too.
	var send sendError
	if goerrors.As(err, &send) {
		return send.err
	}

	if !s.answeredOnce {
		handlers.ObserveRPC(s.rpc, err, time.Since(s.start))
	}
	logFailure(ctx, s.rpc, err)

	return handlers.StatusError(err)
}

// sendError marks an error as a failed write to the caller rather than a failure
// to produce what it asked for, so the accounting above can tell them apart. It
// carries a status of its own already, since it came from gRPC.
type sendError struct {
	err error
}

func (e sendError) Error() string { return e.err.Error() }

func (e sendError) Unwrap() error { return e.err }

// logFailure logs an error the handler answers with, at the level the error's own
// mapping decides: one that maps to Internal is unexpected and nobody's to act on
// but ours, and the rest are refusals the caller can do something about. The same
// split workloadapi's logFailure makes, worded for this interface.
func logFailure(ctx context.Context, rpc string, err error) {
	log := logger.FromContext(ctx).WithField("rpc", rpc)
	if handlers.StatusCode(err) == codes.Internal {
		log.Errorf("Unexpected error serving Envoy SDS: %v", err)
		return
	}
	log.Infof("Refusing the SDS call: %v", err)
}
