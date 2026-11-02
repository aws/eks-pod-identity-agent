package handlers

// One RPC's progress and retry pace, shared by the Workload API and SDS
// handlers so the RPC metrics mean the same thing on both: one RPC counts
// once, at the answer it gave or at the error that ended it before one, and a
// caller that left counts neither way.

import (
	"context"
	goerrors "errors"
	"time"

	"google.golang.org/grpc/codes"
	"k8s.io/apimachinery/pkg/util/wait"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
)

// RPCState is one RPC's progress: when it started, whether it has answered, and
// how long its next retry waits.
type RPCState struct {
	rpc   string
	start time.Time
	// sent is set by the first answer. A stream that then sends a hundred
	// rotations is still one RPC.
	sent bool
	// backoff is this RPC's own retry pace and initial what it resets to, so one
	// stream's failures never slow another's retries.
	backoff wait.Backoff
	initial wait.Backoff
}

// NewRPCState starts the clock for one RPC.
func NewRPCState(rpc string, backoff wait.Backoff) *RPCState {
	return &RPCState{rpc: rpc, start: time.Now(), backoff: backoff, initial: backoff}
}

// Await runs op until it succeeds, returning nil, fails non-retryably, returning
// its mapped status, or ctx ends, returning ctx's. Between retryable failures it
// waits out a backoff, cut short by a signal when there is a channel to hear one
// on, since a signal means there is something new to read.
func (s *RPCState) Await(ctx context.Context, signals <-chan struct{}, op func() error) error {
	for {
		err := op()
		switch {
		case ctx.Err() != nil:
			return s.Ended(ctx)
		case err == nil:
			s.backoff = s.initial
			return nil
		case !errors.IsRetryable(err):
			return s.Failed(ctx, err)
		}

		delay := s.backoff.Step()
		logger.FromContext(ctx).WithField("rpc", s.rpc).Debugf("Retrying the stream in %s: %v", delay, err)
		if !s.wait(ctx, signals, delay) {
			return s.Ended(ctx)
		}
	}
}

// wait blocks for delay, or until a signal arrives, and reports false if ctx
// ended first. The timer is stopped on every path, so nothing outlives the RPC.
func (s *RPCState) wait(ctx context.Context, signals <-chan struct{}, delay time.Duration) bool {
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

// Answered records the RPC's first answer; later ones are not counted again.
func (s *RPCState) Answered() {
	if s.sent {
		return
	}
	s.sent = true
	ObserveRPC(s.rpc, nil, time.Since(s.start))
}

// Failed ends the RPC with err's mapped code. It is counted only if the RPC never
// answered, so each one counts once.
//
// Two cases are not counted. A caller whose context ended got no answer from the
// agent, and the error in flight would only say its wait was cut short. A failed
// write is the caller going away mid-send rather than a failure to produce an
// answer, so it is returned as the status it already carries.
func (s *RPCState) Failed(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return StatusErrorFromContext(ctx)
	}

	var send SendError
	if goerrors.As(err, &send) {
		return send.Err
	}

	if !s.sent {
		ObserveRPC(s.rpc, err, time.Since(s.start))
	}
	LogFailure(ctx, s.rpc, err)
	return StatusError(err)
}

// Ended returns the status for an RPC whose context ended, which is how a client
// disconnect and a server shutdown arrive. It counts nothing.
func (s *RPCState) Ended(ctx context.Context) error {
	return StatusErrorFromContext(ctx)
}

// SendError marks an error as a failed write to the caller rather than a failure
// to produce what it asked for. It already carries a status, since it came from
// gRPC.
type SendError struct {
	Err error
}

func (e SendError) Error() string { return e.Err.Error() }

func (e SendError) Unwrap() error { return e.Err }

// LogFailure logs an error a handler answers with, at the level the error's own
// mapping decides: one that maps to Internal is unexpected and ours to act on,
// and the rest are refusals the caller can do something about.
func LogFailure(ctx context.Context, rpc string, err error) {
	log := logger.FromContext(ctx).WithField("rpc", rpc)
	if StatusCode(err) == codes.Internal {
		log.Errorf("Unexpected error serving a workload identity RPC: %v", err)
		return
	}
	log.Infof("Refusing the call: %v", err)
}
