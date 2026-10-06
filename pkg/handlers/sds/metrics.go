package sds

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/handlers"
)

// This file is how SDS reports on the RPC metrics, and it deliberately accounts
// the same way workloadapi's stream engine does: one RPC counts once, at the
// answer it gave or at the error that ended it before one, and a caller that left
// counts neither. The two interfaces share the collectors in
// pkg/handlers/rpc_metrics.go, so a series that meant "per stream" on one
// interface and "per response" on the other would make the shared metric
// unreadable.
//
// The accounting is duplicated rather than imported because workloadapi's
// streamState is unexported and bound to that handler, and because SDS cannot use
// its stream engine at all: that engine builds one response per wake from the
// caller alone, while SDS has to answer per resource name off a bidirectional
// request stream.

// rpcState is one RPC's obligation to the metrics: when it started, and whether it
// has answered yet.
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
}

// newRPCState starts the clock for one RPC.
func newRPCState(rpc string) *rpcState {
	return &rpcState{rpc: rpc, start: time.Now()}
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
	if errors.As(err, &send) {
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
