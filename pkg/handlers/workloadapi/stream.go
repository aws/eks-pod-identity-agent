package workloadapi

import (
	"context"
	"time"

	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/util/wait"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/handlers"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// streamSpec is what differs between the three streams: the RPC label, the
// subscription that wakes the stream, how a response is built and sent, and what
// of it dedupe compares.
type streamSpec[R proto.Message] struct {
	rpc       string
	subscribe func(context.Context, *workloadidentity.Workload) (<-chan struct{}, func(), error)
	build     func(context.Context, *workloadidentity.Workload) (R, error)
	send      func(R) error
	// view is what dedupe compares and keeps between sends; nil keeps the whole
	// response. Only the handler knows what it last sent, so dedupe is here.
	view func(R) proto.Message
}

// serve runs one stream: attest, subscribe, lease the provider, then send the full
// current state on every wake until the stream's context ends. A retryable failure
// at any step blocks the stream and retries it, because a cold start is multi-hop
// and slow and a library may not retry an error gracefully; a non-retryable one
// ends the stream with its mapped code.
func serve[R proto.Message](h *Handler, ctx context.Context, spec streamSpec[R]) error {
	s := &streamState{rpc: spec.rpc, start: time.Now(), backoff: h.backoff, initial: h.backoff}

	var caller *workloadidentity.Workload
	if err := s.await(ctx, nil, func() (err error) {
		caller, err = h.attest(ctx)
		return err
	}); err != nil {
		return err
	}

	var signals <-chan struct{}
	var unsubscribe func()
	if err := s.await(ctx, nil, func() (err error) {
		signals, unsubscribe, err = spec.subscribe(ctx, caller)
		return err
	}); err != nil {
		return err
	}
	defer unsubscribe()

	// A stream reads only when signalled, so without a lease a provider whose
	// bundles hold still looks unused to the bundle tier, which then evicts it
	// and stops refreshing it, and the stream hears nothing of the next rotation.
	var releaseLease func()
	if err := s.await(ctx, nil, func() (err error) {
		releaseLease, err = h.opts.Bundles.Lease(ctx, caller)
		return err
	}); err != nil {
		return err
	}
	defer releaseLease()

	// The channel arrives with one signal pending, so the first pass is the
	// initial send. It is never closed, so the loop selects beside ctx rather
	// than ranging over it, and a signal carries nothing but "read again".
	var last proto.Message
	for {
		select {
		case <-ctx.Done():
			return s.ended(ctx)
		case <-signals:
		}

		var resp R
		if err := s.await(ctx, signals, func() (err error) {
			resp, err = spec.build(ctx, caller)
			return err
		}); err != nil {
			return err
		}

		var view proto.Message = resp
		if spec.view != nil {
			view = spec.view(resp)
		}
		if last != nil && proto.Equal(view, last) {
			continue
		}
		if err := spec.send(resp); err != nil {
			return err
		}
		last = view
		s.answered()
	}
}

// streamState is one stream's progress: whether it has answered, and how long its
// next retry waits.
type streamState struct {
	rpc   string
	start time.Time
	// sent is set by the first response. The RPC metrics count a stream once,
	// at its first response or at the error that ends it before one.
	sent bool
	// backoff is the stream's own retry pace, and initial what it resets to.
	backoff wait.Backoff
	initial wait.Backoff
}

// await runs op until it succeeds, returning nil, fails non-retryably, returning
// its mapped status, or ctx ends, returning ctx's. Between retryable failures it
// waits out a backoff, cut short by a signal when there is a channel to hear one
// on, since a signal means there is something new to read.
func (s *streamState) await(ctx context.Context, signals <-chan struct{}, op func() error) error {
	for {
		err := op()
		switch {
		case ctx.Err() != nil:
			return s.ended(ctx)
		case err == nil:
			s.backoff = s.initial
			return nil
		case !wierrors.IsRetryable(err):
			return s.failed(ctx, err)
		}

		delay := s.backoff.Step()
		logger.FromContext(ctx).WithField("rpc", s.rpc).Debugf("Retrying the stream in %s: %v", delay, err)
		if !s.wait(ctx, signals, delay) {
			return s.ended(ctx)
		}
	}
}

// wait blocks for delay, or until a signal arrives, and reports false if ctx
// ended first. The timer is stopped on every path, so nothing outlives the stream.
func (s *streamState) wait(ctx context.Context, signals <-chan struct{}, delay time.Duration) bool {
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

// answered records the stream's first response; later ones are not counted again.
func (s *streamState) answered() {
	if s.sent {
		return
	}
	s.sent = true
	handlers.ObserveRPC(s.rpc, nil, time.Since(s.start))
}

// failed ends the stream with err's mapped code. It is counted only if the stream
// never answered, so each stream counts once.
func (s *streamState) failed(ctx context.Context, err error) error {
	if !s.sent {
		handlers.ObserveRPC(s.rpc, err, time.Since(s.start))
	}
	logFailure(ctx, s.rpc, err)
	return handlers.StatusError(err)
}

// ended returns the status for a stream whose context ended, which is how a client
// disconnect and a server shutdown arrive. It counts nothing, as for a unary call
// whose client left: the stream got no answer, and a retryable error it was
// waiting out did not end it.
func (s *streamState) ended(ctx context.Context) error {
	return handlers.StatusErrorFromContext(ctx)
}
