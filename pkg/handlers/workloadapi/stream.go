package workloadapi

import (
	"context"

	"google.golang.org/protobuf/proto"

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
	s := handlers.NewRPCState(spec.rpc, h.backoff)

	var caller *workloadidentity.Workload
	if err := s.Await(ctx, nil, func() (err error) {
		caller, err = handlers.Attest(ctx, h.opts.Attestor)
		return err
	}); err != nil {
		return err
	}

	var signals <-chan struct{}
	var unsubscribe func()
	if err := s.Await(ctx, nil, func() (err error) {
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
	if err := s.Await(ctx, nil, func() (err error) {
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
			return s.Ended(ctx)
		case <-signals:
		}

		var resp R
		if err := s.Await(ctx, signals, func() (err error) {
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
		s.Answered()
	}
}
