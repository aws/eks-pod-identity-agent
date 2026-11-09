package handlers

import (
	"context"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// Attest resolves the caller from the Peer the transport pinned for this RPC's
// connection, and returns ctx with the caller's pod on its logger, so every
// later log line for the RPC, the refusal included, names the workload it is
// about. A failure returns ctx unchanged and is ErrUnattestable.
func Attest(ctx context.Context, attestor workloadidentity.Attestor) (context.Context, *workloadidentity.Workload, error) {
	peer, ok := grpcserver.PeerFromContext(ctx)
	if !ok {
		return ctx, nil, errors.ErrUnattestable.Wrapf(nil, "attestation refused")
	}

	caller, err := attestor.Attest(ctx, peer)
	if err != nil {
		return ctx, nil, err
	}
	if caller == nil {
		// A nil workload would panic a tier rather than refuse the RPC.
		return ctx, nil, errors.ErrUnattestable.Wrapf(nil, "attestation named no workload")
	}

	ctx = logger.ContextWithField(ctx, "pod", caller.Namespace+"/"+caller.PodName, "pod-uid", caller.PodUID)
	return ctx, caller, nil
}
