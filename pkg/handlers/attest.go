package handlers

import (
	"context"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// Attest resolves the caller from the Peer the transport pinned for this RPC's
// connection. Failures are ErrUnattestable.
func Attest(ctx context.Context, attestor workloadidentity.Attestor) (*workloadidentity.Workload, error) {
	peer, ok := grpcserver.PeerFromContext(ctx)
	if !ok {
		return nil, errors.ErrUnattestable.Wrapf(nil, "attestation refused")
	}

	caller, err := attestor.Attest(ctx, peer)
	if err != nil {
		return nil, err
	}
	if caller == nil {
		// A nil workload would panic a tier rather than refuse the RPC.
		return nil, errors.ErrUnattestable.Wrapf(nil, "attestation named no workload")
	}

	return caller, nil
}
