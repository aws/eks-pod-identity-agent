package handlers

import (
	"context"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// Attest resolves the caller from the connection in ctx. Failures are
// ErrUnattestable.
func Attest(ctx context.Context, attestor workloadidentity.Attestor) (*workloadidentity.Workload, error) {
	conn, ok := grpcserver.ConnFromContext(ctx)
	if !ok {
		return nil, errors.ErrUnattestable.Wrapf(nil, "the caller's connection is not available, so it cannot be attested")
	}

	caller, err := attestor.Attest(ctx, conn)
	if err != nil {
		return nil, err
	}
	if caller == nil {
		// A nil workload would panic a tier rather than refuse the RPC.
		return nil, errors.ErrUnattestable.Wrapf(nil, "attestation named no workload")
	}

	return caller, nil
}
