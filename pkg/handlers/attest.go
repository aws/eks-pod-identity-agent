package handlers

import (
	"context"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// Attest resolves the caller from the connection the server's transport
// credentials put in ctx, the only route to it.
//
// Shared by both interfaces on the socket, because a workload refused on one and
// served on the other is the customer's to reverse engineer. Two identical copies
// would pass their own packages' tests while drifting apart.
//
// Failures are ErrUnattestable rather than a status built here, which leaves the
// gRPC code to StatusCode and gives the RPC metrics a real error label.
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
		// Nothing downstream nil-checks the workload, and a tier handed a nil one
		// would panic the RPC rather than refuse it.
		return nil, errors.ErrUnattestable.Wrapf(nil, "attestation named no workload")
	}

	return caller, nil
}
