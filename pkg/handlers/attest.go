package handlers

import (
	"context"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// Attest resolves the caller from the connection the server's transport
// credentials put in ctx, the only route to it. A missing connection is a wiring
// bug, and refusing is still the only safe answer.
//
// It lives here, beside the status mapping, because both interfaces on the
// workload identity socket have to attest the same way. A workload refused on the
// SPIFFE Workload API and served over Envoy SDS, or refused by each for different
// reasons, is the customer's to reverse engineer. One function makes that
// agreement structural rather than maintained by hand: two identical copies would
// pass their own packages' tests while drifting apart.
//
// The failures are raised as ErrUnattestable rather than as a status built here,
// which keeps the gRPC code StatusCode's to decide and gives the RPC metrics a
// real error label instead of none.
//
// The attestor is a parameter rather than read off a handler, which is the only
// reason this can be shared at all.
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
