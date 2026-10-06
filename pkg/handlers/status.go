package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
)

// This file maps the workload identity error taxonomy onto gRPC status codes for
// both handlers on the workload identity socket, the SPIFFE Workload API (T10)
// and Envoy SDS (T11). One table means a workload is never refused on one
// interface and served, or refused with a different code, on the other. The
// clients are third-party SPIFFE libraries and Envoy, so where SPIRE has an
// established answer it is the answer here.

// statusCodes maps each taxonomy kind onto the code a caller on the socket sees.
// It is a map rather than a switch so TestStatusCode_IsTotalOverTaxonomy fails on
// a missing kind instead of that kind reaching a client as Internal.
var statusCodes = map[errors.Kind]codes.Code{
	// PermissionDenied: the caller could not be resolved to a pod on this node,
	// so it gets no identity. go-spiffe retries every code but Canceled and
	// InvalidArgument, so a pod the store has not caught up with still recovers.
	errors.KindUnattestable: codes.PermissionDenied,

	// PermissionDenied is SPIRE's "no identity issued", which is what a pod with
	// no workload identity association is. SPIFFE libraries already report it
	// as unregistered and keep retrying through it.
	errors.KindNotEnrolled: codes.PermissionDenied,

	// Unavailable: a TokenRequest against the API server failed transiently.
	errors.KindTokenMintFailed: codes.Unavailable,

	// FailedPrecondition: the CSIDriver object does not declare tokenRequests for
	// the EKS Auth audience. An operator has to fix a cluster-scoped object, and
	// unlike PermissionDenied the code does not blame the caller.
	errors.KindTokenMintForbidden: codes.FailedPrecondition,

	// Unavailable: the EKS Auth exchange failed transiently.
	errors.KindSessionUnavailable: codes.Unavailable,

	// PermissionDenied: EKS Auth understood the caller's identity and rejected it
	// with AccessDenied or InvalidToken, and a repeat gets the same answer.
	errors.KindSessionRefused: codes.PermissionDenied,

	// Unavailable: STS issuance failed transiently, as SPIRE answers its own SVID
	// fetch failures.
	errors.KindIssuanceFailed: codes.Unavailable,

	// FailedPrecondition: STS refused issuance for a reason a repeat cannot change,
	// such as a Provider with no outbound signer for the format. The customer's
	// configuration has to change, and the code does not blame the caller.
	errors.KindIssuanceRefused: codes.FailedPrecondition,

	// ResourceExhausted, apart from Unavailable, so a client's backoff can tell a
	// rate limit from an outage, which is why the taxonomy splits the two.
	errors.KindIssuanceThrottled: codes.ResourceExhausted,

	// Unavailable: sts:GetTrustBundles failed transiently.
	errors.KindBundleUnavailable: codes.Unavailable,

	// PermissionDenied: STS refused the provider's bundles, typically a workload
	// role missing sts:GetTrustBundles. Understood and rejected, not an outage.
	errors.KindBundleRefused: codes.PermissionDenied,

	// InvalidArgument: an audience the agent will never accept, as SPIRE answers
	// a caller-supplied value it rejects.
	errors.KindInvalidAudience: codes.InvalidArgument,

	// InvalidArgument for a token that fails validation and for a malformed
	// request, as SPIRE answers both.
	errors.KindInvalidToken:   codes.InvalidArgument,
	errors.KindInvalidRequest: codes.InvalidArgument,

	// PermissionDenied: SPIRE's "no identity issued", for a caller holding no SVID
	// that matches what it asked for.
	errors.KindNoIdentity: codes.PermissionDenied,
}

// StatusCode returns the code a caller on the workload identity socket sees for
// err. It is total: nil is OK, a taxonomy member takes its entry even when its
// cause carries a status, any other error carrying a status keeps its code, and
// anything else is Internal, a bare context error from a tier included, since the
// caller is still there and go-spiffe never retries a Canceled.
func StatusCode(err error) codes.Code {
	if err == nil {
		return codes.OK
	}

	if wiErr, ok := errors.AsWorkloadIdentityError(err); ok {
		if code, ok := statusCodes[wiErr.Kind()]; ok {
			return code
		}
		// Unreachable while the totality test passes.
		return codes.Internal
	}

	if st, ok := status.FromError(err); ok {
		return st.Code()
	}

	return codes.Internal
}

// StatusError converts a tier error into the error a handler returns to gRPC. A
// taxonomy member carries its Message and not its cause, since a cause can be a
// reply to another pod's request, such as the bundle tier's last STS refusal. An
// unclassified error is Internal with a fixed text, its detail left to the log. A
// status passes unchanged.
func StatusError(err error) error {
	if err == nil {
		return nil
	}

	if wiErr, ok := errors.AsWorkloadIdentityError(err); ok {
		return status.Error(StatusCode(err), wiErr.Message())
	}

	if _, ok := status.FromError(err); ok {
		return err
	}

	return status.Error(codes.Internal, "the agent failed unexpectedly; its log has the cause")
}

// StatusErrorFromContext returns the status for a call that ended because its own
// context did, which is how both a client disconnect and a server shutdown
// arrive, so a disconnect is reported as Canceled rather than Unknown. It is the
// only route to Canceled and DeadlineExceeded.
func StatusErrorFromContext(ctx context.Context) error {
	return status.FromContextError(ctx.Err()).Err()
}
