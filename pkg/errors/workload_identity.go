package errors

import (
	"errors"
	"fmt"
	"strings"
)

// Kind identifies a member of the workload identity error taxonomy. Kinds start
// at one so the zero value belongs to no member and an unclassified failure can
// never be mistaken for a classified one.
type Kind uint8

const (
	// KindUnattestable is the kind of ErrUnattestable.
	KindUnattestable Kind = iota + 1
	// KindNotEnrolled is the kind of ErrNotEnrolled.
	KindNotEnrolled
	// KindTokenMintFailed is the kind of ErrTokenMintFailed.
	KindTokenMintFailed
	// KindTokenMintForbidden is the kind of ErrTokenMintForbidden.
	KindTokenMintForbidden
	// KindSessionUnavailable is the kind of ErrSessionUnavailable.
	KindSessionUnavailable
	// KindIssuanceFailed is the kind of ErrIssuanceFailed.
	KindIssuanceFailed
	// KindIssuanceThrottled is the kind of ErrIssuanceThrottled.
	KindIssuanceThrottled
	// KindBundleUnavailable is the kind of ErrBundleUnavailable.
	KindBundleUnavailable
	// KindInvalidAudience is the kind of ErrInvalidAudience.
	KindInvalidAudience
	// KindSessionRefused is the kind of ErrSessionRefused.
	KindSessionRefused
	// KindBundleRefused is the kind of ErrBundleRefused.
	KindBundleRefused
	// KindIssuanceRefused is the kind of ErrIssuanceRefused.
	KindIssuanceRefused
)

// MetricLabelUnknown is the metric label reported for a non-nil error that is
// not a member of the workload identity taxonomy.
const MetricLabelUnknown = "unknown"

// MetricLabelNone is the metric label reported for a nil error, so a
// successful emission on a metric that carries an error label is
// distinguishable from a failure that could not be classified.
const MetricLabelNone = "none"

// WorkloadIdentityError is a member of the workload identity error taxonomy. It
// carries the kind a handler branches on, a stable metric label so no caller has
// to parse a message to emit a metric, and the retryable decision the credential
// tiers branch on. Values are compared by kind rather than by pointer, so a copy
// annotated by Wrapf still matches its sentinel under errors.Is.
type WorkloadIdentityError struct {
	kind      Kind
	label     string
	retryable bool
	message   string
	cause     error
}

// Error returns the error's message followed by its cause when one is present. A
// sentinel carries no message of its own and renders human-readable text derived
// from its metric label, so the result is never empty.
func (e *WorkloadIdentityError) Error() string {
	msg := e.message
	if msg == "" {
		msg = strings.ReplaceAll(e.label, "_", " ")
	}
	if msg == "" {
		msg = "workload identity error"
	}
	if e.cause != nil {
		return fmt.Sprintf("%s: %v", msg, e.cause)
	}
	return msg
}

// Unwrap returns the cause e was annotated with, or nil for a bare sentinel.
func (e *WorkloadIdentityError) Unwrap() error {
	return e.cause
}

// Is reports whether target is a taxonomy member of the same kind. This is what
// makes errors.Is match a Wrapf'd copy, or anything wrapping one, against the
// package sentinel.
func (e *WorkloadIdentityError) Is(target error) bool {
	other, ok := target.(*WorkloadIdentityError)
	if !ok {
		return false
	}
	return other.kind == e.kind
}

// Kind returns the taxonomy member e belongs to.
func (e *WorkloadIdentityError) Kind() Kind {
	return e.kind
}

// MetricLabel returns e's stable short metric label. Every taxonomy member
// carries one, fixed per kind and safe to use as a metric dimension value. A
// value forged outside this package's constructor carries no label, so callers
// wanting a total mapping should use the package-level MetricLabel.
func (e *WorkloadIdentityError) MetricLabel() string {
	return e.label
}

// Retryable reports whether retrying the operation that produced e can plausibly
// succeed without anything else changing.
func (e *WorkloadIdentityError) Retryable() bool {
	return e.retryable
}

// Wrapf returns a copy of e annotated with cause and a formatted message. The
// copy keeps e's kind, so errors.Is against the sentinel still matches. The
// receiver is never modified, because the sentinels are package-level values
// shared across goroutines. Annotating an already annotated error replaces its
// message and cause rather than chaining them.
func (e *WorkloadIdentityError) Wrapf(cause error, format string, args ...any) *WorkloadIdentityError {
	annotated := *e
	annotated.cause = cause
	annotated.message = fmt.Sprintf(format, args...)
	return &annotated
}

// newWorkloadIdentityError builds a bare taxonomy sentinel.
func newWorkloadIdentityError(kind Kind, label string, retryable bool) *WorkloadIdentityError {
	return &WorkloadIdentityError{
		kind:      kind,
		label:     label,
		retryable: retryable,
	}
}

var (
	// ErrUnattestable is produced by the attestor (T3) when the caller on an
	// accepted connection, including one not on a Unix socket, cannot be resolved
	// to a pod, by the bundle source (T6) for a nil workload, and by the token
	// source (T8) for a pod no longer in the node store. Not retryable.
	ErrUnattestable = newWorkloadIdentityError(KindUnattestable, "unattestable", false)

	// ErrNotEnrolled is produced by the token minter (T4) and the session
	// provider (T5) when the attested pod has no workload identity association,
	// and by the bundle source (T6) for a session that names no provider. Not
	// retryable: the pod has no association and a retry cannot create one.
	ErrNotEnrolled = newWorkloadIdentityError(KindNotEnrolled, "not_enrolled", false)

	// ErrTokenMintFailed is produced by the token minter (T4) when a TokenRequest
	// against the API server does not yield a pod-bound ServiceAccount token.
	// Retryable: transient failures dominate on that path.
	ErrTokenMintFailed = newWorkloadIdentityError(KindTokenMintFailed, "token_mint_failed", true)

	// ErrTokenMintForbidden is produced by the token minter (T4) when the API
	// server refuses a TokenRequest for the EKS Auth audience. The usual cause is
	// the CSIDriver object for spiffe.csi.eks.amazonaws.com not declaring
	// tokenRequests for that audience, which the node audience restriction
	// requires. Not retryable: the request stays refused until an operator
	// creates or fixes that object.
	ErrTokenMintForbidden = newWorkloadIdentityError(KindTokenMintForbidden, "token_mint_forbidden", false)

	// ErrSessionUnavailable is produced by the session provider (T5) when the EKS
	// Auth exchange does not yield a decorated session. Retryable: transient
	// failures dominate on that path.
	ErrSessionUnavailable = newWorkloadIdentityError(KindSessionUnavailable, "session_unavailable", true)

	// ErrIssuanceFailed is produced by the certificate source (T7) and the token
	// source (T8) when STS issuance fails. Retryable: STS issuance is a remote
	// call and a repeat can succeed.
	ErrIssuanceFailed = newWorkloadIdentityError(KindIssuanceFailed, "issuance_failed", true)

	// ErrIssuanceThrottled is produced by the certificate source (T7) and the
	// token source (T8) when STS throttles issuance. Retryable: throttling is the
	// retryable case by definition. It is distinct from ErrIssuanceFailed so
	// callers can back off differently.
	ErrIssuanceThrottled = newWorkloadIdentityError(KindIssuanceThrottled, "issuance_throttled", true)

	// ErrBundleUnavailable is produced by the bundle source (T6) when
	// sts:GetTrustBundles does not yield trust material. Retryable: the fetch is
	// a remote call and a repeat can succeed.
	ErrBundleUnavailable = newWorkloadIdentityError(KindBundleUnavailable, "bundle_unavailable", true)

	// ErrInvalidAudience is produced by the token source (T8) and the Workload
	// API handler (T10) for a caller-supplied audience the agent will never
	// accept. Not retryable: the same request will be rejected the same way.
	ErrInvalidAudience = newWorkloadIdentityError(KindInvalidAudience, "invalid_audience", false)

	// ErrSessionRefused is produced by the session provider (T5) when EKS Auth
	// refuses the exchange with AccessDenied (such as a role missing
	// sts:SetContext) or InvalidToken. Not retryable: a repeat gets the same
	// answer. It is distinct from ErrSessionUnavailable so a misconfigured role
	// or node does not read as an EKS Auth outage.
	ErrSessionRefused = newWorkloadIdentityError(KindSessionRefused, "session_refused", false)

	// ErrBundleRefused is produced by the bundle source (T6) when STS refuses a
	// provider's bundles for a reason a repeat cannot change. Not retryable. It is
	// distinct from ErrBundleUnavailable so a workload role missing
	// sts:GetTrustBundles does not read as an STS outage.
	ErrBundleRefused = newWorkloadIdentityError(KindBundleRefused, "bundle_refused", false)

	// ErrIssuanceRefused is produced by the certificate source (T7) and the token
	// source (T8) when STS refuses issuance for a reason a repeat cannot change, such
	// as a Provider with no outbound signer. Not retryable, which is what separates it
	// from ErrIssuanceFailed.
	ErrIssuanceRefused = newWorkloadIdentityError(KindIssuanceRefused, "issuance_refused", false)
)

// AsWorkloadIdentityError reports whether err is or wraps a taxonomy member, and
// returns that member when it does. An error interface holding a typed nil
// *WorkloadIdentityError is not a member, so the caller never receives a pointer
// it would have to nil-check before classifying.
func AsWorkloadIdentityError(err error) (*WorkloadIdentityError, bool) {
	if err == nil {
		return nil, false
	}
	var wiErr *WorkloadIdentityError
	if errors.As(err, &wiErr) && wiErr != nil {
		return wiErr, true
	}
	return nil, false
}

// MetricLabel returns the stable metric label for err. The mapping is total: a
// nil error is MetricLabelNone, so a successful emission is distinguishable from
// a failure, and any other error outside the taxonomy is MetricLabelUnknown. A
// caller never has to branch and never produces an empty label.
func MetricLabel(err error) string {
	if err == nil {
		return MetricLabelNone
	}
	if wiErr, ok := AsWorkloadIdentityError(err); ok {
		if label := wiErr.MetricLabel(); label != "" {
			return label
		}
	}
	return MetricLabelUnknown
}

// IsRetryable reports whether retrying the operation that produced err can
// plausibly succeed. An error outside the taxonomy is not retryable: the agent
// does not retry a failure it cannot classify.
func IsRetryable(err error) bool {
	if wiErr, ok := AsWorkloadIdentityError(err); ok {
		return wiErr.Retryable()
	}
	return false
}

// WorkloadIdentityTaxonomy returns every taxonomy member in kind order, so a
// caller mapping the taxonomy onto gRPC status codes (T10, T11) can assert its
// own mapping is total.
func WorkloadIdentityTaxonomy() []*WorkloadIdentityError {
	return []*WorkloadIdentityError{
		ErrUnattestable,
		ErrNotEnrolled,
		ErrTokenMintFailed,
		ErrTokenMintForbidden,
		ErrSessionUnavailable,
		ErrIssuanceFailed,
		ErrIssuanceThrottled,
		ErrBundleUnavailable,
		ErrInvalidAudience,
		ErrSessionRefused,
		ErrBundleRefused,
		ErrIssuanceRefused,
	}
}
