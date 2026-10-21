package handlers

import (
	"context"
	stderrors "errors"
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
)

// pinnedStatusCodes states every code as a literal, so changing one is a
// deliberate edit to a test rather than a quiet change to what a deployed Envoy or
// SPIFFE library sees. It is keyed by kind so a new taxonomy member fails
// TestStatusCode_PinnedMapping until someone decides its code here too.
var pinnedStatusCodes = map[errors.Kind]codes.Code{
	// Decided for this agent, not SPIRE's Unavailable: a caller that cannot be
	// resolved to a pod gets no identity. go-spiffe still retries it.
	errors.KindUnattestable: codes.PermissionDenied,
	// SPIRE's "no identity issued". Changing it changes how every SPIFFE library
	// reports an unenrolled pod.
	errors.KindNotEnrolled:        codes.PermissionDenied,
	errors.KindTokenMintFailed:    codes.Unavailable,
	errors.KindTokenMintForbidden: codes.FailedPrecondition,
	errors.KindSessionUnavailable: codes.Unavailable,
	errors.KindSessionRefused:     codes.PermissionDenied,
	errors.KindIssuanceFailed:     codes.Unavailable,
	errors.KindIssuanceThrottled:  codes.ResourceExhausted,
	errors.KindIssuanceRefused:    codes.FailedPrecondition,
	errors.KindBundleUnavailable:  codes.Unavailable,
	errors.KindBundleRefused:      codes.PermissionDenied,
	errors.KindInvalidAudience:    codes.InvalidArgument,
	errors.KindInvalidToken:       codes.InvalidArgument,
	errors.KindInvalidRequest:     codes.InvalidArgument,
	errors.KindNoIdentity:         codes.PermissionDenied,
}

// TestStatusCode_IsTotalOverTaxonomy is the tripwire the mapping exists for. A
// new taxonomy member fails here until it is mapped, rather than reaching a
// workload as an unexplained Internal. OK counts as unmapped too, since it is
// reserved for a nil error.
func TestStatusCode_IsTotalOverTaxonomy(t *testing.T) {
	g := NewWithT(t)

	taxonomy := errors.WorkloadIdentityTaxonomy()
	g.Expect(taxonomy).ToNot(BeEmpty(), "the taxonomy is empty, so this test proves nothing")

	for _, member := range taxonomy {
		code := StatusCode(member)

		g.Expect(code).ToNot(Equal(codes.Internal),
			"%s has no entry in statusCodes, so it reaches a workload as Internal: add one", member.MetricLabel())
		g.Expect(code).ToNot(Equal(codes.OK),
			"%s maps to OK, but OK is only for a nil error", member.MetricLabel())
	}
}

// TestStatusCode_PinnedMapping checks every member against pinnedStatusCodes, and
// that the pin names no kind the taxonomy lacks, so the two lists stay one list.
func TestStatusCode_PinnedMapping(t *testing.T) {
	taxonomy := errors.WorkloadIdentityTaxonomy()
	NewWithT(t).Expect(pinnedStatusCodes).To(HaveLen(len(taxonomy)),
		"pinnedStatusCodes and the taxonomy disagree on how many members there are")

	for _, member := range taxonomy {
		t.Run(member.MetricLabel(), func(t *testing.T) {
			g := NewWithT(t)

			want, pinned := pinnedStatusCodes[member.Kind()]
			g.Expect(pinned).To(BeTrue(), "%s has no pinned code: decide one here", member.MetricLabel())
			g.Expect(StatusCode(member)).To(Equal(want))
		})
	}
}

// TestStatusCode_ClassifiesThroughAnnotation pins that the mapping survives the
// annotation the tiers apply. A tier returns a member's Wrapf with a cause, and a
// handler may wrap that again with fmt.Errorf, so a mapping that matched only a
// bare sentinel would answer Internal for every real error.
func TestStatusCode_ClassifiesThroughAnnotation(t *testing.T) {
	for _, member := range errors.WorkloadIdentityTaxonomy() {
		t.Run(member.MetricLabel(), func(t *testing.T) {
			g := NewWithT(t)

			annotated := member.Wrapf(stderrors.New("remote said no"), "serving %s", "uid-a")
			g.Expect(StatusCode(annotated)).To(Equal(StatusCode(member)))

			wrapped := fmt.Errorf("building a response: %w", annotated)
			g.Expect(StatusCode(wrapped)).To(Equal(StatusCode(member)))
		})
	}
}

// TestStatusCode_NilIsOK pins the nil answer, which lets a caller use StatusCode on
// a success as well as a failure.
func TestStatusCode_NilIsOK(t *testing.T) {
	g := NewWithT(t)
	g.Expect(StatusCode(nil)).To(Equal(codes.OK))
}

// TestStatusCode_ContextErrorsFromATierAreInternal pins that a bare context error
// a tier returns while its caller is still connected is unexpected, not Canceled:
// go-spiffe stops watching for good on Canceled. A caller that left is answered
// by StatusErrorFromContext before anything is mapped.
func TestStatusCode_ContextErrorsFromATierAreInternal(t *testing.T) {
	g := NewWithT(t)

	g.Expect(StatusCode(context.Canceled)).To(Equal(codes.Internal))
	g.Expect(StatusCode(context.DeadlineExceeded)).To(Equal(codes.Internal))
	g.Expect(StatusCode(fmt.Errorf("reading bundles: %w", context.Canceled))).To(Equal(codes.Internal))
	g.Expect(StatusCode(fmt.Errorf("reading bundles: %w", context.DeadlineExceeded))).To(Equal(codes.Internal))
}

// TestStatusCode_TaxonomyWinsOverItsContextCause pins the order: a tier that gave
// up on its own deadline and classified the failure answers its kind's code, not
// DeadlineExceeded, which would read as the caller's deadline.
func TestStatusCode_TaxonomyWinsOverItsContextCause(t *testing.T) {
	g := NewWithT(t)

	err := errors.ErrSessionUnavailable.Wrapf(context.DeadlineExceeded, "exchanging with EKS Auth")
	g.Expect(StatusCode(err)).To(Equal(codes.Unavailable))
}

// TestStatusCode_UnclassifiedIsInternal pins the fallback. An error the agent
// cannot classify is the server's fault as far as the caller is concerned.
func TestStatusCode_UnclassifiedIsInternal(t *testing.T) {
	g := NewWithT(t)

	g.Expect(StatusCode(stderrors.New("something nobody classified"))).To(Equal(codes.Internal))
	g.Expect(StatusCode(fmt.Errorf("marshalling: %w", stderrors.New("bad key")))).To(Equal(codes.Internal))
}

// TestStatusCode_ExistingStatusKeepsItsCode pins that a status built deeper down,
// such as a handler's own InvalidArgument or a failed send, is not reclassified.
func TestStatusCode_ExistingStatusKeepsItsCode(t *testing.T) {
	g := NewWithT(t)

	existing := status.Error(codes.NotFound, "no such resource name")
	g.Expect(StatusCode(existing)).To(Equal(codes.NotFound))
	g.Expect(StatusCode(fmt.Errorf("sending: %w", existing))).To(Equal(codes.NotFound))
}

func TestStatusError(t *testing.T) {
	t.Run("nil stays nil", func(t *testing.T) {
		g := NewWithT(t)
		g.Expect(StatusError(nil)).To(BeNil())
	})

	t.Run("every member carries its mapped code and its text", func(t *testing.T) {
		for _, member := range errors.WorkloadIdentityTaxonomy() {
			g := NewWithT(t)

			st, ok := status.FromError(StatusError(member))
			g.Expect(ok).To(BeTrue(), member.MetricLabel())
			g.Expect(st.Code()).To(Equal(StatusCode(member)), member.MetricLabel())
			g.Expect(st.Message()).To(Equal(member.Error()), member.MetricLabel())
		}
	})

	// The cause can be the bundle tier's last STS refusal, which it replays to
	// every reader of the provider, so it names another pod's role.
	t.Run("an annotated error keeps its message and not its cause", func(t *testing.T) {
		g := NewWithT(t)

		cause := stderrors.New("AccessDenied: arn:aws:sts::111122223333:assumed-role/other-pods-role/session")
		annotated := errors.ErrBundleRefused.Wrapf(cause, "GetTrustBundles for %s was refused", "arn:provider")

		st, ok := status.FromError(StatusError(fmt.Errorf("reading bundles: %w", annotated)))
		g.Expect(ok).To(BeTrue())
		g.Expect(st.Code()).To(Equal(codes.PermissionDenied))
		g.Expect(st.Message()).To(Equal("GetTrustBundles for arn:provider was refused"))
		g.Expect(st.Message()).ToNot(ContainSubstring("other-pods-role"))
	})

	t.Run("a member whose cause carries a status keeps the member's code", func(t *testing.T) {
		g := NewWithT(t)

		annotated := errors.ErrBundleRefused.Wrapf(status.Error(codes.Internal, "inner"), "outer")

		g.Expect(StatusCode(annotated)).To(Equal(codes.PermissionDenied))
		st, ok := status.FromError(StatusError(annotated))
		g.Expect(ok).To(BeTrue())
		g.Expect(st.Code()).To(Equal(codes.PermissionDenied))
		g.Expect(st.Message()).To(Equal("outer"))
	})

	t.Run("an unclassified error is Internal and keeps its text to the log", func(t *testing.T) {
		g := NewWithT(t)

		st, ok := status.FromError(StatusError(stderrors.New("something nobody classified")))
		g.Expect(ok).To(BeTrue())
		g.Expect(st.Code()).To(Equal(codes.Internal))
		g.Expect(st.Message()).ToNot(ContainSubstring("nobody classified"))
	})

	t.Run("a context error from a tier is Internal", func(t *testing.T) {
		g := NewWithT(t)

		g.Expect(status.Code(StatusError(context.Canceled))).To(Equal(codes.Internal))
		g.Expect(status.Code(StatusError(context.DeadlineExceeded))).To(Equal(codes.Internal))
	})

	t.Run("an existing status is returned unchanged rather than nested", func(t *testing.T) {
		g := NewWithT(t)

		existing := status.Error(codes.Unimplemented, "DeltaSecrets is not served")

		g.Expect(StatusError(existing)).To(BeIdenticalTo(existing))
	})
}

// TestStatusErrorFromContext pins the stream teardown helper, which is what the
// send loops return when their context ends, by disconnect or by deadline.
func TestStatusErrorFromContext(t *testing.T) {
	t.Run("cancelled is Canceled", func(t *testing.T) {
		g := NewWithT(t)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		st, ok := status.FromError(StatusErrorFromContext(ctx))
		g.Expect(ok).To(BeTrue())
		g.Expect(st.Code()).To(Equal(codes.Canceled))
	})

	t.Run("expired is DeadlineExceeded", func(t *testing.T) {
		g := NewWithT(t)

		ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
		defer cancel()

		st, ok := status.FromError(StatusErrorFromContext(ctx))
		g.Expect(ok).To(BeTrue())
		g.Expect(st.Code()).To(Equal(codes.DeadlineExceeded))
	})
}
