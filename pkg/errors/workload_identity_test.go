package errors

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// workloadIdentitySourceFile is the file the taxonomy contract is read back from.
// Go runs a test binary with its own package directory as the working directory,
// so the bare file name resolves.
const workloadIdentitySourceFile = "workload_identity.go"

// kindConstantPrefix marks the constants that name a taxonomy kind. There is
// exactly one per sentinel.
const kindConstantPrefix = "Kind"

// sentinelVarPrefix marks the package variables that hold a taxonomy sentinel.
const sentinelVarPrefix = "Err"

// sentinelConstructor is the function every sentinel is built with, and the only
// thing that gives one a label and a retryable decision.
const sentinelConstructor = "newWorkloadIdentityError"

// taxonomyCase pins the classification a single sentinel is expected to carry.
type taxonomyCase struct {
	name              string
	err               *WorkloadIdentityError
	expectedKind      Kind
	expectedLabel     string
	expectedRetryable bool
}

// taxonomyCases lists every taxonomy member in kind order.
func taxonomyCases() []taxonomyCase {
	return []taxonomyCase{
		{
			name:              "unattestable",
			err:               ErrUnattestable,
			expectedKind:      KindUnattestable,
			expectedLabel:     "unattestable",
			expectedRetryable: false,
		},
		{
			name:              "not enrolled",
			err:               ErrNotEnrolled,
			expectedKind:      KindNotEnrolled,
			expectedLabel:     "not_enrolled",
			expectedRetryable: false,
		},
		{
			name:              "token mint failed",
			err:               ErrTokenMintFailed,
			expectedKind:      KindTokenMintFailed,
			expectedLabel:     "token_mint_failed",
			expectedRetryable: true,
		},
		{
			name:              "token mint forbidden",
			err:               ErrTokenMintForbidden,
			expectedKind:      KindTokenMintForbidden,
			expectedLabel:     "token_mint_forbidden",
			expectedRetryable: false,
		},
		{
			name:              "session unavailable",
			err:               ErrSessionUnavailable,
			expectedKind:      KindSessionUnavailable,
			expectedLabel:     "session_unavailable",
			expectedRetryable: true,
		},
		{
			name:              "issuance failed",
			err:               ErrIssuanceFailed,
			expectedKind:      KindIssuanceFailed,
			expectedLabel:     "issuance_failed",
			expectedRetryable: true,
		},
		{
			name:              "issuance throttled",
			err:               ErrIssuanceThrottled,
			expectedKind:      KindIssuanceThrottled,
			expectedLabel:     "issuance_throttled",
			expectedRetryable: true,
		},
		{
			name:              "bundle unavailable",
			err:               ErrBundleUnavailable,
			expectedKind:      KindBundleUnavailable,
			expectedLabel:     "bundle_unavailable",
			expectedRetryable: true,
		},
		{
			name:              "invalid audience",
			err:               ErrInvalidAudience,
			expectedKind:      KindInvalidAudience,
			expectedLabel:     "invalid_audience",
			expectedRetryable: false,
		},
		{
			name:          "session refused",
			err:           ErrSessionRefused,
			expectedKind:  KindSessionRefused,
			expectedLabel: "session_refused",
		},
		{
			name:              "bundle refused",
			err:               ErrBundleRefused,
			expectedKind:      KindBundleRefused,
			expectedLabel:     "bundle_refused",
			expectedRetryable: false,
		},
		{
			name:              "issuance refused",
			err:               ErrIssuanceRefused,
			expectedKind:      KindIssuanceRefused,
			expectedLabel:     "issuance_refused",
			expectedRetryable: false,
		},
	}
}

// declaredSentinel is one taxonomy sentinel as written in workload_identity.go:
// the variable name, the Kind constant it was built with, and the label and
// retryable literals handed to the constructor.
type declaredSentinel struct {
	name      string
	kindName  string
	label     string
	retryable bool
}

// parseDeclaredTaxonomy returns the Kind constant names and the sentinels
// declared in workload_identity.go, both in declaration order, so the contract
// tests assert against what that file declares rather than against a list copied
// into this one. Kind constants are declared with iota starting at one, so the
// first name is Kind(1).
//
// It fails the test if the file cannot be parsed, or if a sentinel is not written
// as a direct call to the constructor with a kind identifier, a string literal
// label and a bool literal retryable decision, because a sentinel written any
// other way would carry a classification this test cannot read.
func parseDeclaredTaxonomy(t *testing.T) ([]string, []declaredSentinel) {
	t.Helper()
	g := NewWithT(t)

	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, workloadIdentitySourceFile, nil, parser.SkipObjectResolution)
	g.Expect(err).ToNot(HaveOccurred(),
		"cannot parse %s, which the taxonomy contract tests read their expectations from",
		workloadIdentitySourceFile)

	var kinds []string
	var sentinels []declaredSentinel
	for _, decl := range parsed.Decls {
		genDecl, isGenDecl := decl.(*ast.GenDecl)
		if !isGenDecl {
			continue
		}
		for _, spec := range genDecl.Specs {
			valueSpec, isValueSpec := spec.(*ast.ValueSpec)
			if !isValueSpec {
				continue
			}
			for i, ident := range valueSpec.Names {
				switch {
				case genDecl.Tok == token.CONST && strings.HasPrefix(ident.Name, kindConstantPrefix):
					kinds = append(kinds, ident.Name)
				case genDecl.Tok == token.VAR && strings.HasPrefix(ident.Name, sentinelVarPrefix):
					g.Expect(valueSpec.Values).To(HaveLen(len(valueSpec.Names)),
						"sentinel %s in %s is declared without its own value, "+
							"so this test cannot read its classification",
						ident.Name, workloadIdentitySourceFile)
					sentinels = append(sentinels, parseDeclaredSentinel(t, ident.Name, valueSpec.Values[i]))
				}
			}
		}
	}

	g.Expect(kinds).ToNot(BeEmpty(),
		"no %s* constants found in %s", kindConstantPrefix, workloadIdentitySourceFile)
	g.Expect(sentinels).ToNot(BeEmpty(),
		"no %s* sentinels found in %s", sentinelVarPrefix, workloadIdentitySourceFile)
	return kinds, sentinels
}

// parseDeclaredSentinel reads one sentinel's declared classification out of its
// constructor call.
func parseDeclaredSentinel(t *testing.T, name string, value ast.Expr) declaredSentinel {
	t.Helper()
	g := NewWithT(t)

	call, isCall := value.(*ast.CallExpr)
	g.Expect(isCall).To(BeTrue(),
		"sentinel %s in %s is not built by a call to %s",
		name, workloadIdentitySourceFile, sentinelConstructor)

	constructor, isIdent := call.Fun.(*ast.Ident)
	g.Expect(isIdent && constructor.Name == sentinelConstructor).To(BeTrue(),
		"sentinel %s in %s is not built by %s", name, workloadIdentitySourceFile, sentinelConstructor)
	g.Expect(call.Args).To(HaveLen(3),
		"sentinel %s in %s is built with %d arguments, want kind, label and retryable",
		name, workloadIdentitySourceFile, len(call.Args))

	kind, isIdent := call.Args[0].(*ast.Ident)
	g.Expect(isIdent).To(BeTrue(),
		"sentinel %s in %s is not built with a kind identifier", name, workloadIdentitySourceFile)

	literal, isLiteral := call.Args[1].(*ast.BasicLit)
	g.Expect(isLiteral && literal.Kind == token.STRING).To(BeTrue(),
		"sentinel %s in %s is not built with a string literal label", name, workloadIdentitySourceFile)
	label, unquoteErr := strconv.Unquote(literal.Value)
	g.Expect(unquoteErr).ToNot(HaveOccurred(),
		"cannot read the label of sentinel %s in %s", name, workloadIdentitySourceFile)

	retryable, isIdent := call.Args[2].(*ast.Ident)
	g.Expect(isIdent && (retryable.Name == "true" || retryable.Name == "false")).To(BeTrue(),
		"sentinel %s in %s is not built with a bool literal retryable decision",
		name, workloadIdentitySourceFile)

	return declaredSentinel{
		name:      name,
		kindName:  kind.Name,
		label:     label,
		retryable: retryable.Name == "true",
	}
}

func TestDeclaredTaxonomy_EverySentinel_IsRegisteredWithItsDeclaredClassification(t *testing.T) {
	g := NewWithT(t)

	kinds, sentinels := parseDeclaredTaxonomy(t)
	taxonomy := WorkloadIdentityTaxonomy()

	g.Expect(kinds).To(HaveLen(len(sentinels)),
		"%s declares %d %s* constants and %d sentinels, so one of them has no counterpart",
		workloadIdentitySourceFile, len(kinds), kindConstantPrefix, len(sentinels))
	g.Expect(taxonomy).To(HaveLen(len(sentinels)),
		"WorkloadIdentityTaxonomy() returns %d members but %s declares %d sentinels, "+
			"so a handler asserting its mapping is total over the taxonomy would miss one",
		len(taxonomy), workloadIdentitySourceFile, len(sentinels))
	g.Expect(taxonomyCases()).To(HaveLen(len(sentinels)),
		"taxonomyCases() pins %d members but %s declares %d sentinels",
		len(taxonomyCases()), workloadIdentitySourceFile, len(sentinels))

	kindOf := make(map[string]Kind, len(kinds))
	for i, name := range kinds {
		kindOf[name] = Kind(i + 1)
	}

	memberByLabel := make(map[string]*WorkloadIdentityError, len(taxonomy))
	for _, member := range taxonomy {
		memberByLabel[member.MetricLabel()] = member
	}

	caseByLabel := make(map[string]taxonomyCase, len(taxonomyCases()))
	for _, tc := range taxonomyCases() {
		caseByLabel[tc.expectedLabel] = tc
	}

	declaredLabels := make(map[string]bool, len(sentinels))
	for _, declared := range sentinels {
		declaredLabels[declared.label] = true
	}
	for _, member := range taxonomy {
		g.Expect(declaredLabels).To(HaveKey(member.MetricLabel()),
			"WorkloadIdentityTaxonomy() returns a member labelled %q, which no sentinel in %s declares",
			member.MetricLabel(), workloadIdentitySourceFile)
	}

	for _, declared := range sentinels {
		t.Run(declared.name, func(t *testing.T) {
			g := NewWithT(t)

			member, registered := memberByLabel[declared.label]
			g.Expect(registered).To(BeTrue(),
				"sentinel %s is declared with label %q in %s but WorkloadIdentityTaxonomy() "+
					"returns no member carrying it",
				declared.name, declared.label, workloadIdentitySourceFile)

			expectedKind, isDeclaredKind := kindOf[declared.kindName]
			g.Expect(isDeclaredKind).To(BeTrue(),
				"sentinel %s is built with %s, which is not a %s* constant declared in %s",
				declared.name, declared.kindName, kindConstantPrefix, workloadIdentitySourceFile)
			g.Expect(member.Kind()).To(Equal(expectedKind))

			g.Expect(member.Retryable()).To(Equal(declared.retryable))
			g.Expect(IsRetryable(member)).To(Equal(declared.retryable))
			g.Expect(MetricLabel(member)).To(Equal(declared.label))

			pinned, hasCase := caseByLabel[declared.label]
			g.Expect(hasCase).To(BeTrue(),
				"sentinel %s is declared in %s but taxonomyCases() pins no case for label %q",
				declared.name, workloadIdentitySourceFile, declared.label)
			g.Expect(pinned.err).To(BeIdenticalTo(member))
			g.Expect(pinned.expectedKind).To(Equal(expectedKind))
			g.Expect(pinned.expectedRetryable).To(Equal(declared.retryable))
		})
	}
}

func TestWorkloadIdentitySentinel_EverySentinel_HasOneKindLabelAndRetryableDecision(t *testing.T) {
	for _, tc := range taxonomyCases() {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			g.Expect(tc.err.Kind()).To(Equal(tc.expectedKind))
			g.Expect(tc.err.MetricLabel()).To(Equal(tc.expectedLabel))
			g.Expect(tc.err.Retryable()).To(Equal(tc.expectedRetryable))

			// the package level accessors agree with the methods
			g.Expect(MetricLabel(tc.err)).To(Equal(tc.expectedLabel))
			g.Expect(IsRetryable(tc.err)).To(Equal(tc.expectedRetryable))

			wiErr, ok := AsWorkloadIdentityError(tc.err)
			g.Expect(ok).To(BeTrue())
			g.Expect(wiErr).To(BeIdenticalTo(tc.err))
		})
	}
}

func TestWorkloadIdentityTaxonomy_AllMembers_AreContiguousDistinctAndLabelled(t *testing.T) {
	g := NewWithT(t)
	taxonomy := WorkloadIdentityTaxonomy()

	g.Expect(taxonomy).To(HaveLen(12))

	seenKinds := make(map[Kind]bool, len(taxonomy))
	seenLabels := make(map[string]bool, len(taxonomy))
	for i, member := range taxonomy {
		g.Expect(member).ToNot(BeNil())

		// kinds are contiguous 1..12 in slice order, so there is no gap and no
		// duplicate
		g.Expect(member.Kind()).To(Equal(Kind(i + 1)))
		g.Expect(seenKinds).ToNot(HaveKey(member.Kind()))
		seenKinds[member.Kind()] = true

		g.Expect(member.MetricLabel()).ToNot(BeEmpty())
		g.Expect(seenLabels).ToNot(HaveKey(member.MetricLabel()))
		seenLabels[member.MetricLabel()] = true

		// the label mapping is total over the taxonomy
		g.Expect(MetricLabel(member)).To(Equal(member.MetricLabel()))
		g.Expect(MetricLabel(member)).ToNot(Equal(MetricLabelUnknown))
	}

	g.Expect(seenKinds).To(HaveLen(12))
	g.Expect(seenLabels).To(HaveLen(12))

	// every sentinel declared in the package is reachable from the taxonomy
	g.Expect(taxonomy).To(ConsistOf(
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
	))
}

func TestMetricLabelAndIsRetryable_WrappedAndForeignErrors_ClassifyThroughTheChain(t *testing.T) {
	// typedNil is an error interface holding a nil taxonomy pointer, which is what
	// a tier returns when it declares a *WorkloadIdentityError result and returns
	// it unset on the success path.
	var typedNilPointer *WorkloadIdentityError
	var typedNil error = typedNilPointer

	testCases := []struct {
		name               string
		err                error
		expectedLabel      string
		expectedRetryable  bool
		expectedClassified bool
	}{
		{
			name:               "nil error",
			err:                nil,
			expectedLabel:      MetricLabelNone,
			expectedRetryable:  false,
			expectedClassified: false,
		},
		{
			name:               "typed nil taxonomy pointer in an error interface",
			err:                typedNil,
			expectedLabel:      MetricLabelUnknown,
			expectedRetryable:  false,
			expectedClassified: false,
		},
		{
			name:               "forged zero value",
			err:                &WorkloadIdentityError{},
			expectedLabel:      MetricLabelUnknown,
			expectedRetryable:  false,
			expectedClassified: true,
		},
		{
			name:               "error outside the taxonomy",
			err:                fmt.Errorf("something else went wrong"),
			expectedLabel:      MetricLabelUnknown,
			expectedRetryable:  false,
			expectedClassified: false,
		},
		{
			name:               "bare non retryable sentinel",
			err:                ErrUnattestable,
			expectedLabel:      "unattestable",
			expectedRetryable:  false,
			expectedClassified: true,
		},
		{
			name:               "bare retryable sentinel",
			err:                ErrIssuanceThrottled,
			expectedLabel:      "issuance_throttled",
			expectedRetryable:  true,
			expectedClassified: true,
		},
		{
			name:               "wrapped sentinel",
			err:                fmt.Errorf("minting for pod: %w", ErrTokenMintFailed),
			expectedLabel:      "token_mint_failed",
			expectedRetryable:  true,
			expectedClassified: true,
		},
		{
			name:               "wrapped forbidden mint sentinel",
			err:                fmt.Errorf("minting for pod: %w", ErrTokenMintForbidden),
			expectedLabel:      "token_mint_forbidden",
			expectedRetryable:  false,
			expectedClassified: true,
		},
		{
			name:               "doubly wrapped sentinel",
			err:                fmt.Errorf("serving request: %w", fmt.Errorf("fetching session: %w", ErrSessionUnavailable)),
			expectedLabel:      "session_unavailable",
			expectedRetryable:  true,
			expectedClassified: true,
		},
		{
			name:               "annotated sentinel",
			err:                ErrBundleUnavailable.Wrapf(fmt.Errorf("connection reset"), "fetching trust bundles for %s", "cluster-a"),
			expectedLabel:      "bundle_unavailable",
			expectedRetryable:  true,
			expectedClassified: true,
		},
		{
			name:               "wrapped annotated sentinel",
			err:                fmt.Errorf("serving request: %w", ErrInvalidAudience.Wrapf(nil, "audience %q is not accepted", "nope")),
			expectedLabel:      "invalid_audience",
			expectedRetryable:  false,
			expectedClassified: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			g.Expect(MetricLabel(tc.err)).To(Equal(tc.expectedLabel))
			g.Expect(IsRetryable(tc.err)).To(Equal(tc.expectedRetryable))

			wiErr, ok := AsWorkloadIdentityError(tc.err)
			g.Expect(ok).To(Equal(tc.expectedClassified))
			g.Expect(wiErr != nil).To(Equal(tc.expectedClassified))
		})
	}
}

func TestAsWorkloadIdentityError_TypedNilTaxonomyPointer_ReportsUnclassifiedWithoutPanicking(t *testing.T) {
	g := NewWithT(t)

	var typed *WorkloadIdentityError
	var err error = typed

	// the interface itself is not nil, so a caller that only checks err != nil
	// hands this value straight to the classifiers
	g.Expect(err == nil).To(BeFalse())

	wiErr, ok := AsWorkloadIdentityError(err)
	g.Expect(ok).To(BeFalse())
	g.Expect(wiErr).To(BeNil())

	// both mappings answer for it instead of dereferencing the nil pointer
	g.Expect(func() { _ = MetricLabel(err) }).ToNot(Panic())
	g.Expect(func() { _ = IsRetryable(err) }).ToNot(Panic())
	g.Expect(MetricLabel(err)).To(Equal(MetricLabelUnknown))
	g.Expect(IsRetryable(err)).To(BeFalse())
}

func TestMetricLabel_ForgedZeroValue_FallsBackToTheUnclassifiedLabel(t *testing.T) {
	g := NewWithT(t)

	// every field is unexported, so any package can build this value but none can
	// give it a label
	forged := &WorkloadIdentityError{}
	g.Expect(forged.MetricLabel()).To(BeEmpty())

	g.Expect(MetricLabel(forged)).To(Equal(MetricLabelUnknown))
	g.Expect(MetricLabel(fmt.Errorf("serving request: %w", forged))).To(Equal(MetricLabelUnknown))
	g.Expect(MetricLabel(forged.Wrapf(fmt.Errorf("cause"), "annotated"))).To(Equal(MetricLabelUnknown))
}

func TestMetricLabelConstants_ReservedLabels_AreDistinctAndValidLabelValues(t *testing.T) {
	g := NewWithT(t)
	// lower_snake_case, which is what every taxonomy label and both reserved
	// labels have to be to sit in one metric dimension
	labelPattern := regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)

	g.Expect(MetricLabelNone).To(Equal("none"))
	g.Expect(MetricLabelUnknown).To(Equal("unknown"))
	g.Expect(labelPattern.MatchString(MetricLabelNone)).To(BeTrue())
	g.Expect(labelPattern.MatchString(MetricLabelUnknown)).To(BeTrue())

	// no taxonomy member collides with either reserved value, so success, an
	// unclassified failure, and a classified failure are three distinct readings
	for _, member := range WorkloadIdentityTaxonomy() {
		label := member.MetricLabel()
		g.Expect(labelPattern.MatchString(label)).To(BeTrue(), "label %q is not lower_snake_case", label)
		g.Expect(label).ToNot(Equal(MetricLabelNone))
		g.Expect(label).ToNot(Equal(MetricLabelUnknown))
	}
}

func TestErrorsIs_FullTaxonomyMatrix_MatchesOnlyTheSameKind(t *testing.T) {
	cases := taxonomyCases()

	for _, subject := range cases {
		for _, target := range cases {
			t.Run(fmt.Sprintf("%s against %s", subject.name, target.name), func(t *testing.T) {
				g := NewWithT(t)
				expected := subject.expectedKind == target.expectedKind

				g.Expect(errors.Is(subject.err, target.err)).To(Equal(expected))
				g.Expect(errors.Is(fmt.Errorf("wrapped: %w", subject.err), target.err)).To(Equal(expected))
				g.Expect(errors.Is(
					fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", subject.err)),
					target.err,
				)).To(Equal(expected))
				g.Expect(errors.Is(
					subject.err.Wrapf(fmt.Errorf("cause"), "annotated"),
					target.err,
				)).To(Equal(expected))
			})
		}
	}
}

func TestWrapf_OnSentinel_KeepsClassificationAndLeavesSentinelUnchanged(t *testing.T) {
	for _, tc := range taxonomyCases() {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			sentinelMessage := tc.err.Error()
			cause := fmt.Errorf("underlying i/o failure")

			annotated := tc.err.Wrapf(cause, "operating on %s attempt %d", "pod-a", 2)

			// classification survives
			g.Expect(annotated.Kind()).To(Equal(tc.expectedKind))
			g.Expect(annotated.MetricLabel()).To(Equal(tc.expectedLabel))
			g.Expect(annotated.Retryable()).To(Equal(tc.expectedRetryable))
			g.Expect(MetricLabel(annotated)).To(Equal(tc.expectedLabel))
			g.Expect(IsRetryable(annotated)).To(Equal(tc.expectedRetryable))
			g.Expect(errors.Is(annotated, tc.err)).To(BeTrue())

			// message and cause are both rendered, and the cause is reachable
			g.Expect(annotated.Error()).To(ContainSubstring("operating on pod-a attempt 2"))
			g.Expect(annotated.Error()).To(ContainSubstring("underlying i/o failure"))
			g.Expect(errors.Unwrap(annotated)).To(BeIdenticalTo(cause))
			g.Expect(errors.Is(annotated, cause)).To(BeTrue())

			// the shared sentinel is untouched
			g.Expect(annotated).ToNot(BeIdenticalTo(tc.err))
			g.Expect(tc.err.Error()).To(Equal(sentinelMessage))
			g.Expect(tc.err.Error()).ToNot(ContainSubstring("operating on pod-a"))
			g.Expect(tc.err.Error()).ToNot(ContainSubstring("underlying i/o failure"))
			g.Expect(errors.Unwrap(tc.err)).To(BeNil())
		})
	}
}

func TestError_BareSentinel_RendersNonEmptyText(t *testing.T) {
	for _, tc := range taxonomyCases() {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			g.Expect(tc.err.Error()).ToNot(BeEmpty())
		})
	}
}
