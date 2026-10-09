package workloadidentity

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
)

// metricsSourceFile is the file the constant contract is read back from. Go runs
// a test binary with its own package directory as the working directory, so the
// bare file name resolves.
const metricsSourceFile = "metrics.go"

// metricConstantPrefix marks the constants that carry a metric name. Every one
// of them has to be returned by MetricNames().
const metricConstantPrefix = "Metric"

// labelConstantPrefix marks the constants that carry a label name. Every one of
// them has to be in labelNames, so the cardinality and naming checks see it.
const labelConstantPrefix = "Label"

// valueConstantPrefixes marks the constants that carry a label value. Every one
// of them has to be in labelValueSets, so the lower_snake_case check sees it.
var valueConstantPrefixes = []string{"Outcome", "Format", "CacheTier", "CacheResult", "CredentialSource", "Reason", "RPC", "Delivery"}

// prometheusMetricName is the metric name grammar Prometheus enforces.
var prometheusMetricName = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)

// lowerSnakeCase is the shape required of every label name and label value.
var lowerSnakeCase = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// labelNames is every label name this package declares. The declared set is read
// back out of metrics.go by
// TestDeclaredConstants_EveryLabelConstant_IsCoveredByLabelNames, so a label
// constant missing from this slice fails rather than going unchecked.
var labelNames = []string{
	LabelOutcome,
	LabelReason,
	LabelError,
	LabelFormat,
	LabelRPC,
	LabelDelivery,
	LabelTier,
	LabelResult,
	LabelSource,
}

// labelValueSets is every label value set this package declares, keyed by the
// label the values belong to. The declared set is read back out of metrics.go by
// TestDeclaredConstants_EveryValueConstant_IsCoveredByLabelValueSets, so a value
// constant missing from these sets fails rather than going unchecked.
var labelValueSets = map[string][]string{
	"outcome":  {OutcomeSuccess, OutcomeFailure},
	"format":   {FormatX509SVID, FormatJWTSVID},
	"tier":     {CacheTierToken, CacheTierSession, CacheTierX509SVID, CacheTierJWTSVID, CacheTierBundle},
	"result":   {CacheResultHit, CacheResultMiss, CacheResultExpired, CacheResultEvicted},
	"delivery": {DeliverySignalled, DeliveryCoalesced},
	"source":   {CredentialSourceEKSAuth, CredentialSourceIMDSFirst},
	"rpc": {
		RPCFetchX509SVID,
		RPCFetchX509Bundles,
		RPCFetchJWTSVID,
		RPCFetchJWTBundles,
		RPCValidateJWTSVID,
		RPCStreamSecrets,
		RPCFetchSecrets,
	},
	"reason": {
		ReasonNotUnixSocket,
		ReasonPeerCredFailed,
		ReasonPeerPIDZero,
		ReasonPeerGone,
		ReasonLivenessRecheckFailed,
		ReasonCgroupNoPodUID,
		ReasonCgroupReadFailed,
		ReasonPodNotInStore,
		ReasonPodNodeMismatch,
	},
}

// forbiddenLabelNames is every label name the cardinality rule rejects. Each one
// identifies a pod, a namespace or a ServiceAccount, so its value count grows
// with cluster churn.
var forbiddenLabelNames = []string{
	"pod",
	"pod_uid",
	"poduid",
	"pod_name",
	"podname",
	"namespace",
	"ns",
	"service_account",
	"serviceaccount",
	"sa",
	"uid",
	"container_id",
}

// declaredConstant is one exported top-level constant of metrics.go, as read
// from the source rather than from a list copied into this test.
type declaredConstant struct {
	name  string
	value string
}

// parseDeclaredConstants returns every exported top-level constant declared in
// metrics.go, in declaration order. It fails the test if the file cannot be
// parsed, and if any exported constant is not written as a plain string literal,
// because metrics.go declares names only and this test reads the literals
// directly rather than evaluating expressions.
func parseDeclaredConstants(t *testing.T) []declaredConstant {
	t.Helper()
	g := NewWithT(t)

	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, metricsSourceFile, nil, parser.SkipObjectResolution)
	g.Expect(err).ToNot(HaveOccurred(),
		"cannot parse %s, which the constant contract tests read their expectations from",
		metricsSourceFile)

	var constants []declaredConstant
	for _, decl := range parsed.Decls {
		genDecl, isGenDecl := decl.(*ast.GenDecl)
		if !isGenDecl || genDecl.Tok != token.CONST {
			continue
		}
		for _, spec := range genDecl.Specs {
			valueSpec, isValueSpec := spec.(*ast.ValueSpec)
			g.Expect(isValueSpec).To(BeTrue(),
				"a const spec in %s is not a value spec", metricsSourceFile)
			g.Expect(valueSpec.Values).To(HaveLen(len(valueSpec.Names)),
				"every constant in %s must be declared with its own literal value, "+
					"otherwise this test cannot read it", metricsSourceFile)
			for i, ident := range valueSpec.Names {
				if !ident.IsExported() {
					continue
				}
				literal, isLiteral := valueSpec.Values[i].(*ast.BasicLit)
				g.Expect(isLiteral && literal.Kind == token.STRING).To(BeTrue(),
					"constant %s in %s is not a string literal, but that file declares names only",
					ident.Name, metricsSourceFile)
				value, unquoteErr := strconv.Unquote(literal.Value)
				g.Expect(unquoteErr).ToNot(HaveOccurred(),
					"cannot read the value of constant %s in %s", ident.Name, metricsSourceFile)
				constants = append(constants, declaredConstant{name: ident.Name, value: value})
			}
		}
	}

	g.Expect(constants).ToNot(BeEmpty(),
		"no exported constants found in %s, so the contract tests would assert nothing",
		metricsSourceFile)
	return constants
}

// declaredConstantsWithPrefix returns the constants whose name starts with
// prefix, in declaration order.
func declaredConstantsWithPrefix(constants []declaredConstant, prefix string) []declaredConstant {
	var matched []declaredConstant
	for _, constant := range constants {
		if strings.HasPrefix(constant.name, prefix) {
			matched = append(matched, constant)
		}
	}
	return matched
}

// declaredMetricConstants returns every Metric* constant declared in metrics.go.
func declaredMetricConstants(t *testing.T) []declaredConstant {
	t.Helper()
	return declaredConstantsWithPrefix(parseDeclaredConstants(t), metricConstantPrefix)
}

// auditedLabelNames returns every label name the cardinality rule is enforced
// over: the value of every Label* constant declared in metrics.go, unioned with
// the labelNames slice. Sorted, so subtest names are stable.
func auditedLabelNames(t *testing.T) []string {
	t.Helper()

	seen := map[string]bool{}
	for _, constant := range declaredConstantsWithPrefix(parseDeclaredConstants(t), labelConstantPrefix) {
		seen[constant.value] = true
	}
	for _, name := range labelNames {
		seen[name] = true
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func TestDeclaredConstants_EveryMetricConstant_IsReturnedByMetricNamesAndNothingElse(t *testing.T) {
	g := NewWithT(t)

	declared := declaredMetricConstants(t)
	names := MetricNames()

	g.Expect(names).To(HaveLen(len(declared)),
		"MetricNames() returns %d names but %s declares %d %s* constants",
		len(names), metricsSourceFile, len(declared), metricConstantPrefix)

	returned := map[string]bool{}
	for _, name := range names {
		returned[name] = true
	}
	for _, constant := range declared {
		g.Expect(returned).To(HaveKey(constant.value),
			"constant %s = %q is declared in %s but MetricNames() does not return it",
			constant.name, constant.value, metricsSourceFile)
	}

	declaredValues := map[string]bool{}
	for _, constant := range declared {
		declaredValues[constant.value] = true
	}
	for _, name := range names {
		g.Expect(declaredValues).To(HaveKey(name),
			"MetricNames() returns %q, which no %s* constant in %s declares",
			name, metricConstantPrefix, metricsSourceFile)
	}
}

func TestDeclaredConstants_EveryLabelConstant_IsCoveredByLabelNames(t *testing.T) {
	declared := declaredConstantsWithPrefix(parseDeclaredConstants(t), labelConstantPrefix)

	g := NewWithT(t)
	g.Expect(declared).ToNot(BeEmpty(),
		"no %s* constants found in %s", labelConstantPrefix, metricsSourceFile)

	for _, constant := range declared {
		t.Run(constant.name, func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(labelNames).To(ContainElement(constant.value),
				"constant %s = %q is declared in %s but is absent from labelNames, "+
					"so it escapes the label naming and cardinality checks",
				constant.name, constant.value, metricsSourceFile)
		})
	}
}

func TestDeclaredConstants_EveryValueConstant_IsCoveredByLabelValueSets(t *testing.T) {
	constants := parseDeclaredConstants(t)

	covered := map[string]bool{}
	for _, values := range labelValueSets {
		for _, value := range values {
			covered[value] = true
		}
	}

	for _, prefix := range valueConstantPrefixes {
		declared := declaredConstantsWithPrefix(constants, prefix)
		t.Run(prefix, func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(declared).ToNot(BeEmpty(),
				"no %s* constants found in %s", prefix, metricsSourceFile)
			for _, constant := range declared {
				g.Expect(covered).To(HaveKey(constant.value),
					"constant %s = %q is declared in %s but is absent from labelValueSets, "+
						"so it escapes the lower_snake_case check",
					constant.name, constant.value, metricsSourceFile)
			}
		})
	}
}

func TestDeclaredConstants_EveryValue_IsANonEmptyString(t *testing.T) {
	g := NewWithT(t)

	for _, constant := range parseDeclaredConstants(t) {
		g.Expect(constant.value).ToNot(BeEmpty(),
			"constant %s in %s has an empty value", constant.name, metricsSourceFile)
	}
}

func TestMetricNames_Declared_MatchesExpectedListExactly(t *testing.T) {
	g := NewWithT(t)

	expected := []string{
		"workload_identity_attestation_total",
		"workload_identity_attestation_duration_seconds",
		"workload_identity_token_mint_total",
		"workload_identity_token_mint_duration_seconds",
		"workload_identity_session_total",
		"workload_identity_session_duration_seconds",
		"workload_identity_svid_issuance_total",
		"workload_identity_svid_issuance_duration_seconds",
		"workload_identity_svid_renewal_total",
		"workload_identity_bundle_fetch_total",
		"workload_identity_bundle_fetch_duration_seconds",
		"workload_identity_bundle_change_total",
		"workload_identity_subscriptions_active",
		"workload_identity_notification_total",
		"workload_identity_cache_total",
		"workload_identity_credential_source_total",
		"workload_identity_rpc_total",
		"workload_identity_rpc_duration_seconds",
	}

	// The count comes from the declared constants, so adding a metric constant
	// without adding it here fails.
	declaredCount := len(declaredMetricConstants(t))

	names := MetricNames()
	g.Expect(names).To(HaveLen(declaredCount))
	g.Expect(expected).To(HaveLen(declaredCount))
	g.Expect(names).To(Equal(expected))

	seen := map[string]bool{}
	for _, name := range names {
		g.Expect(seen[name]).To(BeFalse(), "duplicate metric name %q", name)
		seen[name] = true
	}
}

func TestMetricNames_EveryName_MatchesPrometheusGrammarWithFeaturePrefix(t *testing.T) {
	for _, name := range MetricNames() {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(prometheusMetricName.MatchString(name)).To(BeTrue(),
				"metric name %q does not match the Prometheus grammar", name)
			g.Expect(name).To(HavePrefix("workload_identity_"))
		})
	}
}

func TestMetricNames_ByInstrumentKind_HasExpectedSuffix(t *testing.T) {
	testCases := []struct {
		name       string
		metric     string
		wantSuffix string
	}{
		{name: "attestation counter", metric: MetricAttestationTotal, wantSuffix: "_total"},
		{name: "attestation histogram", metric: MetricAttestationDuration, wantSuffix: "_duration_seconds"},
		{name: "token mint counter", metric: MetricTokenMintTotal, wantSuffix: "_total"},
		{name: "token mint histogram", metric: MetricTokenMintDuration, wantSuffix: "_duration_seconds"},
		{name: "session counter", metric: MetricSessionTotal, wantSuffix: "_total"},
		{name: "session histogram", metric: MetricSessionDuration, wantSuffix: "_duration_seconds"},
		{name: "svid issuance counter", metric: MetricSvidIssuanceTotal, wantSuffix: "_total"},
		{name: "svid issuance histogram", metric: MetricSvidIssuanceDuration, wantSuffix: "_duration_seconds"},
		{name: "svid renewal counter", metric: MetricSvidRenewalTotal, wantSuffix: "_total"},
		{name: "bundle fetch counter", metric: MetricBundleFetchTotal, wantSuffix: "_total"},
		{name: "bundle fetch histogram", metric: MetricBundleFetchDuration, wantSuffix: "_duration_seconds"},
		{name: "bundle change counter", metric: MetricBundleChangeTotal, wantSuffix: "_total"},
		{name: "notification counter", metric: MetricNotificationTotal, wantSuffix: "_total"},
		{name: "cache counter", metric: MetricCacheTotal, wantSuffix: "_total"},
		{name: "credential source counter", metric: MetricCredentialSourceTotal, wantSuffix: "_total"},
		{name: "rpc counter", metric: MetricRPCTotal, wantSuffix: "_total"},
		{name: "rpc histogram", metric: MetricRPCDuration, wantSuffix: "_duration_seconds"},
		// The only gauge carries neither suffix, because it is a level rather
		// than an accumulation or an observation.
		{name: "subscriptions gauge", metric: MetricSubscriptionsActive, wantSuffix: ""},
	}

	g := NewWithT(t)

	// The table is checked against the declared constants, so adding a metric
	// constant without adding a case here fails.
	declared := declaredMetricConstants(t)
	g.Expect(testCases).To(HaveLen(len(declared)))

	covered := map[string]bool{}
	for _, tc := range testCases {
		covered[tc.metric] = true
	}
	for _, constant := range declared {
		g.Expect(covered).To(HaveKey(constant.value),
			"constant %s = %q is declared in %s but has no suffix case here",
			constant.name, constant.value, metricsSourceFile)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			if tc.wantSuffix == "" {
				g.Expect(tc.metric).ToNot(HaveSuffix("_total"))
				g.Expect(tc.metric).ToNot(HaveSuffix("_duration_seconds"))
				return
			}
			g.Expect(tc.metric).To(HaveSuffix(tc.wantSuffix))
			// A histogram name must not also read as a counter.
			if tc.wantSuffix == "_duration_seconds" {
				g.Expect(tc.metric).ToNot(HaveSuffix("_total"))
			}
		})
	}
}

func TestLabelNames_Declared_AreLowerSnakeCaseAndUnique(t *testing.T) {
	g := NewWithT(t)

	seen := map[string]bool{}
	for _, name := range labelNames {
		g.Expect(lowerSnakeCase.MatchString(name)).To(BeTrue(),
			"label name %q is not lower_snake_case", name)
		g.Expect(seen[name]).To(BeFalse(), "duplicate label name %q", name)
		seen[name] = true
	}
	g.Expect(seen).To(HaveLen(len(labelNames)))
}

func TestLabelValues_EverySet_IsLowerSnakeCaseAndUniqueWithinTheSet(t *testing.T) {
	for label, values := range labelValueSets {
		t.Run(label, func(t *testing.T) {
			g := NewWithT(t)
			seen := map[string]bool{}
			for _, value := range values {
				g.Expect(lowerSnakeCase.MatchString(value)).To(BeTrue(),
					"value %q of label %q is not lower_snake_case", value, label)
				g.Expect(seen[value]).To(BeFalse(),
					"duplicate value %q for label %q", value, label)
				seen[value] = true
			}
		})
	}
}

func TestLabelNames_CardinalityRule_RejectsPodIdentifyingLabels(t *testing.T) {
	// The names come from the Label* constants declared in metrics.go, so a
	// label constant added there is subject to the rule whether or not anyone
	// remembered to list it in this file.
	for _, name := range auditedLabelNames(t) {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			for _, bad := range forbiddenLabelNames {
				g.Expect(strings.EqualFold(name, bad)).To(BeFalse(),
					"label %q is forbidden by the cardinality rule: no per-pod, "+
						"per-namespace or per-service-account labels", name)
			}
		})
	}
}
