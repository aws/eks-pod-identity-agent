package cmd

import (
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	. "github.com/onsi/gomega"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/handlers"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// TestServerCmd_WorkloadIdentityFlags_AreRegisteredWithTheAgreedDefaults pins the
// flag names and defaults that the workload identity tasks agreed on. A flag
// missing from this table is a flag missing from --help.
func TestServerCmd_WorkloadIdentityFlags_AreRegisteredWithTheAgreedDefaults(t *testing.T) {
	x509Lower, x509Upper := handlers.X509SVIDDurationBounds()
	jwtLower, jwtUpper := handlers.JWTSVIDDurationBounds()

	testCases := []struct {
		flag            string
		expectedDefault string
		// expectedUsageBound is the envelope the usage string has to name, for
		// the flags that have one.
		expectedUsageBound string
	}{
		{
			// Twelve hours, which is both the top of the envelope and what STS issues
			// when the request names no lifetime. Confirmed with STS on 2026-10-02.
			flag:               handlers.FlagX509SVIDDuration,
			expectedDefault:    "12h0m0s",
			expectedUsageBound: fmt.Sprintf("between %s and %s", x509Lower, x509Upper),
		},
		{
			flag:               handlers.FlagJWTSVIDDuration,
			expectedDefault:    "6h0m0s",
			expectedUsageBound: fmt.Sprintf("between %s and %s", jwtLower, jwtUpper),
		},
		// Half life, which STS recommended on 2026-10-02.
		{flag: handlers.FlagSVIDRenewalFraction, expectedDefault: "0.5"},
		{flag: handlers.FlagSVIDRenewalJitter, expectedDefault: "0.1"},
		{
			flag:               handlers.FlagSVIDKeyType,
			expectedDefault:    string(workloadidentity.DefaultKeyType),
			expectedUsageBound: workloadidentity.KeyTypeList(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.flag, func(t *testing.T) {
			g := NewWithT(t)

			flag := serverCmd.Flags().Lookup(tc.flag)
			g.Expect(flag).ToNot(BeNil(), "flag --%s is not registered on the server command", tc.flag)
			g.Expect(flag.DefValue).To(Equal(tc.expectedDefault))
			g.Expect(flag.Usage).ToNot(BeEmpty(), "a flag with no usage string is invisible in --help")
			g.Expect(serverCmd.Flags().FlagUsages()).To(ContainSubstring("--" + tc.flag))
			if tc.expectedUsageBound != "" {
				g.Expect(flag.Usage).To(ContainSubstring(tc.expectedUsageBound),
					"--help has to state the envelope, and state the one validation enforces")
			}
		})
	}
}

// TestNewWorkloadIdentityServerOpts_RegisteredDefaults_PassValidation is the test
// that catches a default drifting outside its envelope. pflag writes each default
// into its bound variable at registration, so the values read here are the ones a
// boot with no workload identity flags would use.
func TestNewWorkloadIdentityServerOpts_RegisteredDefaults_PassValidation(t *testing.T) {
	g := NewWithT(t)

	opts := newWorkloadIdentityServerOpts(aws.Config{})

	g.Expect(opts.Validate()).To(Succeed())
	g.Expect(opts.X509SVIDDuration).To(Equal(12 * time.Hour))
	g.Expect(opts.JWTSVIDDuration).To(Equal(6 * time.Hour))
	g.Expect(opts.SVIDRenewalFraction).To(Equal(0.5))
	g.Expect(opts.SVIDRenewalJitter).To(Equal(0.1))
	g.Expect(opts.SVIDKeyType).To(Equal(workloadidentity.DefaultKeyType))
}

// TestNewWorkloadIdentityServerOpts_ParsedFlags_ReachTheOptions proves the wiring
// from the command line to the struct the tiers read, so a tier never has to read
// a flag itself.
func TestNewWorkloadIdentityServerOpts_ParsedFlags_ReachTheOptions(t *testing.T) {
	g := NewWithT(t)

	restoreWorkloadIdentityFlags(t)

	err := serverCmd.Flags().Parse([]string{
		"--cluster-name=cluster-a",
		"--x509-svid-duration=1h",
		"--jwt-svid-duration=2h",
		"--svid-renewal-fraction=0.75",
		"--svid-renewal-jitter=0.25",
		// Not a workload identity flag. It is the credentials path's cache bound,
		// which the token tier reads rather than defining a second one, so this
		// asserts the shared value arrives and not just that the field exists.
		"--max-cache-size=512",
	})
	g.Expect(err).ToNot(HaveOccurred())

	cfg := aws.Config{Region: "us-west-2"}
	opts := newWorkloadIdentityServerOpts(cfg)

	g.Expect(opts.Validate()).To(Succeed())
	g.Expect(opts.Cfg.Region).To(Equal("us-west-2"))
	g.Expect(opts.ClusterName).To(Equal("cluster-a"))
	g.Expect(opts.X509SVIDDuration).To(Equal(time.Hour))
	g.Expect(opts.JWTSVIDDuration).To(Equal(2 * time.Hour))
	g.Expect(opts.SVIDRenewalFraction).To(Equal(0.75))
	g.Expect(opts.SVIDRenewalJitter).To(Equal(0.25))
	g.Expect(opts.MaxCacheSize).To(Equal(512))
}

// TestNewWorkloadIdentityServerOpts_AnOutOfEnvelopeFlag_FailsValidation is the
// path that fails a boot. The command's Run turns this error into a fatal, which
// a test cannot exercise without ending the test binary, so the check is on the
// error the fatal reports.
func TestNewWorkloadIdentityServerOpts_AnOutOfEnvelopeFlag_FailsValidation(t *testing.T) {
	g := NewWithT(t)

	restoreWorkloadIdentityFlags(t)

	err := serverCmd.Flags().Parse([]string{"--cluster-name=cluster-a", "--x509-svid-duration=24h"})
	g.Expect(err).ToNot(HaveOccurred())

	validationErr := newWorkloadIdentityServerOpts(aws.Config{}).Validate()
	g.Expect(validationErr).To(HaveOccurred())
	g.Expect(validationErr.Error()).To(ContainSubstring("--" + handlers.FlagX509SVIDDuration))
}

// restoreWorkloadIdentityFlags puts the flag-bound package variables back after a
// test parses a command line into them, since they are process wide.
func restoreWorkloadIdentityFlags(t *testing.T) {
	t.Helper()

	originalCluster := clusterName
	originalX509 := x509SVIDDuration
	originalJWT := jwtSVIDDuration
	originalFraction := svidRenewalFraction
	originalJitter := svidRenewalJitter
	// maxCacheSize is not a workload identity flag, it is the credentials path's
	// --max-cache-size that both paths now read. It is restored here because a
	// test that parses it would otherwise leave the AWS credentials cache resized
	// for every test that runs after it.
	originalMaxCacheSize := maxCacheSize

	t.Cleanup(func() {
		clusterName = originalCluster
		x509SVIDDuration = originalX509
		jwtSVIDDuration = originalJWT
		svidRenewalFraction = originalFraction
		svidRenewalJitter = originalJitter
		maxCacheSize = originalMaxCacheSize
	})
}
