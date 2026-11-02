package cmd

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/types"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/credcache"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
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
			expectedDefault:    "1h0m0s",
			expectedUsageBound: fmt.Sprintf("between %s and %s", jwtLower, jwtUpper),
		},
		// Half life, which STS recommended on 2026-10-02.
		{flag: handlers.FlagSVIDRenewalFraction, expectedDefault: "0.5"},
		{flag: handlers.FlagSVIDRenewalJitter, expectedDefault: "0.1"},
		// Empty is the in-cluster API server, which every chart install has.
		{flag: handlers.FlagNodeKubeconfig, expectedDefault: ""},
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
	g.Expect(opts.JWTSVIDDuration).To(Equal(time.Hour))
	g.Expect(opts.SVIDRenewalFraction).To(Equal(0.5))
	g.Expect(opts.SVIDRenewalJitter).To(Equal(0.1))
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
		"--jwt-svid-duration=30m",
		"--svid-renewal-fraction=0.75",
		"--svid-renewal-jitter=0.25",
		// Not a workload identity flag. It is the credentials path's cache bound,
		// which the token tier reads rather than defining a second one, so this
		// asserts the shared value arrives and not just that the field exists.
		"--max-cache-size=512",
		"--node-kubeconfig=/etc/kubernetes/kubelet/kubeconfig",
	})
	g.Expect(err).ToNot(HaveOccurred())

	cfg := aws.Config{Region: "us-west-2"}
	opts := newWorkloadIdentityServerOpts(cfg)

	g.Expect(opts.Validate()).To(Succeed())
	g.Expect(opts.Cfg.Region).To(Equal("us-west-2"))
	g.Expect(opts.ClusterName).To(Equal("cluster-a"))
	g.Expect(opts.X509SVIDDuration).To(Equal(time.Hour))
	g.Expect(opts.JWTSVIDDuration).To(Equal(30 * time.Minute))
	g.Expect(opts.SVIDRenewalFraction).To(Equal(0.75))
	g.Expect(opts.SVIDRenewalJitter).To(Equal(0.25))
	g.Expect(opts.MaxCacheSize).To(Equal(512))
	g.Expect(opts.NodeKubeconfig).To(Equal("/etc/kubernetes/kubelet/kubeconfig"))
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
	originalNodeKubeconfig := nodeKubeconfig

	t.Cleanup(func() {
		nodeKubeconfig = originalNodeKubeconfig
		clusterName = originalCluster
		x509SVIDDuration = originalX509
		jwtSVIDDuration = originalJWT
		svidRenewalFraction = originalFraction
		svidRenewalJitter = originalJitter
		maxCacheSize = originalMaxCacheSize
	})
}

// namedRetriever is a retriever a test can tell apart from another by identity.
type namedRetriever struct {
	wiNoExchange
	name string
}

// TestShareCredentialManager_HandsTheManagersPartsToBothServers proves every
// bind host serves from the manager's retriever and the session tier gets the
// manager's cache and EKS Auth client, so both share one cache.
func TestShareCredentialManager_HandsTheManagersPartsToBothServers(t *testing.T) {
	g := NewWithT(t)
	manager := handlers.CredentialManager{
		Retriever: &namedRetriever{name: "cached-retriever"},
		Cache: credcache.New(credcache.Opts{
			Delegate: wiNoExchange{}, RenewalTtl: time.Hour, MaxSize: 10, CleanupInterval: time.Hour,
		}),
		EKSAuth: &namedRetriever{name: "eks-auth"},
	}
	credentialOpts := handlers.EksCredentialHandlerOpts{ClusterName: "test-cluster"}
	workloadIdentityOpts := handlers.WorkloadIdentityServerOpts{ClusterName: "test-cluster"}

	shareCredentialManager(manager, &credentialOpts, &workloadIdentityOpts)

	g.Expect(credentialOpts.CredentialRetriever).To(BeIdenticalTo(manager.Retriever))
	g.Expect(workloadIdentityOpts.CredentialCache).To(BeIdenticalTo(manager.Cache))
	g.Expect(workloadIdentityOpts.EKSAuth).To(BeIdenticalTo(manager.EKSAuth))
	g.Expect(credentialOpts.ClusterName).To(Equal("test-cluster"), "only the shared parts may change")
}

// TestCreateServers_WorkloadIdentityOff_BuildsNoNodeClient proves boot with
// workload identity off builds no node client, so it needs no API server.
// Nothing listens until the servers run.
func TestCreateServers_WorkloadIdentityOff_BuildsNoNodeClient(t *testing.T) {
	g := NewWithT(t)
	builds := countNodeClientBuilds(t, newWINodeClientset("system:node:"+wiTestNode))
	original := enableWorkloadIdentity
	enableWorkloadIdentity = false
	t.Cleanup(func() { enableWorkloadIdentity = original })

	servers, err := createServers(t.Context(), aws.Config{})

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(servers).ToNot(BeEmpty())
	g.Expect(builds.Load()).To(BeZero(), "no node client may be built with workload identity off")
}

// TestCreateServers_WorkloadIdentityServersFailing_NamesTheOptOut proves a failure
// building the workload identity servers, which is fatal, names the opt-out flag.
// A zero credential manager gives the session tier a nil cache, which it refuses.
func TestCreateServers_WorkloadIdentityServersFailing_NamesTheOptOut(t *testing.T) {
	g := NewWithT(t)
	countNodeClientBuilds(t, newWINodeClientset("system:node:"+wiTestNode))
	originalEnabled, originalCluster := enableWorkloadIdentity, clusterName
	enableWorkloadIdentity, clusterName = true, "test-cluster"
	t.Cleanup(func() { enableWorkloadIdentity, clusterName = originalEnabled, originalCluster })
	originalManager := newCredentialManager
	newCredentialManager = func(context.Context, handlers.EksCredentialHandlerOpts) handlers.CredentialManager {
		return handlers.CredentialManager{}
	}
	t.Cleanup(func() { newCredentialManager = originalManager })

	_, err := createServers(t.Context(), aws.Config{})

	g.Expect(err).To(MatchError(ContainSubstring("building the workload identity servers")))
	g.Expect(err).To(MatchError(ContainSubstring("--" + handlers.FlagEnableWorkloadIdentity + "=false")))
}

// TestBuildSharedCredentialManager_Off_GivesTheCacheNoTokenSource proves the
// credential manager is built without the workload identity token source when
// the feature is off, so its cache refreshes every entry through the general
// delegate, and no node client is built.
func TestBuildSharedCredentialManager_Off_GivesTheCacheNoTokenSource(t *testing.T) {
	g := NewWithT(t)
	builds := countNodeClientBuilds(t, newWINodeClientset("system:node:"+wiTestNode))
	built := captureCredentialManagerOpts(t)
	credentialOpts := handlers.EksCredentialHandlerOpts{ClusterName: "test-cluster"}
	workloadIdentityOpts := wiOpts
	workloadIdentityOpts.Enabled = false

	clients, err := buildSharedCredentialManager(t.Context(), &credentialOpts, &workloadIdentityOpts)

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(clients).To(BeNil())
	g.Expect(*built).To(HaveLen(1))
	g.Expect((*built)[0].WorkloadIdentityTokens).To(BeNil())
	g.Expect(builds.Load()).To(BeZero())
}

// TestBuildSharedCredentialManager_On_RefreshesWithTheTiersMinter proves the
// credential manager's cache gets a token source over the minter the returned
// clients hand the session tier: a token it mints is what that minter then
// serves for the pod, from one TokenRequest on the one node client.
func TestBuildSharedCredentialManager_On_RefreshesWithTheTiersMinter(t *testing.T) {
	g := NewWithT(t)
	w := &workloadidentity.Workload{PodUID: "pod-uid-1", PodName: "pod-1", Namespace: "default", ServiceAccount: "sa-1"}
	client := newWINodeClientset("system:node:"+wiTestNode, w)
	builds := countNodeClientBuilds(t, client)
	built := captureCredentialManagerOpts(t)
	credentialOpts := handlers.EksCredentialHandlerOpts{
		ClusterName: "test-cluster", CredentialRenewal: time.Hour, MaxCacheSize: 100,
	}
	workloadIdentityOpts := wiOpts

	clients, err := buildSharedCredentialManager(t.Context(), &credentialOpts, &workloadIdentityOpts)

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(builds.Load()).To(Equal(int32(1)))
	g.Expect(*built).To(HaveLen(1))
	g.Expect(workloadIdentityOpts.CredentialCache).ToNot(BeNil(), "the session tier gets the manager's cache")
	tokens := (*built)[0].WorkloadIdentityTokens
	g.Expect(tokens).ToNot(BeNil())

	stored := wiPodToken(w.Namespace, w.ServiceAccount, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{BoundObjectRef: &authenticationv1.BoundObjectReference{
			Name: w.PodName, UID: types.UID(w.PodUID),
		}},
	}, time.Now().Add(time.Minute))
	token, err := tokens.Token(t.Context(), &credentials.EksCredentialsRequest{ServiceAccountToken: stored})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(client.tokenRequests()).To(Equal([]string{token}), "the cache's token source mints on the node client")

	minted, err := clients.minter.Mint(t.Context(), w)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(minted.Token).To(Equal(token), "the session tier's minter serves the token the cache's source minted")
	g.Expect(client.tokenRequests()).To(HaveLen(1))
}

// captureCredentialManagerOpts makes newCredentialManager record the options
// each manager is built with, for the rest of the test.
func captureCredentialManagerOpts(t *testing.T) *[]handlers.EksCredentialHandlerOpts {
	t.Helper()
	var built []handlers.EksCredentialHandlerOpts
	original := newCredentialManager
	newCredentialManager = func(ctx context.Context, opts handlers.EksCredentialHandlerOpts) handlers.CredentialManager {
		built = append(built, opts)
		return original(ctx, opts)
	}
	t.Cleanup(func() { newCredentialManager = original })
	return &built
}

func TestValidateBindHosts(t *testing.T) {
	testCases := []struct {
		name    string
		hosts   []string
		wantErr bool
	}{
		{
			name:  "default link-local hosts are allowed",
			hosts: []string{configuration.DefaultIpv4TargetHost, "[" + configuration.DefaultIpv6TargetHost + "]"},
		},
		{
			name:  "bare ipv6 link-local host is allowed",
			hosts: []string{configuration.DefaultIpv6TargetHost},
		},
		{
			name:  "loopback is allowed",
			hosts: []string{"127.0.0.1"},
		},
		{
			name:  "ipv6 loopback is allowed",
			hosts: []string{"::1"},
		},
		{
			name:  "localhost is allowed",
			hosts: []string{"localhost"},
		},
		{
			name:    "wildcard bind is rejected",
			hosts:   []string{"0.0.0.0"},
			wantErr: true,
		},
		{
			name:    "ipv6 wildcard bind is rejected",
			hosts:   []string{"::"},
			wantErr: true,
		},
		{
			name:    "arbitrary routable address is rejected",
			hosts:   []string{"10.0.0.5"},
			wantErr: true,
		},
		{
			name:    "a disallowed host alongside allowed ones is rejected",
			hosts:   []string{configuration.DefaultIpv4TargetHost, "0.0.0.0"},
			wantErr: true,
		},
		{
			name:    "unparseable host is rejected",
			hosts:   []string{"not-an-ip"},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBindHosts(tc.hosts)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
