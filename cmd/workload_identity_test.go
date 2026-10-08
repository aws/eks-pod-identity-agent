package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	. "github.com/onsi/gomega"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/handlers"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

const wiTestNode = "node-1"

// wiOpts are the workload identity options the wiring tests build the tiers with.
var wiOpts = handlers.WorkloadIdentityServerOpts{
	Enabled:             true,
	ClusterName:         "test-cluster",
	MaxCacheSize:        100,
	X509SVIDDuration:    12 * time.Hour,
	SVIDRenewalFraction: 0.5,
	SVIDRenewalJitter:   0.1,
}

// wiNodeClientset is a fake clientset whose SelfSubjectReview reports username,
// which is how the API server names the identity the agent presented. It also
// records the field selector of every pod list, so a test can see which node the
// pod store was scoped to.
type wiNodeClientset struct {
	*fake.Clientset

	mu            sync.Mutex
	podSelectors  []string
	podListsTotal int
}

func newWINodeClientset(username string) *wiNodeClientset {
	c := &wiNodeClientset{Clientset: fake.NewSimpleClientset()}
	c.PrependReactor("create", "selfsubjectreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authenticationv1.SelfSubjectReview{
			Status: authenticationv1.SelfSubjectReviewStatus{UserInfo: authenticationv1.UserInfo{Username: username}},
		}, nil
	})
	// Not handled, so the default tracker still answers the list with no pods.
	c.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.podListsTotal++
		if list, ok := action.(k8stesting.ListAction); ok {
			c.podSelectors = append(c.podSelectors, list.GetListRestrictions().Fields.String())
		}
		return false, nil, nil
	})
	return c
}

func (c *wiNodeClientset) podLists() (int, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.podListsTotal, append([]string(nil), c.podSelectors...)
}

// wiCountingFetcher is an STS client that counts calls and never answers, so a
// test can assert the wiring reached no STS call.
type wiCountingFetcher struct {
	calls atomic.Int32
}

func (f *wiCountingFetcher) GetTrustBundles(context.Context, aws.Credentials, string) ([]sts.TrustBundle, error) {
	f.calls.Add(1)
	return nil, errors.New("wiCountingFetcher serves no trust bundles")
}

func (f *wiCountingFetcher) GetWorkloadIdentityCertificate(context.Context, aws.Credentials, sts.CertificateRequest) (*sts.IssuedCertificate, error) {
	f.calls.Add(1)
	return nil, errors.New("wiCountingFetcher issues no certificates")
}

func (f *wiCountingFetcher) GetWebIdentityToken(context.Context, aws.Credentials, sts.WebIdentityTokenRequest) (*sts.IssuedWebIdentityToken, error) {
	f.calls.Add(1)
	return nil, errors.New("wiCountingFetcher issues no tokens")
}

// wiBuildTiers builds the tiers as production does over a node-identity fake
// clientset. The pod store's informer runs under a context cancelled at cleanup.
func wiBuildTiers(t *testing.T) (*workloadIdentityTiers, *wiNodeClientset, *wiCountingFetcher) {
	t.Helper()
	g := NewWithT(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	client := newWINodeClientset("system:node:" + wiTestNode)
	fetcher := &wiCountingFetcher{}
	tiers, err := buildWorkloadIdentityTiers(ctx, wiOpts, client, fetcher)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(tiers).ToNot(BeNil())
	return tiers, client, fetcher
}

// TestBuildWorkloadIdentityTiers_ANodeIdentity_BuildsEveryTier covers the boot
// path: the node name comes from SelfSubjectReview and scopes the pod store, and
// building the tiers fetches no trust bundle, since no workload has named a
// provider yet.
func TestBuildWorkloadIdentityTiers_ANodeIdentity_BuildsEveryTier(t *testing.T) {
	g := NewWithT(t)

	tiers, client, fetcher := wiBuildTiers(t)

	g.Expect(tiers.handler).ToNot(BeNil())
	g.Expect(tiers.bundleSource).ToNot(BeNil())

	// The store synced before the build returned, so its list has happened.
	lists, selectors := client.podLists()
	g.Expect(lists).To(BeNumerically(">=", 1))
	g.Expect(selectors).To(ContainElement("spec.nodeName="+wiTestNode),
		"the pod store must be scoped to the node the API server named")
	g.Expect(fetcher.calls.Load()).To(BeZero())
}

// TestBuildWorkloadIdentityTiers_ANonNodeIdentity_Fails proves a client that is not
// the node fails the boot before the pod store starts, since nothing it listed
// would be scoped by what the Node authorizer enforces.
func TestBuildWorkloadIdentityTiers_ANonNodeIdentity_Fails(t *testing.T) {
	testCases := []struct {
		name     string
		username string
	}{
		{name: "service account", username: "system:serviceaccount:kube-system:eks-pod-identity-agent"},
		{name: "anonymous", username: "system:anonymous"},
		{name: "empty node name", username: "system:node:"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client := newWINodeClientset(tc.username)
			fetcher := &wiCountingFetcher{}

			tiers, err := buildWorkloadIdentityTiers(ctx, wiOpts, client, fetcher)

			g.Expect(err).To(MatchError(ContainSubstring("not a node identity")))
			g.Expect(ctx.Err()).ToNot(HaveOccurred(), "the boot waited instead of failing at once")
			g.Expect(tiers).To(BeNil())
			lists, _ := client.podLists()
			g.Expect(lists).To(BeZero(), "no pod store is started for a client that is not the node")
			g.Expect(fetcher.calls.Load()).To(BeZero())
		})
	}
}

// wiServe serves the production registration over a temporary socket and dials it.
// The directory is under os.MkdirTemp because a Unix socket path is limited to 107
// bytes and t.TempDir embeds the test name. The limiter is unbounded so the calls a
// test makes are never throttled.
func wiServe(t *testing.T, tiers *workloadIdentityTiers) *grpc.ClientConn {
	t.Helper()
	g := NewWithT(t)

	dir, err := os.MkdirTemp("", "pia")
	g.Expect(err).ToNot(HaveOccurred())
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	srv, err := grpcserver.New(grpcserver.Opts{
		SocketPath:     filepath.Join(dir, "agent.sock"),
		ShutdownWait:   time.Second,
		Register:       registerWorkloadIdentityServices(tiers.handler),
		RequestLimiter: rate.NewLimiter(rate.Inf, 0),
	})
	g.Expect(err).ToNot(HaveOccurred())

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		srv.ListenUntilContextCancelled(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-stopped
	})

	conn, err := grpc.NewClient("unix://"+srv.Addr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	g.Expect(err).ToNot(HaveOccurred())
	// Cleanups run last in, first out, so the client closes before the server stops.
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// wiFirstRecv returns the error a stream ends with before or at its first message.
// Each case opens its stream under a context the case cancels, which tears it down.
func wiFirstRecv[R any](stream interface{ Recv() (R, error) }, err error) error {
	if err != nil {
		return err
	}
	_, err = stream.Recv()
	return err
}

// TestRegisterWorkloadIdentityServices_ServesTheHandlerBesideTheSDSStub calls every
// Workload API method through the server cmd builds. The test process is not a pod,
// so the real handler refuses each in-scope method at attestation with
// PermissionDenied, where the stub would have answered Unimplemented. The WIT methods
// and SDS stay Unimplemented until their handlers land, and a Workload API call
// without the SPIFFE header stops at the gate.
func TestRegisterWorkloadIdentityServices_ServesTheHandlerBesideTheSDSStub(t *testing.T) {
	tiers, _, fetcher := wiBuildTiers(t)
	conn := wiServe(t, tiers)
	client := workload.NewSpiffeWorkloadAPIClient(conn)
	sds := secretv3.NewSecretDiscoveryServiceClient(conn)

	testCases := []struct {
		name     string
		call     func(ctx context.Context) error
		wantCode codes.Code
		// wantMessage is part of the status message, for a refusal that has to
		// come from the attestor rather than from a tier or the gate.
		wantMessage string
		// withoutHeader leaves out the SPIFFE header, as Envoy does on SDS.
		withoutHeader bool
	}{
		{
			name: "ValidateJWTSVID",
			call: func(ctx context.Context) error {
				_, err := client.ValidateJWTSVID(ctx, &workload.ValidateJWTSVIDRequest{
					Audience: "spiffe://example.org/audience",
					Svid:     "not-a-jwt",
				})
				return err
			},
			wantCode:    codes.PermissionDenied,
			wantMessage: "attestation refused",
		},
		{
			name: "FetchJWTSVID",
			call: func(ctx context.Context) error {
				_, err := client.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{Audience: []string{"spiffe://example.org/audience"}})
				return err
			},
			wantCode:    codes.PermissionDenied,
			wantMessage: "attestation refused",
		},
		{
			name: "FetchX509SVID",
			call: func(ctx context.Context) error {
				return wiFirstRecv(client.FetchX509SVID(ctx, &workload.X509SVIDRequest{}))
			},
			wantCode:    codes.PermissionDenied,
			wantMessage: "attestation refused",
		},
		{
			name: "FetchX509Bundles",
			call: func(ctx context.Context) error {
				return wiFirstRecv(client.FetchX509Bundles(ctx, &workload.X509BundlesRequest{}))
			},
			wantCode:    codes.PermissionDenied,
			wantMessage: "attestation refused",
		},
		{
			name: "FetchJWTBundles",
			call: func(ctx context.Context) error {
				return wiFirstRecv(client.FetchJWTBundles(ctx, &workload.JWTBundlesRequest{}))
			},
			wantCode:    codes.PermissionDenied,
			wantMessage: "attestation refused",
		},
		{
			name: "FetchWITSVID",
			call: func(ctx context.Context) error {
				return wiFirstRecv(client.FetchWITSVID(ctx, &workload.WITSVIDRequest{}))
			},
			wantCode: codes.Unimplemented,
		},
		{
			name: "FetchWITBundles",
			call: func(ctx context.Context) error {
				return wiFirstRecv(client.FetchWITBundles(ctx, &workload.WITBundlesRequest{}))
			},
			wantCode: codes.Unimplemented,
		},
		{
			name: "FetchX509SVID without the SPIFFE header",
			call: func(ctx context.Context) error {
				return wiFirstRecv(client.FetchX509SVID(ctx, &workload.X509SVIDRequest{}))
			},
			wantCode:      codes.InvalidArgument,
			wantMessage:   grpcserver.SpiffeSecurityHeader,
			withoutHeader: true,
		},
		// SDS reaches its stub without the header, which the gate asks of the
		// Workload API only: Envoy sends none.
		{
			name: "SDS StreamSecrets",
			call: func(ctx context.Context) error {
				return wiFirstRecv(sds.StreamSecrets(ctx))
			},
			wantCode:      codes.Unimplemented,
			withoutHeader: true,
		},
		{
			name: "SDS FetchSecrets",
			call: func(ctx context.Context) error {
				_, err := sds.FetchSecrets(ctx, nil)
				return err
			},
			wantCode:      codes.Unimplemented,
			withoutHeader: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if !tc.withoutHeader {
				ctx = metadata.AppendToOutgoingContext(ctx, grpcserver.SpiffeSecurityHeader, grpcserver.SpiffeSecurityHeaderValue)
			}

			err := tc.call(ctx)

			g.Expect(status.Code(err)).To(Equal(tc.wantCode), "status: %v", err)
			if tc.wantMessage != "" {
				g.Expect(status.Convert(err).Message()).To(ContainSubstring(tc.wantMessage))
			}
		})
	}

	NewWithT(t).Expect(fetcher.calls.Load()).To(BeZero(), "a caller refused at attestation reaches no tier")
}

// TestBackgroundLoop_RunsBesideTheServersUntilShutdown drives a loop through the
// same shutdown as the servers. Its name is its bind-addr log field, and it keeps
// running until the shutdown cancels its context.
func TestBackgroundLoop_RunsBesideTheServersUntilShutdown(t *testing.T) {
	g := NewWithT(t)

	const name = "trust-bundle-refresh"
	received := make(chan context.Context, 1)
	finished := make(chan struct{})
	loop := backgroundLoop{name: name, run: func(ctx context.Context) {
		received <- ctx
		<-ctx.Done()
		close(finished)
	}}
	g.Expect(loop.Addr()).To(Equal(name))

	server := newFakeRunnable("169.254.170.23:80")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		runServersUntilShutdown(ctx, []runnable{server, loop})
	}()

	var loopCtx context.Context
	g.Eventually(received, 10*time.Second).Should(Receive(&loopCtx))
	g.Expect(logger.FromContext(loopCtx).Data).To(HaveKeyWithValue("bind-addr", name))
	g.Eventually(server.started, 10*time.Second).Should(BeClosed())
	g.Consistently(finished, 100*time.Millisecond).ShouldNot(BeClosed(), "the loop runs until shutdown")

	cancel()

	g.Eventually(returned, 10*time.Second).Should(BeClosed())
	g.Expect(finished).To(BeClosed(), "the drive loop returns only after the loop has")
	g.Expect(server.stopped).To(BeClosed())
}

// TestBackgroundLoop_TheTrustBundleRefreshStopsAtShutdown pairs the loop with the
// registry's Run as createServers does, so a refresh that ignored its context would
// hold the whole shutdown open.
func TestBackgroundLoop_TheTrustBundleRefreshStopsAtShutdown(t *testing.T) {
	g := NewWithT(t)

	tiers, _, _ := wiBuildTiers(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		runServersUntilShutdown(ctx, []runnable{backgroundLoop{name: "trust-bundle-refresh", run: tiers.bundleSource.Run}})
	}()
	g.Consistently(returned, 100*time.Millisecond).ShouldNot(BeClosed(), "the refresh runs until shutdown")

	cancel()

	g.Eventually(returned, 10*time.Second).Should(BeClosed())
}

// TestUnimplementedSources_FailRetryably pins what the placeholder for T8
// answers: a retryable ErrIssuanceFailed, so FetchJWTSVID answers Unavailable
// rather than Internal.
func TestUnimplementedSources_FailRetryably(t *testing.T) {
	caller := &workloadidentity.Workload{PodUID: "pod-uid", PodName: "pod", Namespace: "default", ServiceAccount: "sa", NodeName: wiTestNode}
	testCases := []struct {
		name string
		call func(ctx context.Context) (any, error)
	}{
		{
			name: "token source",
			call: func(ctx context.Context) (any, error) {
				return unimplementedTokenSource{}.JWTSVIDs(ctx, caller, []string{"spiffe://example.org/audience"})
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := tc.call(context.Background())

			g.Expect(got).To(BeNil())
			g.Expect(err).To(MatchError(wierrors.ErrIssuanceFailed))
			g.Expect(wierrors.IsRetryable(err)).To(BeTrue())
			g.Expect(err.Error()).To(ContainSubstring("not implemented"))
			g.Expect(handlers.StatusCode(err)).To(Equal(codes.Unavailable))
		})
	}
}

// TestBuildWorkloadIdentityTiers_NoCacheBound_FailsBuildingTheMinter proves the
// token minter is built with the tiers: it refuses --max-cache-size 0, which the
// credentials path accepts as no caching, and names the flag.
func TestBuildWorkloadIdentityTiers_NoCacheBound_FailsBuildingTheMinter(t *testing.T) {
	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	opts := wiOpts
	opts.MaxCacheSize = 0

	tiers, err := buildWorkloadIdentityTiers(ctx, opts, newWINodeClientset("system:node:"+wiTestNode), &wiCountingFetcher{})

	g.Expect(err).To(MatchError(ContainSubstring("--max-cache-size")))
	g.Expect(tiers).To(BeNil())
}

// TestWorkloadIdentityServers_Off_BuildsNothing proves the feature off builds no
// tier and binds no socket, so boot reaches neither the API server nor the
// kubelet's kubeconfig, which this host does not have either.
func TestWorkloadIdentityServers_Off_BuildsNothing(t *testing.T) {
	g := NewWithT(t)
	opts := wiOpts
	opts.Enabled = false

	servers, err := workloadIdentityServers(context.Background(), opts)

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(servers).To(BeEmpty())
}

// TestServerCmd_EnableWorkloadIdentity_IsOnByDefault pins the feature flag: on by
// default, and its value reaches the options the wiring reads.
func TestServerCmd_EnableWorkloadIdentity_IsOnByDefault(t *testing.T) {
	g := NewWithT(t)

	flag := serverCmd.Flags().Lookup(handlers.FlagEnableWorkloadIdentity)
	g.Expect(flag).ToNot(BeNil())
	g.Expect(flag.DefValue).To(Equal("true"))
	g.Expect(newWorkloadIdentityServerOpts(aws.Config{}).Enabled).To(BeTrue())

	g.Expect(serverCmd.Flags().Set(handlers.FlagEnableWorkloadIdentity, "false")).To(Succeed())
	t.Cleanup(func() { _ = serverCmd.Flags().Set(handlers.FlagEnableWorkloadIdentity, flag.DefValue) })
	g.Expect(newWorkloadIdentityServerOpts(aws.Config{}).Enabled).To(BeFalse())
}
