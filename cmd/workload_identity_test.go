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
	"github.com/golang-jwt/jwt/v5"
	. "github.com/onsi/gomega"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/credcache"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
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
	JWTSVIDDuration:     time.Hour,
	SVIDRenewalFraction: 0.5,
	SVIDRenewalJitter:   0.1,
	// Sweep an hour away: building the tiers caches nothing, so there's nothing to refresh.
	CredentialCache: credcache.New(credcache.Opts{
		Delegate: wiNoExchange{}, RenewalTtl: time.Hour, MaxSize: 100, CleanupInterval: time.Hour,
	}),
	EKSAuth: wiNoExchange{},
}

// wiNoExchange stands in for EKS Auth. Building the tiers exchanges nothing, so
// it fails every call.
type wiNoExchange struct{}

func (wiNoExchange) GetIamCredentials(context.Context, *credentials.EksCredentialsRequest) (
	*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
	return nil, nil, errors.New("wiNoExchange exchanges no tokens")
}

func (wiNoExchange) String() string                       { return "wi-no-exchange" }
func (wiNoExchange) IsIrrecoverable(error) (string, bool) { return "Unknown", false }

// wiNodeClientset is a fake clientset whose SelfSubjectReview reports username,
// which is how the API server names the identity the agent presented. It also
// records the field selector of every pod list, so a test can see which node the
// pod store was scoped to, and answers every TokenRequest with an hour-long JWT
// naming the pod, counting them.
type wiNodeClientset struct {
	*fake.Clientset

	mu            sync.Mutex
	podSelectors  []string
	podListsTotal int
	tokens        []string
}

func newWINodeClientset(username string) *wiNodeClientset {
	c := &wiNodeClientset{Clientset: fake.NewSimpleClientset()}
	c.PrependReactor("create", "selfsubjectreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authenticationv1.SelfSubjectReview{
			Status: authenticationv1.SelfSubjectReviewStatus{UserInfo: authenticationv1.UserInfo{Username: username}},
		}, nil
	})
	c.PrependReactor("create", "serviceaccounts", func(action k8stesting.Action) (bool, runtime.Object, error) {
		create, ok := action.(k8stesting.CreateActionImpl)
		if !ok || action.GetSubresource() != "token" {
			return false, nil, nil
		}
		request := create.GetObject().(*authenticationv1.TokenRequest).DeepCopy()
		expires := time.Now().Add(time.Hour)
		request.Status.Token = wiPodToken(action.GetNamespace(), create.Name, request, expires)
		request.Status.ExpirationTimestamp = metav1.NewTime(expires)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.tokens = append(c.tokens, request.Status.Token)
		return true, request, nil
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

// tokenRequests returns every token the clientset's TokenRequests answered, in
// order.
func (c *wiNodeClientset) tokenRequests() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.tokens...)
}

// wiPodToken is the unsigned JWT the API server would mint for request: its
// kubernetes.io claims name the bound pod and the ServiceAccount in namespace.
func wiPodToken(namespace, serviceAccount string, request *authenticationv1.TokenRequest, expires time.Time) string {
	ref := request.Spec.BoundObjectRef
	token, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"exp": expires.Unix(),
		"kubernetes.io": map[string]any{
			"namespace":      namespace,
			"pod":            map[string]any{"name": ref.Name, "uid": string(ref.UID)},
			"serviceaccount": map[string]any{"name": serviceAccount},
		},
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		panic(err)
	}
	return token
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

// wiClients builds the workload identity clients as createServers does, over
// client.
func wiClients(t *testing.T, ctx context.Context, client kubernetes.Interface) *workloadIdentityClients {
	t.Helper()
	clients, err := buildWorkloadIdentityClients(ctx, wiOpts, client)
	NewWithT(t).Expect(err).ToNot(HaveOccurred())
	return clients
}

// wiBuildTiers builds the tiers as production does over a node-identity fake
// clientset. The pod store's informer runs under a context cancelled at cleanup.
func wiBuildTiers(t *testing.T) (*workloadIdentityTiers, *wiNodeClientset, *wiCountingFetcher) {
	t.Helper()
	tiers, client, fetcher, _ := wiBuildTiersAndClients(t)
	return tiers, client, fetcher
}

// wiBuildTiersAndClients is wiBuildTiers that also returns the clients the tiers
// were built over.
func wiBuildTiersAndClients(t *testing.T) (*workloadIdentityTiers, *wiNodeClientset, *wiCountingFetcher, *workloadIdentityClients) {
	t.Helper()
	g := NewWithT(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	client := newWINodeClientset("system:node:" + wiTestNode)
	fetcher := &wiCountingFetcher{}
	clients := wiClients(t, ctx, client)
	tiers, err := buildWorkloadIdentityTiers(ctx, wiOpts, clients, fetcher)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(tiers).ToNot(BeNil())
	return tiers, client, fetcher, clients
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

// TestBuildWorkloadIdentityClients_ANonNodeIdentity_Fails proves a client that
// is not the node fails the boot before the minter's pre-flight and before any
// pod store starts, since nothing it listed would be scoped by what the Node
// authorizer enforces.
func TestBuildWorkloadIdentityClients_ANonNodeIdentity_Fails(t *testing.T) {
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

			clients, err := buildWorkloadIdentityClients(ctx, wiOpts, client)

			g.Expect(err).To(MatchError(ContainSubstring("not a node identity")))
			g.Expect(ctx.Err()).ToNot(HaveOccurred(), "the boot waited instead of failing at once")
			g.Expect(clients).To(BeNil())
			g.Expect(csiDriverReads(client)).To(BeZero(), "the pre-flight must not run for a client that is not the node")
			lists, _ := client.podLists()
			g.Expect(lists).To(BeZero(), "no pod store is started for a client that is not the node")
		})
	}
}

// TestBuildWorkloadIdentityClients_ThePreflightWaitsForTheNodeName proves a
// transient API server failure at boot is absorbed by the node name's retry, not
// failed by the minter's CSIDriver pre-flight: the API server refuses everything
// until the first SelfSubjectReview it answers.
func TestBuildWorkloadIdentityClients_ThePreflightWaitsForTheNodeName(t *testing.T) {
	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := newWINodeClientset("system:node:" + wiTestNode)
	var reviews atomic.Int32
	client.PrependReactor("create", "selfsubjectreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		if reviews.Add(1) == 1 {
			return true, nil, errors.New("connection refused")
		}
		return false, nil, nil
	})
	client.PrependReactor("get", "csidrivers", func(k8stesting.Action) (bool, runtime.Object, error) {
		if reviews.Load() < 2 {
			return true, nil, errors.New("connection refused")
		}
		return false, nil, nil
	})

	clients, err := buildWorkloadIdentityClients(ctx, wiOpts, client)

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(clients.nodeName).To(Equal(wiTestNode))
	g.Expect(reviews.Load()).To(Equal(int32(2)), "the node name was retried once")
	g.Expect(csiDriverReads(client)).To(Equal(1))
}

// csiDriverReads counts the CSIDriver reads client has seen.
func csiDriverReads(client *wiNodeClientset) int {
	reads := 0
	for _, action := range client.Actions() {
		if action.Matches("get", "csidrivers") {
			reads++
		}
	}
	return reads
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
		Register:       registerWorkloadIdentityServices(tiers.handler, tiers.sdsHandler),
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

// TestRegisterWorkloadIdentityServices_ServesBothInterfaces calls every method on
// both services through the server cmd builds. The test process is not a pod, so
// each in-scope method refuses at attestation with PermissionDenied; only the two
// WIT methods, which this agent does not serve, answer Unimplemented.
func TestRegisterWorkloadIdentityServices_ServesBothInterfaces(t *testing.T) {
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
		// Both SDS methods are served now, so they refuse at attestation like
		// the Workload API RPCs above rather than answering Unimplemented. That
		// they refuse identically is the point: a workload reaching the socket
		// over either interface is turned away for the same reason, with the
		// same code.
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
			wantCode:    codes.PermissionDenied,
			wantMessage: "attestation refused",
		},
		{
			name: "SDS FetchSecrets",
			call: func(ctx context.Context) error {
				_, err := sds.FetchSecrets(ctx, nil)
				return err
			},
			wantCode:    codes.PermissionDenied,
			wantMessage: "attestation refused",
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

// TestBuildWorkloadIdentityClients_NoCacheBound_FailsBuildingTheMinter proves
// the token minter is built with the clients: it refuses --max-cache-size 0,
// which the credential endpoint's cache accepts as no caching, and names the flag.
func TestBuildWorkloadIdentityClients_NoCacheBound_FailsBuildingTheMinter(t *testing.T) {
	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	opts := wiOpts
	opts.MaxCacheSize = 0

	clients, err := buildWorkloadIdentityClients(ctx, opts, newWINodeClientset("system:node:"+wiTestNode))

	g.Expect(err).To(MatchError(ContainSubstring("building the token minter")))
	g.Expect(err).To(MatchError(ContainSubstring("--max-cache-size")))
	g.Expect(clients).To(BeNil())
}

// TestBuildWorkloadIdentityTiers_NoCredentialCache_FailsBuildingTheSessionTier
// proves the session tier is built over the credential cache cmd hands it: with
// none, which --max-credential-retention-before-renewal 0 yields, the build
// fails naming both flags that turn the cache off.
func TestBuildWorkloadIdentityTiers_NoCredentialCache_FailsBuildingTheSessionTier(t *testing.T) {
	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	opts := wiOpts
	opts.CredentialCache = nil

	tiers, err := buildWorkloadIdentityTiers(ctx, opts, wiClients(t, ctx, newWINodeClientset("system:node:"+wiTestNode)),
		&wiCountingFetcher{})

	g.Expect(err).To(MatchError(ContainSubstring("building the session tier")))
	g.Expect(err).To(MatchError(ContainSubstring("--max-credential-retention-before-renewal")))
	g.Expect(err).To(MatchError(ContainSubstring("--max-cache-size")))
	g.Expect(tiers).To(BeNil())
}

// TestBuildWorkloadIdentityTiers_NoJWTSVIDDuration_FailsBuildingTheTokenSource
// proves the JWT-SVID source is built with the tiers over the attestor's pod
// store: a zero lifetime, which Validate would have refused, fails the build.
func TestBuildWorkloadIdentityTiers_NoJWTSVIDDuration_FailsBuildingTheTokenSource(t *testing.T) {
	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	opts := wiOpts
	opts.JWTSVIDDuration = 0

	tiers, err := buildWorkloadIdentityTiers(ctx, opts, wiClients(t, ctx, newWINodeClientset("system:node:"+wiTestNode)),
		&wiCountingFetcher{})

	g.Expect(err).To(MatchError(ContainSubstring("building the JWT-SVID tier")))
	g.Expect(tiers).To(BeNil())
}

// TestWorkloadIdentityServers_Off_BuildsNothing proves the feature off builds no
// node client, no token source for the credential cache, no tier and no socket,
// so boot reaches neither the API server nor the kubelet's kubeconfig.
func TestWorkloadIdentityServers_Off_BuildsNothing(t *testing.T) {
	g := NewWithT(t)
	builds := countNodeClientBuilds(t, newWINodeClientset("system:node:"+wiTestNode))
	opts := wiOpts
	opts.Enabled = false

	clients, err := newWorkloadIdentityClients(context.Background(), opts)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(clients).To(BeNil())
	g.Expect(clients.credentialTokens()).To(BeNil(), "the credential cache gets no token source")
	servers, err := workloadIdentityServers(context.Background(), opts, clients)

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(servers).To(BeEmpty())
	g.Expect(builds.Load()).To(BeZero(), "no node client may be built with workload identity off")
}

// TestNewWorkloadIdentityClients_On_BuildsOneNodeClient proves the feature on
// builds the node client once, from the default kubeconfig, and the minter over
// it.
func TestNewWorkloadIdentityClients_On_BuildsOneNodeClient(t *testing.T) {
	g := NewWithT(t)
	client := newWINodeClientset("system:node:" + wiTestNode)
	builds := countNodeClientBuilds(t, client)

	clients, err := newWorkloadIdentityClients(t.Context(), wiOpts)

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(builds.Load()).To(Equal(int32(1)))
	g.Expect(clients.clientset).To(BeIdenticalTo(client))
	g.Expect(clients.minter).ToNot(BeNil())
	g.Expect(clients.credentialTokens()).ToNot(BeNil())
}

// TestWorkloadIdentityServers_OnWithoutClients_Fails proves the feature on never
// builds the tiers over clients createServers didn't build.
func TestWorkloadIdentityServers_OnWithoutClients_Fails(t *testing.T) {
	servers, err := workloadIdentityServers(t.Context(), wiOpts, nil)

	NewWithT(t).Expect(err).To(MatchError(ContainSubstring("clients weren't built")))
	NewWithT(t).Expect(servers).To(BeEmpty())
}

// countNodeClientBuilds makes newNodeClient count its calls and answer client,
// for the rest of the test.
func countNodeClientBuilds(t *testing.T, client kubernetes.Interface) *atomic.Int32 {
	t.Helper()
	var builds atomic.Int32
	original := newNodeClient
	newNodeClient = func(kubeconfigPath string) (kubernetes.Interface, error) {
		builds.Add(1)
		if kubeconfigPath != "" {
			t.Errorf("the node client must come from the default kubeconfig, got %q", kubeconfigPath)
		}
		return client, nil
	}
	t.Cleanup(func() { newNodeClient = original })
	return &builds
}

// TestServerCmd_EnableWorkloadIdentity_IsOffByDefault pins the feature flag: off by
// default, so an agent upgraded with no new flags boots as before, and its value
// reaches the options the wiring reads.
func TestServerCmd_EnableWorkloadIdentity_IsOffByDefault(t *testing.T) {
	g := NewWithT(t)

	flag := serverCmd.Flags().Lookup(handlers.FlagEnableWorkloadIdentity)
	g.Expect(flag).ToNot(BeNil())
	g.Expect(flag.DefValue).To(Equal("false"))
	g.Expect(newWorkloadIdentityServerOpts(aws.Config{}).Enabled).To(BeFalse())

	g.Expect(serverCmd.Flags().Set(handlers.FlagEnableWorkloadIdentity, "true")).To(Succeed())
	t.Cleanup(func() { _ = serverCmd.Flags().Set(handlers.FlagEnableWorkloadIdentity, flag.DefValue) })
	g.Expect(newWorkloadIdentityServerOpts(aws.Config{}).Enabled).To(BeTrue())
}

// TestBuildSharedCredentialManager_OnAndFailing_NamesTheOptOut proves a failure
// building the workload identity clients, which is fatal, tells the operator which
// flag turns the feature off.
func TestBuildSharedCredentialManager_OnAndFailing_NamesTheOptOut(t *testing.T) {
	g := NewWithT(t)
	original := newNodeClient
	newNodeClient = func(string) (kubernetes.Interface, error) {
		return nil, errors.New("no kubeconfig")
	}
	t.Cleanup(func() { newNodeClient = original })
	credentialOpts := handlers.EksCredentialHandlerOpts{ClusterName: "test-cluster"}
	workloadIdentityOpts := wiOpts

	_, err := buildSharedCredentialManager(t.Context(), &credentialOpts, &workloadIdentityOpts)

	g.Expect(err).To(MatchError(ContainSubstring("no kubeconfig")))
	g.Expect(err).To(MatchError(ContainSubstring("--" + handlers.FlagEnableWorkloadIdentity + "=false")))
}

// TestWorkloadIdentityClients_TheSessionTierAndTheCredentialCacheShareOneMinter
// proves the credential cache's token source and the session tier mint through
// one token cache: a token the tier's exchange minted is what the cache's
// source is handed for the same pod, with no second TokenRequest.
func TestWorkloadIdentityClients_TheSessionTierAndTheCredentialCacheShareOneMinter(t *testing.T) {
	g := NewWithT(t)
	tiers, client, _, clients := wiBuildTiersAndClients(t)
	w := &workloadidentity.Workload{PodUID: "pod-uid-1", PodName: "pod-1", Namespace: "default", ServiceAccount: "sa-1"}

	_, err := tiers.sessions.Session(t.Context(), w)
	g.Expect(err).To(MatchError(wierrors.ErrSessionUnavailable), "wiNoExchange refuses the exchange after the mint")
	minted := client.tokenRequests()
	g.Expect(minted).To(HaveLen(1), "the session tier's exchange mints once")

	token, err := clients.credentialTokens().Token(t.Context(),
		&credentials.EksCredentialsRequest{ClusterName: wiOpts.ClusterName, ServiceAccountToken: minted[0]})

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(token).To(Equal(minted[0]), "the cache's source must be served from the token cache the tier filled")
	g.Expect(client.tokenRequests()).To(HaveLen(1), "no second TokenRequest")
}
