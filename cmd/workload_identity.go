package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"k8s.io/client-go/kubernetes"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/attestation"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/credcache"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/kube"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/material/bundle"
	jwttier "go.amzn.com/eks/eks-pod-identity-agent/internal/material/jwt"
	x509tier "go.amzn.com/eks/eks-pod-identity-agent/internal/material/x509"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/notify"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/session"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/tokenminter"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/handlers"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/handlers/workloadapi"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// workloadIdentityClients is what workload identity reaches the API server with,
// built once by createServers before the credential manager: the node client, the
// node name it authenticates as, and T4's cached token minter. The minter is the
// one token cache, shared by the session tier's exchanges and the credential
// cache's refreshes.
type workloadIdentityClients struct {
	clientset kubernetes.Interface
	nodeName  string
	minter    workloadidentity.TokenMinter
}

// newNodeClient builds the node client from the kubelet's kubeconfig. Tests
// replace it.
var newNodeClient = kube.NewNodeClient

// newWorkloadIdentityClients builds the clients when workload identity is on,
// blocking until the node name resolves. Off, it builds nothing and returns nil,
// so boot needs neither the API server nor the kubelet's kubeconfig.
func newWorkloadIdentityClients(ctx context.Context, opts handlers.WorkloadIdentityServerOpts) (*workloadIdentityClients, error) {
	if !opts.Enabled {
		return nil, nil
	}
	clientset, err := newNodeClient("")
	if err != nil {
		return nil, err
	}
	return buildWorkloadIdentityClients(ctx, opts, clientset)
}

// buildWorkloadIdentityClients is newWorkloadIdentityClients past the node
// client, so a test can drive it with a fake clientset. The node name's retry
// comes first, so the minter's pre-flight reaches an API server that has answered.
func buildWorkloadIdentityClients(ctx context.Context, opts handlers.WorkloadIdentityServerOpts,
	clientset kubernetes.Interface) (*workloadIdentityClients, error) {
	nodeName, err := kube.ResolveNodeNameWithRetry(ctx, clientset)
	if err != nil {
		return nil, err
	}
	// It refuses a --max-cache-size of zero, which the credential endpoint's cache
	// reads as no caching.
	minter, err := tokenminter.NewMinter(ctx, clientset, tokenminter.CachedMinterOpts{MaxCacheSize: opts.MaxCacheSize})
	if err != nil {
		return nil, fmt.Errorf("building the token minter: %w", err)
	}
	return &workloadIdentityClients{clientset: clientset, nodeName: nodeName, minter: minter}, nil
}

// credentialTokens is the token source the credential cache refreshes with: the
// shared minter's, or nil with workload identity off.
func (c *workloadIdentityClients) credentialTokens() credcache.TokenSource {
	if c == nil {
		return nil
	}
	return session.MinterTokens(c.minter)
}

// workloadIdentityServers is what the workload identity feature runs: the gRPC
// server on its socket and the trust bundle refresh loop, over the clients
// createServers built. Off, it builds nothing. On, it blocks until the pod store
// syncs, so a node the agent cannot attest on fails the boot.
func workloadIdentityServers(ctx context.Context, opts handlers.WorkloadIdentityServerOpts,
	clients *workloadIdentityClients) ([]runnable, error) {
	if !opts.Enabled {
		logger.FromContext(ctx).Infof("Workload identity is off (--%s=false), so %s is not served",
			handlers.FlagEnableWorkloadIdentity, configuration.WorkloadIdentitySocketPath)
		return nil, nil
	}
	if clients == nil {
		return nil, errors.New("workload identity is on, but its clients weren't built")
	}

	tiers, err := newWorkloadIdentityTiers(ctx, opts, clients)
	if err != nil {
		return nil, fmt.Errorf("building the workload identity tiers: %w", err)
	}

	// The path is the constant rather than a flag because it is a contract with
	// the Pod Identity webhook and the CSI driver. The shutdown budget is left to
	// the package, since this server's streams are held open by design.
	server, err := grpcserver.New(grpcserver.Opts{
		SocketPath: configuration.WorkloadIdentitySocketPath,
		Register:   registerWorkloadIdentityServices(tiers.handler),
	})
	if err != nil {
		return nil, err
	}
	// log.Fatalf exits without running deferred functions, but logrus runs its
	// exit handlers on any fatal entry, so a crash in an HTTP server does not
	// leave the socket on disk. The gRPC server's own shutdown defers the same.
	logrus.RegisterExitHandler(server.RemoveSocket)

	return []runnable{server, backgroundLoop{name: "trust-bundle-refresh", run: tiers.bundleSource.Run}}, nil
}

// workloadIdentityTiers is what the workload identity socket serves from, built
// once per node: the Workload API handler over its tiers, the trust bundle tier,
// whose refresh loop runs beside the servers, and the session tier they share.
type workloadIdentityTiers struct {
	handler      *workloadapi.Handler
	bundleSource *bundle.Registry
	// sessions is read only by tests, which mint through it.
	sessions *session.Provider
}

// newWorkloadIdentityTiers builds the tiers over clients and a new STS client. It
// blocks until the pod store syncs, since nothing can be attested before then.
func newWorkloadIdentityTiers(ctx context.Context, opts handlers.WorkloadIdentityServerOpts,
	clients *workloadIdentityClients) (*workloadIdentityTiers, error) {
	return buildWorkloadIdentityTiers(ctx, opts, clients, sts.NewService(opts.Cfg))
}

// buildWorkloadIdentityTiers is newWorkloadIdentityTiers past the STS client, so
// a test can drive the wiring with fake clients and STS. One hub serves the node:
// the bundle and X.509-SVID tiers publish to it, and each stream subscribes
// through its own hub.ForRPC under that RPC's constant.
func buildWorkloadIdentityTiers(ctx context.Context, opts handlers.WorkloadIdentityServerOpts,
	clients *workloadIdentityClients, stsClient sts.Iface) (*workloadIdentityTiers, error) {
	attestor, pods, err := attestation.NewAttestor(ctx, clients.clientset, clients.nodeName)
	if err != nil {
		return nil, err
	}

	// Cache is the credential cache every bind host serves from, so one session
	// per pod serves both the HTTP endpoint and this socket. The tier refuses a
	// nil cache, which either caching flag at zero yields. Minter is the one the
	// cache refreshes with.
	sessionProvider, err := session.New(session.Opts{
		ClusterName: opts.ClusterName,
		Minter:      clients.minter,
		Cache:       opts.CredentialCache,
		EKSAuth:     opts.EKSAuth,
	})
	if err != nil {
		return nil, fmt.Errorf("building the session tier: %w", err)
	}
	providers := workloadidentity.SessionProviderArns(sessionProvider)
	hub := notify.NewHub(providers)

	bundleSource, err := bundle.New(bundle.Opts{
		Fetcher:   stsClient,
		Notifier:  hub,
		Providers: providers,
		Signer:    bundle.WorkloadSessionSigner(sessionProvider),
	})
	if err != nil {
		return nil, fmt.Errorf("building the trust bundle tier: %w", err)
	}

	certs, err := x509tier.New(x509tier.Opts{
		Issuer:          stsClient,
		SessionProvider: sessionProvider,
		Notifier:        hub,
		MaxCacheSize:    opts.MaxCacheSize,
		Duration:        opts.X509SVIDDuration,
		RenewFraction:   opts.SVIDRenewalFraction,
		RenewJitter:     opts.SVIDRenewalJitter,
		KeyType:         opts.SVIDKeyType,
	})
	if err != nil {
		return nil, fmt.Errorf("building the X.509-SVID tier: %w", err)
	}

	// Watches the attestor's pod store, so a deleted pod's tokens go with it.
	tokens, err := jwttier.New(jwttier.Opts{
		Issuer:          stsClient,
		SessionProvider: sessionProvider,
		PodStore:        pods,
		MaxCacheSize:    opts.MaxCacheSize,
		Duration:        opts.JWTSVIDDuration,
		RenewalFraction: opts.SVIDRenewalFraction,
		RenewalJitter:   opts.SVIDRenewalJitter,
	})
	if err != nil {
		return nil, fmt.Errorf("building the JWT-SVID tier: %w", err)
	}

	handler := workloadapi.New(workloadapi.Opts{
		Attestor:              attestor,
		Certs:                 certs,
		Tokens:                tokens,
		Bundles:               bundleSource,
		X509SVIDSubscriber:    hub.ForRPC(workloadidentity.RPCFetchX509SVID),
		X509BundlesSubscriber: hub.ForRPC(workloadidentity.RPCFetchX509Bundles),
		JWTBundlesSubscriber:  hub.ForRPC(workloadidentity.RPCFetchJWTBundles),
	})
	return &workloadIdentityTiers{handler: handler, bundleSource: bundleSource, sessions: sessionProvider}, nil
}

// registerWorkloadIdentityServices returns the registration the workload identity
// gRPC server runs before it accepts anything.
//
// PLACEHOLDER(T11): the SDS stub answers every method with Unimplemented until the
// SDS handler replaces it here.
func registerWorkloadIdentityServices(handler *workloadapi.Handler) func(registrar grpc.ServiceRegistrar) {
	return func(registrar grpc.ServiceRegistrar) {
		handler.Register(registrar)
		grpcserver.RegisterStubSDS(registrar)
	}
}

// backgroundLoop drives a loop that is not a server, such as the trust bundle
// refresh, beside the servers, so it starts with them and stops at the same
// shutdown. Its name stands in for an address in the bind-addr log field.
type backgroundLoop struct {
	name string
	run  func(ctx context.Context)
}

// ListenUntilContextCancelled runs the loop until ctx is cancelled.
func (l backgroundLoop) ListenUntilContextCancelled(ctx context.Context) { l.run(ctx) }

// Addr names the loop.
func (l backgroundLoop) Addr() string { return l.name }

var _ runnable = backgroundLoop{}
