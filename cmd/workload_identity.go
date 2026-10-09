package cmd

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"google.golang.org/grpc"
	"k8s.io/client-go/kubernetes"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/attestation"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/credsretriever"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/kube"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/material/bundle"
	x509tier "go.amzn.com/eks/eks-pod-identity-agent/internal/material/x509"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/notify"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/tokenminter"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/handlers"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/handlers/sds"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/handlers/workloadapi"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// workloadIdentityServers is what the workload identity feature runs: the gRPC
// server on its socket and the trust bundle refresh loop. Off, it builds nothing,
// so boot needs neither the API server nor the kubelet's kubeconfig. On, it blocks
// until the pod store syncs, so a node the agent cannot attest on fails the boot.
func workloadIdentityServers(ctx context.Context, opts handlers.WorkloadIdentityServerOpts) ([]runnable, error) {
	if !opts.Enabled {
		logger.FromContext(ctx).Infof("Workload identity is off (--%s=false), so %s is not served",
			handlers.FlagEnableWorkloadIdentity, configuration.WorkloadIdentitySocketPath)
		return nil, nil
	}

	tiers, err := newWorkloadIdentityTiers(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("building the workload identity tiers: %w", err)
	}

	// The path is the constant rather than a flag because it is a contract with
	// the Pod Identity webhook and the CSI driver. The shutdown budget is left to
	// the package, since this server's streams are held open by design.
	server, err := grpcserver.New(grpcserver.Opts{
		SocketPath: configuration.WorkloadIdentitySocketPath,
		Register:   registerWorkloadIdentityServices(tiers.handler, tiers.sdsHandler),
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
// once per node: the Workload API handler and the Envoy SDS handler over the same
// tiers, and the trust bundle tier, whose refresh loop runs beside the servers.
//
// One set of tiers for both handlers, so a workload reaching the agent over both
// interfaces gets the same certificate from the same cache rather than two
// issuances, two leases and two renewal schedules.
type workloadIdentityTiers struct {
	handler      *workloadapi.Handler
	sdsHandler   *sds.Handler
	bundleSource *bundle.Registry
}

// newWorkloadIdentityTiers builds the tiers over the node credential. It blocks
// until the node name resolves and the pod store syncs, since nothing can be
// attested before then, and it needs the kubelet's kubeconfig on the node.
func newWorkloadIdentityTiers(ctx context.Context, opts handlers.WorkloadIdentityServerOpts) (*workloadIdentityTiers, error) {
	clientset, err := kube.NewNodeClient("")
	if err != nil {
		return nil, err
	}
	return buildWorkloadIdentityTiers(ctx, opts, clientset, sts.NewService(opts.Cfg))
}

// buildWorkloadIdentityTiers is newWorkloadIdentityTiers past the clients, so a
// test can drive the wiring with a fake clientset and STS. One hub serves the
// node: the bundle and X.509-SVID tiers publish to it, and each stream subscribes
// through its own hub.ForRPC under that RPC's constant.
func buildWorkloadIdentityTiers(ctx context.Context, opts handlers.WorkloadIdentityServerOpts, clientset kubernetes.Interface, stsClient sts.Iface) (*workloadIdentityTiers, error) {
	nodeName, err := kube.ResolveNodeNameWithRetry(ctx, clientset)
	if err != nil {
		return nil, err
	}
	attestor, err := attestation.NewAttestor(ctx, clientset, nodeName)
	if err != nil {
		return nil, err
	}

	// Shares the attestor's node client. It refuses a --max-cache-size of zero,
	// which the credentials path reads as no caching.
	minter, err := tokenminter.NewMinter(ctx, clientset, tokenminter.CachedMinterOpts{MaxCacheSize: opts.MaxCacheSize})
	if err != nil {
		return nil, fmt.Errorf("building the token minter: %w", err)
	}

	// PLACEHOLDER(T5): the session tier's API without its implementation, which
	// answers every session ErrSessionUnavailable until T5 lands. Cache is the
	// credentials path's shared cache, which T5 builds once for every bind host.
	sessionProvider, err := credsretriever.NewSessionProvider(credsretriever.SessionProviderOpts{
		ClusterName: opts.ClusterName,
		Minter:      minter,
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

	handler := workloadapi.New(workloadapi.Opts{
		Attestor:              attestor,
		Certs:                 certs,
		Tokens:                unimplementedTokenSource{},
		Bundles:               bundleSource,
		X509SVIDSubscriber:    hub.ForRPC(workloadidentity.RPCFetchX509SVID),
		X509BundlesSubscriber: hub.ForRPC(workloadidentity.RPCFetchX509Bundles),
		JWTBundlesSubscriber:  hub.ForRPC(workloadidentity.RPCFetchJWTBundles),
	})
	sdsHandler := sds.New(sds.Opts{
		Attestor: attestor,
		Certs:    certs,
		Bundles:  bundleSource,
		// Its own hub.ForRPC, so an Envoy stream and a FetchX509SVID stream never
		// share a subscription series. FetchSecrets has none: it answers once.
		StreamSecretsSubscriber: hub.ForRPC(workloadidentity.RPCStreamSecrets),
	})

	return &workloadIdentityTiers{handler: handler, sdsHandler: sdsHandler, bundleSource: bundleSource}, nil
}

// registerWorkloadIdentityServices returns the registration the workload identity
// gRPC server runs before it accepts anything. Both services are real now, so the
// SDS stub is gone: one listener serves the SPIFFE Workload API and Envoy SDS.
func registerWorkloadIdentityServices(handler *workloadapi.Handler, sdsHandler *sds.Handler) func(registrar grpc.ServiceRegistrar) {
	return func(registrar grpc.ServiceRegistrar) {
		handler.Register(registrar)
		sdsHandler.Register(registrar)
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

// unimplementedTokenSource stands in for the JWT-SVID tier until T8 lands. Every
// call fails retryably, so FetchJWTSVID answers Unavailable.
//
// PLACEHOLDER(T8): replace with the internal/material/jwt source.
type unimplementedTokenSource struct{}

func (unimplementedTokenSource) JWTSVIDs(context.Context, *workloadidentity.Workload, []string) ([]*jwtsvid.SVID, error) {
	return nil, wierrors.ErrIssuanceFailed.Wrapf(nil, "the JWT-SVID tier is not implemented yet")
}

var _ workloadidentity.TokenSource = unimplementedTokenSource{}
