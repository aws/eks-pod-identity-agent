package cmd

import (
	"context"
	"fmt"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/eksauth"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/notify"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/sharedcredsrotater"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/handlers"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/server"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

var (
	serverPort              uint16
	probePort               uint16
	metricsAddress          string
	metricsPort             uint16
	bindHosts               []string
	clusterName             string
	overrideEksAuthEndpoint string
	maxCredentialRenewal    time.Duration
	maxCacheSize            int
	refreshQps              int
	rotateCredentials       bool

	// Workload identity tunables. The values the workload identity path shares
	// with the Pod Identity webhook, the CSI driver or EKS Auth are constants in
	// package configuration and deliberately not flags.
	x509SVIDDuration    time.Duration
	jwtSVIDDuration     time.Duration
	svidRenewalFraction float64
	svidRenewalJitter   float64
	svidKeyType         string
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "A proxy server that exchanges kubernetes service account token with temporary AWS credentials by calling EKS Auth APIs",
	Long: fmt.Sprintf(`This command initalizes a proxy server that will listen by default on port %d.

	Request that are sent to the credential path (/v1/credentials) will be proxied to EKS to fetch temporary
	AWS credentials. The AWS SDKs used from within EKS workloads can be configured to invoke this endpoint
	for granular IAM permissions.

	Example use: './eks-pod-identity-agent server'`, serverPort),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()
		log := logger.FromContext(ctx)
		cfg, err := config.LoadDefaultConfig(ctx)
		if overrideEksAuthEndpoint != "" {
			overrideEndpointInCfg(log, &cfg, overrideEksAuthEndpoint)
		}
		if err != nil {
			log.Fatal("Unable to initialize aws configuration, exiting")
		}
		if rotateCredentials {
			log.Info("Credentials rotation enabled. Creds will be fetched and rotated from shared credentials file")
			cfg.Credentials = aws.NewCredentialsCache(sharedcredsrotater.NewRotatingSharedCredentialsProvider())
		}

		// Fail the boot on a bad workload identity value rather than every pod on
		// the node. An out-of-envelope SVID lifetime is rejected by STS on every
		// issuance, and a renewal band outside the credential's life renews at
		// the wrong time for every workload.
		if err := newWorkloadIdentityServerOpts(cfg).Validate(); err != nil {
			log.Fatalf("Invalid workload identity configuration: %v", err)
		}

		startServers(ctx, cfg)
	},
}

// runnable is a server that startServers can drive. The HTTP servers in pkg/server
// and the workload identity gRPC server in pkg/grpcserver both satisfy it
// unchanged, which is the only thing they have in common.
//
// It is declared here because this is the only place that consumes it. Putting it
// in pkg/server would hand the HTTP package an abstraction it does not use and
// invite pkg/grpcserver to import the HTTP server just to assert against it.
type runnable interface {
	// ListenUntilContextCancelled serves until ctx is cancelled and then shuts
	// down. It does not return until the shutdown has finished, which is what
	// makes the WaitGroup below a shutdown barrier rather than a formality.
	ListenUntilContextCancelled(ctx context.Context)
	// Addr names what the server is bound to: host and port for the HTTP servers,
	// the socket path for the gRPC server. It is a log field, not an identity.
	Addr() string
}

var (
	_ runnable = &server.Server{}
	_ runnable = &grpcserver.Server{}
)

func startServers(pCtx context.Context, cfg aws.Config) {
	servers, err := createServers(cfg)
	if err != nil {
		// Nothing is left half-started: createServers binds the workload identity
		// socket after building every other server and before any of them serve.
		logger.FromContext(pCtx).Fatalf("Unable to create servers: %v", err)
	}

	runServersUntilShutdown(pCtx, servers)
}

// runServersUntilShutdown drives every server until SIGTERM, SIGINT, or pCtx being
// cancelled, and returns once all of them have stopped.
//
// signal.NotifyContext replaces the signal channel this used to own. The diversion
// stays in place until the deferred stop runs, so a second SIGTERM arriving during
// shutdown is swallowed exactly as the buffered channel swallowed it, and the only
// behaviour that changes is that cancelling pCtx now stops the servers too. In
// production pCtx is context.Background(), so that path exists for tests, which is
// the point: driving shutdown through a signal sent to a test binary is the only
// other way to cover this loop.
func runServersUntilShutdown(pCtx context.Context, servers []runnable) {
	// syscall.SIGTERM is what kill sends, which gives the process time to clean up.
	// The gRPC server needs that time: it has streams to drain.
	ctx, stopListening := signal.NotifyContext(pCtx, syscall.SIGTERM, syscall.SIGINT)
	defer stopListening()

	wg := sync.WaitGroup{}

	// start servers
	for _, srv := range servers {
		wg.Add(1)
		go func(srv runnable, childCtx context.Context) {
			defer wg.Done()
			srv.ListenUntilContextCancelled(childCtx)
		}(srv, logger.ContextWithField(ctx, "bind-addr", srv.Addr()))
	}

	wg.Wait()
}

func createServers(cfg aws.Config) ([]runnable, error) {
	servers := make([]runnable, len(bindHosts))
	// listen on all bindHosts
	for i, ip := range bindHosts {
		addr := fmt.Sprintf("%s:%d", ip, serverPort)
		servers[i] = server.NewEksCredentialServer(addr, handlers.EksCredentialHandlerOpts{
			Cfg:                cfg,
			ClusterName:        clusterName,
			CredentialRenewal:  maxCredentialRenewal,
			MaxCacheSize:       maxCacheSize,
			RefreshQPS:         refreshQps,
			EndpointOverridden: overrideEksAuthEndpoint != "",
		})
	}

	// add health probes listening on host's network
	servers = append(servers, server.NewProbeServer(fmt.Sprintf("localhost:%d", probePort), bindHosts, serverPort))
	servers = append(servers, server.NewMetricsServer(fmt.Sprintf("%s:%d", metricsAddress, metricsPort), bindHosts, serverPort))

	// The change notification tier, built once because the handlers subscribe
	// through it and the bundle and SVID tiers publish to it. It owns no goroutine.
	// PLACEHOLDER(T10): pass the bundle tier's ProviderArnResolver once T5 is
	// wired; nothing subscribes before the handlers replace the stub services.
	notificationHub := notify.NewHub(nil)

	// The workload identity socket is bound here, last, so a socket that cannot be
	// bound fails the boot before anything is serving. The path is the constant
	// rather than a flag because it is a contract with the Pod Identity webhook and
	// the CSI driver; see configuration.WorkloadIdentitySocketPath.
	workloadIdentityServer, err := grpcserver.New(grpcserver.Opts{
		SocketPath: configuration.WorkloadIdentitySocketPath,
		// The shutdown budget is left to the package: this server's streams are held
		// open by design, so its drain is bounded by a few seconds rather than by the
		// HTTP servers' request timeout. See grpcserver.DefaultShutdownWait.
		Register: registerWorkloadIdentityServices(notificationHub),
	})
	if err != nil {
		return nil, err
	}
	// A socket file outlives the process that bound it, and the agent's servers report
	// a failure they cannot serve through with log.Fatalf, which exits without running
	// any deferred function. logrus runs its exit handlers on a fatal entry from any
	// logger, so this is what keeps a crash in one of the HTTP servers from leaving the
	// workload identity socket on disk. The gRPC server's own shutdown path defers the
	// same call.
	logrus.RegisterExitHandler(workloadIdentityServer.RemoveSocket)
	servers = append(servers, workloadIdentityServer)

	return servers, nil
}

// registerWorkloadIdentityServices returns the registration the workload identity
// gRPC server runs before it accepts anything. The hub is threaded in here
// because this is where the handlers that subscribe to it are registered, each
// taking its own hub.ForRPC(<its label>).
//
// PLACEHOLDER(T10): the stubs answer every method with Unimplemented. The Workload
// API and SDS handlers replace one stub each here and nothing else changes.
func registerWorkloadIdentityServices(hub *notify.Hub) func(registrar grpc.ServiceRegistrar) {
	return func(registrar grpc.ServiceRegistrar) {
		grpcserver.RegisterStubServices(registrar)
	}
}

// newWorkloadIdentityServerOpts collects the workload identity flag values into
// the options struct the workload identity tiers read. Flags are read here and
// passed in, never read from inside a package, so a tier can be tested with a
// value it chose.
//
// The socket the server listens on is not part of this: it is the constant
// configuration.WorkloadIdentitySocketPath, passed to the server the way an HTTP
// server is given its addr.
func newWorkloadIdentityServerOpts(cfg aws.Config) handlers.WorkloadIdentityServerOpts {
	return handlers.WorkloadIdentityServerOpts{
		Cfg:                 cfg,
		ClusterName:         clusterName,
		MaxCacheSize:        maxCacheSize,
		X509SVIDDuration:    x509SVIDDuration,
		JWTSVIDDuration:     jwtSVIDDuration,
		SVIDRenewalFraction: svidRenewalFraction,
		SVIDRenewalJitter:   svidRenewalJitter,
		SVIDKeyType:         workloadidentity.KeyType(svidKeyType),
	}
}

func overrideEndpointInCfg(log *logrus.Entry, cfg *aws.Config, endpoint string) {
	log.Printf("Overriding %s default endpoint with %s\n", eksauth.ServiceID, endpoint)
	cfg.EndpointResolverWithOptions = aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		if service == eksauth.ServiceID {
			return aws.Endpoint{
				PartitionID:   "aws",
				URL:           endpoint,
				SigningRegion: region,
			}, nil
		}
		return aws.Endpoint{}, &aws.EndpointNotFoundError{}
	})
}

func init() {
	rootCmd.AddCommand(serverCmd)
	// Read cluster name for CLI. This flag must be provided
	serverCmd.Flags().StringVarP(&clusterName, "cluster-name", "c", "", "Name of the EKS Cluster the agent will run on")
	err := serverCmd.MarkFlagRequired("cluster-name")
	if err != nil {
		panic(fmt.Sprintf("Unable to configure server command flags: %v", err))
	}

	// Setup the port where the proxy server will listen to connections
	serverCmd.Flags().Uint16VarP(&serverPort, "port", "p", 80, "Listening port of the proxy server")
	serverCmd.Flags().Uint16Var(&probePort, "probe-port", 2703, "Health and readiness listening port")
	serverCmd.Flags().StringVar(&metricsAddress, "metrics-address", "0.0.0.0", "Metrics listening address")
	serverCmd.Flags().Uint16Var(&metricsPort, "metrics-port", 2705, "Metrics listening port")
	serverCmd.Flags().DurationVar(&maxCredentialRenewal, "max-credential-retention-before-renewal", 3*time.Hour,
		"Maximum amount of time that agent waits before renewing credentials. Set 0 to disable caching.")
	serverCmd.Flags().IntVar(&maxCacheSize, "max-cache-size", 2000,
		"Maximum amount of unique credentials to cache. Set 0 to disable caching.")
	serverCmd.Flags().IntVar(&refreshQps, "max-service-qps", 3,
		"Maximum amount of queries per second to EKS Auth")
	serverCmd.Flags().StringArrayVarP(&bindHosts, "bind-hosts", "b",
		[]string{configuration.DefaultIpv4TargetHost, "[" + configuration.DefaultIpv6TargetHost + "]"}, "Hosts to bind server to")
	serverCmd.Flags().BoolVar(&rotateCredentials, "rotate-credentials", false, "Enable credentials rotation from shared credentials file")
	serverCmd.Flags().StringVar(&overrideEksAuthEndpoint, "endpoint", "", "Override for EKS auth endpoint")

	// Workload identity. Each requested SVID lifetime is a ceiling and not a
	// grant: STS issues the least of what is asked for and what it allows, and
	// the renewal schedule is derived from what it issued.
	// the accepted range is read off the envelope rather than written out again,
	// so --help cannot claim a bound validation does not enforce
	// Twelve hours is both the top of the envelope and what STS issues when the request
	// names no lifetime. Asking for less does not make anything
	// safer, because a shorter certificate is replaced sooner and each replacement is a
	// signing operation.
	x509Lower, x509Upper := handlers.X509SVIDDurationBounds()
	serverCmd.Flags().DurationVar(&x509SVIDDuration, handlers.FlagX509SVIDDuration, 12*time.Hour,
		fmt.Sprintf("Lifetime requested for each X.509-SVID, between %s and %s", x509Lower, x509Upper))
	jwtLower, jwtUpper := handlers.JWTSVIDDurationBounds()
	serverCmd.Flags().DurationVar(&jwtSVIDDuration, handlers.FlagJWTSVIDDuration, time.Hour,
		fmt.Sprintf("Lifetime requested for each JWT-SVID, between %s and %s", jwtLower, jwtUpper))
	serverCmd.Flags().Float64Var(&svidRenewalFraction, handlers.FlagSVIDRenewalFraction, 0.5,
		"Fraction of an SVID's issued lifetime at which renewal starts")
	serverCmd.Flags().StringVar(&svidKeyType, handlers.FlagSVIDKeyType, string(workloadidentity.DefaultKeyType),
		fmt.Sprintf("Key type generated for each X.509-SVID, one of %s", workloadidentity.KeyTypeList()))
	serverCmd.Flags().Float64Var(&svidRenewalJitter, handlers.FlagSVIDRenewalJitter, 0.1,
		"Jitter applied to X.509-SVID and JWT-SVID renewal points, as a fraction of half the issued lifetime, so renewals on a node do not synchronise")
}
