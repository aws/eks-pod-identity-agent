package cmd

import (
	"context"
	"fmt"
	"net"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/eksauth"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/sharedcredsrotater"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/handlers"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/server"
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
	enableIMDSCredentials   bool

	// Workload identity tunables. The values the workload identity path shares
	// with the Pod Identity webhook, the CSI driver or EKS Auth are constants in
	// package configuration and deliberately not flags.
	enableWorkloadIdentity bool
	nodeKubeconfig         string
	x509SVIDDuration       time.Duration
	jwtSVIDDuration        time.Duration
	svidRenewalFraction    float64
	svidRenewalJitter      float64
	peerPidfd              bool
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
		// issuance. With the feature off the values are unused, so they are not
		// checked.
		if opts := newWorkloadIdentityServerOpts(cfg); opts.Enabled {
			if err := opts.Validate(); err != nil {
				log.Fatalf("Invalid workload identity configuration: %v", err)
			}
		}

		startServers(ctx, cfg)
	},
}

// runnable is anything startServers drives until shutdown: the HTTP servers in
// pkg/server and the workload identity gRPC server in pkg/grpcserver satisfy it
// unchanged, and backgroundLoop adapts a loop such as the trust bundle refresh.
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
	// the socket path for the gRPC server, a name for a loop. It is a log field,
	// not an identity.
	Addr() string
}

var (
	_ runnable = &server.Server{}
	_ runnable = &grpcserver.Server{}
)

func startServers(pCtx context.Context, cfg aws.Config) {
	servers, err := createServers(pCtx, cfg)
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

func createServers(ctx context.Context, cfg aws.Config) ([]runnable, error) {
	// Refuse to start if the credential server is pointed at anything other
	// than a node-local address. The agent vends AWS credentials in exchange
	// for a service-account token, and its only locality control assumes the
	// listener is reachable solely from the node. Binding a routable address
	// (e.g. 0.0.0.0, which also covers the node's VPC IP) would expose the
	// credential endpoint to the rest of the network.
	if err := validateBindHosts(bindHosts); err != nil {
		return nil, err
	}

	credentialOpts := handlers.EksCredentialHandlerOpts{
		Cfg:                cfg,
		ClusterName:        clusterName,
		CredentialRenewal:  maxCredentialRenewal,
		MaxCacheSize:       maxCacheSize,
		RefreshQPS:         refreshQps,
		EndpointOverridden: overrideEksAuthEndpoint != "",
		EnableIMDS:         enableIMDSCredentials,
	}
	workloadIdentityOpts := newWorkloadIdentityServerOpts(cfg)
	wiClients, err := buildSharedCredentialManager(ctx, &credentialOpts, &workloadIdentityOpts)
	if err != nil {
		return nil, err
	}
	servers := make([]runnable, len(bindHosts))
	// listen on all bindHosts
	for i, ip := range bindHosts {
		addr := fmt.Sprintf("%s:%d", ip, serverPort)
		servers[i] = server.NewEksCredentialServer(ctx, addr, credentialOpts)
	}

	// add health probes listening on host's network
	servers = append(servers, server.NewProbeServer(fmt.Sprintf("localhost:%d", probePort), bindHosts, serverPort))
	servers = append(servers, server.NewMetricsServer(fmt.Sprintf("%s:%d", metricsAddress, metricsPort), bindHosts, serverPort))

	// Last, so a tier that cannot be built, or a socket that cannot be bound,
	// fails the boot before anything is serving. A node the agent cannot attest
	// on already failed it, in buildSharedCredentialManager.
	workloadIdentity, err := workloadIdentityServers(ctx, workloadIdentityOpts, wiClients)
	if err != nil {
		return nil, fmt.Errorf("building the workload identity servers (--%s=false turns workload identity off): %w",
			handlers.FlagEnableWorkloadIdentity, err)
	}
	return append(servers, workloadIdentity...), nil
}

// newCredentialManager builds the credential manager. Tests replace it.
var newCredentialManager = handlers.NewCredentialManager

// buildSharedCredentialManager builds the workload identity clients, nil with the
// feature off, then the one credential manager every bind host and the session
// tier share. Its cache refreshes with the clients' shared token minter. It
// returns the clients for the workload identity servers.
func buildSharedCredentialManager(ctx context.Context, credentialOpts *handlers.EksCredentialHandlerOpts,
	workloadIdentityOpts *handlers.WorkloadIdentityServerOpts) (*workloadIdentityClients, error) {
	wiClients, err := newWorkloadIdentityClients(ctx, *workloadIdentityOpts)
	if err != nil {
		return nil, fmt.Errorf("building the workload identity clients (--%s=false turns workload identity off): %w",
			handlers.FlagEnableWorkloadIdentity, err)
	}
	credentialOpts.WorkloadIdentityTokens = wiClients.credentialTokens()
	shareCredentialManager(newCredentialManager(ctx, *credentialOpts), credentialOpts, workloadIdentityOpts)
	return wiClients, nil
}

// shareCredentialManager hands manager's retriever to every bind host's handler
// and its cache and EKS Auth client to the workload identity session tier.
func shareCredentialManager(manager handlers.CredentialManager, credentialOpts *handlers.EksCredentialHandlerOpts,
	workloadIdentityOpts *handlers.WorkloadIdentityServerOpts) {
	credentialOpts.CredentialRetriever = manager.Retriever
	workloadIdentityOpts.CredentialCache = manager.Cache
	workloadIdentityOpts.EKSAuth = manager.EKSAuth
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
		Enabled:             enableWorkloadIdentity,
		Cfg:                 cfg,
		NodeKubeconfig:      nodeKubeconfig,
		ClusterName:         clusterName,
		MaxCacheSize:        maxCacheSize,
		X509SVIDDuration:    x509SVIDDuration,
		JWTSVIDDuration:     jwtSVIDDuration,
		SVIDRenewalFraction: svidRenewalFraction,
		SVIDRenewalJitter:   svidRenewalJitter,
		PeerPidfd:           peerPidfd,
	}
}

// validateBindHosts returns an error if any requested credential-server bind
// host is not node-local. Only loopback and the two link-local target hosts the
// agent authorizes against are permitted; anything else (notably 0.0.0.0) would
// move the credential listener onto a network-reachable address.
func validateBindHosts(hosts []string) error {
	for _, h := range hosts {
		if !isNodeLocalBindHost(h) {
			return fmt.Errorf(
				"refusing to bind credential server to non-node-local host %q; "+
					"only loopback and the link-local hosts %s / %s are permitted",
				h, configuration.DefaultIpv4TargetHost, configuration.DefaultIpv6TargetHost)
		}
	}
	return nil
}

// isNodeLocalBindHost reports whether host is safe to bind the credential
// server to: loopback, localhost, or one of the agent's link-local target
// hosts. IPv6 hosts may arrive bracketed (e.g. "[fd00:ec2::23]").
func isNodeLocalBindHost(host string) bool {
	if len(host) > 1 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() ||
		ip.Equal(net.ParseIP(configuration.DefaultIpv4TargetHost)) ||
		ip.Equal(net.ParseIP(configuration.DefaultIpv6TargetHost))
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
	serverCmd.Flags().BoolVar(&enableIMDSCredentials, "enable-imds-credentials", false,
		"Enable consuming credentials from IMDS when available on the node")

	serverCmd.Flags().BoolVar(&enableWorkloadIdentity, handlers.FlagEnableWorkloadIdentity, false,
		"Serve SPIFFE workload identity on its socket. When on, boot fails if the API server can't be reached as the node")
	serverCmd.Flags().StringVar(&nodeKubeconfig, handlers.FlagNodeKubeconfig, "",
		"Kubeconfig workload identity reaches the API server with. Empty uses the in-cluster API server and CA, and the agent authenticates as the node with an IAM token signed from its AWS credentials. A kubeconfig whose user runs an exec plugin gets the same IAM token in place of the plugin; any other user (client certificate, token) is used as is, so it must be the node")

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
	serverCmd.Flags().Float64Var(&svidRenewalJitter, handlers.FlagSVIDRenewalJitter, 0.1,
		"Jitter applied to X.509-SVID and JWT-SVID renewal points, as a fraction of half the issued lifetime, so renewals on a node do not synchronise")
	serverCmd.Flags().BoolVar(&peerPidfd, handlers.FlagPeerPidfd, false,
		"Pin workload identity callers by SO_PEERPIDFD on kernels that have it (Linux 6.5+). Off, or on an older kernel, callers are pinned through their /proc handle")
}
