package cmd

import (
	"context"
	"fmt"
	"os"
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

		startServers(ctx, cfg)
	},
}

func startServers(pCtx context.Context, cfg aws.Config) {
	ctx, cancel := context.WithCancel(pCtx)
	wg := sync.WaitGroup{}

	servers := createServers(cfg)

	// start servers
	for _, srv := range servers {
		wg.Add(1)
		go func(server *server.Server, childCtx context.Context) {
			defer wg.Done()
			server.ListenUntilContextCancelled(childCtx)
		}(srv, logger.ContextWithField(ctx, "bind-addr", srv.Addr()))
	}

	// Create a channel to listen for an interrupt or terminate signal from the operating system
	// syscall.SIGTERM is equivalent to kill which allows the process time to cleanup
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	<-quit
	cancel()
	wg.Wait()
}

func createServers(cfg aws.Config) []*server.Server {
	servers := make([]*server.Server, len(bindHosts))
	// listen on all bindHosts
	for i, ip := range bindHosts {
		addr := fmt.Sprintf("%s:%d", ip, serverPort)
		servers[i] = server.NewEksCredentialServer(addr, handlers.EksCredentialHandlerOpts{
			Cfg:               cfg,
			ClusterName:       clusterName,
			CredentialRenewal: maxCredentialRenewal,
			MaxCacheSize:      maxCacheSize,
			RefreshQPS:        refreshQps,
		})
	}

	// add health probes listening on host's network
	servers = append(servers, server.NewProbeServer(fmt.Sprintf("localhost:%d", probePort), bindHosts, serverPort))
	servers = append(servers, server.NewMetricsServer(fmt.Sprintf("%s:%d", metricsAddress, metricsPort), bindHosts, serverPort))
	return servers
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

}
