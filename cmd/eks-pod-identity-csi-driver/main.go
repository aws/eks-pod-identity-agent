// Command eks-pod-identity-csi-driver is the workload identity CSI node plugin. The chart
// runs it as a privileged sidecar of the Pod Identity Agent, so the agent itself needs no
// privilege; see internal/csidriver.
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/csidriver"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
)

// nodeNameEnvVar carries the node's name, which the chart sets from the downward API.
const nodeNameEnvVar = "NODE_NAME"

func main() {
	verbosity := flag.String("v", "info", "Logging verbosity can be one of: panic, error, info, debug, trace")
	flag.Parse()
	logger.Initialize(*verbosity)
	log := logger.FromContext(context.Background())
	log.Infof("Pod Identity Agent CSI driver version %v", configuration.AgentVersion)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	if err := csidriver.WaitForSocket(ctx, log, configuration.WorkloadIdentitySocketPath); err != nil {
		log.Infof("Stopped before the agent served its socket: %v", err)
		return
	}

	driver, err := csidriver.New(csidriver.Opts{NodeName: nodeName(log)})
	if err != nil {
		log.Fatalf("Unable to start the CSI driver: %v", err)
	}
	if err := driver.Run(ctx); err != nil {
		// Run has removed the sockets; exiting restarts the container, which registers again.
		log.Errorf("CSI driver stopped: %v", err)
		stop()
		os.Exit(1)
	}
}

// nodeName is the node's name as the kubelet knows it, with the hostname as a fallback.
// The value is bookkeeping in the node's CSINode object, so the fallback is safe.
func nodeName(log *logrus.Entry) string {
	if name := os.Getenv(nodeNameEnvVar); name != "" {
		return name
	}
	hostname, err := os.Hostname()
	if err != nil {
		log.Warnf("%s is unset and the hostname could not be read: %v", nodeNameEnvVar, err)
		return ""
	}
	log.Warnf("%s is unset, falling back to the hostname %q as the CSI node ID", nodeNameEnvVar, hostname)
	return hostname
}
