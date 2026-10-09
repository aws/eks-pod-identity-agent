// Package csidriver is the CSI node plugin for spiffe.csi.eks.amazonaws.com, run as a
// sidecar of the Pod Identity Agent by cmd/eks-pod-identity-csi-driver. It bind mounts
// the agent's socket directory into enrolled pods, so they reach the socket without a
// hostPath, which a restricted Pod Security Standard forbids.
//
// The CSI Identity and Node services are upstream spiffe-csi's (pkg/driver). This package
// adds what spiffe-csi leaves to node-driver-registrar: the kubelet registration handshake,
// on its own socket, and the lifecycle of both sockets.
package csidriver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/bombsimon/logrusr/v4"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/sirupsen/logrus"
	spiffecsi "github.com/spiffe/spiffe-csi/pkg/driver"
	"google.golang.org/grpc"
	pluginregistration "k8s.io/kubelet/pkg/apis/pluginregistration/v1"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
)

const (
	// socketMode is 0600: the only caller is the kubelet, which is root, and the calls
	// behind the plugin socket mount.
	socketMode os.FileMode = 0o600

	// defaultShutdownWait bounds each server's graceful stop. Short because every call
	// here is a unary request the kubelet waits for; nothing is held open.
	defaultShutdownWait = 2 * time.Second

	// forcedStopWait bounds the wait for an accept loop to unwind after in-flight calls
	// are cancelled. By then the listener is closed and the socket unlinked.
	forcedStopWait = 1 * time.Second
)

// Driver serves the CSI plugin and the kubelet registration handshake for the life of a
// context.
type Driver struct {
	plugin    *grpc.Server
	pluginLis net.Listener

	registration    *grpc.Server
	registrationLis net.Listener

	pluginSocketPath       string
	registrationSocketPath string

	// refused carries the kubelet's reason when it refuses the registration.
	refused chan string

	shutdownWait time.Duration
}

// Opts configures the driver. Every path defaults to the constant production uses, so a
// caller passes the node name and nothing else, and a test passes temporary paths.
type Opts struct {
	// NodeName is reported to the kubelet as the CSI node ID, which it records in the
	// node's CSINode object. Nothing routes or authorizes on it.
	NodeName string

	// SocketDir is the directory published into each enrolled pod. Empty means
	// configuration.WorkloadIdentitySocketMountPath.
	SocketDir string

	// PluginSocketPath serves the CSI Identity and Node services. Empty means
	// configuration.KubeletPluginSocketPath.
	PluginSocketPath string

	// RegistrationSocketPath serves the kubelet's registration handshake. Empty means
	// configuration.KubeletRegistrationSocketPath.
	RegistrationSocketPath string

	// ShutdownWait bounds each graceful stop. Zero or less means defaultShutdownWait.
	ShutdownWait time.Duration
}

// New binds both sockets and returns a driver ready to be driven. Binding here makes an
// unbindable socket a start-up failure. The plugin socket is bound first, since the
// kubelet asks for it as soon as the registration socket exists; serving can follow, as a
// connection waits in the backlog.
func New(opts Opts) (*Driver, error) {
	if opts.NodeName == "" {
		return nil, errors.New("csidriver: no node name configured: neither the NODE_NAME environment variable " +
			"the chart sets from spec.nodeName nor the hostname yielded one")
	}

	node, err := spiffecsi.New(nodeConfig(opts))
	if err != nil {
		return nil, err
	}

	pluginSocketPath := valueOrDefault(opts.PluginSocketPath, configuration.KubeletPluginSocketPath)
	registrationSocketPath := valueOrDefault(opts.RegistrationSocketPath, configuration.KubeletRegistrationSocketPath)

	shutdownWait := opts.ShutdownWait
	if shutdownWait <= 0 {
		shutdownWait = defaultShutdownWait
	}

	pluginLis, err := grpcserver.ListenUnix(pluginSocketPath, socketMode)
	if err != nil {
		return nil, err
	}

	registrationLis, err := grpcserver.ListenUnix(registrationSocketPath, socketMode)
	if err != nil {
		// Nothing else will close the plugin socket if this returns an error.
		_ = pluginLis.Close()
		_ = grpcserver.UnlinkIfStale(pluginSocketPath)
		return nil, err
	}

	plugin := grpc.NewServer()
	csi.RegisterIdentityServer(plugin, node)
	csi.RegisterNodeServer(plugin, nodeServer{node})

	refused := make(chan string, 1)
	registration := grpc.NewServer()
	pluginregistration.RegisterRegistrationServer(registration,
		newRegistrationServer(configuration.WorkloadIdentityCSIDriver, pluginSocketPath, refused))

	return &Driver{
		plugin:                 plugin,
		pluginLis:              pluginLis,
		registration:           registration,
		registrationLis:        registrationLis,
		pluginSocketPath:       pluginSocketPath,
		registrationSocketPath: registrationSocketPath,
		refused:                refused,
		shutdownWait:           shutdownWait,
	}, nil
}

// nodeConfig is the upstream node service's configuration for opts.
func nodeConfig(opts Opts) spiffecsi.Config {
	return spiffecsi.Config{
		Log:                  logrusr.New(logger.FromContext(context.Background())),
		NodeID:               opts.NodeName,
		PluginName:           configuration.WorkloadIdentityCSIDriver,
		WorkloadAPISocketDir: valueOrDefault(opts.SocketDir, configuration.WorkloadIdentitySocketMountPath),
	}
}

// nodeServer is the upstream node service reporting no capabilities. Upstream reports
// GET_VOLUME_STATS, which has the kubelet poll every volume each minute for statistics a
// socket directory does not have.
type nodeServer struct{ *spiffecsi.Driver }

func (nodeServer) NodeGetCapabilities(context.Context, *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	return &csi.NodeGetCapabilitiesResponse{}, nil
}

// Run serves both sockets until ctx is cancelled, the kubelet refuses the registration or
// a socket fails, then shuts them down. It returns nil only for ctx: a refusal or a
// failure is an error, so the process exits and its container restarts and re-registers,
// as with node-driver-registrar.
func (d *Driver) Run(ctx context.Context) error {
	log := logger.FromContext(ctx)

	// Deferred so the sockets are cleaned up on every way out, a panic included.
	defer d.RemoveSockets()

	pluginServed := serveInBackground(d.plugin, d.pluginLis)
	log.Infof("Serving CSI plugin for driver %s at %s", configuration.WorkloadIdentityCSIDriver, d.pluginSocketPath)
	registrationServed := serveInBackground(d.registration, d.registrationLis)
	log.Infof("Serving kubelet plugin registration at %s", d.registrationSocketPath)

	var result error
	select {
	case err := <-pluginServed:
		// After a successful bind, Serve returning means the accept loop failed.
		result = fmt.Errorf("serving the CSI plugin socket: %w", err)
	case err := <-registrationServed:
		result = fmt.Errorf("serving the kubelet registration socket: %w", err)
	case reason := <-d.refused:
		result = fmt.Errorf("the kubelet refused to register CSI driver %s: %s", configuration.WorkloadIdentityCSIDriver, reason)
	case <-ctx.Done():
	}

	log.Info("Shutting down the CSI driver...")

	// Registration first, so the kubelet cannot start a registration the plugin server
	// is about to stop answering.
	d.stop(log, "kubelet plugin registration", d.registration, registrationServed)
	d.stop(log, "CSI plugin", d.plugin, pluginServed)

	log.Info("CSI driver stopped")
	return result
}

// serveInBackground runs server on lis. The channel delivers Serve's error and is then
// closed, so a stop can wait on it whether or not the error was already received.
func serveInBackground(server *grpc.Server, lis net.Listener) <-chan error {
	served := make(chan error, 1)
	go func() {
		served <- server.Serve(lis)
		close(served)
	}()
	return served
}

// stop runs GracefulStop under a deadline, escalates to Stop, and returns once Serve has
// returned or the escalation has had its own slice of time. Neither wait may be
// unbounded: gRPC holds the server lock while waiting for handlers, so a wedged handler
// would otherwise hold up the whole shutdown.
func (d *Driver) stop(log *logrus.Entry, name string, server *grpc.Server, served <-chan error) {
	stopped := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(stopped)
	}()

	select {
	case <-stopped:
		<-served
		return
	case <-time.After(d.shutdownWait):
		log.Warnf("Graceful stop of the %s server did not finish within %s, cancelling in-flight calls", name, d.shutdownWait)
	}

	// In its own goroutine: the GracefulStop in flight may hold the lock Stop needs.
	go server.Stop()

	select {
	case <-served:
	case <-time.After(forcedStopWait):
		log.Warnf("The %s server did not stop within %s of cancelling its calls, abandoning it", name, forcedStopWait)
	}
}

// RemoveSockets unlinks both sockets if they are still there. Safe to call more than once.
// The registration socket matters most: the kubelet watches its directory, so one left
// behind advertises a plugin that is not running.
func (d *Driver) RemoveSockets() {
	for _, socket := range []struct {
		path     string
		listener net.Listener
	}{
		{path: d.registrationSocketPath, listener: d.registrationLis},
		{path: d.pluginSocketPath, listener: d.pluginLis},
	} {
		// Close first: UnlinkIfStale would otherwise read our own still-open socket as a
		// live successor's and leave it behind.
		if socket.listener != nil {
			_ = socket.listener.Close()
		}
		if err := grpcserver.UnlinkIfStale(socket.path); err != nil {
			logger.FromContext(context.Background()).Warnf("Leaving %s in place: %v", socket.path, err)
		}
	}
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
