package csidriver

import (
	"context"

	pluginregistration "k8s.io/kubelet/pkg/apis/pluginregistration/v1"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
)

// csiPluginAPIVersion is the version of the registration handshake, not of the CSI
// specification. Every upstream driver reports 1.0.0, node-driver-registrar included.
const csiPluginAPIVersion = "1.0.0"

// registrationServer tells the kubelet this node has a CSI plugin and where to call it.
// It is node-driver-registrar's two methods, served in-process so the sidecar needs no
// second image. Like the registrar, a refused registration ends the process (through
// refused and Driver.Run), so the container restarts and registers again.
type registrationServer struct {
	pluginregistration.UnimplementedRegistrationServer

	driverName string
	endpoint   string
	// refused receives the kubelet's reason for a refusal. Buffered; a second refusal
	// before the first is handled is dropped.
	refused chan<- string
}

func newRegistrationServer(driverName, endpoint string, refused chan<- string) *registrationServer {
	return &registrationServer{driverName: driverName, endpoint: endpoint, refused: refused}
}

// GetInfo answers the kubelet's question about the socket it just found. The endpoint is
// the plugin socket as the kubelet opens it, in the host mount namespace; it equals the
// path bound here only because the chart mounts the plugin directory at its host path.
func (s *registrationServer) GetInfo(ctx context.Context, _ *pluginregistration.InfoRequest) (*pluginregistration.PluginInfo, error) {
	logger.FromContext(ctx).Infof("Kubelet asked for plugin info, reporting driver %s at %s", s.driverName, s.endpoint)

	return &pluginregistration.PluginInfo{
		Type:              pluginregistration.CSIPlugin,
		Name:              s.driverName,
		Endpoint:          s.endpoint,
		SupportedVersions: []string{csiPluginAPIVersion},
	}, nil
}

// NotifyRegistrationStatus records what the kubelet decided and reports a refusal. No
// error is returned: the kubelet has already decided, and on success an error would make
// it deregister the plugin it just registered.
func (s *registrationServer) NotifyRegistrationStatus(ctx context.Context, status *pluginregistration.RegistrationStatus) (*pluginregistration.RegistrationStatusResponse, error) {
	log := logger.FromContext(ctx)

	if status.GetPluginRegistered() {
		log.Infof("Kubelet registered CSI driver %s", s.driverName)
		return &pluginregistration.RegistrationStatusResponse{}, nil
	}

	log.Errorf("Kubelet refused to register CSI driver %s, so no enrolled pod on this node can be given the "+
		"workload identity socket; restarting to register again: %s", s.driverName, status.GetError())
	select {
	case s.refused <- status.GetError():
	default:
	}

	return &pluginregistration.RegistrationStatusResponse{}, nil
}
