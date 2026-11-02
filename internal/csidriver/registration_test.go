package csidriver

import (
	"context"
	"testing"

	. "github.com/onsi/gomega"
	pluginregistration "k8s.io/kubelet/pkg/apis/pluginregistration/v1"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// Each field fails differently: wrong type goes to the device plugin machinery, wrong name
// never resolves the volume, wrong endpoint registers a plugin nothing calls.
func TestGetInfo_ReportsACSIPluginAtThePluginSocket(t *testing.T) {
	g := NewWithT(t)

	registration := newRegistrationServer(configuration.WorkloadIdentityCSIDriver, configuration.KubeletPluginSocketPath, make(chan string, 1))

	info, err := registration.GetInfo(context.Background(), &pluginregistration.InfoRequest{})
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(info.GetType()).To(Equal(pluginregistration.CSIPlugin))
	g.Expect(info.GetName()).To(Equal(configuration.WorkloadIdentityCSIDriver))
	g.Expect(info.GetEndpoint()).To(Equal(configuration.KubeletPluginSocketPath))
	g.Expect(info.GetSupportedVersions()).To(Equal([]string{csiPluginAPIVersion}))
}

// The namespace check: the kubelet opens the endpoint in the host namespace, the driver
// binds it in its own, and they match only because the chart mounts the plugin directory at
// its host path. Getting this wrong registers a plugin nothing ever calls.
func TestGetInfo_TheReportedEndpoint_IsThePathTheDriverBinds(t *testing.T) {
	g := NewWithT(t)

	g.Expect(configuration.KubeletPluginSocketPath).To(HavePrefix(configuration.KubeletPluginDir+"/"),
		"the plugin socket has to live in the directory the chart mounts for it")
	g.Expect(configuration.KubeletPluginDir).To(HaveSuffix("/"+configuration.WorkloadIdentityCSIDriver),
		"the kubelet convention is one directory per driver, named after the driver")
	g.Expect(configuration.KubeletRegistrationSocketPath).To(HavePrefix(configuration.KubeletPluginRegistrationDir+"/"),
		"the kubelet only watches its own registration directory")
}

func TestNotifyRegistrationStatus_Registered_IsAcknowledgedAndNotReported(t *testing.T) {
	g := NewWithT(t)

	refused := make(chan string, 1)
	registration := newRegistrationServer(configuration.WorkloadIdentityCSIDriver, configuration.KubeletPluginSocketPath, refused)

	resp, err := registration.NotifyRegistrationStatus(context.Background(),
		&pluginregistration.RegistrationStatus{PluginRegistered: true})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp).ToNot(BeNil())
	g.Expect(refused).ToNot(Receive())
}

// The refusal is reported to Driver.Run rather than returned: an error would reach the
// kubelet, which has already decided. A second refusal before the first is handled does
// not block the kubelet's call.
func TestNotifyRegistrationStatus_Refused_IsReportedRatherThanReturnedAsAnError(t *testing.T) {
	g := NewWithT(t)

	refused := make(chan string, 1)
	registration := newRegistrationServer(configuration.WorkloadIdentityCSIDriver, configuration.KubeletPluginSocketPath, refused)

	for range 2 {
		resp, err := registration.NotifyRegistrationStatus(context.Background(),
			&pluginregistration.RegistrationStatus{PluginRegistered: false, Error: "plugin name mismatch"})
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(resp).ToNot(BeNil())
	}
	g.Expect(refused).To(Receive(Equal("plugin name mismatch")))
}
