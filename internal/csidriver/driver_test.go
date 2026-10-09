package csidriver

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	pluginregistration "k8s.io/kubelet/pkg/apis/pluginregistration/v1"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// testOpts puts the sockets in a short temporary directory, so a test binds real Unix
// sockets without the kubelet's directories.
func testOpts(t *testing.T) Opts {
	t.Helper()
	root, err := os.MkdirTemp("", "csi")
	if err != nil {
		t.Fatalf("creating a temporary directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return Opts{
		NodeName:               "ip-10-0-0-1.ec2.internal",
		SocketDir:              filepath.Join(root, "socket"),
		PluginSocketPath:       filepath.Join(root, "plugins", "csi.sock"),
		RegistrationSocketPath: filepath.Join(root, "registry", "driver-reg.sock"),
		ShutdownWait:           100 * time.Millisecond,
	}
}

// publishRequest is what the kubelet sends for the volume the webhook injects.
func publishRequest(target string) *csi.NodePublishVolumeRequest {
	return &csi.NodePublishVolumeRequest{
		VolumeId:   "csi-volume-1",
		TargetPath: target,
		VolumeCapability: &csi.VolumeCapability{
			AccessType: &csi.VolumeCapability_Mount{Mount: &csi.VolumeCapability_MountVolume{}},
			AccessMode: &csi.VolumeCapability_AccessMode{Mode: csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER},
		},
		VolumeContext: map[string]string{"csi.storage.k8s.io/ephemeral": "true"},
		Readonly:      true,
	}
}

// serve runs the driver until the test ends. The channel delivers Run's result.
func serve(t *testing.T, driver *Driver) <-chan error {
	t.Helper()
	g := NewWithT(t)

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		result <- driver.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		g.Eventually(stopped, 5*time.Second).Should(BeClosed(), "the driver must return once its context is cancelled")
	})
	return result
}

func dial(t *testing.T, socketPath string) *grpc.ClientConn {
	t.Helper()
	g := NewWithT(t)

	conn, err := grpc.NewClient("unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	g.Expect(err).ToNot(HaveOccurred())
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// The kubelet's two conversations end to end, through generated clients over real sockets,
// so the socket wiring and the upstream node service's registration are covered. The bind
// mount itself needs root; see TestNodePublishVolume_AsRoot_BindMountsTheSocketDirectory.
func TestNew_ServesBothSocketsEndToEnd(t *testing.T) {
	g := NewWithT(t)

	opts := testOpts(t)
	driver, err := New(opts)
	g.Expect(err).ToNot(HaveOccurred())
	serve(t, driver)

	// 1. The kubelet finds the registration socket and asks who this is.
	info, err := pluginregistration.NewRegistrationClient(dial(t, opts.RegistrationSocketPath)).
		GetInfo(context.Background(), &pluginregistration.InfoRequest{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(info.GetType()).To(Equal(pluginregistration.CSIPlugin))
	g.Expect(info.GetName()).To(Equal(configuration.WorkloadIdentityCSIDriver))
	g.Expect(info.GetEndpoint()).To(Equal(opts.PluginSocketPath))

	pluginConn := dial(t, info.GetEndpoint())

	// 2. The node service reports the same driver name the registration did.
	pluginInfo, err := csi.NewIdentityClient(pluginConn).GetPluginInfo(context.Background(), &csi.GetPluginInfoRequest{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(pluginInfo.GetName()).To(Equal(info.GetName()))

	// 3. The kubelet records the node ID.
	nodeInfo, err := csi.NewNodeClient(pluginConn).NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(nodeInfo.GetNodeId()).To(Equal(opts.NodeName))

	// No capabilities: GET_VOLUME_STATS, which upstream reports, has the kubelet poll every
	// volume each minute for statistics a socket directory does not have.
	capabilities, err := csi.NewNodeClient(pluginConn).NodeGetCapabilities(context.Background(), &csi.NodeGetCapabilitiesRequest{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(capabilities.GetCapabilities()).To(BeEmpty())

	// 4. A volume not marked read-only is refused, since the kubelet is what makes it
	// read-only inside the pod.
	request := publishRequest(filepath.Join(t.TempDir(), "mount"))
	request.Readonly = false
	_, err = csi.NewNodeClient(pluginConn).NodePublishVolume(context.Background(), request)
	g.Expect(status.Code(err)).To(Equal(codes.InvalidArgument))
	g.Expect(err.Error()).To(ContainSubstring("csi.readOnly"))

	// 5. Unpublishing a volume that was never published succeeds, as the kubelet retries it.
	_, err = csi.NewNodeClient(pluginConn).NodeUnpublishVolume(context.Background(),
		&csi.NodeUnpublishVolumeRequest{VolumeId: "csi-volume-1", TargetPath: filepath.Join(t.TempDir(), "mount")})
	g.Expect(err).ToNot(HaveOccurred())
}

// The bind mount, which needs CAP_SYS_ADMIN: the socket directory appears at the target
// and is gone again after the unpublish.
func TestNodePublishVolume_AsRoot_BindMountsTheSocketDirectory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("bind mounting needs root")
	}
	g := NewWithT(t)

	opts := testOpts(t)
	g.Expect(os.MkdirAll(opts.SocketDir, 0o755)).To(Succeed())
	g.Expect(os.WriteFile(filepath.Join(opts.SocketDir, "agent.sock"), nil, 0o600)).To(Succeed())
	driver, err := New(opts)
	g.Expect(err).ToNot(HaveOccurred())
	serve(t, driver)
	node := csi.NewNodeClient(dial(t, opts.PluginSocketPath))

	target := filepath.Join(t.TempDir(), "mount")
	_, err = node.NodePublishVolume(context.Background(), publishRequest(target))
	g.Expect(err).ToNot(HaveOccurred())
	t.Cleanup(func() {
		_, _ = node.NodeUnpublishVolume(context.Background(),
			&csi.NodeUnpublishVolumeRequest{VolumeId: "csi-volume-1", TargetPath: target})
	})
	g.Expect(isMountPoint(t, target)).To(BeTrue())
	g.Expect(filepath.Join(target, "agent.sock")).To(BeAnExistingFile())

	_, err = node.NodeUnpublishVolume(context.Background(),
		&csi.NodeUnpublishVolumeRequest{VolumeId: "csi-volume-1", TargetPath: target})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(isMountPoint(t, target)).To(BeFalse())
	g.Expect(target).ToNot(BeADirectory())
}

func isMountPoint(t *testing.T, path string) bool {
	t.Helper()
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		t.Fatalf("reading the mount table: %v", err)
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if fields := strings.Fields(scanner.Text()); len(fields) > 4 && fields[4] == path {
			return true
		}
	}
	return false
}

// 0600, unlike the workload identity socket's 0666: only the kubelet dials these, and the
// calls behind the plugin socket mount.
func TestNew_BindsBothSockets0600(t *testing.T) {
	g := NewWithT(t)

	opts := testOpts(t)
	driver, err := New(opts)
	g.Expect(err).ToNot(HaveOccurred())
	t.Cleanup(driver.RemoveSockets)

	for _, socketPath := range []string{opts.PluginSocketPath, opts.RegistrationSocketPath} {
		info, err := os.Stat(socketPath)
		g.Expect(err).ToNot(HaveOccurred(), "New must bind %s before it returns", socketPath)
		g.Expect(info.Mode().Perm()).To(Equal(socketMode),
			"%s is reachable by anything with the bits to dial it", socketPath)
	}
}

// Refused where the process can still exit non-zero, rather than registering without a
// node ID.
func TestNew_NoNodeName_Fails(t *testing.T) {
	g := NewWithT(t)

	opts := testOpts(t)
	opts.NodeName = ""

	_, err := New(opts)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("node name"))
}

// The half-built case: a registration socket with no plugin behind it advertises a plugin
// that is not running, and the kubelet would try to register from it.
func TestNew_UnbindablePluginSocket_LeavesNoRegistrationSocketBehind(t *testing.T) {
	g := NewWithT(t)

	opts := testOpts(t)
	// A directory where the socket should go: the bind cannot replace it, and
	// UnlinkIfStale refuses to remove something that is not a socket.
	g.Expect(os.MkdirAll(opts.PluginSocketPath, 0o755)).To(Succeed())

	_, err := New(opts)
	g.Expect(err).To(HaveOccurred())

	_, err = os.Stat(opts.RegistrationSocketPath)
	g.Expect(os.IsNotExist(err)).To(BeTrue(),
		"a failed New must not leave a registration socket the kubelet can find")
}

// What the next boot inherits. The registration socket matters most: the kubelet watches
// that directory.
func TestRemoveSockets_AfterShutdown_UnlinksBoth(t *testing.T) {
	g := NewWithT(t)

	opts := testOpts(t)
	driver, err := New(opts)
	g.Expect(err).ToNot(HaveOccurred())

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		g.Expect(driver.Run(ctx)).To(Succeed(), "a cancelled context is an ordinary shutdown")
	}()

	// Reached through the socket rather than by waiting, so the shutdown below happens
	// to a driver that was actually serving.
	_, err = pluginregistration.NewRegistrationClient(dial(t, opts.RegistrationSocketPath)).
		GetInfo(context.Background(), &pluginregistration.InfoRequest{})
	g.Expect(err).ToNot(HaveOccurred())

	cancel()
	g.Eventually(stopped, 5*time.Second).Should(BeClosed())

	for _, socketPath := range []string{opts.PluginSocketPath, opts.RegistrationSocketPath} {
		_, err := os.Stat(socketPath)
		g.Expect(os.IsNotExist(err)).To(BeTrue(), "%s outlived the driver", socketPath)
	}
}

// It is both deferred in the serve loop and registered as a logrus exit handler.
func TestRemoveSockets_CalledTwice_IsSafe(t *testing.T) {
	g := NewWithT(t)

	opts := testOpts(t)
	driver, err := New(opts)
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(driver.RemoveSockets).ToNot(Panic())
	g.Expect(driver.RemoveSockets).ToNot(Panic())
}

// The production paths come from package configuration. Not bound here: the kubelet's
// directories do not exist on a test host.
func TestNew_DefaultOpts_UseTheConfigurationConstants(t *testing.T) {
	g := NewWithT(t)

	g.Expect(valueOrDefault("", configuration.KubeletPluginSocketPath)).To(Equal("/var/lib/kubelet/plugins/spiffe.csi.eks.amazonaws.com/csi.sock"))
	g.Expect(valueOrDefault("", configuration.KubeletRegistrationSocketPath)).To(Equal("/var/lib/kubelet/plugins_registry/spiffe.csi.eks.amazonaws.com-reg.sock"))
	g.Expect(valueOrDefault("", configuration.WorkloadIdentitySocketMountPath)).
		To(Equal("/var/run/secrets/pods.eks.amazonaws.com/workloadidentity"),
			"the published directory is the one the agent's socket lives in")
	g.Expect(valueOrDefault("set", configuration.KubeletPluginSocketPath)).To(Equal("set"))
}

// The directory handed to the upstream node service is what every pod gets published.
func TestNodeConfig_PublishesTheAgentsSocketDirectory(t *testing.T) {
	g := NewWithT(t)

	g.Expect(nodeConfig(Opts{NodeName: "n"}).WorkloadAPISocketDir).To(Equal(configuration.WorkloadIdentitySocketMountPath))
	g.Expect(nodeConfig(Opts{NodeName: "n", SocketDir: "/tmp/socket"}).WorkloadAPISocketDir).To(Equal("/tmp/socket"))
	g.Expect(nodeConfig(Opts{NodeName: "n"}).PluginName).To(Equal(configuration.WorkloadIdentityCSIDriver))
	g.Expect(nodeConfig(Opts{NodeName: "n"}).NodeID).To(Equal("n"))
}

// As node-driver-registrar does: a refusal ends the driver with the kubelet's reason, so
// the process exits and its container restarts and registers again, and it ends in an
// orderly way that removes the sockets.
func TestRun_RefusedRegistration_ReturnsTheReasonAndRemovesTheSockets(t *testing.T) {
	g := NewWithT(t)

	opts := testOpts(t)
	driver, err := New(opts)
	g.Expect(err).ToNot(HaveOccurred())
	result := serve(t, driver)

	_, err = pluginregistration.NewRegistrationClient(dial(t, opts.RegistrationSocketPath)).
		NotifyRegistrationStatus(context.Background(),
			&pluginregistration.RegistrationStatus{PluginRegistered: false, Error: "plugin name mismatch"})
	g.Expect(err).ToNot(HaveOccurred(), "the kubelet has already decided, so it gets no error back")

	var runErr error
	g.Eventually(result, 5*time.Second).Should(Receive(&runErr))
	g.Expect(runErr).To(MatchError(ContainSubstring("plugin name mismatch")))
	for _, socketPath := range []string{opts.PluginSocketPath, opts.RegistrationSocketPath} {
		_, err := os.Stat(socketPath)
		g.Expect(os.IsNotExist(err)).To(BeTrue(), "%s outlived the driver", socketPath)
	}
}
