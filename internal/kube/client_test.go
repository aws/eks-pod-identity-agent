package kube

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/rest"
)

// testAWSConfig signs with fixed credentials, so a token can be inspected without
// reaching IMDS or any other credential source.
var testAWSConfig = aws.Config{
	Region: "us-west-2",
	Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "secret", SessionToken: "session"}, nil
	}),
}

// recordingAWSConfig signs like testAWSConfig and records the x-k8s-aws-id each
// presign carries, which the URL can't show: the header is signed but not sent.
func recordingAWSConfig() (aws.Config, func() []string) {
	var mu sync.Mutex
	var clusters []string
	cfg := testAWSConfig.Copy()
	cfg.APIOptions = append(cfg.APIOptions, func(stack *middleware.Stack) error {
		return stack.Finalize.Add(middleware.FinalizeMiddlewareFunc("recordClusterHeader",
			func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (
				middleware.FinalizeOutput, middleware.Metadata, error) {
				if request, ok := in.Request.(*smithyhttp.Request); ok {
					mu.Lock()
					clusters = append(clusters, request.Header.Get("x-k8s-aws-id"))
					mu.Unlock()
				}
				return next.HandleFinalize(ctx, in)
			}), middleware.Before)
	})
	return cfg, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), clusters...)
	}
}

// presignedURL decodes a token back to the URL the EKS authenticator replays. The
// prefix and encoding are literals: the authenticator's, not this package's.
func presignedURL(t *testing.T, token string) *url.URL {
	t.Helper()
	encoded, ok := strings.CutPrefix(token, "k8s-aws-v1.")
	if !ok {
		t.Fatalf("token %q lacks the k8s-aws-v1. prefix", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("token is not base64url without padding: %v", err)
	}
	parsed, err := url.Parse(string(raw))
	if err != nil {
		t.Fatalf("token does not hold a URL: %v", err)
	}
	return parsed
}

// TestIAMTokenSource_SignsWhatTheEKSAuthenticatorReplays pins the token to the shape
// `aws eks get-token` emits. The cluster header has to be signed but left out of the
// URL: the authenticator adds it back when it replays the URL against STS. A second
// region gives a URL whose length catches padded or non-URL base64.
func TestIAMTokenSource_SignsWhatTheEKSAuthenticatorReplays(t *testing.T) {
	for _, region := range []string{"us-west-2", "ap-southeast-1"} {
		t.Run(region, func(t *testing.T) {
			g := NewWithT(t)
			cfg, signedFor := recordingAWSConfig()
			cfg.Region = region
			source, err := newIAMTokenSource(cfg, "my-cluster")
			g.Expect(err).ToNot(HaveOccurred())
			before := time.Now()

			token, err := source.Token()

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(token.Expiry).To(BeTemporally(">=", before.Add(14*time.Minute)))
			g.Expect(token.Expiry).To(BeTemporally("<=", time.Now().Add(14*time.Minute)))
			g.Expect(signedFor()).To(Equal([]string{"my-cluster"}))
			u := presignedURL(t, token.AccessToken)
			g.Expect(u.Scheme).To(Equal("https"))
			g.Expect(u.Host).To(Equal("sts." + region + ".amazonaws.com"))
			query := u.Query()
			g.Expect(query.Get("Action")).To(Equal("GetCallerIdentity"))
			g.Expect(query.Get("Version")).To(Equal("2011-06-15"))
			g.Expect(query["X-Amz-Expires"]).To(Equal([]string{"60"}))
			g.Expect(query.Get("X-Amz-Credential")).To(HavePrefix("AKIDEXAMPLE/"))
			g.Expect(query.Get("X-Amz-Credential")).To(HaveSuffix("/" + region + "/sts/aws4_request"))
			g.Expect(query.Get("X-Amz-Security-Token")).To(Equal("session"))
			g.Expect(query.Get("X-Amz-SignedHeaders")).To(Equal("host;x-k8s-aws-id"))
			g.Expect(query.Has("x-k8s-aws-id")).To(BeFalse(), "the cluster travels as a signed header, not in the URL")
			g.Expect(query.Get("X-Amz-Signature")).ToNot(BeEmpty())
		})
	}
}

// TestIAMTokenSource_WithoutCredentials_Fails keeps a credential failure an error
// rather than an unsigned token the API server would answer 401 to.
func TestIAMTokenSource_WithoutCredentials_Fails(t *testing.T) {
	cfg := testAWSConfig
	cfg.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{}, fmt.Errorf("no IMDS")
	})
	source, err := newIAMTokenSource(cfg, "my-cluster")
	NewWithT(t).Expect(err).ToNot(HaveOccurred())

	_, err = source.Token()

	NewWithT(t).Expect(err).To(MatchError(ContainSubstring("no IMDS")))
}

func TestClusterFromExecArgs(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"nodeadm", []string{"eks", "get-token", "--cluster-name", "my-cluster", "--region", "us-west-2"}, "my-cluster"},
		{"bottlerocket", []string{"token", "-i", "my-cluster", "--region", "us-west-2"}, "my-cluster"},
		{"cluster id", []string{"token", "--cluster-id", "1234-abcd"}, "1234-abcd"},
		{"equals form", []string{"eks", "get-token", "--cluster-name=my-cluster"}, "my-cluster"},
		{"none", []string{"eks", "get-token", "--region", "us-west-2"}, ""},
		{"flag without a value", []string{"token", "-i"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			NewWithT(t).Expect(clusterFromExecArgs(tc.args)).To(Equal(tc.want))
		})
	}
}

// fakeAPIServer answers SelfSubjectReview as system:node:<node> and records the
// Authorization header of every request.
type fakeAPIServer struct {
	*httptest.Server
	mu            sync.Mutex
	authorization []string
}

func newFakeAPIServer(t *testing.T) *fakeAPIServer {
	t.Helper()
	s := &fakeAPIServer{}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.authorization = append(s.authorization, r.Header.Get("Authorization"))
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview",`+
			`"status":{"userInfo":{"username":"system:node:%s"}}}`, testNode)
	}))
	t.Cleanup(s.Close)
	return s
}

// caPEM is the server's certificate, which is its own CA.
func (s *fakeAPIServer) caPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
}

func (s *fakeAPIServer) lastAuthorization() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.authorization) == 0 {
		return ""
	}
	return s.authorization[len(s.authorization)-1]
}

// TestNewNodeClient_InCluster_AuthenticatesWithTheIAMTokenNotTheServiceAccount is the
// property the in-cluster path exists for. rest.InClusterConfig carries the agent's
// ServiceAccount token, which the API server would map to the agent rather than the
// node, and the Node authorizer would then refuse every pod read and TokenRequest.
func TestNewNodeClient_InCluster_AuthenticatesWithTheIAMTokenNotTheServiceAccount(t *testing.T) {
	g := NewWithT(t)
	server := newFakeAPIServer(t)
	original := inClusterConfig
	inClusterConfig = func() (*rest.Config, error) {
		return &rest.Config{
			Host:            server.URL,
			BearerToken:     "service-account-token",
			BearerTokenFile: filepath.Join(t.TempDir(), "token"),
			TLSClientConfig: rest.TLSClientConfig{CAData: server.caPEM()},
		}, nil
	}
	t.Cleanup(func() { inClusterConfig = original })
	cfg, signedFor := recordingAWSConfig()

	client, err := NewNodeClient(NodeClientOpts{Cfg: cfg, ClusterName: "my-cluster"})
	g.Expect(err).ToNot(HaveOccurred())
	nodeName, err := ResolveNodeName(t.Context(), client)
	g.Expect(err).ToNot(HaveOccurred())
	_, err = ResolveNodeName(t.Context(), client)

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(nodeName).To(Equal(testNode))
	g.Expect(server.lastAuthorization()).To(HavePrefix("Bearer k8s-aws-v1."))
	g.Expect(server.lastAuthorization()).ToNot(ContainSubstring("service-account-token"))
	g.Expect(signedFor()).To(Equal([]string{"my-cluster"}), "one token, cached across requests, for --cluster-name")
}

func TestNewNodeClient_InClusterUnavailable_Fails(t *testing.T) {
	original := inClusterConfig
	inClusterConfig = func() (*rest.Config, error) { return nil, rest.ErrNotInCluster }
	t.Cleanup(func() { inClusterConfig = original })

	_, err := NewNodeClient(NodeClientOpts{Cfg: testAWSConfig, ClusterName: "my-cluster"})

	NewWithT(t).Expect(err).To(MatchError(rest.ErrNotInCluster))
}

// writeKubeconfig writes a kubeconfig for server with the given user stanza.
func writeKubeconfig(t *testing.T, server *fakeAPIServer, user string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	contents := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: kubernetes
  cluster:
    certificate-authority-data: %s
    server: %s
contexts:
- name: kubelet
  context:
    cluster: kubernetes
    user: kubelet
current-context: kubelet
users:
- name: kubelet
  user:
%s
`, base64.StdEncoding.EncodeToString(server.caPEM()), server.URL, user)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("writing kubeconfig: %v", err)
	}
	return path
}

// TestNewNodeClient_KubeconfigExecUser_IsReplacedByTheIAMToken covers EKS kubelet
// kubeconfigs, which exec a binary the agent image doesn't ship. The exec command
// here would leave a marker file if anything ran it. The cluster the exec user
// names wins over --cluster-name, since on Outposts it is the cluster ID.
func TestNewNodeClient_KubeconfigExecUser_IsReplacedByTheIAMToken(t *testing.T) {
	for _, tc := range []struct {
		name, args, want string
	}{
		{"names a cluster", `"--cluster-name", "my-cluster"`, "my-cluster"},
		{"names none", `"--region", "us-west-2"`, "fallback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			server := newFakeAPIServer(t)
			marker := filepath.Join(t.TempDir(), "exec-ran")
			path := writeKubeconfig(t, server, fmt.Sprintf(`    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: /bin/sh
      args: ["-c", "touch %s", %s]`, marker, tc.args))
			cfg, signedFor := recordingAWSConfig()

			client, err := NewNodeClient(NodeClientOpts{KubeconfigPath: path, Cfg: cfg, ClusterName: "fallback"})
			g.Expect(err).ToNot(HaveOccurred())
			_, err = ResolveNodeName(t.Context(), client)

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(server.lastAuthorization()).To(HavePrefix("Bearer k8s-aws-v1."))
			g.Expect(signedFor()).To(Equal([]string{tc.want}))
			g.Expect(marker).ToNot(BeAnExistingFile(), "the exec plugin must never run")
		})
	}
}

// selfSignedClientCert returns a PEM certificate and key for a node client.
func selfSignedClientCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "system:node:" + testNode},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// TestNewNodeClient_KubeconfigOtherUser_IsUsedAsIs covers kubeconfigs that already
// carry a credential, such as kind's client certificate. AWS signing fails here, so
// an IAM token added on top would fail every request rather than go unnoticed.
func TestNewNodeClient_KubeconfigOtherUser_IsUsedAsIs(t *testing.T) {
	certPEM, keyPEM := selfSignedClientCert(t)
	for _, tc := range []struct {
		name, user, wantAuthorization string
	}{
		{"client certificate", fmt.Sprintf("    client-certificate-data: %s\n    client-key-data: %s",
			base64.StdEncoding.EncodeToString(certPEM), base64.StdEncoding.EncodeToString(keyPEM)), ""},
		{"token", "    token: static-node-token", "Bearer static-node-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			server := newFakeAPIServer(t)
			path := writeKubeconfig(t, server, tc.user)
			cfg := testAWSConfig.Copy()
			cfg.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
				return aws.Credentials{}, fmt.Errorf("no AWS credentials on this node")
			})

			client, err := NewNodeClient(NodeClientOpts{KubeconfigPath: path, Cfg: cfg, ClusterName: "my-cluster"})
			g.Expect(err).ToNot(HaveOccurred())
			_, err = ResolveNodeName(t.Context(), client)

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(server.lastAuthorization()).To(Equal(tc.wantAuthorization))
		})
	}
}

func TestNewNodeClient_MissingKubeconfig_Fails(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "kubeconfig")

	_, err := NewNodeClient(NodeClientOpts{KubeconfigPath: missing, Cfg: testAWSConfig})

	NewWithT(t).Expect(err).To(MatchError(ContainSubstring(missing)))
}
