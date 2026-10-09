package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkimds "github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/eksauth"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/imds"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/credcache"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/credsretriever"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/validation"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	"go.uber.org/mock/gomock"
)

type mockResponseWriter struct {
	g           Gomega
	expectBytes []byte
	http.ResponseWriter
	statusCode int
}

func (m *mockResponseWriter) Write(bytes []byte) (int, error) {
	m.g.Expect(string(bytes)).To(ContainSubstring(string(m.expectBytes)))
	return 0, nil
}
func (m *mockResponseWriter) Header() http.Header {
	// Implement the Header method if needed for your tests
	return http.Header{}
}

func (m *mockResponseWriter) WriteHeader(statusCode int) {
	m.statusCode = statusCode
}

func TestEksCredentialHandler_GetIamCredentialsHandler(t *testing.T) {
	const (
		someValidClusterName = "cluster-a"
	)

	var (
		validTargetHost              = configuration.DefaultIpv4TargetHost
		someFutureTime               = time.Now().Add(1 * time.Hour)
		someValidServiceAccountToken = test.CreateToken(t, test.TokenConfig{Expiry: someFutureTime, Iat: time.Now(), Nbf: time.Now()})
		validEksCredentialResponse   = &credentials.EksCredentialsResponse{
			AccessKeyId:     "access-key-id",
			SecretAccessKey: "secret-access-key",
			Token:           "token",
			AccountId:       "account-id",
			Expiration:      credentials.SdkCompliantExpirationTime{Time: someFutureTime},
		}
		marshalledCreds, _ = json.Marshal(validEksCredentialResponse)
	)

	testCases := []struct {
		name            string
		sentBytes       []byte
		clusterName     string
		token           string
		targetHost      string
		eksAuthResponse *credentials.EksCredentialsResponse
	}{
		{
			name:      "No IP is provided",
			sentBytes: []byte(fmt.Sprintf("Access Denied. Called agent through invalid address")),
		},
		{
			name:       "Invalid calling IP",
			sentBytes:  []byte(fmt.Sprintf("Access Denied. Called agent through invalid address")),
			targetHost: "127.0.0.1:24432",
		},
		{
			name:        "service account token is not passed as header",
			sentBytes:   []byte("Service account token cannot be empty\n"),
			targetHost:  validTargetHost,
			clusterName: someValidClusterName,
		},
		{
			name:            "Fetch credentials successfully",
			sentBytes:       marshalledCreds,
			targetHost:      validTargetHost,
			clusterName:     someValidClusterName,
			token:           someValidServiceAccountToken,
			eksAuthResponse: validEksCredentialResponse,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			controller := gomock.NewController(t)
			defer controller.Finish()

			// setup
			eksAuthService := eksauth.NewMockIface(controller)
			handler := EksCredentialHandler{
				CredentialRetriever: eksAuthService,
				RequestValidator:    validation.DefaultCredentialValidator{},
				ClusterName:         tc.clusterName,
			}
			request := buildRequest(tc.token, tc.targetHost)
			if tc.eksAuthResponse != nil {
				eksAuthService.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
					Return(tc.eksAuthResponse, nil, nil)
			}

			// trigger
			handler.HandleRequest(&mockResponseWriter{g: g, expectBytes: tc.sentBytes}, request)

		})
	}
}

// TestNewEksCredentialHandler_IMDSDisabled_UsesAuthServiceOnly verifies the flag
// gate: with IMDS left at its default (disabled), the handler wires eksauth as the
// sole delegate (no chain).
func TestNewEksCredentialHandler_IMDSDisabled_UsesAuthServiceOnly(t *testing.T) {
	handler := NewEksCredentialHandler(context.Background(), EksCredentialHandlerOpts{
		ClusterName: "test-cluster",
	})
	assert.Equal(t, "eks-auth", handler.CredentialRetriever.String())
}

// TestNewCredentialManager_WithCaching_BuildsTheCache verifies a renewal TTL and
// cache size give the handler the cache's retriever and return the cache.
func TestNewCredentialManager_WithCaching_BuildsTheCache(t *testing.T) {
	manager := NewCredentialManager(context.Background(), EksCredentialHandlerOpts{
		ClusterName:       "test-cluster",
		CredentialRenewal: time.Hour,
		MaxCacheSize:      10,
	})
	assert.NotNil(t, manager.Cache)
	assert.Equal(t, "cached-retriever", manager.Retriever.String())
	assert.Equal(t, "eks-auth", manager.EKSAuth.String())
}

// TestNewCredentialManager_CacheRefreshesThroughTheGeneralDelegate verifies the
// wiring: a miss goes to EKS Auth, and the cache refreshes what it stored through
// the general delegate, the [imds, eksauth] chain when IMDS is on.
func TestNewCredentialManager_CacheRefreshesThroughTheGeneralDelegate(t *testing.T) {
	g := NewWithT(t)
	general := &recordingRetriever{name: "chained-retriever", accessKeyId: "AKIA-REFRESHED"}
	authSvc := &recordingRetriever{name: "eks-auth", accessKeyId: "AKIA-MISS"}
	const renewal = 50 * time.Millisecond
	manager := newCredentialManager(context.Background(), EksCredentialHandlerOpts{
		CredentialRenewal: renewal,
		// One pod, and a size the cache's QPS check passes at this renewal TTL.
		MaxCacheSize: 1,
		RefreshQPS:   5,
	}, credcache.Opts{CleanupInterval: renewal / 5}, general, authSvc, nil)
	request := chainTestRequest(t, "pod-1")

	cred, _, err := manager.Retriever.GetIamCredentials(context.Background(), request)

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(cred.AccessKeyId).To(Equal("AKIA-MISS"))
	g.Eventually(func() string {
		e, ok := manager.Cache.Get("pod-1")
		if !ok {
			return ""
		}
		return e.Credentials.AccessKeyId
	}).WithTimeout(5 * time.Second).WithPolling(renewal / 5).Should(Equal("AKIA-REFRESHED"))
	g.Expect(authSvc.calls()).To(Equal(1), "only the miss goes to EKS Auth")
	g.Expect(manager.EKSAuth).To(BeIdenticalTo(authSvc))
}

// recordingRetriever serves new hour-long credentials with accessKeyId and counts
// its calls. Unlike a gomock mock it's safe to call after the test ends, as the
// cache's sweep may.
type recordingRetriever struct {
	name, accessKeyId string

	mu sync.Mutex
	n  int
}

func (r *recordingRetriever) GetIamCredentials(context.Context, *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.n++
	return &credentials.EksCredentialsResponse{
		AccessKeyId: r.accessKeyId,
		Expiration:  credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
	}, credentials.CredentialMetadata{Association: "a-1", CredSource: credentials.SourceAuthService}, nil
}

func (r *recordingRetriever) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

func (r *recordingRetriever) String() string                     { return r.name }
func (*recordingRetriever) IsIrrecoverable(error) (string, bool) { return "Unknown", false }

// TestEndToEnd_CredentialChain_ReturnsCorrectSource ensures the [imds, eksauth]
// chain returns IMDS credentials when the pod is in IMDS, falls back to eksauth
// when it is not, and uses eksauth alone when IMDS is unavailable.
//
// Each case builds a real imds.NewService over a fake IMDS HTTP backend (or none,
// to simulate IMDS being down), creates a chain of [imds, eksauth], and checks
// which source's credential comes back.
func TestEndToEnd_CredentialChain_ReturnsCorrectSource(t *testing.T) {
	authCred := &credentials.EksCredentialsResponse{
		AccessKeyId: "AKIA-AUTH", SecretAccessKey: "s", Token: "t",
		AccountId: "222222222222", Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(6 * time.Hour)},
	}
	authMeta := credentials.CredentialMetadata{Association: "a-1", CredSource: credentials.SourceAuthService}

	tests := []struct {
		name          string
		imdsPods      map[string]string // nil = no IMDS service
		requestPodUID string
		authCalled    bool
		wantKeyId     string
		wantAccountId string
	}{
		{
			name:          "IMDS up, pod in IMDS — returns IMDS credential",
			imdsPods:      map[string]string{"pod-1": credJSON("AKIA-IMDS", "111111111111")},
			requestPodUID: "pod-1",
			authCalled:    false,
			wantKeyId:     "AKIA-IMDS",
			wantAccountId: "111111111111",
		},
		{
			name:          "IMDS up, pod not in IMDS — falls back to eksauth",
			imdsPods:      map[string]string{"pod-1": credJSON("AKIA-IMDS", "111111111111")},
			requestPodUID: "pod-2",
			authCalled:    true,
			wantKeyId:     "AKIA-AUTH",
			wantAccountId: "222222222222",
		},
		{
			name:          "IMDS down — returns eksauth credential",
			imdsPods:      nil,
			requestPodUID: "pod-1",
			authCalled:    true,
			wantKeyId:     "AKIA-AUTH",
			wantAccountId: "222222222222",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Build the IMDS delegate over a fake IMDS HTTP backend, or leave it
			// nil to simulate IMDS being unavailable on the node.
			var imdsSvc credentials.CredentialRetriever
			if tt.imdsPods != nil {
				imdsSvc = imds.NewService(ctx, aws.Config{}, func(o *sdkimds.Options) {
					o.HTTPClient = &fakeHTTPClient{handler: &fakeIMDSHandler{pods: tt.imdsPods}}
					o.ClientEnableState = sdkimds.ClientEnabled
				})
			}

			// Program eksauth: it should only be called when we expect fallback.
			mockAuth := eksauth.NewMockIface(ctrl)
			mockAuth.EXPECT().String().Return("auth").AnyTimes()
			if tt.authCalled {
				mockAuth.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
					Return(authCred, authMeta, nil)
			}

			// Assemble the delegate exactly as the handler does: chain when IMDS
			// is present, otherwise eksauth alone.
			var delegate credentials.CredentialRetriever = mockAuth
			if imdsSvc != nil {
				delegate = credsretriever.NewChainedRetriever(imdsSvc, mockAuth)
			}
			handler := chainTestHandler(delegate)
			cred, err := handler.GetEksCredentials(ctx, chainTestRequest(t, tt.requestPodUID))

			require.NoError(t, err)
			assert.Equal(t, tt.wantKeyId, cred.AccessKeyId)
			assert.Equal(t, tt.wantAccountId, cred.AccountId)
		})
	}
}

func buildRequest(token string, targetHost string) *http.Request {
	baseURL := fmt.Sprintf("http://%s/api", targetHost)
	parsedUrl, err := url.Parse(baseURL)
	if err != nil {
		fmt.Println("Error parsing URL:", err)
		return nil
	}

	// Create a new HTTP request object
	request, err := http.NewRequest(http.MethodGet, parsedUrl.String(), nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return nil
	}

	if token != "" {
		request.Header.Set("Authorization", token)
	}

	request.RemoteAddr = "localhost"
	return request
}

// chainTestHandler builds a handler around a pre-assembled credential retriever.
func chainTestHandler(chain credentials.CredentialRetriever) *EksCredentialHandler {
	return &EksCredentialHandler{
		ClusterName: "test-cluster", CredentialRetriever: chain,
		RequestValidator: validation.DefaultCredentialValidator{TargetHosts: []string{configuration.DefaultIpv4TargetHost}},
	}
}

// chainTestRequest builds a credentials request whose SA token carries podUID.
func chainTestRequest(t *testing.T, podUID string) *credentials.EksCredentialsRequest {
	t.Helper()
	return &credentials.EksCredentialsRequest{
		ClusterName: "test-cluster", RequestTargetHost: configuration.DefaultIpv4TargetHost,
		ServiceAccountToken: test.CreateToken(t, test.TokenConfig{
			Expiry: time.Now().Add(time.Hour), Iat: time.Now(), Nbf: time.Now(), PodUID: podUID,
		}),
	}
}

// credJSON marshals a pod credential file as IMDS would serve it.
func credJSON(accessKeyId, accountId string) string {
	b, _ := json.Marshal(credentials.EksCredentialsResponse{
		AccessKeyId: accessKeyId, SecretAccessKey: "secret", Token: "token",
		AccountId: accountId, Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(6 * time.Hour)},
	})
	return string(b)
}

// fakeIMDSHandler serves IMDS-like responses with all pods in iam-eks-1.
type fakeIMDSHandler struct{ pods map[string]string }

func (f *fakeIMDSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case strings.HasSuffix(p, "/latest/meta-data/") || strings.HasSuffix(p, "/latest/meta-data"):
		io.WriteString(w, "iam-eks-1\n")
	case strings.HasSuffix(p, "iam-eks-1/info"):
		pods := make(map[string]string)
		for uid := range f.pods {
			pods[uid] = credentials.PodCredentialSuccessCode
		}
		json.NewEncoder(w).Encode(credentials.NamespaceInfo{Code: "Success", LastUpdated: "2025-01-01T00:00:00Z", PodCredentials: pods})
	case strings.HasSuffix(p, "instance-id"):
		io.WriteString(w, "i-1234567890abcdef0")
	default:
		for uid, cj := range f.pods {
			if strings.HasSuffix(p, "security-credentials/"+uid) {
				io.WriteString(w, cj)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}
}

// fakeHTTPClient routes IMDS SDK requests to an in-process http.Handler.
type fakeHTTPClient struct{ handler http.Handler }

func (f *fakeHTTPClient) Do(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec.Result(), nil
}
