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
	"go.amzn.com/eks/eks-pod-identity-agent/internal/credsretriever"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
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

func TestCredentialChain_IMDSPresent_ReturnsIMDSThenFallsBack(t *testing.T) {
	// Verifies the chain ordering using gomock mocks for both delegates.
	// IMDS has the pod → returns IMDS cred. IMDS misses → falls back to eksauth.
	imdsCred := &credentials.EksCredentialsResponse{
		AccessKeyId: "AKIA-IMDS", SecretAccessKey: "s", Token: "t",
		AccountId: "111111111111", Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(6 * time.Hour)},
	}
	authCred := &credentials.EksCredentialsResponse{
		AccessKeyId: "AKIA-AUTH", SecretAccessKey: "s", Token: "t",
		AccountId: "222222222222", Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(6 * time.Hour)},
	}

	req := chainTestRequest(t, "pod-1")

	// IMDS has the pod — should return IMDS cred without calling eksauth.
	ctrl := gomock.NewController(t)
	mockIMDS := imds.NewMockIface(ctrl)
	mockAuth := eksauth.NewMockIface(ctrl)

	mockIMDS.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
		Return(imdsCred, credentials.CredentialMetadata{CredSource: credentials.SourceIMDS}, nil)
	mockIMDS.EXPECT().String().Return("imds").AnyTimes()
	mockAuth.EXPECT().String().Return("auth").AnyTimes()

	handler := chainTestHandler(credsretriever.NewChainedRetriever(mockIMDS, mockAuth))
	cred, err := handler.GetEksCredentials(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "AKIA-IMDS", cred.AccessKeyId)
	assert.Equal(t, "111111111111", cred.AccountId)

	// IMDS doesn't have the pod — should fall through to eksauth.
	ctrl2 := gomock.NewController(t)
	mockIMDS2 := imds.NewMockIface(ctrl2)
	mockAuth2 := eksauth.NewMockIface(ctrl2)

	mockIMDS2.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
		Return(nil, nil, imds.ErrPodNotInMapping)
	mockIMDS2.EXPECT().String().Return("imds").AnyTimes()
	mockIMDS2.EXPECT().IsIrrecoverable(gomock.Any()).Return("PodNotInMapping", true).AnyTimes()
	mockAuth2.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
		Return(authCred, credentials.CredentialMetadata{Association: "a-1", CredSource: credentials.SourceAuthService}, nil)
	mockAuth2.EXPECT().String().Return("auth").AnyTimes()

	handler.CredentialRetriever = credsretriever.NewChainedRetriever(mockIMDS2, mockAuth2)
	cred, err = handler.GetEksCredentials(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "AKIA-AUTH", cred.AccessKeyId)
	assert.Equal(t, "222222222222", cred.AccountId)
}

func TestNewEksCredentialHandler_IMDSDisabled_UsesAuthServiceOnly(t *testing.T) {
	// Verifies that the delegate only contains eksauth when IMDS is disabled
	handler := NewEksCredentialHandler(EksCredentialHandlerOpts{
		ClusterName: "test-cluster",
		EnableIMDS:  false,
	})
	assert.Equal(t, "eks-auth", handler.CredentialRetriever.String())
}

func TestEndToEnd_CredentialChain_ReturnsCorrectSource(t *testing.T) {
	// Uses a real imds.NewService backed by a fake HTTP server to exercise the full
	// IMDS stack (namespace discovery, mapping, credential fetch). Auth Service is a
	// gomock mock. Verifies credentials come from the correct source.
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

			// Build IMDS delegate with fake HTTP backend, or nil if IMDS is down.
			var imdsSvc credentials.CredentialRetriever
			if tt.imdsPods != nil {
				imdsSvc = imds.NewService(ctx, aws.Config{}, func(o *sdkimds.Options) {
					o.HTTPClient = &fakeHTTPClient{handler: &fakeIMDSHandler{pods: tt.imdsPods}}
					o.ClientEnableState = sdkimds.ClientEnabled
				})
			}

			// Build eksauth delegate
			mockAuth := eksauth.NewMockIface(ctrl)
			mockAuth.EXPECT().String().Return("auth").AnyTimes()
			if tt.authCalled {
				mockAuth.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
					Return(authCred, authMeta, nil)
			}

			// Build the delegate the same way the handler does: chain when IMDS
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

func chainTestHandler(chain credentials.CredentialRetriever) *EksCredentialHandler {
	return &EksCredentialHandler{
		ClusterName: "test-cluster", CredentialRetriever: chain,
		RequestValidator: validation.DefaultCredentialValidator{TargetHosts: []string{configuration.DefaultIpv4TargetHost}},
	}
}

func chainTestRequest(t *testing.T, podUID string) *credentials.EksCredentialsRequest {
	t.Helper()
	return &credentials.EksCredentialsRequest{
		ClusterName: "test-cluster", RequestTargetHost: configuration.DefaultIpv4TargetHost,
		ServiceAccountToken: test.CreateToken(t, test.TokenConfig{
			Expiry: time.Now().Add(time.Hour), Iat: time.Now(), Nbf: time.Now(), PodUID: podUID,
		}),
	}
}

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
		pods := make(map[string]credentials.PodCredentialEntry)
		for uid := range f.pods {
			pods[uid] = credentials.PodCredentialEntry{Code: "Success", RoleARN: "arn:aws:iam::123456789012:role/R"}
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

type fakeHTTPClient struct{ handler http.Handler }

func (f *fakeHTTPClient) Do(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec.Result(), nil
}
