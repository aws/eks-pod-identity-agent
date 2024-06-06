package handlers

import (
	"encoding/json"
	"fmt"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"net/http"
	"net/url"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/eksauth"
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
		someValidServiceAccountToken = test.CreateTokenForTest(someFutureTime, time.Now(), time.Now())
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
