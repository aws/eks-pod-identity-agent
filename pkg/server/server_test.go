package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"io"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/eksauth"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/validation"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/handlers"
	"go.uber.org/mock/gomock"
)

func TestEksCredentialServer(t *testing.T) {
	const (
		someClusterName = "cluster-a"
	)

	var (
		someValidServiceAccountToken = test.CreateToken(test.TokenConfig{Expiry: time.Now().Add(1 * time.Hour), Iat: time.Now(), Nbf: time.Now()})
		getMockCredentials           = func() *credentials.EksCredentialsResponse {
			expTime, _ := time.Parse(time.RFC3339Nano, "2023-07-13T20:49:35.999999999Z")
			return &credentials.EksCredentialsResponse{
				AccessKeyId:     "access-key-id",
				SecretAccessKey: "secret-access-key",
				Token:           "token",
				AccountId:       "account-id",
				Expiration:      credentials.SdkCompliantExpirationTime{Time: expTime},
			}
		}
		serializedMockCredentials, _ = json.Marshal(getMockCredentials())
	)

	testCases := []struct {
		name           string
		performRequest func(urlPrefix string) (*http.Response, error)
		responseBody   string
		headers        map[string]string
		httpCode       int
		requestAddress string
	}{
		{
			name: "server starts and is able to get queries",
			performRequest: func(urlPrefix string) (*http.Response, error) {
				client := http.Client{}
				request, err := http.NewRequest("GET", urlPrefix+"/v1/credentials", nil)
				if err != nil {
					return nil, err
				}
				request.Header.Add("Authorization", someValidServiceAccountToken)
				return client.Do(request)
			},
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			responseBody: string(serializedMockCredentials),
			httpCode:     200,
		},
		{
			name: "returns 400 on missing jwt token input",
			performRequest: func(urlPrefix string) (*http.Response, error) {
				client := http.Client{}
				request, err := http.NewRequest("GET", urlPrefix+"/v1/credentials", nil)
				if err != nil {
					return nil, err
				}
				return client.Do(request)
			},
			responseBody: "Service account token cannot be empty",
			httpCode:     400,
		},
		{
			name: "returns 403 when using illegal address",
			performRequest: func(urlPrefix string) (*http.Response, error) {
				client := http.Client{}
				request, err := http.NewRequest("GET", urlPrefix+"/v1/credentials", nil)
				if err != nil {
					return nil, err
				}
				request.Header.Add("Authorization", someValidServiceAccountToken)
				return client.Do(request)
			},
			responseBody:   fmt.Sprintf("Access Denied. Called agent through invalid address, please use either [%s] address not", configuration.DefaultIpv4TargetHost),
			httpCode:       403,
			requestAddress: configuration.DefaultIpv4TargetHost,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// setup
			g := NewWithT(t)
			controller := gomock.NewController(t)
			defer controller.Finish()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// select a random number between (1024-math.MaxUint16) to be used as the port.
			// We use a number >= 1024 because lower-ordered port numbers are restricted
			// and the upper bound is enforced by the OS as ports are described by
			// an uint16.
			n, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint16-1024))
			httpPort := int(n.Int64() + 1024)
			httpMux := http.NewServeMux()

			// setup the handler
			eksAuthMockService := eksauth.NewMockIface(controller)
			validator := validation.DefaultCredentialValidator{
				TargetHosts: []string{"localhost"},
			}
			if tc.requestAddress != "" {
				validator.TargetHosts = []string{tc.requestAddress}
			}

			handler := &handlers.EksCredentialHandler{
				CredentialRetriever: eksAuthMockService,
				RequestValidator:    validator,
				ClusterName:         someClusterName,
			}

			// setup EKS Auth Service call Interceptor
			if tc.httpCode == 200 {
				eksAuthMockService.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).Return(getMockCredentials(), nil, nil)
			}

			// create server
			server := &Server{
				configurer: handler,
				server: &http.Server{
					Addr:    ":" + strconv.Itoa(httpPort),
					Handler: httpMux,
				},
				mux: httpMux,
			}
			go func() {
				// keep the server running until the test is finished
				server.ListenUntilContextCancelled(ctx)
			}()
			pollingCtx, cancelPoll := context.WithTimeout(ctx, 5*time.Second)
			defer cancelPoll()

			// trigger
			urlPrefix := "http://localhost:" + strconv.Itoa(httpPort)
			var resp *http.Response
			var err error
			// server sometimes takes a bit to come online, yield if we end up
			// waiting a bit more than usual
			g.Eventually(pollingCtx, func() error {
				resp, err = tc.performRequest(urlPrefix)
				return err
			}).ShouldNot(HaveOccurred())

			// validate
			body, err := io.ReadAll(resp.Body)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(string(body)).To(ContainSubstring(tc.responseBody))

			g.Expect(resp.StatusCode).To(Equal(tc.httpCode))

			// validate headers
			for headerName, expectedValue := range tc.headers {
				content := resp.Header.Get(headerName)
				g.Expect(content).To(Equal(expectedValue))
			}
		})
	}
}
