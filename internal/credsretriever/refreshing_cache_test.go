package credsretriever

import (
	"context"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/eksauth/types"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cache/expiring"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/eksauth"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials/mockcreds"
	"go.uber.org/mock/gomock"
)

type spyTokenValidator struct {
	refreshKeysCalled   bool
	validateTokenCalled bool
	refreshKeysErr      error
	validateTokenErr    error
}

func (s *spyTokenValidator) RefreshKeys(_ context.Context, _ string) error {
	s.refreshKeysCalled = true
	return s.refreshKeysErr
}

func (s *spyTokenValidator) ValidateToken(_ context.Context, _ *credentials.EksCredentialsRequest) error {
	s.validateTokenCalled = true
	return s.validateTokenErr
}

type responseMetadataTest string

func (receiver responseMetadataTest) AssociationId() string {
	return string(receiver)
}

func (receiver responseMetadataTest) Source() credentials.CredentialSource {
	return credentials.SourceAuthService
}

func TestCachedCredentialRetriever_GetIamCredentials_Fetching(t *testing.T) {
	sampleResponse := credentials.EksCredentialsResponse{
		Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
	}
	longLivedCreds := credentials.EksCredentialsResponse{
		Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(6 * time.Hour)},
	}
	const ttlToRefreshDuration = 3 * time.Hour
	tests := []struct {
		name                  string
		request               *credentials.EksCredentialsRequest
		expectedErrMsg        string
		expectedDelegateCalls func(retriever *mockcreds.MockCredentialRetriever)
		expectedCredentials   credentials.EksCredentialsResponse
		expectedTtlLessThan   time.Duration
	}{
		{
			name: "it can call the delegate to fetch credentials",
			request: &credentials.EksCredentialsRequest{
				ServiceAccountToken: test.CreateToken(t, test.TokenConfig{
					Expiry: time.Now().Add(time.Hour),
					Iat:    time.Now(),
					Nbf:    time.Now(),
					PodUID: "some.jwt.token",
				}),
			},
			expectedDelegateCalls: func(delegate *mockcreds.MockCredentialRetriever) {
				delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
					Return(&sampleResponse, responseMetadataTest("test"), nil)
			},
			expectedCredentials: sampleResponse,
			expectedTtlLessThan: time.Hour,
		},
		{
			name:           "it can handle a request with no token",
			request:        &credentials.EksCredentialsRequest{},
			expectedErrMsg: "service account is empty",
		},
		{
			name:           "it can handle no request at all",
			request:        nil,
			expectedErrMsg: "request to fetch credentials is empty",
		},
		{
			name: "error out if ttl is too small",
			request: &credentials.EksCredentialsRequest{
				ServiceAccountToken: test.CreateToken(t, test.TokenConfig{
					Expiry: time.Now().Add(time.Hour),
					Iat:    time.Now(),
					Nbf:    time.Now(),
					PodUID: "some.jwt.token",
				}),
			},
			expectedDelegateCalls: func(delegate *mockcreds.MockCredentialRetriever) {
				delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
					Return(&credentials.EksCredentialsResponse{
						Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().
							Add(defaultMinCredentialTtl - time.Second)},
					}, responseMetadataTest("test"), nil)
			},
			expectedErrMsg: "fetched credentials are expired or will expire within the next",
		},
		{
			name: "uses ttl provided for cred expiration when credentials have long expiry",
			request: &credentials.EksCredentialsRequest{
				ServiceAccountToken: test.CreateToken(t, test.TokenConfig{
					Expiry: time.Now().Add(time.Hour),
					Iat:    time.Now(),
					Nbf:    time.Now(),
					PodUID: "some.jwt.token",
				}),
			},
			expectedDelegateCalls: func(delegate *mockcreds.MockCredentialRetriever) {
				delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
					Return(&longLivedCreds, responseMetadataTest("test"), nil)
			},
			expectedCredentials: longLivedCreds,
		},
		{
			name: "bubbles up errors from delegate",
			request: &credentials.EksCredentialsRequest{
				ServiceAccountToken: test.CreateToken(t, test.TokenConfig{
					Expiry: time.Now().Add(time.Hour),
					Iat:    time.Now(),
					Nbf:    time.Now(),
					PodUID: "some.jwt.token",
				}),
			},
			expectedDelegateCalls: func(delegate *mockcreds.MockCredentialRetriever) {
				delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
					Return(nil, nil, fmt.Errorf("my special error"))
			},
			expectedErrMsg: "my special error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			g := NewWithT(t)

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctx := context.Background()

			// setup
			delegate := mockcreds.NewMockCredentialRetriever(ctrl)
			if test.expectedDelegateCalls != nil {
				test.expectedDelegateCalls(delegate)
			}
			opts := CachedCredentialRetrieverOpts{
				Delegate:              delegate,
				CredentialsRenewalTtl: ttlToRefreshDuration,
				MaxCacheSize:          5,
				CleanupInterval:       0, // Disable janitor in tests
				RefreshQPS:            1,
			}
			retriever := newCachedCredentialRetriever(opts)

			// trigger
			iamCredentials, _, err := retriever.GetIamCredentials(ctx, test.request)

			// validate
			if test.expectedErrMsg != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(test.expectedErrMsg))
				g.Expect(iamCredentials).To(BeNil())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(*iamCredentials).To(Equal(test.expectedCredentials))

				// Get pod UID from service account token to check cache
				podUID, err := credentials.GetPodUIDFromToken(test.request.ServiceAccountToken)
				g.Expect(err).ToNot(HaveOccurred())

				_, renew, expiration, found := retriever.internalCache.GetWithRenewExpiry(podUID)
				g.Expect(found).To(BeTrue())
				if test.expectedTtlLessThan != 0 {
					g.Expect(renew.Sub(time.Now())).To(BeNumerically("<=", test.expectedTtlLessThan))
				}
				g.Expect(renew.Sub(time.Now())).To(BeNumerically("<=", ttlToRefreshDuration))
				fmt.Printf("%v, %v \n", expiration, test.expectedCredentials.Expiration.Time)
				expirationDiff := math.Abs(
					float64(expiration.Sub(time.Now()) - test.expectedCredentials.Expiration.Time.Sub(time.Now())))
				g.Expect(expirationDiff).To(BeNumerically("<", time.Second))

			}
		})
	}
}

func TestCachedCredentialRetriever_GetIamCredentials_Caching(t *testing.T) {
	var (
		sampleRequestOne = credentials.EksCredentialsRequest{
			ServiceAccountToken: test.CreateToken(t, test.TokenConfig{
				Expiry: time.Now().Add(time.Hour),
				Iat:    time.Now(),
				Nbf:    time.Now(),
				PodUID: "some.jwt.token.one",
			}),
		}
		sampleResponseOne = credentials.EksCredentialsResponse{
			AccountId:  "accountOne",
			Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
		}

		sampleRequestTwo = credentials.EksCredentialsRequest{
			ServiceAccountToken: test.CreateToken(t, test.TokenConfig{
				Expiry: time.Now().Add(time.Hour),
				Iat:    time.Now(),
				Nbf:    time.Now(),
				PodUID: "some.jwt.token.two",
			}),
		}
		sampleResponseTwo = credentials.EksCredentialsResponse{
			AccountId:  "accountTwo",
			Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
		}
	)

	tests := []struct {
		name                        string
		requests                    []credentials.EksCredentialsRequest
		expectedCredentialsResponse []credentials.EksCredentialsResponse
		expectedErrMsg              string
		expectedDelegateCalls       func(retriever *mockcreds.MockCredentialRetriever)
	}{
		{
			name: "two equal requests, single call",
			requests: []credentials.EksCredentialsRequest{
				sampleRequestOne, sampleRequestOne,
			},
			expectedDelegateCalls: func(delegate *mockcreds.MockCredentialRetriever) {
				delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
					Return(&sampleResponseOne, responseMetadataTest("one"), nil).Times(1)
			},
			expectedCredentialsResponse: []credentials.EksCredentialsResponse{
				sampleResponseOne, sampleResponseOne,
			},
		},
		{
			name: "two different jwts, two calls to server delegate",
			requests: []credentials.EksCredentialsRequest{
				sampleRequestOne, sampleRequestTwo, sampleRequestOne,
			},
			expectedDelegateCalls: func(delegate *mockcreds.MockCredentialRetriever) {
				delegate.EXPECT().GetIamCredentials(gomock.Any(), &sampleRequestOne).
					Return(&sampleResponseOne, responseMetadataTest("one"), nil).Times(1)
				delegate.EXPECT().GetIamCredentials(gomock.Any(), &sampleRequestTwo).
					Return(&sampleResponseTwo, responseMetadataTest("two"), nil).Times(1)
			},
			expectedCredentialsResponse: []credentials.EksCredentialsResponse{
				sampleResponseOne, sampleResponseTwo, sampleResponseOne,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			g := NewWithT(t)
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctx := context.Background()

			// setup
			delegate := mockcreds.NewMockCredentialRetriever(ctrl)
			if test.expectedDelegateCalls != nil {
				test.expectedDelegateCalls(delegate)
			}

			opts := CachedCredentialRetrieverOpts{
				Delegate:              delegate,
				CredentialsRenewalTtl: 1 * time.Minute,
				MaxCacheSize:          5,
				CleanupInterval:       0, // Disable janitor in tests
				RefreshQPS:            1,
			}

			retriever := newCachedCredentialRetriever(opts)
			for i := range test.requests {
				req := test.requests[i]

				// trigger
				iamCredentials, _, err := retriever.GetIamCredentials(ctx, &req)

				// validate
				if test.expectedErrMsg != "" {
					g.Expect(err).To(HaveOccurred())
					g.Expect(err.Error()).To(ContainSubstring(test.expectedErrMsg))
					g.Expect(iamCredentials).To(BeNil())
					return
				} else {
					expectedResponse := test.expectedCredentialsResponse[i]
					g.Expect(err).ToNot(HaveOccurred())
					g.Expect(*iamCredentials).To(Equal(expectedResponse))
				}
			}
		})
	}
}

func TestCachedCredentialRetriever_GetIamCredentials_Refresh(t *testing.T) {
	now := time.Now()
	longDurationCreds := credentials.EksCredentialsResponse{
		Expiration: credentials.SdkCompliantExpirationTime{Time: now.Add(time.Hour)},
	}
	shortDurationCreds := credentials.EksCredentialsResponse{
		Expiration: credentials.SdkCompliantExpirationTime{Time: now.Add(50 * time.Millisecond)},
	}
	const ttlToRefreshDuration = 50 * time.Millisecond
	tests := []struct {
		name                  string
		request               *credentials.EksCredentialsRequest
		expectedErrMsg        string
		expectedDelegateCalls func(retriever *mockcreds.MockCredentialRetriever)
		expectedCredentials   credentials.EksCredentialsResponse
		timerBuilder          func(counter *int) internalClock
	}{
		{
			name: "it calls for a refresh when the credentials get too old",
			request: &credentials.EksCredentialsRequest{
				ServiceAccountToken: test.CreateToken(t, test.TokenConfig{
					Expiry: time.Now().Add(time.Hour),
					Iat:    time.Now(),
					Nbf:    time.Now(),
					PodUID: "some.jwt.token",
				}),
			},
			expectedDelegateCalls: func(delegate *mockcreds.MockCredentialRetriever) {
				delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
					Return(&longDurationCreds, responseMetadataTest("test"), nil).MinTimes(2)
			},
			expectedCredentials: longDurationCreds,
		},
		{
			name: "it keeps existing credentials if delegate fails to refresh",
			request: &credentials.EksCredentialsRequest{
				ServiceAccountToken: test.CreateToken(t, test.TokenConfig{
					Expiry: time.Now().Add(time.Hour),
					Iat:    time.Now(),
					Nbf:    time.Now(),
					PodUID: "some.jwt.token",
				}),
			},
			expectedDelegateCalls: func(delegate *mockcreds.MockCredentialRetriever) {
				gomock.InOrder(
					delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
						Return(&longDurationCreds, responseMetadataTest("test"), nil).Times(1),
					delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
						Return(nil, responseMetadataTest("test"), fmt.Errorf("error directed at cache")).MinTimes(2),
				)
				delegate.EXPECT().IsIrrecoverable(gomock.Any()).Return("Unknown", false).AnyTimes()
			},
			expectedCredentials: longDurationCreds,
		},
		{
			name: "it evicts credentials if its an known customer API error -- AccessDenied",
			request: &credentials.EksCredentialsRequest{
				ServiceAccountToken: test.CreateToken(t, test.TokenConfig{
					Expiry: time.Now().Add(time.Hour),
					Iat:    time.Now(),
					Nbf:    time.Now(),
					PodUID: "some.jwt.token",
				}),
			},
			expectedDelegateCalls: func(delegate *mockcreds.MockCredentialRetriever) {
				gomock.InOrder(
					delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
						Return(&longDurationCreds, responseMetadataTest("test"), nil).Times(1),
					delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
						Return(nil, nil, &types.AccessDeniedException{}).
						Times(1),
					delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
						Return(nil, nil, fmt.Errorf("error directed at second call")).Times(1),
				)
				delegate.EXPECT().IsIrrecoverable(gomock.Any()).DoAndReturn(func(err error) (string, bool) {
					var ade *types.AccessDeniedException
					if errors.As(err, &ade) {
						return "AccessDeniedException", true
					}
					return "Unknown", false
				}).AnyTimes()
			},
			expectedErrMsg: "error directed at second call",
		},
		{
			name: "it does not evict credentials if its an unknown API error",
			request: &credentials.EksCredentialsRequest{
				ServiceAccountToken: test.CreateToken(t, test.TokenConfig{
					Expiry: time.Now().Add(time.Hour),
					Iat:    time.Now(),
					Nbf:    time.Now(),
					PodUID: "some.jwt.token",
				}),
			},
			expectedDelegateCalls: func(delegate *mockcreds.MockCredentialRetriever) {
				gomock.InOrder(
					delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
						Return(&longDurationCreds, responseMetadataTest("test"), nil).Times(1),
					delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
						Return(nil, nil, &types.InternalServerException{}).
						MinTimes(2),
				)
				delegate.EXPECT().IsIrrecoverable(gomock.Any()).Return("Unknown", false).AnyTimes()
			},
			expectedCredentials: longDurationCreds,
		},
		{
			name: "it keeps existing credentials if delegate fails",
			request: &credentials.EksCredentialsRequest{
				ServiceAccountToken: test.CreateToken(t, test.TokenConfig{
					Expiry: time.Now().Add(time.Hour),
					Iat:    time.Now(),
					Nbf:    time.Now(),
					PodUID: "some.jwt.token",
				}),
			},
			expectedDelegateCalls: func(delegate *mockcreds.MockCredentialRetriever) {
				gomock.InOrder(
					delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
						Return(&shortDurationCreds, responseMetadataTest("test"), nil).Times(1),
					delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
						Return(nil, nil, fmt.Errorf("error directed at cache")).Times(1),
					delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
						Return(nil, nil, fmt.Errorf("error directed at second call")).Times(1),
				)
				delegate.EXPECT().IsIrrecoverable(gomock.Any()).Return("Unknown", false).AnyTimes()
			},
			expectedErrMsg: "error directed at second call",
			timerBuilder: func(counter *int) internalClock {
				return func() time.Time {
					*counter += 1
					switch *counter {
					// first check on getting creds (make sure they are valid)
					case 1:
						return now
					// second call when the entry expires for creds, mark them as expired
					case 2:
						return now.Add(100 * time.Millisecond)
					default:
						panic("should not reach here")
					}
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			g := NewWithT(t)

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctx := context.Background()

			// setup
			delegate := mockcreds.NewMockCredentialRetriever(ctrl)
			if test.expectedDelegateCalls != nil {
				test.expectedDelegateCalls(delegate)
			}

			opts := CachedCredentialRetrieverOpts{
				Delegate:              delegate,
				CredentialsRenewalTtl: ttlToRefreshDuration,
				MaxCacheSize:          5,
				CleanupInterval:       ttlToRefreshDuration / 10,
				RefreshQPS:            5,
			}
			retriever := newCachedCredentialRetriever(opts)
			retriever.retryInterval = ttlToRefreshDuration
			retriever.minCredentialTtl = ttlToRefreshDuration / 10
			retriever.maxRetryJitter = 1
			if test.timerBuilder != nil {
				counter := 0
				retriever.now = test.timerBuilder(&counter)
			}

			// trigger
			_, _, err := retriever.GetIamCredentials(ctx, test.request)
			g.Expect(err).ToNot(HaveOccurred())
			// sleep for a sec to make sure the cache has some time to evict or refresh creds
			time.Sleep(400 * time.Millisecond)
			iamCredentials, _, err := retriever.GetIamCredentials(ctx, test.request)

			// validate
			if test.expectedErrMsg != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(test.expectedErrMsg))
				g.Expect(iamCredentials).To(BeNil())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(*iamCredentials).To(Equal(test.expectedCredentials))
			}
		})
	}
}

type EksCredentialsResponseWithError struct {
	credentialsResponse *credentials.EksCredentialsResponse
	err                 error
}

func TestCachedCredentialRetriever_GetIamCredentials_ActiveRequestCaching(t *testing.T) {
	var (
		numRequests      = 16
		sampleRequestOne = credentials.EksCredentialsRequest{
			ServiceAccountToken: test.CreateToken(t, test.TokenConfig{
				Expiry: time.Now().Add(time.Hour),
				Iat:    time.Now(),
				Nbf:    time.Now(),
				PodUID: "some.jwt.token.one",
			}),
		}
		sampleResponseOne = credentials.EksCredentialsResponse{
			AccountId:  "accountOne",
			Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
		}
	)

	tests := []struct {
		name                        string
		requests                    []credentials.EksCredentialsRequest
		expectedCredentialsResponse []credentials.EksCredentialsResponse
		expectedErrMsg              string
		expectedDelegateCalls       func(retriever *mockcreds.MockCredentialRetriever)
	}{
		{
			name: "calls without error",
			requests: []credentials.EksCredentialsRequest{
				sampleRequestOne,
			},
			expectedDelegateCalls: func(delegate *mockcreds.MockCredentialRetriever) {
				delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).DoAndReturn(
					func(ctx context.Context, request *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
						time.Sleep(200 * time.Millisecond) // Simulate API call latency
						response := sampleResponseOne
						return &response, responseMetadataTest("one"), nil
					}).Times(1)
			},
			expectedCredentialsResponse: []credentials.EksCredentialsResponse{
				sampleResponseOne,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			g := NewWithT(t)
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctx := context.Background()

			// setup
			delegate := mockcreds.NewMockCredentialRetriever(ctrl)
			if test.expectedDelegateCalls != nil {
				test.expectedDelegateCalls(delegate)
			}

			opts := CachedCredentialRetrieverOpts{
				Delegate:              delegate,
				CredentialsRenewalTtl: 1 * time.Minute,
				MaxCacheSize:          5,
				CleanupInterval:       0, // Disable janitor in tests
				RefreshQPS:            1,
			}

			retriever := newCachedCredentialRetriever(opts)
			for i := range test.requests {
				req := test.requests[i]

				// trigger

				// Create a channel to receive iamCredentials from goroutines
				credResponses := make(chan EksCredentialsResponseWithError)
				for j := 0; j < numRequests; j++ {
					go func() {
						cred, _, err := retriever.GetIamCredentials(ctx, &req)
						response := EksCredentialsResponseWithError{
							credentialsResponse: cred,
							err:                 err,
						}
						credResponses <- response
					}()
				}

				responses := make([]EksCredentialsResponseWithError, numRequests)
				// Wait for 3 results
				for j := 0; j < numRequests; j++ {
					response := <-credResponses // Receive result from any goroutine
					responses[j] = response
				}
				t.Logf("All %d GetIamCredentials requests done\n", numRequests)
				close(credResponses)

				// validate
				if test.expectedErrMsg != "" {
					for j, response := range responses {
						t.Logf("Validating %d with error\n", j)
						g.Expect(response.err).To(HaveOccurred())
						g.Expect(response.err.Error()).To(ContainSubstring(test.expectedErrMsg))
						g.Expect(response.credentialsResponse).To(BeNil())
					}
					return
				} else {
					expectedResponse := test.expectedCredentialsResponse[i]
					for j, response := range responses {
						t.Logf("Validating %d without error\n", j)
						g.Expect(response.err).ToNot(HaveOccurred())
						g.Expect(*response.credentialsResponse).To(Equal(expectedResponse))
					}
				}
			}
		})
	}
}
func TestCachedCredentialRetriever_GetIamCredentials_MissingPodUID(t *testing.T) {
	g := NewWithT(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDelegate := mockcreds.NewMockCredentialRetriever(ctrl)
	retriever := newCachedCredentialRetriever(CachedCredentialRetrieverOpts{
		Delegate:              mockDelegate,
		CredentialsRenewalTtl: time.Hour,
		MaxCacheSize:          100,
		RefreshQPS:            3,
		CleanupInterval:       0, // Disable janitor in tests
	})

	request := &credentials.EksCredentialsRequest{
		ServiceAccountToken: test.CreateToken(t, test.TokenConfig{Expiry: time.Now().Add(time.Hour), Iat: time.Now(), Nbf: time.Now()}),
	}

	_, _, err := retriever.GetIamCredentials(context.Background(), request)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("failed to get pod uid from service account token"))
}

func TestCachedCredentialRetriever_CallDelegateAndCache_MissingPodUID(t *testing.T) {
	g := NewWithT(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDelegate := mockcreds.NewMockCredentialRetriever(ctrl)
	retriever := newCachedCredentialRetriever(CachedCredentialRetrieverOpts{
		Delegate:              mockDelegate,
		CredentialsRenewalTtl: time.Hour,
		MaxCacheSize:          100,
		RefreshQPS:            3,
		CleanupInterval:       0, // Disable janitor in tests
	})

	request := &credentials.EksCredentialsRequest{
		ServiceAccountToken: test.CreateToken(t, test.TokenConfig{Expiry: time.Now().Add(time.Hour), Iat: time.Now(), Nbf: time.Now()}),
	}

	_, _, err := retriever.callDelegateAndCache(context.Background(), request)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("failed to get pod uid from service account token"))
}

func TestCachedCredentialRetriever_OnCredentialRenewal_MissingPodUID(t *testing.T) {
	g := NewWithT(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDelegate := mockcreds.NewMockCredentialRetriever(ctrl)
	mockDelegate.EXPECT().IsIrrecoverable(gomock.Any()).Return("Unknown", false).AnyTimes()
	retriever := newCachedCredentialRetriever(CachedCredentialRetrieverOpts{
		Delegate:              mockDelegate,
		CredentialsRenewalTtl: time.Hour,
		MaxCacheSize:          100,
		RefreshQPS:            3,
		CleanupInterval:       0, // Disable janitor in tests
	})

	// Create cache entry with invalid token that will fail pod UID parsing
	entry := cacheEntry{
		requestLogCtx: context.Background(),
		originatingRequest: &credentials.EksCredentialsRequest{
			ServiceAccountToken: test.CreateToken(t, test.TokenConfig{Expiry: time.Now().Add(time.Hour), Iat: time.Now(), Nbf: time.Now()}),
		},
		credentials: &credentials.EksCredentialsResponse{
			Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
		},
	}
	retriever.internalCache.Add("test-key", entry)
	_, foundBefore := retriever.internalCache.Get("test-key")
	g.Expect(foundBefore).To(BeTrue())

	// Renewal will fail due to pod UID parsing error, the cache should be unchanged
	retriever.onCredentialRenewal("test-key", entry)
	_, foundAfter := retriever.internalCache.Get("test-key")
	g.Expect(foundAfter).To(BeTrue())
}

func TestCachedCredentialRetriever_UncachedPodDelegateFailure_ReturnsEmptyCredentials(t *testing.T) {
	g := NewWithT(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx := context.Background()

	delegate := eksauth.NewMockIface(ctrl)

	opts := CachedCredentialRetrieverOpts{
		Delegate:              delegate,
		CredentialsRenewalTtl: time.Hour,
		MaxCacheSize:          5,
		CleanupInterval:       0, // Disable janitor in tests
		RefreshQPS:            1,
	}
	retriever := newCachedCredentialRetriever(opts)

	// Pre-populate the cache with an entry for a pod UID using an initial JWT
	podUID := "test-pod-uid-auth-failure"
	initialTime := time.Now()
	initialJWT := test.CreateToken(t, test.TokenConfig{
		Expiry: initialTime.Add(time.Hour),
		Iat:    initialTime,
		Nbf:    initialTime,
		PodUID: podUID,
	})
	validCreds := &credentials.EksCredentialsResponse{
		Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
	}

	cachedEntry := cacheEntry{
		requestLogCtx: ctx,
		originatingRequest: &credentials.EksCredentialsRequest{
			ServiceAccountToken: initialJWT,
		},
		credentials: validCreds,
	}
	retriever.internalCache.Add(podUID, cachedEntry)

	// Create a different JWT with the same pod UID (different iat/nbf/exp)
	newTime := initialTime.Add(time.Minute)
	newJWT := test.CreateToken(t, test.TokenConfig{
		Expiry: newTime.Add(time.Hour),
		Iat:    newTime,
		Nbf:    newTime,
		PodUID: podUID,
	})
	g.Expect(newJWT).ToNot(Equal(initialJWT))

	// Make a request with the new JWT
	newRequest := &credentials.EksCredentialsRequest{
		ServiceAccountToken: newJWT,
	}

	// The delegate (auth service) returns an error (InternalServerException)
	delegate.EXPECT().GetIamCredentials(gomock.Any(), newRequest).
		Return(nil, nil, &types.InternalServerException{}).Times(1)

	skippedBefore := testutil.ToFloat64(promLocalValidation.WithLabelValues("skipped"))

	// Assert that no credentials are returned — the cached creds from the original JWT are not served
	creds, _, err := retriever.GetIamCredentials(ctx, newRequest)
	g.Expect(err).To(HaveOccurred())
	g.Expect(creds).To(BeNil())
	g.Expect(testutil.ToFloat64(promLocalValidation.WithLabelValues("skipped"))).To(Equal(skippedBefore + 1))
}

func TestCachedCredentialRetriever_ValidateTokenOnlyWhenExpected(t *testing.T) {
	const podUID = "test-pod"

	tests := []struct {
		name                      string
		preCacheEntry             bool
		useSameToken              bool
		cachedCredsValid          bool
		expectValidateTokenCalled bool
	}{
		{
			name:                      "pod not in cache",
			preCacheEntry:             false,
			expectValidateTokenCalled: false,
		},
		{
			name:                      "cached with same token and valid creds",
			preCacheEntry:             true,
			useSameToken:              true,
			cachedCredsValid:          true,
			expectValidateTokenCalled: false,
		},
		{
			name:                      "cached with same token but expired creds",
			preCacheEntry:             true,
			useSameToken:              true,
			cachedCredsValid:          false,
			expectValidateTokenCalled: false,
		},
		{
			name:                      "cached with different token but expired creds",
			preCacheEntry:             true,
			useSameToken:              false,
			cachedCredsValid:          false,
			expectValidateTokenCalled: false,
		},
		{
			name:                      "cached with different token and valid creds",
			preCacheEntry:             true,
			useSameToken:              false,
			cachedCredsValid:          true,
			expectValidateTokenCalled: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctx := context.Background()

			delegate := mockcreds.NewMockCredentialRetriever(ctrl)
			spy := &spyTokenValidator{}
			retriever := newCachedCredentialRetriever(CachedCredentialRetrieverOpts{
				Delegate:              delegate,
				TokenValidator:        spy,
				CredentialsRenewalTtl: time.Hour,
				MaxCacheSize:          100,
				RefreshQPS:            3,
				CleanupInterval:       0,
			})

			cachedJWT := test.CreateToken(t, test.TokenConfig{
				Expiry: time.Now().Add(time.Hour),
				Iat:    time.Now(),
				Nbf:    time.Now(),
				PodUID: podUID,
			})

			if tc.preCacheEntry {
				expiry := time.Now().Add(time.Hour)
				if !tc.cachedCredsValid {
					expiry = time.Now().Add(-time.Second)
				}
				retriever.internalCache.Add(podUID, cacheEntry{
					requestLogCtx:      ctx,
					originatingRequest: &credentials.EksCredentialsRequest{ServiceAccountToken: cachedJWT},
					credentials: &credentials.EksCredentialsResponse{
						Expiration: credentials.SdkCompliantExpirationTime{Time: expiry},
					},
				})
			}

			requestJWT := cachedJWT
			if tc.preCacheEntry && !tc.useSameToken {
				requestJWT = test.CreateToken(t, test.TokenConfig{
					Expiry: time.Now().Add(time.Hour),
					Iat:    time.Now().Add(time.Minute),
					Nbf:    time.Now(),
					PodUID: podUID,
				})
			}

			// For cases that fall through to the delegate, set up the expectation
			if !tc.preCacheEntry || !tc.cachedCredsValid || (tc.expectValidateTokenCalled) {
				delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
					Return(&credentials.EksCredentialsResponse{
						Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
					}, responseMetadataTest("test"), nil).MaxTimes(1)
			}

			request := &credentials.EksCredentialsRequest{ServiceAccountToken: requestJWT}
			successBefore := testutil.ToFloat64(promLocalValidation.WithLabelValues("success"))
			_, _, err := retriever.GetIamCredentials(ctx, request)
			g.Expect(err).ToNot(HaveOccurred())

			g.Expect(spy.validateTokenCalled).To(Equal(tc.expectValidateTokenCalled))
			if tc.expectValidateTokenCalled {
				g.Expect(testutil.ToFloat64(promLocalValidation.WithLabelValues("success"))).To(Equal(successBefore + 1))
			}
		})
	}
}

func TestCachedCredentialRetriever_ValidateTokenOutcome(t *testing.T) {
	t.Run("successful validation returns cached credential and updates cache entry", func(t *testing.T) {
		g := NewWithT(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.Background()

		podUID := "pod1"
		validCreds := &credentials.EksCredentialsResponse{
			Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
		}

		spy := &spyTokenValidator{}
		retriever := newCachedCredentialRetriever(CachedCredentialRetrieverOpts{
			Delegate:              mockcreds.NewMockCredentialRetriever(ctrl),
			TokenValidator:        spy,
			CredentialsRenewalTtl: time.Hour,
			MaxCacheSize:          100,
			RefreshQPS:            3,
			CleanupInterval:       0,
		})

		// Create a token and put it in the credentials cache
		jwt1 := test.CreateToken(t, test.TokenConfig{
			Expiry: time.Now().Add(time.Hour),
			Iat:    time.Now(),
			Nbf:    time.Now(),
			PodUID: podUID,
		})
		retriever.internalCache.Add(podUID, cacheEntry{
			requestLogCtx:      ctx,
			originatingRequest: &credentials.EksCredentialsRequest{ServiceAccountToken: jwt1},
			credentials:        validCreds,
		})

		// Create a request with the same pod but different token
		jwt2 := test.CreateToken(t, test.TokenConfig{
			Expiry: time.Now().Add(time.Hour),
			Iat:    time.Now().Add(time.Minute),
			Nbf:    time.Now(),
			PodUID: podUID,
		})
		g.Expect(jwt2).ToNot(Equal(jwt1))
		request := &credentials.EksCredentialsRequest{ServiceAccountToken: jwt2}

		// Expect ValidateToken to be called and return the cached credentials
		successBefore := testutil.ToFloat64(promLocalValidation.WithLabelValues("success"))
		creds, _, err := retriever.GetIamCredentials(ctx, request)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(creds).To(Equal(validCreds))
		g.Expect(spy.validateTokenCalled).To(BeTrue())
		g.Expect(spy.refreshKeysCalled).To(BeFalse())
		g.Expect(testutil.ToFloat64(promLocalValidation.WithLabelValues("success"))).To(Equal(successBefore + 1))

		// After successful validation, the cache entry should have been updated
		// to jwt2, so a repeat call with jwt2 should be a direct cache hit
		// without calling ValidateToken again.
		spy.validateTokenCalled = false
		creds, _, err = retriever.GetIamCredentials(ctx, request)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(creds).To(Equal(validCreds))
		g.Expect(spy.validateTokenCalled).To(BeFalse())
	})

	t.Run("unsuccessful validation falls through to delegate", func(t *testing.T) {
		g := NewWithT(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.Background()

		podUID := "pod1"
		cachedCreds := &credentials.EksCredentialsResponse{
			AccountId:  "cached",
			Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
		}
		freshCreds := &credentials.EksCredentialsResponse{
			AccountId:  "fresh",
			Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
		}

		delegate := mockcreds.NewMockCredentialRetriever(ctrl)
		delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
			Return(freshCreds, responseMetadataTest("test"), nil).Times(1)

		spy := &spyTokenValidator{validateTokenErr: fmt.Errorf("signature mismatch")}
		retriever := newCachedCredentialRetriever(CachedCredentialRetrieverOpts{
			Delegate:              delegate,
			TokenValidator:        spy,
			CredentialsRenewalTtl: time.Hour,
			MaxCacheSize:          100,
			RefreshQPS:            3,
			CleanupInterval:       0,
		})

		// Create a request with the same pod but different token
		jwt1 := test.CreateToken(t, test.TokenConfig{
			Expiry: time.Now().Add(time.Hour),
			Iat:    time.Now(),
			Nbf:    time.Now(),
			PodUID: podUID,
		})
		retriever.internalCache.Add(podUID, cacheEntry{
			requestLogCtx:      ctx,
			originatingRequest: &credentials.EksCredentialsRequest{ServiceAccountToken: jwt1},
			credentials:        cachedCreds,
		})

		jwt2 := test.CreateToken(t, test.TokenConfig{
			Expiry: time.Now().Add(time.Hour),
			Iat:    time.Now().Add(time.Minute),
			Nbf:    time.Now(),
			PodUID: podUID,
		})
		request := &credentials.EksCredentialsRequest{ServiceAccountToken: jwt2}

		failureBefore := testutil.ToFloat64(promLocalValidation.WithLabelValues("failure"))
		creds, _, err := retriever.GetIamCredentials(ctx, request)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(spy.validateTokenCalled).To(BeTrue())
		// Should have gotten fresh creds from the delegate, not the cached ones
		g.Expect(creds.AccountId).To(Equal("fresh"))
		g.Expect(testutil.ToFloat64(promLocalValidation.WithLabelValues("failure"))).To(Equal(failureBefore + 1))
	})
}

func TestCachedCredentialRetriever_TamperedPodUID_DoesNotReturnOtherPodCreds(t *testing.T) {
	g := NewWithT(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx := context.Background()

	victimUID := "victim-pod"

	victimCreds := &credentials.EksCredentialsResponse{
		AccountId:  "victim-account",
		Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
	}
	freshCreds := &credentials.EksCredentialsResponse{
		AccountId:  "fresh-from-delegate",
		Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
	}

	delegate := mockcreds.NewMockCredentialRetriever(ctrl)
	delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
		Return(freshCreds, responseMetadataTest("test"), nil).Times(1)

	// Validation fails because the token was tampered — signature won't match
	spy := &spyTokenValidator{validateTokenErr: fmt.Errorf("signature mismatch")}
	retriever := newCachedCredentialRetriever(CachedCredentialRetrieverOpts{
		Delegate:              delegate,
		TokenValidator:        spy,
		CredentialsRenewalTtl: time.Hour,
		MaxCacheSize:          100,
		RefreshQPS:            3,
		CleanupInterval:       0,
	})

	// Cache credentials for the victim pod
	victimJWT := test.CreateToken(t, test.TokenConfig{
		Expiry: time.Now().Add(time.Hour),
		Iat:    time.Now(),
		Nbf:    time.Now(),
		PodUID: victimUID,
	})
	retriever.internalCache.Add(victimUID, cacheEntry{
		requestLogCtx:      ctx,
		originatingRequest: &credentials.EksCredentialsRequest{ServiceAccountToken: victimJWT},
		credentials:        victimCreds,
	})

	// Attacker creates a token with the victim's pod UID but a different JWT.
	// Since the cache is keyed by pod UID extracted from claims, the tampered token
	// will match the victim's cache entry. But validation should reject the tampered
	// token and fall through to the delegate instead of returning victim's creds.
	attackerJWT := test.CreateToken(t, test.TokenConfig{
		Expiry: time.Now().Add(time.Hour),
		Iat:    time.Now().Add(time.Minute),
		Nbf:    time.Now(),
		PodUID: victimUID, // pretending to be the victim
	})
	request := &credentials.EksCredentialsRequest{ServiceAccountToken: attackerJWT}

	failureBefore := testutil.ToFloat64(promLocalValidation.WithLabelValues("failure"))
	creds, _, err := retriever.GetIamCredentials(ctx, request)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(spy.validateTokenCalled).To(BeTrue())
	g.Expect(creds.AccountId).To(Equal("fresh-from-delegate"))
	g.Expect(creds.AccountId).ToNot(Equal(victimCreds.AccountId))
	g.Expect(testutil.ToFloat64(promLocalValidation.WithLabelValues("failure"))).To(Equal(failureBefore + 1))
}

// imdsMetadataTest is a test ResponseMetadata for IMDS-sourced credentials.
type imdsMetadataTest struct{}

func (imdsMetadataTest) AssociationId() string                { return "" }
func (imdsMetadataTest) Source() credentials.CredentialSource { return credentials.SourceIMDS }

// TestCacheEntry_Source_DefaultsToAuthService verifies that a cache entry with
// no metadata reports SourceAuthService. This is the safety default that keeps
// pre-existing / IMDS-disabled behavior unchanged: with no source information,
// the cache applies the Auth Service policy (evict on expiry), never the IMDS one.
func TestCacheEntry_Source_DefaultsToAuthService(t *testing.T) {
	g := NewWithT(t)

	g.Expect(cacheEntry{metadata: nil}.source()).To(Equal(credentials.SourceAuthService))
	g.Expect(cacheEntry{metadata: imdsMetadataTest{}}.source()).To(Equal(credentials.SourceIMDS))
	g.Expect(cacheEntry{metadata: responseMetadataTest("a")}.source()).To(Equal(credentials.SourceAuthService))
}

// TestCachedCredentialRetriever_GetCacheTtls verifies that getCacheTtls returns
// the correct refresh and eviction durations for each source.
func TestCachedCredentialRetriever_GetCacheTtls(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	retriever := newSourceTestRetriever(mockcreds.NewMockCredentialRetriever(ctrl))

	tests := []struct {
		name         string
		source       credentials.CredentialSource
		credsDur     time.Duration
		wantRefresh  time.Duration
		wantEviction time.Duration
	}{
		{"IMDS always 30min/NoExpiration", credentials.SourceIMDS, 6 * time.Hour, imdsRefreshInterval, expiring.NoExpiration},
		{"Auth Service short creds", credentials.SourceAuthService, 2 * time.Hour, 2 * time.Hour, 2 * time.Hour},
		{"Auth Service long creds capped by renewalTtl", credentials.SourceAuthService, 6 * time.Hour, 3 * time.Hour, 6 * time.Hour},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			refresh, eviction := retriever.getCacheTtls(tc.source, tc.credsDur)
			g.Expect(refresh).To(Equal(tc.wantRefresh))
			g.Expect(eviction).To(Equal(tc.wantEviction))
		})
	}
}

// TestCachedCredentialRetriever_CredsHandledBySource verifies that the cache
// accepts/serves credentials differently based on source and expiration:
//   - IMDS: both expired and unexpired creds are accepted and served (static stability).
//   - Auth Service: only unexpired creds are accepted; expired creds are rejected and evicted.
func TestCachedCredentialRetriever_CredsHandledBySource(t *testing.T) {
	tests := []struct {
		name          string
		metadata      credentials.ResponseMetadata
		credsAge      time.Duration // positive = unexpired, negative = expired
		wantCached    bool          // callDelegateAndCache accepts it
		wantServed    bool          // tryServingFromCache serves it
		wantKeptAfter bool          // entry remains in cache after sync path
	}{
		{"IMDS: unexpired creds accepted and served", imdsMetadataTest{}, 6 * time.Hour, true, true, true},
		{"IMDS: expired creds accepted and served", imdsMetadataTest{}, -1 * time.Hour, true, true, true},
		{"Auth Service: unexpired creds accepted and served", responseMetadataTest("assoc-1"), 6 * time.Hour, true, true, true},
		{"Auth Service: expired creds rejected", responseMetadataTest("assoc-1"), -1 * time.Hour, false, false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctx := context.Background()

			// Setup: credential with the given age relative to now.
			podUID := "creds-pod"
			token := sourceTestToken(t, podUID)
			creds := &credentials.EksCredentialsResponse{
				AccessKeyId: "AKIA-test",
				Expiration:  credentials.SdkCompliantExpirationTime{Time: time.Now().Add(tc.credsAge)},
			}

			delegate := mockcreds.NewMockCredentialRetriever(ctrl)
			if tc.wantCached {
				delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
					Return(creds, tc.metadata, nil).Times(1)
			}

			retriever := newSourceTestRetriever(delegate)
			request := &credentials.EksCredentialsRequest{ServiceAccountToken: token}

			// Assert: initial fetch (callDelegateAndCache) accepts or rejects creds.
			if tc.wantCached {
				result, _, err := retriever.GetIamCredentials(ctx, request)
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(result.AccessKeyId).To(Equal("AKIA-test"))
			}

			// Setup: pre-populate cache with the entry for sync path test.
			retriever.internalCache.Add(podUID, cacheEntry{
				requestLogCtx:      ctx,
				originatingRequest: request,
				credentials:        creds,
				metadata:           tc.metadata,
			})

			// Assert: tryServingFromCache serves or rejects the entry.
			served, done := retriever.tryServingFromCache(ctx, podUID, request)
			g.Expect(done).To(Equal(tc.wantServed))
			if tc.wantServed {
				g.Expect(served.AccessKeyId).To(Equal("AKIA-test"))
			}

			// Assert: entry kept or evicted from cache.
			_, found := retriever.internalCache.Get(podUID)
			g.Expect(found).To(Equal(tc.wantKeptAfter))
		})
	}
}

// TestCachedCredentialRetriever_OnCredentialRenewal_SourceAware verifies the
// janitor renewal callback (onCredentialRenewal) is source-aware:
//   - Recoverable failure: valid entries are re-inserted — IMDS with NoExpiration
//     (static stability), Auth Service with a finite expiry-based eviction TTL.
//   - Successful refresh: an expired IMDS entry is replaced with the fresh credential.
//   - Irrecoverable failure: the entry is evicted regardless of source.
func TestCachedCredentialRetriever_OnCredentialRenewal_SourceAware(t *testing.T) {
	t.Run("failed recoverable renewal re-inserts valid entries with source-specific TTLs", func(t *testing.T) {
		tests := []struct {
			name             string
			metadata         credentials.ResponseMetadata
			credsAge         time.Duration // relative to now; negative = expired
			wantNoExpiration bool          // IMDS re-inserted with NoExpiration; Auth with a finite TTL
		}{
			// IMDS: kept even when expired, re-inserted with NoExpiration (static stability).
			{"IMDS expired: re-inserted with NoExpiration", imdsMetadataTest{}, -30 * time.Minute, true},
			// Auth Service, still valid: re-inserted with a finite (expiry-based) eviction TTL.
			{"Auth Service valid: re-inserted with finite eviction TTL", responseMetadataTest("assoc-1"), 2 * time.Hour, false},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				g := NewWithT(t)
				ctrl := gomock.NewController(t)
				defer ctrl.Finish()

				podUID := "renewal-pod"
				token := sourceTestToken(t, podUID)

				// Delegate refresh fails with a recoverable error.
				delegate := mockcreds.NewMockCredentialRetriever(ctrl)
				delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
					Return(nil, nil, fmt.Errorf("recoverable error")).Times(1)
				delegate.EXPECT().IsIrrecoverable(gomock.Any()).Return("Unknown", false).Times(1)

				retriever := newSourceTestRetriever(delegate)
				retriever.retryInterval = 5 * time.Minute
				retriever.maxRetryJitter = 1

				entry := cacheEntry{
					requestLogCtx: context.Background(),
					originatingRequest: &credentials.EksCredentialsRequest{
						ServiceAccountToken: token,
					},
					credentials: &credentials.EksCredentialsResponse{
						Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(tc.credsAge)},
					},
					metadata: tc.metadata,
				}
				retriever.internalCache.Add(podUID, entry)

				// Act: trigger the renewal callback (recoverable failure path).
				retriever.onCredentialRenewal(podUID, entry)

				// The entry is re-inserted; assert its eviction TTL matches its source policy.
				_, _, expirationTime, found := retriever.internalCache.GetWithRenewExpiry(podUID)
				g.Expect(found).To(BeTrue())
				if tc.wantNoExpiration {
					g.Expect(expirationTime.IsZero()).To(BeTrue(), "IMDS entry should be re-inserted with NoExpiration")
				} else {
					g.Expect(expirationTime.IsZero()).To(BeFalse(), "Auth Service entry should keep a finite eviction TTL")
				}
			})
		}
	})

	t.Run("successful renewal updates expired IMDS entry with fresh creds", func(t *testing.T) {
		g := NewWithT(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		// Setup: expired IMDS entry in cache, delegate returns fresh creds.
		podUID := "imds-fresh-pod"
		token := sourceTestToken(t, podUID)

		delegate := mockcreds.NewMockCredentialRetriever(ctrl)
		delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
			Return(&credentials.EksCredentialsResponse{
				AccessKeyId: "AKIA-fresh",
				Expiration:  credentials.SdkCompliantExpirationTime{Time: time.Now().Add(6 * time.Hour)},
			}, imdsMetadataTest{}, nil).Times(1)

		retriever := newSourceTestRetriever(delegate)

		entry := cacheEntry{
			requestLogCtx: context.Background(),
			originatingRequest: &credentials.EksCredentialsRequest{
				ServiceAccountToken: token,
			},
			credentials: &credentials.EksCredentialsResponse{
				AccessKeyId: "AKIA-old",
				Expiration:  credentials.SdkCompliantExpirationTime{Time: time.Now().Add(-30 * time.Minute)},
			},
			metadata: imdsMetadataTest{},
		}
		retriever.internalCache.Add(podUID, entry)

		// Act: trigger the renewal callback.
		retriever.onCredentialRenewal(podUID, entry)

		// Assert: cache entry was replaced with the fresh credential.
		updated, found := retriever.internalCache.Get(podUID)
		g.Expect(found).To(BeTrue())
		g.Expect(updated.credentials.AccessKeyId).To(Equal("AKIA-fresh"))
	})

	t.Run("irrecoverable renewal error evicts the entry regardless of source", func(t *testing.T) {
		// When the delegate classifies the refresh error as irrecoverable, the
		// credential is gone/invalid, so the entry is evicted even for IMDS.
		for _, meta := range []credentials.ResponseMetadata{imdsMetadataTest{}, responseMetadataTest("assoc-1")} {
			g := NewWithT(t)
			ctrl := gomock.NewController(t)

			podUID := "irrecoverable-pod"
			token := sourceTestToken(t, podUID)

			delegate := mockcreds.NewMockCredentialRetriever(ctrl)
			delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
				Return(nil, nil, fmt.Errorf("gone")).Times(1)
			delegate.EXPECT().IsIrrecoverable(gomock.Any()).Return("Irrecoverable", true).Times(1)

			retriever := newSourceTestRetriever(delegate)

			entry := cacheEntry{
				requestLogCtx:      context.Background(),
				originatingRequest: &credentials.EksCredentialsRequest{ServiceAccountToken: token},
				credentials: &credentials.EksCredentialsResponse{
					Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(6 * time.Hour)},
				},
				metadata: meta,
			}
			retriever.internalCache.Add(podUID, entry)

			retriever.onCredentialRenewal(podUID, entry)

			_, found := retriever.internalCache.Get(podUID)
			g.Expect(found).To(BeFalse(), "irrecoverable error should evict the entry for source %s", meta.Source())
			ctrl.Finish()
		}
	})
}

// newSourceTestRetriever builds a cachedCredentialRetriever with the standard
// options used by the source-aware tests (janitor disabled via CleanupInterval:0).
func newSourceTestRetriever(delegate credentials.CredentialRetriever) *cachedCredentialRetriever {
	return newCachedCredentialRetriever(CachedCredentialRetrieverOpts{
		Delegate:              delegate,
		CredentialsRenewalTtl: 3 * time.Hour,
		MaxCacheSize:          100,
		RefreshQPS:            3,
		CleanupInterval:       0,
	})
}

// sourceTestToken creates a valid (unexpired) service-account JWT for podUID.
func sourceTestToken(t *testing.T, podUID string) string {
	t.Helper()
	return test.CreateToken(t, test.TokenConfig{
		Expiry: time.Now().Add(time.Hour),
		Iat:    time.Now(),
		Nbf:    time.Now(),
		PodUID: podUID,
	})
}
