package credsretriever

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/eksauth/types"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/eksauth"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/credcache"
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
							Add(credcache.DefaultMinCredentialTtl - time.Second)},
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
			retriever := newTestRetriever(credcache.Opts{
				RenewalTtl:      ttlToRefreshDuration,
				MaxSize:         5,
				CleanupInterval: 0, // Disable janitor in tests
				RefreshQPS:      1,
			}, CachedCredentialRetrieverOpts{
				Delegate:              delegate,
				AuthoritativeDelegate: delegate,
			})

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

				// Get pod UID from service account token to check cache. The
				// refresh and eviction times are credcache's, tested there.
				podUID, err := credentials.GetPodUIDFromToken(test.request.ServiceAccountToken)
				g.Expect(err).ToNot(HaveOccurred())

				cached, found := retriever.cache.Get(podUID)
				g.Expect(found).To(BeTrue())
				g.Expect(*cached.Credentials).To(Equal(test.expectedCredentials))

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

			retriever := newTestRetriever(credcache.Opts{
				RenewalTtl:      1 * time.Minute,
				MaxSize:         5,
				CleanupInterval: 0, // Disable janitor in tests
				RefreshQPS:      1,
			}, CachedCredentialRetrieverOpts{
				Delegate:              delegate,
				AuthoritativeDelegate: delegate,
			})
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
		timerBuilder          func(counter *int) func() time.Time
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
			timerBuilder: func(counter *int) func() time.Time {
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

			cacheOpts := credcache.Opts{
				RenewalTtl: ttlToRefreshDuration,
				// One pod, and a size the QPS check passes at this renewal TTL.
				MaxSize:          1,
				CleanupInterval:  ttlToRefreshDuration / 10,
				RefreshQPS:       5,
				RetryInterval:    ttlToRefreshDuration,
				MinCredentialTtl: ttlToRefreshDuration / 10,
				MaxRetryJitter:   1,
			}
			if test.timerBuilder != nil {
				counter := 0
				cacheOpts.Now = test.timerBuilder(&counter)
			}
			retriever := newTestRetriever(cacheOpts, CachedCredentialRetrieverOpts{
				Delegate:              delegate,
				AuthoritativeDelegate: delegate,
			})

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

			retriever := newTestRetriever(credcache.Opts{
				RenewalTtl:      1 * time.Minute,
				MaxSize:         5,
				CleanupInterval: 0, // Disable janitor in tests
				RefreshQPS:      1,
			}, CachedCredentialRetrieverOpts{
				Delegate:              delegate,
				AuthoritativeDelegate: delegate,
			})
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
	retriever := newTestRetriever(credcache.Opts{
		RenewalTtl:      time.Hour,
		MaxSize:         100,
		RefreshQPS:      3,
		CleanupInterval: 0, // Disable janitor in tests
	}, CachedCredentialRetrieverOpts{
		Delegate:              mockDelegate,
		AuthoritativeDelegate: mockDelegate,
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
	retriever := newTestRetriever(credcache.Opts{
		RenewalTtl:      time.Hour,
		MaxSize:         100,
		RefreshQPS:      3,
		CleanupInterval: 0, // Disable janitor in tests
	}, CachedCredentialRetrieverOpts{
		Delegate:              mockDelegate,
		AuthoritativeDelegate: mockDelegate,
	})

	request := &credentials.EksCredentialsRequest{
		ServiceAccountToken: test.CreateToken(t, test.TokenConfig{Expiry: time.Now().Add(time.Hour), Iat: time.Now(), Nbf: time.Now()}),
	}

	_, _, err := retriever.callDelegateAndCache(context.Background(), mockDelegate, request)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("failed to get pod uid from service account token"))
}

func TestCachedCredentialRetriever_UncachedPodDelegateFailure_ReturnsEmptyCredentials(t *testing.T) {
	g := NewWithT(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx := context.Background()

	delegate := eksauth.NewMockIface(ctrl)

	retriever := newTestRetriever(credcache.Opts{
		RenewalTtl:      time.Hour,
		MaxSize:         5,
		CleanupInterval: 0, // Disable janitor in tests
		RefreshQPS:      1,
	}, CachedCredentialRetrieverOpts{
		Delegate:              delegate,
		AuthoritativeDelegate: delegate,
	})

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

	cachedEntry := &credcache.Entry{
		LogCtx: ctx,
		Request: &credentials.EksCredentialsRequest{
			ServiceAccountToken: initialJWT,
		},
		Credentials: validCreds,
	}
	seed(t, retriever, podUID, cachedEntry)

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
			clock := &testClock{}
			retriever := newTestRetriever(credcache.Opts{
				RenewalTtl: time.Hour,
				MaxSize:    100,
				RefreshQPS: 3,
				Now:        clock.now,
			}, CachedCredentialRetrieverOpts{
				Delegate:              delegate,
				AuthoritativeDelegate: delegate,
				TokenValidator:        spy,
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
				seedAsOfTheirIssue(t, retriever, clock, podUID, &credcache.Entry{
					LogCtx:  ctx,
					Request: &credentials.EksCredentialsRequest{ServiceAccountToken: cachedJWT},
					Credentials: &credentials.EksCredentialsResponse{
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
		retriever := newTestRetriever(credcache.Opts{
			RenewalTtl:      time.Hour,
			MaxSize:         100,
			RefreshQPS:      3,
			CleanupInterval: 0,
		}, CachedCredentialRetrieverOpts{
			Delegate:              mockcreds.NewMockCredentialRetriever(ctrl),
			AuthoritativeDelegate: mockcreds.NewMockCredentialRetriever(ctrl),
			TokenValidator:        spy,
		})

		// Create a token and put it in the credentials cache
		jwt1 := test.CreateToken(t, test.TokenConfig{
			Expiry: time.Now().Add(time.Hour),
			Iat:    time.Now(),
			Nbf:    time.Now(),
			PodUID: podUID,
		})
		seed(t, retriever, podUID, &credcache.Entry{
			LogCtx:      ctx,
			Request:     &credentials.EksCredentialsRequest{ServiceAccountToken: jwt1},
			Credentials: validCreds,
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
	retriever := newTestRetriever(credcache.Opts{
		RenewalTtl:      time.Hour,
		MaxSize:         100,
		RefreshQPS:      3,
		CleanupInterval: 0,
	}, CachedCredentialRetrieverOpts{
		Delegate:              delegate,
		AuthoritativeDelegate: delegate,
		TokenValidator:        spy,
	})

	// Cache credentials for the victim pod
	victimJWT := test.CreateToken(t, test.TokenConfig{
		Expiry: time.Now().Add(time.Hour),
		Iat:    time.Now(),
		Nbf:    time.Now(),
		PodUID: victimUID,
	})
	seed(t, retriever, victimUID, &credcache.Entry{
		LogCtx:      ctx,
		Request:     &credentials.EksCredentialsRequest{ServiceAccountToken: victimJWT},
		Credentials: victimCreds,
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

			clock := &testClock{}
			retriever := newTestRetriever(credcache.Opts{
				RenewalTtl: 3 * time.Hour,
				MaxSize:    100,
				RefreshQPS: 3,
				Now:        clock.now,
			}, CachedCredentialRetrieverOpts{Delegate: delegate, AuthoritativeDelegate: delegate})
			request := &credentials.EksCredentialsRequest{ServiceAccountToken: token}

			// Assert: initial fetch (callDelegateAndCache) accepts or rejects creds.
			if tc.wantCached {
				result, _, err := retriever.GetIamCredentials(ctx, request)
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(result.AccessKeyId).To(Equal("AKIA-test"))
			}

			// Setup: pre-populate cache with the entry for sync path test.
			seedAsOfTheirIssue(t, retriever, clock, podUID, &credcache.Entry{
				LogCtx:      ctx,
				Request:     request,
				Credentials: creds,
				Metadata:    tc.metadata,
			})

			// Assert: tryServingFromCache serves or rejects the entry.
			served, done := retriever.tryServingFromCache(ctx, podUID, request)
			g.Expect(done).To(Equal(tc.wantServed))
			if tc.wantServed {
				g.Expect(served.AccessKeyId).To(Equal("AKIA-test"))
			}

			// Assert: entry kept or evicted from cache.
			_, found := retriever.cache.Get(podUID)
			g.Expect(found).To(Equal(tc.wantKeptAfter))
		})
	}
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

// TestCachedCredentialRetriever_DelegateRouting verifies that when a token
// is unknown or fails validation, the authoritativeDelegate is called. And,
// validated tokens don't call delegates (served from cache).
func TestCachedCredentialRetriever_DelegateRouting(t *testing.T) {
	const samePodUID = "pod1"

	tests := []struct {
		name                string
		validationErr       error // error from local token validation
		seedCached          bool  // whether to seed the cache with an entry for the pod
		sameToken           bool  // whether to reuse the token in the cache
		wantAuthoritative   bool  // authoritative delegate called
		wantServedFromCache bool  // no delegate called - served from cache
	}{
		{
			name:              "cache miss admits via authoritative delegate",
			seedCached:        false,
			wantAuthoritative: true,
		},
		{
			name:              "different token failing validation admits via authoritative delegate",
			seedCached:        true,
			validationErr:     fmt.Errorf("signature mismatch"),
			wantAuthoritative: true,
		},
		{
			name:                "different token passing validation is served from cache",
			seedCached:          true,
			validationErr:       nil,
			wantServedFromCache: true,
		},
		{
			name:                "same token is served from cache",
			seedCached:          true,
			sameToken:           true,
			wantServedFromCache: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctx := context.Background()

			// Distinct creds so the assertions can tell the source apart.
			cachedCreds := &credentials.EksCredentialsResponse{
				AccountId:  "cached",
				Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
			}
			freshCreds := &credentials.EksCredentialsResponse{
				AccountId:  "fresh",
				Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
			}

			generalDelegate := mockcreds.NewMockCredentialRetriever(ctrl)
			authoritativeDelegate := mockcreds.NewMockCredentialRetriever(ctrl)

			// Set delegate expectations for the scenario.
			if tc.wantAuthoritative {
				authoritativeDelegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
					Return(freshCreds, responseMetadataTest("assoc"), nil).Times(1)
				generalDelegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).Times(0)
			} else {
				// Served from cache: neither delegate is consulted.
				authoritativeDelegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).Times(0)
				generalDelegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).Times(0)
			}

			// Build the retriever with both delegates and the scenario's validator result.
			retriever := newTestRetriever(credcache.Opts{
				RenewalTtl: time.Hour,
				MaxSize:    100,
				RefreshQPS: 3,
			}, CachedCredentialRetrieverOpts{
				Delegate:              generalDelegate,
				AuthoritativeDelegate: authoritativeDelegate,
				TokenValidator:        &spyTokenValidator{validateTokenErr: tc.validationErr},
			})

			// Create the token the request will carry (also used to seed the cache).
			seededToken := test.CreateToken(t, test.TokenConfig{
				Expiry: time.Now().Add(time.Hour), Iat: time.Now(), Nbf: time.Now(), PodUID: samePodUID,
			})
			requestToken := seededToken
			if tc.seedCached {
				// Seed a cache entry for the pod under the first token.
				seed(t, retriever, samePodUID, &credcache.Entry{
					LogCtx:      ctx,
					Request:     &credentials.EksCredentialsRequest{ServiceAccountToken: seededToken},
					Credentials: cachedCreds,
				})
				if !tc.sameToken {
					// Request with a different token for the same pod.
					requestToken = test.CreateToken(t, test.TokenConfig{
						Expiry: time.Now().Add(time.Hour), Iat: time.Now().Add(time.Minute), Nbf: time.Now(), PodUID: samePodUID,
					})
				}
			}

			// Fetch credentials and verify which source served them.
			creds, _, err := retriever.GetIamCredentials(ctx, &credentials.EksCredentialsRequest{ServiceAccountToken: requestToken})
			g.Expect(err).ToNot(HaveOccurred())
			if tc.wantAuthoritative {
				// Fresh creds prove the authoritative delegate served.
				g.Expect(creds.AccountId).To(Equal("fresh"))
			}
			if tc.wantServedFromCache {
				// Cached creds prove no delegate was called.
				g.Expect(creds.AccountId).To(Equal("cached"))
			}
		})
	}
}

// TestCachedCredentialRetriever_RefreshUsesGeneralDelegate verifies the
// background refresh of an already-cached entry uses the general delegate.
func TestCachedCredentialRetriever_RefreshUsesGeneralDelegate(t *testing.T) {
	g := NewWithT(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	podUID := "refresh-pod"
	refreshed := &credentials.EksCredentialsResponse{
		AccessKeyId: "AKIA-refreshed",
		Expiration:  credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
	}

	// The general delegate must serve the refresh; the authoritative one must not.
	generalDelegate := mockcreds.NewMockCredentialRetriever(ctrl)
	generalDelegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
		Return(refreshed, responseMetadataTest("assoc"), nil).Times(1)

	authoritativeDelegate := mockcreds.NewMockCredentialRetriever(ctrl)
	authoritativeDelegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).Times(0)

	retriever := newTestRetriever(credcache.Opts{
		RenewalTtl:      time.Hour,
		MaxSize:         100,
		RefreshQPS:      3,
		CleanupInterval: 0,
	}, CachedCredentialRetrieverOpts{
		Delegate:              generalDelegate,
		AuthoritativeDelegate: authoritativeDelegate,
	})

	// Seed a cached entry, then renew it as the cache's sweep would. Storing the
	// renewal is credcache's, tested there.
	entry := &credcache.Entry{
		LogCtx:      context.Background(),
		Request:     &credentials.EksCredentialsRequest{ServiceAccountToken: sourceTestToken(t, podUID)},
		Credentials: &credentials.EksCredentialsResponse{Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)}},
		Metadata:    responseMetadataTest("assoc"),
	}
	seed(t, retriever, podUID, entry)
	next, err := entry.Owner.Renew(context.Background(), podUID, entry)

	// Verify the entry was refreshed from the general delegate.
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(next.Credentials.AccessKeyId).To(Equal("AKIA-refreshed"))
	g.Expect(next.Request).To(Equal(entry.Request))
}

// TestDelegateOwner_RenewWithoutRequest_Fails proves an entry with no request to
// replay fails its renewal without reaching a delegate.
func TestDelegateOwner_RenewWithoutRequest_Fails(t *testing.T) {
	g := NewWithT(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	delegate := mockcreds.NewMockCredentialRetriever(ctrl)
	delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).Times(0)
	retriever := newTestRetriever(credcache.Opts{RenewalTtl: time.Hour, MaxSize: 100, RefreshQPS: 3},
		CachedCredentialRetrieverOpts{Delegate: delegate, AuthoritativeDelegate: delegate})

	next, err := delegateOwner{retriever}.Renew(context.Background(), "pod", &credcache.Entry{
		Credentials: &credentials.EksCredentialsResponse{Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)}},
	})

	g.Expect(err).To(MatchError(ContainSubstring("no request to refresh them with")))
	g.Expect(next).To(BeNil())
}

// newTestRetriever builds a cachedCredentialRetriever over a new cache built
// from cacheOpts. A zero CleanupInterval turns the cache's sweep off.
func newTestRetriever(cacheOpts credcache.Opts, opts CachedCredentialRetrieverOpts) *cachedCredentialRetriever {
	if cacheOpts.CleanupInterval == 0 {
		cacheOpts.CleanupInterval = -1
	}
	opts.Cache = credcache.New(cacheOpts)
	return newCachedCredentialRetriever(opts)
}

// seed stores e for podUID as an entry r stored, failing the test if the cache
// refuses it.
func seed(t *testing.T, r *cachedCredentialRetriever, podUID string, e *credcache.Entry) {
	t.Helper()
	e.Owner = delegateOwner{r}
	if err := r.cache.Store(context.Background(), podUID, e); err != nil {
		t.Fatalf("seeding the cache for pod %s: %v", podUID, err)
	}
}

// testClock is the cache's clock in a test that seeds an entry Store would refuse.
type testClock struct{ offset time.Duration }

func (c *testClock) now() time.Time { return time.Now().Add(c.offset) }

// seedAsOfTheirIssue seeds e with clock wound back two hours, so the cache takes
// credentials that have expired since, then winds clock forward again.
func seedAsOfTheirIssue(t *testing.T, r *cachedCredentialRetriever, clock *testClock, podUID string, e *credcache.Entry) {
	t.Helper()
	clock.offset = -2 * time.Hour
	defer func() { clock.offset = 0 }()
	seed(t, r, podUID, e)
}
