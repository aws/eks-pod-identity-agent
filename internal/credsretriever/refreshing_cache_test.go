package credsretriever

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/eksauth/types"
	. "github.com/onsi/gomega"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials/mockcreds"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.uber.org/mock/gomock"
)

type responseMetadataTest string

func (receiver responseMetadataTest) AssociationId() string {
	return string(receiver)
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
				ServiceAccountToken: "some.jwt.token",
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
				ServiceAccountToken: "some.jwt.token",
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
				ServiceAccountToken: "some.jwt.token",
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
				ServiceAccountToken: "some.jwt.token",
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
				CleanupInterval:       defaultCleanupInterval,
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
				_, renew, expiration, found := retriever.internalCache.GetWithRenewExpiry(test.request.ServiceAccountToken)
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
			ServiceAccountToken: "some.jwt.token.one",
		}
		sampleResponseOne = credentials.EksCredentialsResponse{
			AccountId:  "accountOne",
			Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
		}

		sampleRequestTwo = credentials.EksCredentialsRequest{
			ServiceAccountToken: "some.jwt.token.two",
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
				CleanupInterval:       defaultCleanupInterval,
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
				ServiceAccountToken: "some.jwt.token",
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
				ServiceAccountToken: "some.jwt.token",
			},
			expectedDelegateCalls: func(delegate *mockcreds.MockCredentialRetriever) {
				gomock.InOrder(
					delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
						Return(&longDurationCreds, responseMetadataTest("test"), nil).Times(1),
					delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
						Return(nil, responseMetadataTest("test"), fmt.Errorf("error directed at cache")).MinTimes(2),
				)
			},
			expectedCredentials: longDurationCreds,
		},
		{
			name: "it evicts credentials if its an known customer API error -- AccessDenied",
			request: &credentials.EksCredentialsRequest{
				ServiceAccountToken: "some.jwt.token",
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
			},
			expectedErrMsg: "error directed at second call",
		},
		{
			name: "it does not evict credentials if its an unknown API error",
			request: &credentials.EksCredentialsRequest{
				ServiceAccountToken: "some.jwt.token",
			},
			expectedDelegateCalls: func(delegate *mockcreds.MockCredentialRetriever) {
				gomock.InOrder(
					delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
						Return(&longDurationCreds, responseMetadataTest("test"), nil).Times(1),
					delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
						Return(nil, nil, &types.InternalServerException{}).
						MinTimes(2),
				)
			},
			expectedCredentials: longDurationCreds,
		},
		{
			name: "it keeps existing credentials if delegate fails",
			request: &credentials.EksCredentialsRequest{
				ServiceAccountToken: "some.jwt.token",
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
			ServiceAccountToken: "some.jwt.token.one",
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
		{
			name: "calls with errors",
			requests: []credentials.EksCredentialsRequest{
				sampleRequestOne,
			},
			expectedDelegateCalls: func(delegate *mockcreds.MockCredentialRetriever) {
				delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).DoAndReturn(
					func(ctx context.Context, request *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
						time.Sleep(200 * time.Millisecond) // Simulate API call latency
						return nil, nil, fmt.Errorf("my special error")
					}).Times(numRequests)
			},
			expectedErrMsg: "my special error",
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
				CleanupInterval:       defaultCleanupInterval,
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

func TestCachedCredentialRetriever_GetIamCredentials_ThrottledRequestCaching(t *testing.T) {
	var (
		numRequests      = 4
		sampleRequestOne = credentials.EksCredentialsRequest{
			ServiceAccountToken: "some.jwt.token.one",
		}
		sampleResponseOne = credentials.EksCredentialsResponse{
			AccountId:  "accountOne",
			Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
		}
		sampleRequestTwo = credentials.EksCredentialsRequest{
			ServiceAccountToken: "some.jwt.token.two",
		}
		sampleRequestThree = credentials.EksCredentialsRequest{
			ServiceAccountToken: "some.jwt.token.three",
		}
		sampleResponseThree = credentials.EksCredentialsResponse{
			AccountId:  "accountOne",
			Expiration: credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
		}
		sampleRequestFour = credentials.EksCredentialsRequest{
			ServiceAccountToken: "some.jwt.token.four",
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
			name: "calls throttling error",
			expectedDelegateCalls: func(delegate *mockcreds.MockCredentialRetriever) {
				delegate.EXPECT().GetIamCredentials(gomock.Any(), &sampleRequestOne).DoAndReturn(
					func(ctx context.Context, request *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
						time.Sleep(200 * time.Millisecond) // Simulate API call latency
						response := sampleResponseOne
						return &response, responseMetadataTest("one"), nil
					}).Times(1)
				delegate.EXPECT().GetIamCredentials(gomock.Any(), &sampleRequestTwo).DoAndReturn(
					func(ctx context.Context, request *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
						time.Sleep(20 * time.Millisecond) // Simulate API call latency
						return nil, nil, errors.NewThrottledError("my special error")
					}).Times(1)
				delegate.EXPECT().GetIamCredentials(gomock.Any(), &sampleRequestThree).DoAndReturn(
					func(ctx context.Context, request *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
						time.Sleep(200 * time.Millisecond) // Simulate API call latency
						response := sampleResponseThree
						return &response, responseMetadataTest("three"), nil
					}).Times(1)
				delegate.EXPECT().GetIamCredentials(gomock.Any(), &sampleRequestFour).DoAndReturn(
					func(ctx context.Context, request *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
						time.Sleep(20 * time.Millisecond) // Simulate API call latency
						return nil, nil, fmt.Errorf("my special error")
					}).Times(1)
			},
			expectedErrMsg: "my special error",
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
				CleanupInterval:       defaultCleanupInterval,
				RefreshQPS:            1,
			}

			retriever := newCachedCredentialRetriever(opts)

			// normal request
			req := sampleRequestOne
			_, _, err := retriever.GetIamCredentials(ctx, &req)
			g.Expect(err).ToNot(HaveOccurred())

			// throttle account
			req = sampleRequestTwo
			_, _, err = retriever.GetIamCredentials(ctx, &req)
			g.Expect(err.Error()).To(ContainSubstring(test.expectedErrMsg))

			// account being throttled
			for j := 0; j < numRequests; j++ {
				req = sampleRequestThree
				_, _, err = retriever.GetIamCredentials(ctx, &req)
				g.Expect(err.Error()).To(ContainSubstring(defaultThrottlingMsg))
				req = sampleRequestFour
				_, _, err = retriever.GetIamCredentials(ctx, &req)
				g.Expect(err.Error()).To(ContainSubstring(defaultThrottlingMsg))
			}

			// wait for defaultThrottlingKey to expire after 1s
			time.Sleep(2 * time.Second)

			// account recovered from being throttled
			// normal request
			req = sampleRequestThree
			_, _, err = retriever.GetIamCredentials(ctx, &req)
			g.Expect(err).ToNot(HaveOccurred())
			// error request
			req = sampleRequestFour
			_, _, err = retriever.GetIamCredentials(ctx, &req)
			g.Expect(err.Error()).To(ContainSubstring(test.expectedErrMsg))
		})
	}
}
