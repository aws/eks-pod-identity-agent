package errors

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/eksauth/types"
	"github.com/aws/smithy-go"
	http2 "github.com/aws/smithy-go/transport/http"
	. "github.com/onsi/gomega"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

func Test_HandleCredentialFetchingError(t *testing.T) {
	testCases := []struct {
		name             string
		inputError       error
		expectedMsg      string
		expectedHttpCode int
	}{
		{
			name: "simple operational error",
			inputError: &smithy.OperationError{
				ServiceID:     "Some Service",
				OperationName: "SomeOperation",
				Err:           fmt.Errorf("failed to get region"),
			},
			expectedHttpCode: 500,
		},
		{
			name: "operational with response, no reply",
			inputError: &smithy.OperationError{
				ServiceID:     "Some Service",
				OperationName: "SomeOperation",
				Err: &awshttp.ResponseError{
					RequestID: "some-request-id",
					ResponseError: &http2.ResponseError{
						Response: &http2.Response{Response: &http.Response{
							StatusCode: 0,
						}},
						Err: &http2.RequestSendError{
							Err: fmt.Errorf("some-error"),
						},
					},
				},
			},
			expectedHttpCode: 500,
		},
		{
			name: "error from server, returns valid code",
			inputError: &smithy.OperationError{
				ServiceID:     "Some Service",
				OperationName: "SomeOperation",
				Err: &awshttp.ResponseError{
					RequestID: "some-request-id",
					ResponseError: &http2.ResponseError{
						Response: &http2.Response{Response: &http.Response{
							StatusCode: 400,
						}},
						Err: &types.InvalidTokenException{
							Message: aws.String("some-invalid-msg"),
						},
					},
				},
			},
			expectedHttpCode: 400,
		},
		{
			name:             "validation error",
			inputError:       fmt.Errorf("wrapping error: %w", NewAccessDeniedError("error")),
			expectedHttpCode: http.StatusForbidden,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			ctx := context.Background()

			// trigger
			msg, httpCode := HandleCredentialFetchingError(ctx, tc.inputError)

			// validate
			g.Expect(msg).To(ContainSubstring(tc.expectedMsg))
			g.Expect(httpCode).To(Equal(tc.expectedHttpCode))
		})
	}
}
