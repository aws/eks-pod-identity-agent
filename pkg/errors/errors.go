package errors

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	"github.com/sirupsen/logrus"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
)

type HttpCodeProvidingError interface {
	HttpStatus() int
}

// RequestValidationError is an error indicating the request validation failure.
type RequestValidationError struct {
	Code    int
	Message string
}

func (e *RequestValidationError) Error() string {
	return e.Message
}

func (e *RequestValidationError) HttpStatus() int {
	return e.Code
}

func NewRequestValidationError(errorMessage string) *RequestValidationError {
	return &RequestValidationError{
		Message: errorMessage,
		Code:    http.StatusBadRequest,
	}
}

type AccessDeniedError struct {
	Code    int
	Message string
}

func (e *AccessDeniedError) Error() string {
	return fmt.Sprintf("Access Denied. %s", e.Message)
}

func (e *AccessDeniedError) HttpStatus() int {
	return e.Code
}

func NewAccessDeniedError(reason string) *AccessDeniedError {
	return &AccessDeniedError{
		Message: reason,
		Code:    http.StatusForbidden,
	}
}

type ThrottledError struct {
	Code    int
	Message string
}

func (e *ThrottledError) Error() string {
	return fmt.Sprintf("Too Many Requests. %s", e.Message)
}

func (e *ThrottledError) HttpStatus() int {
	return e.Code
}

func NewThrottledError(reason string) *ThrottledError {
	return &ThrottledError{
		Message: reason,
		Code:    http.StatusTooManyRequests,
	}
}

func HandleCredentialFetchingError(ctx context.Context, err error) (string, int) {
	log := logger.FromContext(ctx)
	defer func() {
		log.Errorf("Error fetching credentials: %v", err)
	}()

	// first try to get validation errors, if there is one short-circuit and return
	var hcpe HttpCodeProvidingError
	if errors.As(err, &hcpe) {
		return err.Error(), hcpe.HttpStatus()
	}

	// grab some metadata about the service failure if there is any
	var oe *smithy.OperationError
	if errors.As(err, &oe) {
		log = log.WithFields(logrus.Fields{
			"service":   oe.Service(),
			"operation": oe.Operation(),
		})
	}

	var errMsg []string
	httpCode := http.StatusInternalServerError

	var re *awshttp.ResponseError
	if errors.As(err, &re) {
		log = log.WithFields(logrus.Fields{
			"request-id": re.ServiceRequestID(),
		})
		// response error does not necessarily imply that there was an HTTP code response
		if re.HTTPStatusCode() != 0 {
			httpCode = re.HTTPStatusCode()
		}
		errMsg = append(errMsg, "["+re.RequestID+"]")
	}

	var ae smithy.APIError
	if errors.As(err, &ae) {
		errMsg = append(errMsg, fmt.Sprintf("(%s): %s, fault: %s", ae.ErrorCode(), ae.ErrorMessage(), ae.ErrorFault().String()))
	}

	if len(errMsg) == 0 {
		return err.Error(), httpCode
	} else {
		return strings.Join(errMsg, ": "), httpCode
	}
}
