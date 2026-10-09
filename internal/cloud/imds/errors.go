package imds

import (
	"errors"

	smithyhttp "github.com/aws/smithy-go/transport/http"
)

var (
	// ErrPodNotInMapping is returned when a pod is not found in the namespace mapping.
	ErrPodNotInMapping = errors.New("pod not found in IMDS namespace mapping")
	// ErrCredentialNotFound is returned when IMDS returns 404 for a credential.
	ErrCredentialNotFound = errors.New("credential not found in IMDS")
)

// isNotFound returns true if the error is an HTTP 404 from IMDS.
func isNotFound(err error) bool {
	var re *smithyhttp.ResponseError
	if errors.As(err, &re) {
		return re.HTTPStatusCode() == 404
	}
	return false
}
