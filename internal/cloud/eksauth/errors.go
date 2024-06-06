package eksauth

import (
	"errors"

	"github.com/aws/aws-sdk-go-v2/service/eksauth/types"
	"github.com/aws/smithy-go"
)

func IsIrrecoverableApiError(err error) bool {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.(type) {
		case *types.ResourceNotFoundException,
			*types.ExpiredTokenException,
			*types.InvalidTokenException,
			*types.AccessDeniedException:
			return true
		default:
			return false
		}
	}
	return false
}
