package eksauth

import (
	"errors"

	"github.com/aws/aws-sdk-go-v2/service/eksauth/types"
	"github.com/aws/smithy-go"
)

const errCodeUnknown = "Unknown"

func IsIrrecoverableApiError(err error) (string, bool) {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.(type) {
		case *types.ResourceNotFoundException,
			*types.ExpiredTokenException,
			*types.InvalidTokenException,
			*types.AccessDeniedException:
			return ae.ErrorCode(), true
		default:
			return ae.ErrorCode(), false
		}
	}
	return errCodeUnknown, false
}
