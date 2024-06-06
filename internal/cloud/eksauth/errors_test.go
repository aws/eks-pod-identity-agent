package eksauth

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/eksauth/types"
	. "github.com/onsi/gomega"
)

func TestIsIrrecoverableApiError(t *testing.T) {
	tests := []struct {
		name   string
		errors []error
		result bool
	}{
		{
			name: "single exception, can be identified as irrecoverable",
			errors: []error{
				&types.AccessDeniedException{},
				&types.ExpiredTokenException{},
				&types.InvalidTokenException{},
				&types.ResourceNotFoundException{},
			},
			result: true,
		},
		{
			name: "single exception, can be identified as recoverable",
			errors: []error{
				&types.InternalServerException{},
			},
			result: false,
		},
		{
			name: "single exception, can be identified as irrecoverable if wrapped",
			errors: []error{
				fmt.Errorf("error, layer 1: %w", &types.AccessDeniedException{}),
			},
			result: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			g := NewWithT(t)

			for _, err := range test.errors {
				g.Expect(IsIrrecoverableApiError(err)).To(Equal(test.result))
			}
		})
	}
}
