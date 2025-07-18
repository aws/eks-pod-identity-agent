package eksauth

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/eksauth/types"
	. "github.com/onsi/gomega"
)

func TestIsIrrecoverableApiError(t *testing.T) {
	tests := []struct {
		name          string
		errors        []error
		expectedCodes []string
		expectedOk    bool
	}{
		{
			name: "single exception, can be identified as irrecoverable",
			errors: []error{
				&types.AccessDeniedException{},
				&types.ExpiredTokenException{},
				&types.InvalidTokenException{},
				&types.ResourceNotFoundException{},
			},
			expectedCodes: []string{
				"AccessDeniedException",
				"ExpiredTokenException",
				"InvalidTokenException",
				"ResourceNotFoundException",
			},
			expectedOk: true,
		},
		{
			name: "single exception, can be identified as recoverable",
			errors: []error{
				&types.InternalServerException{},
			},
			expectedCodes: []string{
				"InternalServerException",
			},
			expectedOk: false,
		},
		{
			name: "single exception, can be identified as irrecoverable if wrapped",
			errors: []error{
				fmt.Errorf("error, layer 1: %w", &types.AccessDeniedException{}),
			},
			expectedCodes: []string{
				"AccessDeniedException",
			},
			expectedOk: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			g := NewWithT(t)

			for i, err := range test.errors {
				code, ok := IsIrrecoverableApiError(err)
				g.Expect(ok).To(Equal(test.expectedOk))
				g.Expect(code).To(Equal(test.expectedCodes[i]))
			}
		})
	}
}
