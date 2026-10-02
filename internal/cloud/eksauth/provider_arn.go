package eksauth

// The released SDK (eksauth v1.11.7) doesn't model the response member
// workloadIdentityProviderArn, which EKS Auth sets only on an enrolled vend, so
// GetIamCredentials installs this middleware to read it off the raw body.
// Delete this file when the SDK ships the field at launch, and read
// creds.WorkloadIdentityProviderArn in GetIamCredentials instead.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eksauth"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// withWorkloadIdentityProviderArn adds the middleware to one call. The SDK
// applies per-call options to a copy of the client's options, so the client's
// own APIOptions never gain it.
func withWorkloadIdentityProviderArn(o *eksauth.Options) {
	o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
		// After is innermost in the deserialize step, so the middleware sees the
		// body before the SDK's deserializer consumes it.
		return stack.Deserialize.Add(workloadIdentityProviderArnMiddleware{}, middleware.After)
	})
}

type workloadIdentityProviderArnKey struct{}

type workloadIdentityProviderArnMiddleware struct{}

func (workloadIdentityProviderArnMiddleware) ID() string { return "WorkloadIdentityProviderArn" }

// HandleDeserialize reads workloadIdentityProviderArn off a 2xx body and hands
// the SDK a replayable copy. A body it can't decode records nothing: the SDK
// reports a malformed body, and GetIamCredentials reads a mistyped member as
// absent.
func (workloadIdentityProviderArnMiddleware) HandleDeserialize(ctx context.Context, in middleware.DeserializeInput,
	next middleware.DeserializeHandler) (middleware.DeserializeOutput, middleware.Metadata, error) {
	out, metadata, err := next.HandleDeserialize(ctx, in)
	resp, ok := out.RawResponse.(*smithyhttp.Response)
	if err != nil || !ok || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return out, metadata, err
	}

	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return out, metadata, &smithy.DeserializationError{Err: fmt.Errorf("failed to read response body, %w", err)}
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))

	var member struct {
		WorkloadIdentityProviderArn *string `json:"workloadIdentityProviderArn"`
	}
	if json.NewDecoder(bytes.NewReader(body)).Decode(&member) == nil {
		metadata.Set(workloadIdentityProviderArnKey{}, aws.ToString(member.WorkloadIdentityProviderArn))
	}
	return out, metadata, nil
}
