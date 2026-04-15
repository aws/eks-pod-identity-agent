package eksauth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eksauth"
	. "github.com/onsi/gomega"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
)

// TestGetIamCredentials_ReturnsAuthServiceSource verifies that GetIamCredentials for
// the EKS Auth Service delegate returns the correct source.
func TestGetIamCredentials_ReturnsAuthServiceSource(t *testing.T) {
	g := NewWithT(t)
	logger.Initialize("error")
	const associationID = "a-1234567890abcdef0"

	// Use an httptest server to simulate an AssumeRoleForPodIdentity call, forcing
	// GetIamCredentials to construct ResponseMetadata.
	// Response format per the EKS Auth AssumeRoleForPodIdentity API:
	// https://docs.aws.amazon.com/eks/latest/APIReference/API_auth_AssumeRoleForPodIdentity.html#API_auth_AssumeRoleForPodIdentity_ResponseSyntax
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"assumedRoleUser": {
				"arn": "arn:aws:sts::123456789012:assumed-role/my-role/session",
				"assumeRoleId": "AROA1234567890EXAMPLE:session"
			},
			"audience": "pods.eks.amazonaws.com",
			"credentials": {
				"accessKeyId": "AKIAIOSFODNN7EXAMPLE",
				"secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"sessionToken": "FwoGZXIvYXdzEBY",
				"expiration": 1924905600
			},
			"podIdentityAssociation": {
				"associationArn": "arn:aws:eks:us-west-2:123456789012:podidentityassociation/my-cluster/%s",
				"associationId": "%s"
			},
			"subject": {
				"namespace": "default",
				"serviceAccount": "my-sa"
			}
		}`, associationID, associationID)
	}))
	defer server.Close()

	client := eksauth.NewFromConfig(aws.Config{
		Region: "us-west-2",
		Credentials: aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "fake", SecretAccessKey: "fake", SessionToken: "fake"}, nil
		}),
	}, func(o *eksauth.Options) {
		o.BaseEndpoint = aws.String(server.URL)
	})

	svc := &service{eksAuthService: client}
	resp, meta, err := svc.GetIamCredentials(context.Background(), &credentials.EksCredentialsRequest{
		ClusterName:         "my-cluster",
		ServiceAccountToken: "fake-token",
	})

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(meta.Source()).To(Equal(credentials.SourceAuthService))
	g.Expect(meta.AssociationId()).To(Equal(associationID))
	g.Expect(resp.AccessKeyId).To(Equal("AKIAIOSFODNN7EXAMPLE"))
	g.Expect(resp.AccountId).To(Equal("123456789012"))
}

func TestResponseMetadata_AuthService_ReturnsCorrectSource(t *testing.T) {
	g := NewWithT(t)
	meta := responseMetadata("assoc-123")
	g.Expect(meta.Source()).To(Equal(credentials.SourceAuthService))
}

func TestResponseMetadata_AssociationId_Preserved(t *testing.T) {
	g := NewWithT(t)
	meta := responseMetadata("assoc-456")
	g.Expect(meta.AssociationId()).To(Equal("assoc-456"))
}
