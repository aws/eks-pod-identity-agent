package eksauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eksauth"
	. "github.com/onsi/gomega"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/imds"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// capturingRoundTripper records the outbound request body so tests can assert
// which fields were serialized and sent to EKS Auth.
type capturingRoundTripper struct {
	capturedBody string
	response     string
}

func (c *capturingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		bodyBytes, _ := io.ReadAll(req.Body)
		c.capturedBody = string(bodyBytes)
	}
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(c.response)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}, nil
}

// newTestService builds a service backed by a capturing HTTP transport so we can
// inspect exactly what is sent to the Auth API.
func newTestService(rt http.RoundTripper, nodeMetadata *imds.NodeMetadata) *service {
	cfg := aws.Config{
		Region:      "us-west-2",
		Credentials: aws.AnonymousCredentials{},
		HTTPClient:  &http.Client{Transport: rt},
	}
	client := eksauth.NewFromConfig(cfg, func(o *eksauth.Options) {
		o.BaseEndpoint = aws.String("https://eks-auth.us-west-2.amazonaws.com")
		// Avoid retries so the capturing transport sees exactly one call.
		o.Retryer = aws.NopRetryer{}
	})
	return &service{
		eksAuthService: client,
		nodeMetadata:   nodeMetadata,
	}
}

const validAssumeRoleResponse = `{
  "credentials": {
    "accessKeyId": "ASIATEST",
    "secretAccessKey": "secret",
    "sessionToken": "token",
    "expiration": 1893456000
  },
  "assumedRoleUser": {
    "arn": "arn:aws:sts::123456789012:assumed-role/my-role/session",
    "assumeRoleId": "AROAEXAMPLE:session"
  },
  "podIdentityAssociation": {
    "associationId": "a-abc123",
    "associationArn": "arn:aws:eks:us-west-2:123456789012:podidentityassociation/cluster/a-abc123"
  },
  "subject": {
    "namespace": "default",
    "serviceAccount": "my-sa"
  }
}`

func TestGetIamCredentials_NodeMetadataSerialization(t *testing.T) {
	testCases := []struct {
		name          string
		nodeMetadata  *imds.NodeMetadata
		expectPresent []string
		expectAbsent  []string
	}{
		{
			name: "zone present is serialized",
			nodeMetadata: &imds.NodeMetadata{
				Zone: "usw2-az1",
			},
			expectPresent: []string{"usw2-az1"},
		},
		{
			name:          "nil node metadata omits zone",
			nodeMetadata:  nil,
			expectPresent: []string{"jwt-token"},
			expectAbsent:  []string{"zone"},
		},
		{
			name: "empty zone is not present",
			nodeMetadata: &imds.NodeMetadata{
				Zone: "",
			},
			expectPresent: []string{"jwt-token"},
			expectAbsent:  []string{"usw2-az1"},
		},
		{
			name:          "all-empty non-nil struct still produces a valid request",
			nodeMetadata:  &imds.NodeMetadata{},
			expectPresent: []string{"jwt-token"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			rt := &capturingRoundTripper{response: validAssumeRoleResponse}
			svc := newTestService(rt, tc.nodeMetadata)

			_, _, err := svc.GetIamCredentials(context.Background(), &credentials.EksCredentialsRequest{
				ClusterName:         "test-cluster",
				ServiceAccountToken: "jwt-token",
			})

			g.Expect(err).NotTo(HaveOccurred())
			for _, s := range tc.expectPresent {
				g.Expect(rt.capturedBody).To(ContainSubstring(s))
			}
			for _, s := range tc.expectAbsent {
				g.Expect(rt.capturedBody).NotTo(ContainSubstring(s))
			}
		})
	}
}

func TestGetIamCredentials_ReturnsParsedCredentials(t *testing.T) {
	g := NewWithT(t)

	rt := &capturingRoundTripper{response: validAssumeRoleResponse}
	svc := newTestService(rt, &imds.NodeMetadata{Zone: "z"})

	resp, meta, err := svc.GetIamCredentials(context.Background(), &credentials.EksCredentialsRequest{
		ClusterName:         "test-cluster",
		ServiceAccountToken: "jwt-token",
	})

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(resp.AccessKeyId).To(Equal("ASIATEST"))
	g.Expect(resp.AccountId).To(Equal("123456789012"))
	g.Expect(meta.AssociationId()).To(Equal("a-abc123"))
}

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

// TestNewService_IMDSDisabled_SkipsMetadataFetch verifies that when the IMDS
// feature is disabled, NewService does not fetch node metadata
func TestNewService_IMDSDisabled_SkipsMetadataFetch(t *testing.T) {
	g := NewWithT(t)
	logger.Initialize("error")

	cfg := aws.Config{
		Region:      "us-west-2",
		Credentials: aws.AnonymousCredentials{},
	}

	iface := NewService(context.Background(), cfg, false)

	svc, ok := iface.(*service)
	g.Expect(ok).To(BeTrue())
	g.Expect(svc.nodeMetadata).To(BeNil())
}
