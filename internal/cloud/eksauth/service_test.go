package eksauth

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eksauth"
	. "github.com/onsi/gomega"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/imds"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
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
		name         string
		nodeMetadata *imds.NodeMetadata
		// substrings expected to be present in the serialized request body
		expectPresent []string
		// substrings expected to be absent from the serialized request body
		expectAbsent []string
	}{
		{
			name: "all fields present are serialized",
			nodeMetadata: &imds.NodeMetadata{
				EksNodeName: "ip-10-0-1-42.us-west-2.compute.internal",
				InstanceId:  "i-0abc123def456",
				Zone:        "usw2-az1",
			},
			expectPresent: []string{"ip-10-0-1-42.us-west-2.compute.internal", "i-0abc123def456", "usw2-az1"},
		},
		{
			name:          "nil node metadata omits all node fields",
			nodeMetadata:  nil,
			expectPresent: []string{"jwt-token"},
			expectAbsent:  []string{"eksNodeName", "instanceId", "zone"},
		},
		{
			name: "partial fields are sent as-is",
			nodeMetadata: &imds.NodeMetadata{
				EksNodeName: "ip-10-0-1-42.us-west-2.compute.internal",
				InstanceId:  "i-0abc123def456",
				Zone:        "",
			},
			expectPresent: []string{"ip-10-0-1-42.us-west-2.compute.internal", "i-0abc123def456"},
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
	svc := newTestService(rt, &imds.NodeMetadata{EksNodeName: "n", InstanceId: "i", Zone: "z"})

	resp, meta, err := svc.GetIamCredentials(context.Background(), &credentials.EksCredentialsRequest{
		ClusterName:         "test-cluster",
		ServiceAccountToken: "jwt-token",
	})

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(resp.AccessKeyId).To(Equal("ASIATEST"))
	g.Expect(resp.AccountId).To(Equal("123456789012"))
	g.Expect(meta.AssociationId()).To(Equal("a-abc123"))
}
