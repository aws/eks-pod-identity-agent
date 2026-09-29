package sts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/smithy-go"
	. "github.com/onsi/gomega"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

const (
	testProviderArn = "arn:aws:iam::111122223333:workload-identity-provider/example"
	nodeAccessKeyID = "AKIDNODEROLE"
	nodeToken       = "node-session-token"
)

// fakeSTS is an httptest STS endpoint that records every request it is sent and
// answers with a canned status and body.
type fakeSTS struct {
	server *httptest.Server
	status int
	body   string

	mu       sync.Mutex
	requests []recordedRequest
}

type recordedRequest struct {
	method string
	path   string
	host   string
	header http.Header
	body   []byte
	form   url.Values
}

func newFakeSTS(t *testing.T, status int, body string) *fakeSTS {
	t.Helper()
	f := &fakeSTS{status: status, body: body}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(raw))
		f.mu.Lock()
		f.requests = append(f.requests, recordedRequest{method: r.Method, path: r.URL.Path, host: r.Host, header: r.Header.Clone(), body: raw, form: form})
		f.mu.Unlock()
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(f.status)
		_, _ = io.WriteString(w, f.body)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeSTS) only(t *testing.T) recordedRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 1 {
		t.Fatalf("fake STS received %d requests, expected 1", len(f.requests))
	}
	return f.requests[0]
}

// nodeConfig is the agent's own AWS configuration: the node's credentials,
// pointed at the fake.
func nodeConfig(endpoint string) aws.Config {
	return aws.Config{
		Region:       "us-west-2",
		Credentials:  credentials.NewStaticCredentialsProvider(nodeAccessKeyID, "node-secret", nodeToken),
		BaseEndpoint: aws.String(endpoint),
	}
}

const twoBundlesResponse = `<GetTrustBundlesResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetTrustBundlesResult>
    <TrustBundles>
      <member>
        <TrustDomain>example.org</TrustDomain>
        <Bundle>{"keys":[{"use":"jwt-svid","kid":"k1"}],"spiffe_refresh_hint":300}</Bundle>
      </member>
      <member>
        <TrustDomain>peer.example.org</TrustDomain>
        <Bundle>{"keys":[]}</Bundle>
      </member>
    </TrustBundles>
  </GetTrustBundlesResult>
  <ResponseMetadata>
    <RequestId>c6104cbe-af31-11e0-8154-cbc7ccf896c7</RequestId>
  </ResponseMetadata>
</GetTrustBundlesResponse>`

func TestGetTrustBundles_SendsAnAwsQueryRequestSignedWithTheNodeCredentials(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusOK, twoBundlesResponse)

	_, err := NewService(nodeConfig(fake.server.URL)).GetTrustBundles(context.Background(), testProviderArn)
	g.Expect(err).ToNot(HaveOccurred())

	req := fake.only(t)
	g.Expect(req.method).To(Equal(http.MethodPost))
	g.Expect(req.header.Get("Content-Type")).To(HavePrefix("application/x-www-form-urlencoded"))
	g.Expect(req.form).To(Equal(url.Values{
		"Action":      {"GetTrustBundles"},
		"Version":     {"2011-06-15"},
		"ProviderArn": {testProviderArn},
	}))

	// SigV4 over the node's credentials, scoped to STS in the client's region
	authorization := req.header.Get("Authorization")
	g.Expect(authorization).To(HavePrefix("AWS4-HMAC-SHA256 "))
	g.Expect(authorization).To(MatchRegexp(`Credential=` + nodeAccessKeyID + `/\d{8}/us-west-2/sts/aws4_request`))
	g.Expect(authorization).To(ContainSubstring("SignedHeaders="))
	g.Expect(req.header.Get("X-Amz-Security-Token")).To(Equal(nodeToken))
	g.Expect(req.header.Get("X-Amz-Date")).ToNot(BeEmpty())
	g.Expect(req.header.Get("X-Amz-Content-Sha256")).To(BeEmpty(), "STS signs the payload hash without sending it")
	g.Expect(verifySignature(req, aws.Credentials{AccessKeyID: nodeAccessKeyID, SecretAccessKey: "node-secret", SessionToken: nodeToken}, "us-west-2")).To(Succeed())
	g.Expect(verifySignature(req, aws.Credentials{AccessKeyID: nodeAccessKeyID, SecretAccessKey: "another-secret", SessionToken: nodeToken}, "us-west-2")).ToNot(Succeed(),
		"the check can tell a wrong secret apart")
}

// verifySignature recomputes the SigV4 signature the way STS does: it re-signs
// the headers the Authorization header lists with creds at the request's own
// X-Amz-Date and compares. Unlike a shape check, that catches a wrong payload
// hash, signing time, scope or secret.
func verifySignature(req recordedRequest, creds aws.Credentials, region string) error {
	authorization := req.header.Get("Authorization")
	_, signedPart, found := strings.Cut(authorization, "SignedHeaders=")
	if !found {
		return errors.New("no SignedHeaders in the Authorization header")
	}
	signedHeaders, _, _ := strings.Cut(signedPart, ",")
	signingTime, err := time.Parse("20060102T150405Z", req.header.Get("X-Amz-Date"))
	if err != nil {
		return err
	}

	rebuilt, err := http.NewRequest(req.method, "http://"+req.host+req.path, bytes.NewReader(req.body))
	if err != nil {
		return err
	}
	rebuilt.Header = http.Header{}
	for _, name := range strings.Split(signedHeaders, ";") {
		if name == "host" || name == "x-amz-date" || name == "x-amz-security-token" {
			continue
		}
		if name == "content-length" {
			continue
		}
		rebuilt.Header.Set(name, req.header.Get(name))
	}
	if !strings.Contains(";"+signedHeaders+";", ";content-length;") {
		rebuilt.ContentLength = 0
	}
	hash := sha256.Sum256(req.body)
	if err := v4.NewSigner().SignHTTP(context.Background(), creds, rebuilt, hex.EncodeToString(hash[:]), "sts", region, signingTime); err != nil {
		return err
	}
	if expected := rebuilt.Header.Get("Authorization"); expected != authorization {
		return fmt.Errorf("signature mismatch:\n got  %s\n want %s", authorization, expected)
	}
	return nil
}

func TestGetTrustBundles_DecodesEveryEntryInResponseOrder(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusOK, twoBundlesResponse)

	entries, err := NewService(nodeConfig(fake.server.URL)).GetTrustBundles(context.Background(), testProviderArn)

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(entries).To(Equal([]TrustBundle{
		{TrustDomain: "example.org", Bundle: `{"keys":[{"use":"jwt-svid","kid":"k1"}],"spiffe_refresh_hint":300}`},
		{TrustDomain: "peer.example.org", Bundle: `{"keys":[]}`},
	}))
}

func TestGetTrustBundles_EmptyList_DecodesToNoEntries(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusOK, `<GetTrustBundlesResponse><GetTrustBundlesResult><TrustBundles/></GetTrustBundlesResult></GetTrustBundlesResponse>`)

	entries, err := NewService(nodeConfig(fake.server.URL)).GetTrustBundles(context.Background(), testProviderArn)

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(entries).To(BeEmpty())
}

func TestGetTrustBundles_ErrorResponse_DecodesToTheSDKErrorChain(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusNotFound, `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>ResourceNotFoundException</Code>
    <Message>provider not found</Message>
  </Error>
  <RequestId>req-404</RequestId>
</ErrorResponse>`)

	_, err := NewService(nodeConfig(fake.server.URL)).GetTrustBundles(context.Background(), testProviderArn)

	var operationErr *smithy.OperationError
	g.Expect(errors.As(err, &operationErr)).To(BeTrue())
	g.Expect(operationErr.Service()).To(Equal("STS"))
	g.Expect(operationErr.Operation()).To(Equal("GetTrustBundles"))
	var apiErr smithy.APIError
	g.Expect(errors.As(err, &apiErr)).To(BeTrue())
	g.Expect(apiErr.ErrorCode()).To(Equal("ResourceNotFoundException"))
	g.Expect(apiErr.ErrorMessage()).To(Equal("provider not found"))
	g.Expect(apiErr.ErrorFault()).To(Equal(smithy.FaultClient))
	var responseErr *awshttp.ResponseError
	g.Expect(errors.As(err, &responseErr)).To(BeTrue())
	g.Expect(responseErr.HTTPStatusCode()).To(Equal(http.StatusNotFound))
	g.Expect(responseErr.ServiceRequestID()).To(Equal("req-404"))
}

func TestGetTrustBundles_UnreadableErrorBody_FallsBackToTheStatus(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusServiceUnavailable, "upstream connect error")

	_, err := NewService(nodeConfig(fake.server.URL)).GetTrustBundles(context.Background(), testProviderArn)

	var apiErr smithy.APIError
	g.Expect(errors.As(err, &apiErr)).To(BeTrue())
	g.Expect(apiErr.ErrorCode()).To(Equal("Service Unavailable"))
	g.Expect(apiErr.ErrorFault()).To(Equal(smithy.FaultServer))
}

func TestGetTrustBundles_MalformedSuccessBody_IsADeserializationError(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusOK, "<GetTrustBundlesResponse><unterminated>")

	_, err := NewService(nodeConfig(fake.server.URL)).GetTrustBundles(context.Background(), testProviderArn)

	var deserializationErr *smithy.DeserializationError
	g.Expect(errors.As(err, &deserializationErr)).To(BeTrue())
}

func TestGetTrustBundles_WrongRootElement_IsADeserializationError(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusOK, "<GetCallerIdentityResponse/>")

	_, err := NewService(nodeConfig(fake.server.URL)).GetTrustBundles(context.Background(), testProviderArn)

	var deserializationErr *smithy.DeserializationError
	g.Expect(errors.As(err, &deserializationErr)).To(BeTrue())
}

func TestGetTrustBundles_CredentialFailure_SendsNothing(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusOK, twoBundlesResponse)
	cfg := nodeConfig(fake.server.URL)
	cfg.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{}, errors.New("IMDS unreachable")
	})

	_, err := NewService(cfg).GetTrustBundles(context.Background(), testProviderArn)

	g.Expect(err).To(MatchError(ContainSubstring("IMDS unreachable")))
	fake.mu.Lock()
	defer fake.mu.Unlock()
	g.Expect(fake.requests).To(BeEmpty())
}

func TestGetTrustBundles_NoCredentials_IsAnError(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusOK, twoBundlesResponse)
	cfg := nodeConfig(fake.server.URL)
	cfg.Credentials = nil

	_, err := NewService(cfg).GetTrustBundles(context.Background(), testProviderArn)

	g.Expect(err).To(MatchError(ContainSubstring("no AWS credentials")))
}

func TestGetTrustBundles_UnreachableEndpoint_IsARequestSendError(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusOK, twoBundlesResponse)
	fake.server.Close()

	_, err := NewService(nodeConfig(fake.server.URL)).GetTrustBundles(context.Background(), testProviderArn)

	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("GetTrustBundles"))
}

func TestResolveEndpoint_FollowsTheSDKsSTSEndpointRules(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg    aws.Config
		host   string
		region string
	}{
		"regional":        {cfg: aws.Config{Region: "us-west-2"}, host: "sts.us-west-2.amazonaws.com", region: "us-west-2"},
		"china partition": {cfg: aws.Config{Region: "cn-north-1"}, host: "sts.cn-north-1.amazonaws.com.cn", region: "cn-north-1"},
		"govcloud":        {cfg: aws.Config{Region: "us-gov-west-1"}, host: "sts.us-gov-west-1.amazonaws.com", region: "us-gov-west-1"},
		// the rules name a signing region other than the client's here, which is
		// the case reading it off the endpoint's auth scheme exists for
		"global pseudo-region": {cfg: aws.Config{Region: "aws-global"}, host: "sts.amazonaws.com", region: "us-east-1"},
		"base endpoint set":    {cfg: aws.Config{Region: "eu-west-1", BaseEndpoint: aws.String("https://sts.gamma.example.com")}, host: "sts.gamma.example.com", region: "eu-west-1"},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			svc := NewService(tc.cfg).(*service)

			endpoint, region, err := svc.resolveEndpoint(context.Background())

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(endpoint.URI.Scheme).To(Equal("https"))
			g.Expect(endpoint.URI.Host).To(Equal(tc.host))
			g.Expect(region).To(Equal(tc.region))
		})
	}
}

func TestResolveEndpoint_FIPS_UsesTheFIPSEndpoint(t *testing.T) {
	g := NewWithT(t)
	svc := NewService(aws.Config{Region: "us-east-1"}).(*service)
	svc.options.EndpointOptions.UseFIPSEndpoint = aws.FIPSEndpointStateEnabled

	endpoint, _, err := svc.resolveEndpoint(context.Background())

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(strings.HasPrefix(endpoint.URI.Host, "sts-fips.")).To(BeTrue(), endpoint.URI.Host)
}

func TestResolveEndpoint_DualStack_UsesTheDualStackEndpoint(t *testing.T) {
	g := NewWithT(t)
	svc := NewService(aws.Config{Region: "us-west-2"}).(*service)
	svc.options.EndpointOptions.UseDualStackEndpoint = aws.DualStackEndpointStateEnabled

	endpoint, _, err := svc.resolveEndpoint(context.Background())

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(endpoint.URI.Host).To(Equal("sts.us-west-2.api.aws"))
}

func TestGetTrustBundles_ErrorWithoutARequestIDInTheBody_TakesItFromTheHeader(t *testing.T) {
	g := NewWithT(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Amzn-RequestId", "req-from-header")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `<ErrorResponse><Error><Code>AccessDenied</Code><Message>no</Message></Error></ErrorResponse>`)
	}))
	defer server.Close()

	_, err := NewService(nodeConfig(server.URL)).GetTrustBundles(context.Background(), testProviderArn)

	var responseErr *awshttp.ResponseError
	g.Expect(errors.As(err, &responseErr)).To(BeTrue())
	g.Expect(responseErr.ServiceRequestID()).To(Equal("req-from-header"))
}

func TestGetTrustBundles_OversizedResponse_IsRefusedNotTruncatedIntoAResult(t *testing.T) {
	g := NewWithT(t)
	oversized := `<GetTrustBundlesResponse><GetTrustBundlesResult><TrustBundles><member><TrustDomain>example.org</TrustDomain><Bundle>` +
		strings.Repeat("A", maxResponseBytes) + `</Bundle></member></TrustBundles></GetTrustBundlesResult></GetTrustBundlesResponse>`
	fake := newFakeSTS(t, http.StatusOK, oversized)

	entries, err := NewService(nodeConfig(fake.server.URL)).GetTrustBundles(context.Background(), testProviderArn)

	g.Expect(entries).To(BeNil())
	var deserializationErr *smithy.DeserializationError
	g.Expect(errors.As(err, &deserializationErr)).To(BeTrue())
}

func TestResolveEndpoint_NoRegion_IsAnError(t *testing.T) {
	g := NewWithT(t)
	svc := NewService(aws.Config{}).(*service)

	_, _, err := svc.resolveEndpoint(context.Background())

	g.Expect(err).To(HaveOccurred())
}
