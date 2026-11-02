package sts

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/protocol/query"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awssts "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	smithyauth "github.com/aws/smithy-go/auth"
	smithyendpoints "github.com/aws/smithy-go/endpoints"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	. "github.com/onsi/gomega"
)

// testOperation is a made-up operation, so the transport is tested apart from any
// real one.
const testOperation = "TestOperation"

type testOperationResponse struct {
	XMLName xml.Name `xml:"TestOperationResponse"`
	Result  struct {
		Value string `xml:"Value"`
	} `xml:"TestOperationResult"`
}

const testOperationOK = `<TestOperationResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <TestOperationResult><Value>ok</Value></TestOperationResult>
  <ResponseMetadata><RequestId>req-200</RequestId></ResponseMetadata>
</TestOperationResponse>`

func invokeTest(svc *service, creds aws.Credentials, params func(*query.Object)) (testOperationResponse, error) {
	var out testOperationResponse
	err := svc.invoke(context.Background(), creds, testOperation, params, &out)
	return out, err
}

func TestInvoke_SendsASignedAwsQueryRequestAndDecodesTheResult(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusOK, testOperationOK)

	out, err := invokeTest(pinnedService(fake), sessionCreds, func(input *query.Object) {
		input.Key("Name").String("a b&c=d")
		items := input.Key("Items").Array("member")
		items.Value().String("x")
		items.Value().String("y")
	})

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(out.Result.Value).To(Equal("ok"))
	req := fake.only(t)
	expectSignedQuery(g, req, testOperation, url.Values{"Name": {"a b&c=d"}, "Items.member.1": {"x"}, "Items.member.2": {"y"}})
	g.Expect(verifySignature(req, aws.Credentials{AccessKeyID: sessionAccessKeyID, SecretAccessKey: "another-secret", SessionToken: sessionToken}, "us-west-2")).ToNot(Succeed(),
		"the check can tell a wrong secret apart")
}

func TestInvoke_ParamsCannotOverrideActionOrVersion(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusOK, testOperationOK)

	_, err := invokeTest(pinnedService(fake), sessionCreds, func(input *query.Object) {
		input.Key("Action").String("AssumeRole")
		input.Key("Version").String("1999-01-01")
	})

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(fake.only(t).form).To(Equal(url.Values{"Action": {testOperation}, "Version": {"2011-06-15"}}))
}

func TestInvoke_ErrorResponse_DecodesToTheSDKErrorChain(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusNotFound, `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>ResourceNotFoundException</Code>
    <Message>provider not found</Message>
  </Error>
  <RequestId>req-404</RequestId>
</ErrorResponse>`)

	_, err := invokeTest(pinnedService(fake), sessionCreds, nil)

	var operationErr *smithy.OperationError
	g.Expect(errors.As(err, &operationErr)).To(BeTrue())
	g.Expect(operationErr.Service()).To(Equal("STS"))
	g.Expect(operationErr.Operation()).To(Equal(testOperation))
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

func TestInvoke_UnreadableErrorBody_FallsBackToTheStatus(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusServiceUnavailable, "upstream connect error")

	_, err := invokeTest(pinnedService(fake), sessionCreds, nil)

	var apiErr smithy.APIError
	g.Expect(errors.As(err, &apiErr)).To(BeTrue())
	g.Expect(apiErr.ErrorCode()).To(Equal("Service Unavailable"))
	g.Expect(apiErr.ErrorFault()).To(Equal(smithy.FaultServer))
}

func TestInvoke_Throttled_IsAnAPIErrorCarryingTheStatus(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusTooManyRequests, `<ErrorResponse><Error><Type>Sender</Type><Code>Throttling</Code><Message>Rate exceeded</Message></Error><RequestId>req-429</RequestId></ErrorResponse>`)

	_, err := invokeTest(pinnedService(fake), sessionCreds, nil)

	var apiErr smithy.APIError
	g.Expect(errors.As(err, &apiErr)).To(BeTrue())
	g.Expect(apiErr.ErrorCode()).To(Equal("Throttling"))
	var responseErr *awshttp.ResponseError
	g.Expect(errors.As(err, &responseErr)).To(BeTrue())
	g.Expect(responseErr.HTTPStatusCode()).To(Equal(http.StatusTooManyRequests))
	g.Expect(fake.requestCount()).To(Equal(1), "one attempt: the calling tier owns retries")
}

func TestInvoke_ErrorWithoutARequestIDInTheBody_TakesItFromTheHeader(t *testing.T) {
	g := NewWithT(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Amzn-RequestId", "req-from-header")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `<ErrorResponse><Error><Code>AccessDenied</Code><Message>no</Message></Error></ErrorResponse>`)
	}))
	defer server.Close()

	_, err := invokeTest(NewService(agentConfig(server.URL)).(*service), sessionCreds, nil)

	var responseErr *awshttp.ResponseError
	g.Expect(errors.As(err, &responseErr)).To(BeTrue())
	g.Expect(responseErr.ServiceRequestID()).To(Equal("req-from-header"))
}

func TestInvoke_UndecodableSuccessBody_IsADeserializationError(t *testing.T) {
	for name, body := range map[string]string{
		"malformed XML":     "<TestOperationResponse><unterminated>",
		"wrong root":        "<GetCallerIdentityResponse/>",
		"over the size cap": `<TestOperationResponse><TestOperationResult><Value>` + strings.Repeat("A", maxResponseBytes) + `</Value></TestOperationResult></TestOperationResponse>`,
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			fake := newFakeSTS(t, http.StatusOK, body)

			out, err := invokeTest(pinnedService(fake), sessionCreds, nil)

			var deserializationErr *smithy.DeserializationError
			g.Expect(errors.As(err, &deserializationErr)).To(BeTrue())
			g.Expect(out.Result.Value).To(BeEmpty(), "nothing is decoded from a truncated body")
		})
	}
}

func TestInvoke_NoCredentials_SendsNothing(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusOK, testOperationOK)

	_, err := invokeTest(pinnedService(fake), aws.Credentials{}, nil)

	g.Expect(err).To(MatchError(ContainSubstring("no AWS credentials")))
	g.Expect(fake.requestCount()).To(BeZero())
}

func TestInvoke_UnreachableEndpoint_IsARequestSendErrorNamingTheOperation(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusOK, testOperationOK)
	fake.server.Close()

	_, err := invokeTest(pinnedService(fake), sessionCreds, nil)

	var sendErr *smithyhttp.RequestSendError
	g.Expect(errors.As(err, &sendErr)).To(BeTrue())
	g.Expect(err.Error()).To(ContainSubstring(testOperation))
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

// fixedEndpoint is an STS endpoint resolver that always returns endpoint.
type fixedEndpoint struct{ endpoint smithyendpoints.Endpoint }

func (r fixedEndpoint) ResolveEndpoint(context.Context, awssts.EndpointParameters) (smithyendpoints.Endpoint, error) {
	return r.endpoint, nil
}

func TestResolveEndpoint_ReadsTheSigningRegionUnderEitherSigV4SchemeID(t *testing.T) {
	for _, schemeID := range []string{"aws.auth#sigv4", "sigv4"} {
		t.Run(schemeID, func(t *testing.T) {
			g := NewWithT(t)
			option := &smithyauth.Option{SchemeID: schemeID}
			smithyhttp.SetSigV4SigningRegion(&option.SignerProperties, "us-east-1")
			var properties smithy.Properties
			smithyauth.SetAuthOptions(&properties, []*smithyauth.Option{option})
			svc := NewService(aws.Config{Region: "aws-global"}).(*service)
			svc.options.EndpointResolverV2 = fixedEndpoint{smithyendpoints.Endpoint{
				URI:        url.URL{Scheme: "https", Host: "sts.amazonaws.com"},
				Properties: properties,
			}}

			_, region, err := svc.resolveEndpoint(context.Background())

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(region).To(Equal("us-east-1"), "not the client's aws-global")
		})
	}
}

func TestResolveEndpoint_NoRegion_IsAnError(t *testing.T) {
	g := NewWithT(t)
	svc := NewService(aws.Config{}).(*service)

	_, _, err := svc.resolveEndpoint(context.Background())

	g.Expect(err).To(HaveOccurred())
}
