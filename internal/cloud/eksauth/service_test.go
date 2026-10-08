package eksauth

// Most of these tests run the real SDK client, built by NewService, against the
// fake EKS Auth in eksauthtest; the upstream tests from capturingRoundTripper on
// build a service directly. They're in-package so they can assert on the
// unexported client and middleware, which only works while eksauthtest doesn't
// import this package.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awseksauth "github.com/aws/aws-sdk-go-v2/service/eksauth"
	"github.com/aws/aws-sdk-go-v2/service/eksauth/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/eksauth/eksauthtest"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/imds"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
)

const (
	testClusterName = "test-cluster"
	testToken       = "projected-service-account-token"
	// providerArnMember is spelled here, not read from the middleware's struct
	// tag, so a wrong tag fails these tests.
	providerArnMember = "workloadIdentityProviderArn"
)

// testExpiration has a fractional second the SDK keeps exactly: it keeps
// milliseconds, and a quarter second is exact in binary, so it survives the
// trip through a JSON number and a float64.
var testExpiration = time.Unix(1790000000, 250*int64(time.Millisecond)).UTC()

func credentialsRequest() *credentials.EksCredentialsRequest {
	return &credentials.EksCredentialsRequest{ClusterName: testClusterName, ServiceAccountToken: testToken}
}

// getIamCredentials calls GetIamCredentials on a new client for cfg.
func getIamCredentials(ctx context.Context, cfg aws.Config) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
	return NewService(ctx, cfg, false).GetIamCredentials(ctx, credentialsRequest())
}

func TestGetIamCredentials_DecodesEveryFieldOfAnEnrolledSession(t *testing.T) {
	g := NewWithT(t)
	fake := eksauthtest.New(t)
	session := eksauthtest.EnrolledSession(testExpiration)
	fake.SetSession(session)

	got, metadata, err := getIamCredentials(context.Background(), fake.Config())
	g.Expect(err).ToNot(HaveOccurred())

	// The whole struct is compared, so a field added to the response and not
	// decoded fails here rather than going unnoticed.
	g.Expect(got).To(Equal(&credentials.EksCredentialsResponse{
		AccessKeyId:     session.AccessKeyID,
		SecretAccessKey: session.SecretAccessKey,
		Token:           session.SessionToken,
		AccountId:       eksauthtest.AccountID,
		Expiration:      credentials.SdkCompliantExpirationTime{Time: testExpiration},
	}))
	g.Expect(metadata).ToNot(BeNil())
	g.Expect(metadata.AssociationId()).To(Equal(session.AssociationID))
	g.Expect(metadata.ProviderArn()).To(Equal(session.ProviderArn))
	g.Expect(metadata.ProviderArn()).ToNot(BeEmpty())
}

func TestGetIamCredentials_LeavesProviderArnEmptyWhenTheMemberIsAbsent(t *testing.T) {
	g := NewWithT(t)
	fake := eksauthtest.New(t)
	session := eksauthtest.NotEnrolledSession(testExpiration)
	fake.SetSession(session)

	got, metadata, err := getIamCredentials(context.Background(), fake.Config())
	g.Expect(err).ToNot(HaveOccurred())

	// An absent member is how EKS Auth answers for a pod not enrolled, so the
	// call succeeds with the same credentials as before.
	g.Expect(got).To(Equal(&credentials.EksCredentialsResponse{
		AccessKeyId:     session.AccessKeyID,
		SecretAccessKey: session.SecretAccessKey,
		Token:           session.SessionToken,
		AccountId:       eksauthtest.AccountID,
		Expiration:      credentials.SdkCompliantExpirationTime{Time: testExpiration},
	}))
	g.Expect(metadata.AssociationId()).To(Equal(session.AssociationID))
	g.Expect(metadata.ProviderArn()).To(BeEmpty())
}

func TestGetIamCredentials_TreatsANullMemberAsAbsent(t *testing.T) {
	g := NewWithT(t)
	fake := eksauthtest.New(t)
	document := successDocument()
	document[providerArnMember] = nil
	fake.SetRawResponse(http.StatusOK, mustJSON(t, document))

	got, metadata, err := getIamCredentials(context.Background(), fake.Config())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(metadata.ProviderArn()).To(BeEmpty())
	g.Expect(got.AccessKeyId).To(Equal(eksauthtest.EnrolledSession(testExpiration).AccessKeyID))
}

// TestGetIamCredentials_ReadsAMistypedMemberAsAbsent pins the hot path's
// tolerance: a member of the wrong type records nothing, and the pod still gets
// its credentials, read as not enrolled.
func TestGetIamCredentials_ReadsAMistypedMemberAsAbsent(t *testing.T) {
	for name, value := range map[string]any{
		"number":  42,
		"boolean": true,
		"object":  map[string]any{"arn": "arn:aws:iam::111122223333:workload-identity-provider/example"},
		"array":   []any{"arn:aws:iam::111122223333:workload-identity-provider/example"},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			fake := eksauthtest.New(t)
			document := successDocument()
			document[providerArnMember] = value
			fake.SetRawResponse(http.StatusOK, mustJSON(t, document))

			got, metadata, err := getIamCredentials(context.Background(), fake.Config())
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(metadata.ProviderArn()).To(BeEmpty())
			session := eksauthtest.EnrolledSession(testExpiration)
			g.Expect(got.AccessKeyId).To(Equal(session.AccessKeyID))
			g.Expect(got.SecretAccessKey).To(Equal(session.SecretAccessKey))
			g.Expect(got.Token).To(Equal(session.SessionToken))
			g.Expect(metadata.AssociationId()).To(Equal(session.AssociationID))
		})
	}
}

// TestGetIamCredentials_IgnoresMembersItDoesNotRead proves that a member EKS
// Auth's model does not have, such as a stray spiffeId, neither fails the call
// nor changes what is decoded, whatever its type: the middleware reads its one
// member and the SDK drops what it does not model.
func TestGetIamCredentials_IgnoresMembersItDoesNotRead(t *testing.T) {
	g := NewWithT(t)
	fake := eksauthtest.New(t)
	svc := NewService(context.Background(), fake.Config(), false)

	fake.SetRawResponse(http.StatusOK, mustJSON(t, successDocument()))
	want, wantMetadata, err := svc.GetIamCredentials(context.Background(), credentialsRequest())
	g.Expect(err).ToNot(HaveOccurred())

	document := successDocument()
	document["spiffeId"] = "spiffe://example.org/ns/default/sa/example-sa"
	document["someFutureMember"] = map[string]any{"nested": []any{1, true, nil}}
	fake.SetRawResponse(http.StatusOK, mustJSON(t, document))

	got, metadata, err := svc.GetIamCredentials(context.Background(), credentialsRequest())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(got).To(Equal(want))
	g.Expect(metadata.AssociationId()).To(Equal(wantMetadata.AssociationId()))
	g.Expect(metadata.ProviderArn()).To(Equal(eksauthtest.EnrolledSession(testExpiration).ProviderArn))
}

func TestGetIamCredentials_SendsTheOperationSignedByTheNode(t *testing.T) {
	g := NewWithT(t)
	fake := eksauthtest.New(t)

	_, _, err := getIamCredentials(context.Background(), fake.Config())
	g.Expect(err).ToNot(HaveOccurred())

	requests := fake.Requests()
	g.Expect(requests).To(HaveLen(1))
	request := requests[0]
	g.Expect(request.Method).To(Equal(http.MethodPost))
	g.Expect(request.Path).To(Equal("/clusters/" + testClusterName + "/assume-role-for-pod-identity"))
	g.Expect(request.ClusterName).To(Equal(testClusterName))
	g.Expect(request.Token).To(Equal(testToken))
	g.Expect(request.Header.Get("Content-Type")).To(Equal("application/json"))

	var body map[string]any
	g.Expect(json.Unmarshal(request.Body, &body)).To(Succeed())
	// The service is built with node metadata off, so the request names no zone.
	g.Expect(body).To(Equal(map[string]any{"token": testToken}),
		"the body carries the token and nothing else")

	// Signed by the node credentials, for the eks-auth service in the
	// configured region.
	authorization := request.Header.Get("Authorization")
	g.Expect(authorization).To(HavePrefix("AWS4-HMAC-SHA256 Credential=" + eksauthtest.NodeAccessKeyID + "/"))
	g.Expect(authorization).To(ContainSubstring("/" + eksauthtest.Region + "/eks-auth/aws4_request"))
	g.Expect(request.Header.Get("X-Amz-Security-Token")).To(Equal(eksauthtest.NodeSessionToken))
}

// isA reports whether err wraps a T, the way a caller classifying the error
// would look for it.
func isA[T error](err error) bool {
	var target T
	return errors.As(err, &target)
}

func TestGetIamCredentials_SurfacesEveryModelledErrorAsItsSDKType(t *testing.T) {
	tests := []struct {
		name          string
		apiErr        *eksauthtest.APIError
		isType        func(error) bool
		irrecoverable bool
	}{
		{"AccessDenied", eksauthtest.AccessDenied(), isA[*types.AccessDeniedException], true},
		{"ExpiredToken", eksauthtest.ExpiredToken(), isA[*types.ExpiredTokenException], true},
		{"InvalidParameter", eksauthtest.InvalidParameter(), isA[*types.InvalidParameterException], false},
		{"InvalidRequest", eksauthtest.InvalidRequest(), isA[*types.InvalidRequestException], false},
		{"InvalidToken", eksauthtest.InvalidToken(), isA[*types.InvalidTokenException], true},
		{"ResourceNotFound", eksauthtest.ResourceNotFound(), isA[*types.ResourceNotFoundException], true},
		{"Throttling", eksauthtest.Throttling(), isA[*types.ThrottlingException], false},
		{"InternalServer", eksauthtest.InternalServer(), isA[*types.InternalServerException], false},
		{"ServiceUnavailable", eksauthtest.ServiceUnavailable(), isA[*types.ServiceUnavailableException], false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			g := NewWithT(t)
			fake := eksauthtest.New(t)
			fake.SetError(test.apiErr)

			got, metadata, err := getIamCredentials(context.Background(), fake.Config())
			g.Expect(err).To(HaveOccurred())
			g.Expect(got).To(BeNil())
			g.Expect(metadata).To(BeNil())

			// The middleware is installed on this call, so this is also the proof
			// that it leaves an error response for the SDK to decode.
			g.Expect(test.isType(err)).To(BeTrue(), "%v does not wrap the modelled type", err)
			var apiErr smithy.APIError
			g.Expect(errors.As(err, &apiErr)).To(BeTrue())
			g.Expect(apiErr.ErrorCode()).To(Equal(test.apiErr.Code))
			g.Expect(apiErr.ErrorMessage()).To(Equal(test.apiErr.Message))
			var responseErr *awshttp.ResponseError
			g.Expect(errors.As(err, &responseErr)).To(BeTrue())
			g.Expect(responseErr.HTTPStatusCode()).To(Equal(test.apiErr.Status))
			g.Expect(err.Error()).ToNot(ContainSubstring(testToken))

			code, irrecoverable := IsIrrecoverableApiError(err)
			g.Expect(code).To(Equal(test.apiErr.Code))
			g.Expect(irrecoverable).To(Equal(test.irrecoverable))
		})
	}
}

// successDocument is a complete successful response body as a map, for the
// tests that break one part of it.
func successDocument() map[string]any {
	session := eksauthtest.EnrolledSession(testExpiration)
	return map[string]any{
		"assumedRoleUser": map[string]any{
			"arn":          session.AssumedRoleArn,
			"assumeRoleId": session.AssumeRoleID,
		},
		"audience": session.Audience,
		"credentials": map[string]any{
			"accessKeyId":     session.AccessKeyID,
			"secretAccessKey": session.SecretAccessKey,
			"sessionToken":    session.SessionToken,
			"expiration":      json.Number("1790000000.25"),
		},
		"podIdentityAssociation": map[string]any{
			"associationArn": session.AssociationArn,
			"associationId":  session.AssociationID,
		},
		"subject": map[string]any{
			"namespace":      session.Namespace,
			"serviceAccount": session.ServiceAccount,
		},
		providerArnMember: session.ProviderArn,
	}
}

func mustJSON(t *testing.T, document any) []byte {
	t.Helper()
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encoding %v: %v", document, err)
	}
	return body
}

func TestGetIamCredentials_ReportsABodyThatIsNotAJSONObject(t *testing.T) {
	for name, body := range map[string]string{
		"not JSON":   "<html>not json</html>",
		"truncated":  `{"credentials": {"accessKeyId": "ASIA`,
		"JSON array": `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			fake := eksauthtest.New(t)
			fake.SetRawResponse(http.StatusOK, []byte(body))

			got, _, err := getIamCredentials(context.Background(), fake.Config())
			g.Expect(got).To(BeNil())
			// The middleware leaves a body it cannot read to the SDK, so the error
			// is the SDK's own deserialization error.
			var deserializationErr *smithy.DeserializationError
			g.Expect(errors.As(err, &deserializationErr)).To(BeTrue(), "%v", err)
		})
	}
}

// TestGetIamCredentials_ReportsAResponseMissingAMemberItReads proves a 200
// response missing any member GetIamCredentials dereferences is an invalid
// response error rather than a panic. The cache's janitor and the workload
// identity session tier call it on their own goroutines, where a panic ends
// the agent.
func TestGetIamCredentials_ReportsAResponseMissingAMemberItReads(t *testing.T) {
	for _, path := range [][]string{
		{"credentials"},
		{"credentials", "accessKeyId"},
		{"credentials", "secretAccessKey"},
		{"credentials", "sessionToken"},
		{"credentials", "expiration"},
		{"assumedRoleUser"},
		{"assumedRoleUser", "arn"},
		{"assumedRoleUser", "assumeRoleId"},
		{"podIdentityAssociation"},
		{"podIdentityAssociation", "associationId"},
	} {
		t.Run(strings.Join(path, "."), func(t *testing.T) {
			g := NewWithT(t)
			document := successDocument()
			parent := document
			for _, member := range path[:len(path)-1] {
				parent = parent[member].(map[string]any)
			}
			delete(parent, path[len(path)-1])
			fake := eksauthtest.New(t)
			fake.SetRawResponse(http.StatusOK, mustJSON(t, document))

			var got *credentials.EksCredentialsResponse
			var err error
			g.Expect(func() { got, _, err = getIamCredentials(context.Background(), fake.Config()) }).NotTo(Panic())
			g.Expect(got).To(BeNil())
			g.Expect(err).To(MatchError(ContainSubstring("invalid response from server")))
		})
	}
}

// TestGetIamCredentials_DecodesTheFirstValueAsTheSDKDoes pins that the
// middleware and the SDK agree on a body with bytes after its object. The SDK
// decodes the first JSON value and ignores the rest, so the middleware has to
// as well, or an enrolled pod would read as not enrolled.
func TestGetIamCredentials_DecodesTheFirstValueAsTheSDKDoes(t *testing.T) {
	g := NewWithT(t)
	fake := eksauthtest.New(t)
	fake.SetRawResponse(http.StatusOK, append(mustJSON(t, successDocument()), []byte(" trailing")...))

	got, metadata, err := getIamCredentials(context.Background(), fake.Config())
	g.Expect(err).ToNot(HaveOccurred())
	session := eksauthtest.EnrolledSession(testExpiration)
	g.Expect(metadata.ProviderArn()).To(Equal(session.ProviderArn))
	g.Expect(got.AccessKeyId).To(Equal(session.AccessKeyID))
}

// TestGetIamCredentials_ReadsTheMemberOffTheAttemptThatSucceeded runs the
// middleware under the SDK's standard retryer. The deserialize step runs once
// per attempt and the retry middleware returns the last attempt's metadata, so
// the member of a retried call comes from the response that was decoded.
func TestGetIamCredentials_ReadsTheMemberOffTheAttemptThatSucceeded(t *testing.T) {
	g := NewWithT(t)
	fake := eksauthtest.New(t)
	session := eksauthtest.EnrolledSession(testExpiration)
	var mu sync.Mutex
	calls := 0
	fake.SetFunc(func(eksauthtest.Request) (*eksauthtest.Session, *eksauthtest.APIError) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			return nil, eksauthtest.Throttling()
		}
		return &session, nil
	})
	cfg := fake.Config()
	cfg.Retryer = func() aws.Retryer {
		return retry.NewStandard(func(o *retry.StandardOptions) {
			o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
		})
	}

	_, metadata, err := getIamCredentials(context.Background(), cfg)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(fake.Calls()).To(Equal(2))
	g.Expect(metadata.ProviderArn()).To(Equal(session.ProviderArn))
}

func TestGetIamCredentials_ReturnsWhenTheContextEnds(t *testing.T) {
	g := NewWithT(t)
	fake := eksauthtest.New(t)
	fake.Block()
	defer fake.Release()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 1)
	go func() {
		_, _, err := getIamCredentials(ctx, fake.Config())
		errs <- err
	}()
	g.Expect(fake.WaitForBlocked(context.Background(), 1)).To(Succeed())
	cancel()

	g.Expect(errors.Is(<-errs, context.Canceled)).To(BeTrue())
}

// deserializeStep returns an optFn that records the IDs of the deserialize step,
// in order, from the stack of the call it is passed to. APIOptions run in the
// order they were appended, so passed after withWorkloadIdentityProviderArn it
// sees the step as that left it.
func deserializeStep(ids *[]string) func(*awseksauth.Options) {
	return func(options *awseksauth.Options) {
		options.APIOptions = append(options.APIOptions, func(stack *middleware.Stack) error {
			*ids = stack.Deserialize.List()
			return nil
		})
	}
}

func assumeRoleInput() *awseksauth.AssumeRoleForPodIdentityInput {
	return &awseksauth.AssumeRoleForPodIdentityInput{
		ClusterName: aws.String(testClusterName),
		Token:       aws.String(testToken),
	}
}

// TestWorkloadIdentityProviderArnMiddleware_RunsInsideTheOperationDeserializer pins
// the order the middleware depends on: it has to be inside (after)
// OperationDeserializer to see the body before it's consumed, so an SDK change
// that moves it fails with the reason.
func TestWorkloadIdentityProviderArnMiddleware_RunsInsideTheOperationDeserializer(t *testing.T) {
	g := NewWithT(t)
	fake := eksauthtest.New(t)
	client := NewService(context.Background(), fake.Config(), false).(*service).eksAuthService
	middlewareID := workloadIdentityProviderArnMiddleware{}.ID()

	var ids []string
	out, err := client.AssumeRoleForPodIdentity(context.Background(), assumeRoleInput(),
		withWorkloadIdentityProviderArn, deserializeStep(&ids))
	g.Expect(err).ToNot(HaveOccurred())
	t.Logf("deserialize step, outermost first: %v", ids)

	g.Expect(ids).ToNot(BeEmpty())
	g.Expect(ids[len(ids)-1]).To(Equal(middlewareID), "the middleware is innermost")
	g.Expect(slices.Index(ids, "OperationDeserializer")).To(BeNumerically(">=", 0))
	g.Expect(slices.Index(ids, "OperationDeserializer")).To(BeNumerically("<", slices.Index(ids, middlewareID)))

	// And the SDK still decoded the body the middleware had already read.
	g.Expect(out.Credentials).ToNot(BeNil())
	g.Expect(aws.ToString(out.Credentials.AccessKeyId)).To(Equal(eksauthtest.EnrolledSession(time.Time{}).AccessKeyID))
}

func TestWorkloadIdentityProviderArnMiddleware_IsInstalledPerCallOnly(t *testing.T) {
	g := NewWithT(t)
	fake := eksauthtest.New(t)
	svc := NewService(context.Background(), fake.Config(), false).(*service)
	client := svc.eksAuthService
	apiOptionsBefore := len(client.Options().APIOptions)

	_, _, err := svc.GetIamCredentials(context.Background(), credentialsRequest())
	g.Expect(err).ToNot(HaveOccurred())

	// The call did not leave the middleware on its client.
	g.Expect(client.Options().APIOptions).To(HaveLen(apiOptionsBefore))
	var ids []string
	_, err = client.AssumeRoleForPodIdentity(context.Background(), assumeRoleInput(), deserializeStep(&ids))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(ids).To(ContainElement("OperationDeserializer"))
	g.Expect(ids).ToNot(ContainElement(workloadIdentityProviderArnMiddleware{}.ID()))
}

func TestGetIamCredentials_LogsTheSessionButNeverItsSecrets(t *testing.T) {
	g := NewWithT(t)
	fake := eksauthtest.New(t)
	session := eksauthtest.EnrolledSession(testExpiration)
	fake.SetSession(session)
	logs := captureLog(t)

	_, _, err := getIamCredentials(context.Background(), fake.Config())
	g.Expect(err).ToNot(HaveOccurred())

	var fields map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var entry map[string]any
		g.Expect(json.Unmarshal([]byte(line), &entry)).To(Succeed())
		if entry["msg"] == "Successfully fetched credentials from EKS Auth" {
			fields = entry
		}
	}
	g.Expect(fields).ToNot(BeNil(), "no success line in %s", logs.String())
	g.Expect(fields).To(HaveKey("request_time_ms"))
	g.Expect(fields).To(HaveKeyWithValue("fetched_role_arn", session.AssumedRoleArn))
	g.Expect(fields).To(HaveKeyWithValue("fetched_role_id", session.AssumeRoleID))

	for _, secret := range []string{session.AccessKeyID, session.SecretAccessKey, session.SessionToken, testToken,
		eksauthtest.NodeSecretAccessKey, eksauthtest.NodeSessionToken} {
		g.Expect(logs.String()).ToNot(ContainSubstring(secret))
	}
}

// syncBuffer is a bytes.Buffer safe to read while logrus writes to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLog redirects the logger package's output into a buffer for the length
// of the test, as pkg/grpcserver's tests do. FromContext hands back an entry
// whose Logger is the package's unexported global, already initialised by the
// blank import of internal/test.
func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	// The level is pinned too, since a test that calls logger.Initialize leaves a
	// quieter global behind.
	global := logger.FromContext(context.Background()).Logger
	previous, previousLevel := global.Out, global.GetLevel()
	global.SetOutput(buf)
	global.SetLevel(logrus.TraceLevel)
	t.Cleanup(func() {
		global.SetOutput(previous)
		global.SetLevel(previousLevel)
	})
	return buf
}

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
	client := awseksauth.NewFromConfig(cfg, func(o *awseksauth.Options) {
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

	client := awseksauth.NewFromConfig(aws.Config{
		Region: "us-west-2",
		Credentials: aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "fake", SecretAccessKey: "fake", SessionToken: "fake"}, nil
		}),
	}, func(o *awseksauth.Options) {
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
