package eksauthtest

// These tests prove each capability of the fake through the real SDK client, so
// that what they establish is what any client built on the SDK will see.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awseksauth "github.com/aws/aws-sdk-go-v2/service/eksauth"
	"github.com/aws/aws-sdk-go-v2/service/eksauth/types"
	"github.com/aws/smithy-go"
	. "github.com/onsi/gomega"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/eksauth"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
)

const (
	testClusterName = "test-cluster"
	testToken       = "projected-service-account-token"
	// serverTestTimeout bounds every wait in this file, so a fake that fails to
	// answer fails the test instead of hanging the suite.
	serverTestTimeout = 5 * time.Second
)

func serverTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), serverTestTimeout)
	t.Cleanup(cancel)
	return ctx
}

func assumeRole(ctx context.Context, client *awseksauth.Client) (*awseksauth.AssumeRoleForPodIdentityOutput, error) {
	return client.AssumeRoleForPodIdentity(ctx, &awseksauth.AssumeRoleForPodIdentityInput{
		ClusterName: aws.String(testClusterName),
		Token:       aws.String(testToken),
	})
}

// assumeRoleAsync makes the call on a new goroutine and returns the channel its
// error arrives on. The channel is buffered so the goroutine finishes even if
// the test stops reading.
func assumeRoleAsync(ctx context.Context, client *awseksauth.Client) <-chan error {
	errs := make(chan error, 1)
	go func() {
		_, err := assumeRole(ctx, client)
		errs <- err
	}()
	return errs
}

func awaitCall(t *testing.T, ctx context.Context, errs <-chan error) error {
	t.Helper()
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		t.Fatalf("call did not return before the test context expired: %v", ctx.Err())
		return nil
	}
}

// rawPost sends an unsigned request and returns the status and the decoded
// JSON body. The fake does not verify signatures, and this is the only way to
// see the member the SDK drops.
func rawPost(t *testing.T, url string, body string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(url+"/clusters/"+testClusterName+"/assume-role-for-pod-identity", "application/json",
		bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("posting to the fake: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the fake's response: %v", err)
	}
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("decoding %q: %v", raw, err)
	}
	return resp.StatusCode, document
}

func TestServer_AnswersWithAnEnrolledSessionForAnHourByDefault(t *testing.T) {
	g := NewWithT(t)
	fake := New(t)

	before := time.Now().Truncate(time.Millisecond)
	out, err := assumeRole(context.Background(), awseksauth.NewFromConfig(fake.Config()))
	after := time.Now()
	g.Expect(err).ToNot(HaveOccurred())

	want := EnrolledSession(time.Time{})
	g.Expect(aws.ToString(out.Credentials.AccessKeyId)).To(Equal(want.AccessKeyID))
	g.Expect(aws.ToString(out.AssumedRoleUser.Arn)).To(Equal(want.AssumedRoleArn))
	g.Expect(aws.ToString(out.Audience)).To(Equal(DefaultAudience))
	g.Expect(*out.Credentials.Expiration).To(BeTemporally(">=", before.Add(time.Hour)))
	g.Expect(*out.Credentials.Expiration).To(BeTemporally("<=", after.Add(time.Hour)))

	// The member the SDK drops is there too, read by the agent's client.
	_, metadata, err := eksauth.NewService(context.Background(), fake.Config(), false).GetIamCredentials(context.Background(),
		&credentials.EksCredentialsRequest{ClusterName: testClusterName, ServiceAccountToken: testToken})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(metadata.ProviderArn()).To(Equal(want.ProviderArn))
}

func TestServer_SetSessionControlsEveryMember(t *testing.T) {
	g := NewWithT(t)
	fake := New(t)
	expiration := time.Unix(1790000000, 250*int64(time.Millisecond)).UTC()
	session := Session{
		AccessKeyID:     "ASIACUSTOMACCESSKEY1",
		SecretAccessKey: "custom-secret",
		SessionToken:    "custom-session-token",
		Expiration:      expiration,
		AssumedRoleArn:  "arn:aws:sts::444455556666:assumed-role/custom-role/custom-session",
		AssumeRoleID:    "AROACUSTOM:custom-session",
		AssociationArn:  "arn:aws:eks:us-west-2:444455556666:podidentityassociation/c/a-custom",
		AssociationID:   "a-custom",
		Namespace:       "custom-ns",
		ServiceAccount:  "custom-sa",
		ProviderArn:     "arn:aws:iam::444455556666:workload-identity-provider/custom",
	}
	fake.SetSession(session)

	out, err := assumeRole(context.Background(), awseksauth.NewFromConfig(fake.Config()))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(aws.ToString(out.Credentials.AccessKeyId)).To(Equal(session.AccessKeyID))
	g.Expect(aws.ToString(out.Credentials.SecretAccessKey)).To(Equal(session.SecretAccessKey))
	g.Expect(aws.ToString(out.Credentials.SessionToken)).To(Equal(session.SessionToken))
	g.Expect(*out.Credentials.Expiration).To(Equal(expiration), "fractional epoch seconds survive to the millisecond")
	g.Expect(aws.ToString(out.AssumedRoleUser.Arn)).To(Equal(session.AssumedRoleArn))
	g.Expect(aws.ToString(out.AssumedRoleUser.AssumeRoleId)).To(Equal(session.AssumeRoleID))
	g.Expect(aws.ToString(out.PodIdentityAssociation.AssociationArn)).To(Equal(session.AssociationArn))
	g.Expect(aws.ToString(out.PodIdentityAssociation.AssociationId)).To(Equal(session.AssociationID))
	g.Expect(aws.ToString(out.Subject.Namespace)).To(Equal(session.Namespace))
	g.Expect(aws.ToString(out.Subject.ServiceAccount)).To(Equal(session.ServiceAccount))
	g.Expect(aws.ToString(out.Audience)).To(Equal(DefaultAudience), "an empty Audience is sent as the default")

	_, metadata, err := eksauth.NewService(context.Background(), fake.Config(), false).GetIamCredentials(context.Background(),
		&credentials.EksCredentialsRequest{ClusterName: testClusterName, ServiceAccountToken: testToken})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(metadata.ProviderArn()).To(Equal(session.ProviderArn))
}

func TestServer_SendsTheUnmodelledMemberOnlyWhenSet(t *testing.T) {
	g := NewWithT(t)
	fake := New(t)
	expiration := time.Unix(1790000000, 250*int64(time.Millisecond))

	fake.SetSession(EnrolledSession(expiration))
	status, enrolled := rawPost(t, fake.URL, `{"token":"t"}`)
	g.Expect(status).To(Equal(http.StatusOK))
	// Spelled out rather than taken from the constant, so the name on the wire
	// is pinned to EKS Auth's model and not to whatever the constant says.
	g.Expect(enrolled).To(HaveKeyWithValue("workloadIdentityProviderArn", EnrolledSession(expiration).ProviderArn))
	// The wire shape the SDK needs: lowerCamel members and the expiration as a
	// JSON number of epoch seconds, not a string.
	g.Expect(enrolled).To(HaveKeyWithValue("audience", DefaultAudience))
	g.Expect(enrolled["credentials"]).To(HaveKeyWithValue("expiration", json.Number("1790000000.25")))
	g.Expect(enrolled).To(HaveKey("assumedRoleUser"))
	g.Expect(enrolled).To(HaveKey("podIdentityAssociation"))
	g.Expect(enrolled).To(HaveKey("subject"))

	fake.SetSession(NotEnrolledSession(expiration))
	_, notEnrolled := rawPost(t, fake.URL, `{"token":"t"}`)
	g.Expect(notEnrolled).ToNot(HaveKey("workloadIdentityProviderArn"))
	g.Expect(notEnrolled).To(HaveKey("credentials"))
}

func TestServer_ServesSessionsWithLittleOrNoLifeLeft(t *testing.T) {
	g := NewWithT(t)
	fake := New(t)
	client := awseksauth.NewFromConfig(fake.Config())

	for _, expiration := range []time.Time{
		time.Now().Add(2 * time.Second),
		time.Now().Add(-time.Minute),
	} {
		fake.SetSession(EnrolledSession(expiration))
		out, err := assumeRole(context.Background(), client)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(*out.Credentials.Expiration).To(Equal(expiration.Truncate(time.Millisecond).UTC()))
	}
}

// isA reports whether err wraps a T.
func isA[T error](err error) bool {
	var target T
	return errors.As(err, &target)
}

func TestServer_ErrorsDecodeToTheSDKsModelledTypes(t *testing.T) {
	tests := []struct {
		apiErr *APIError
		isType func(error) bool
	}{
		{AccessDenied(), isA[*types.AccessDeniedException]},
		{ExpiredToken(), isA[*types.ExpiredTokenException]},
		{InvalidParameter(), isA[*types.InvalidParameterException]},
		{InvalidRequest(), isA[*types.InvalidRequestException]},
		{InvalidToken(), isA[*types.InvalidTokenException]},
		{ResourceNotFound(), isA[*types.ResourceNotFoundException]},
		{Throttling(), isA[*types.ThrottlingException]},
		{InternalServer(), isA[*types.InternalServerException]},
		{ServiceUnavailable(), isA[*types.ServiceUnavailableException]},
	}
	for _, test := range tests {
		t.Run(test.apiErr.Code, func(t *testing.T) {
			g := NewWithT(t)
			fake := New(t)
			fake.SetError(test.apiErr)

			_, err := assumeRole(context.Background(), awseksauth.NewFromConfig(fake.Config()))
			g.Expect(test.isType(err)).To(BeTrue(), "%v", err)
			var apiErr smithy.APIError
			g.Expect(errors.As(err, &apiErr)).To(BeTrue())
			g.Expect(apiErr.ErrorCode()).To(Equal(test.apiErr.Code))
			g.Expect(apiErr.ErrorMessage()).To(Equal(test.apiErr.Message))
			var responseErr *awshttp.ResponseError
			g.Expect(errors.As(err, &responseErr)).To(BeTrue())
			g.Expect(responseErr.HTTPStatusCode()).To(Equal(test.apiErr.Status))
			g.Expect(responseErr.ServiceRequestID()).To(Equal("eksauthtest-1"))
		})
	}
}

func TestServer_AnUnmodelledOrMissingCodeIsAGenericError(t *testing.T) {
	g := NewWithT(t)
	fake := New(t)
	client := awseksauth.NewFromConfig(fake.Config())

	fake.SetError(&APIError{Status: http.StatusBadRequest, Code: "SomethingNewException", Message: "new"})
	_, err := assumeRole(context.Background(), client)
	var generic *smithy.GenericAPIError
	g.Expect(errors.As(err, &generic)).To(BeTrue(), "%v", err)
	g.Expect(generic.ErrorCode()).To(Equal("SomethingNewException"))

	fake.SetError(&APIError{Message: "no code"})
	_, err = assumeRole(context.Background(), client)
	g.Expect(errors.As(err, &generic)).To(BeTrue(), "%v", err)
	g.Expect(generic.ErrorCode()).To(Equal("UnknownError"))
	var responseErr *awshttp.ResponseError
	g.Expect(errors.As(err, &responseErr)).To(BeTrue())
	g.Expect(responseErr.HTTPStatusCode()).To(Equal(http.StatusBadRequest), "a zero Status is sent as 400")
}

func TestServer_SetFuncAnswersPerRequest(t *testing.T) {
	g := NewWithT(t)
	fake := New(t)
	client := awseksauth.NewFromConfig(fake.Config())

	var mu sync.Mutex
	var seen []Request
	fake.SetFunc(func(r Request) (*Session, *APIError) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, r)
		switch len(seen) {
		case 1:
			return nil, Throttling()
		case 2:
			session := NotEnrolledSession(time.Now().Add(time.Minute))
			return &session, nil
		default:
			return nil, nil
		}
	})

	_, err := assumeRole(context.Background(), client)
	g.Expect(isA[*types.ThrottlingException](err)).To(BeTrue(), "%v", err)
	out, err := assumeRole(context.Background(), client)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(aws.ToString(out.Credentials.AccessKeyId)).To(Equal(NotEnrolledSession(time.Time{}).AccessKeyID))
	_, err = assumeRole(context.Background(), client)
	g.Expect(err).ToNot(HaveOccurred(), "a nil session and nil error answer with the default")

	mu.Lock()
	defer mu.Unlock()
	g.Expect(seen).To(HaveLen(3))
	g.Expect(seen[0].ClusterName).To(Equal(testClusterName))
	g.Expect(seen[0].Token).To(Equal(testToken))
}

func TestServer_TheLastSetterWinsAndResetRestoresTheDefault(t *testing.T) {
	g := NewWithT(t)
	fake := New(t)
	client := awseksauth.NewFromConfig(fake.Config())
	custom := EnrolledSession(time.Now().Add(time.Minute))
	custom.AccessKeyID = "ASIACUSTOMACCESSKEY1"

	fake.SetError(AccessDenied())
	fake.SetSession(custom)
	out, err := assumeRole(context.Background(), client)
	g.Expect(err).ToNot(HaveOccurred(), "SetSession replaced the error")
	g.Expect(aws.ToString(out.Credentials.AccessKeyId)).To(Equal(custom.AccessKeyID))

	fake.SetRawResponse(http.StatusOK, []byte("not json"))
	fake.SetError(InternalServer())
	_, err = assumeRole(context.Background(), client)
	g.Expect(isA[*types.InternalServerException](err)).To(BeTrue(), "SetError replaced the raw response: %v", err)

	fake.SetError(nil)
	out, err = assumeRole(context.Background(), client)
	g.Expect(err).ToNot(HaveOccurred(), "SetError(nil) restores the default")
	g.Expect(aws.ToString(out.Credentials.AccessKeyId)).To(Equal(EnrolledSession(time.Time{}).AccessKeyID))

	fake.SetFunc(func(Request) (*Session, *APIError) { return nil, Throttling() })
	fake.Reset()
	_, err = assumeRole(context.Background(), client)
	g.Expect(err).ToNot(HaveOccurred(), "Reset restores the default")
}

func TestServer_SetErrorCopiesItsArgument(t *testing.T) {
	g := NewWithT(t)
	fake := New(t)
	apiErr := AccessDenied()
	fake.SetError(apiErr)
	apiErr.Code = "InternalServerException"
	apiErr.Status = http.StatusInternalServerError

	_, err := assumeRole(context.Background(), awseksauth.NewFromConfig(fake.Config()))
	g.Expect(isA[*types.AccessDeniedException](err)).To(BeTrue(), "%v", err)
}

func TestServer_SetRawResponseSendsExactlyThat(t *testing.T) {
	g := NewWithT(t)
	fake := New(t)
	client := awseksauth.NewFromConfig(fake.Config())

	fake.SetRawResponse(0, []byte("{}"))
	out, err := assumeRole(context.Background(), client)
	g.Expect(err).ToNot(HaveOccurred(), "a zero status is sent as 200")
	g.Expect(out.Credentials).To(BeNil(), "the SDK does not enforce required members")

	fake.SetRawResponse(http.StatusOK, []byte("<html>"))
	_, err = assumeRole(context.Background(), client)
	g.Expect(isA[*smithy.DeserializationError](err)).To(BeTrue(), "%v", err)
}

func TestServer_RecordsEveryRequest(t *testing.T) {
	g := NewWithT(t)
	fake := New(t)
	g.Expect(fake.Calls()).To(Equal(0))

	_, err := assumeRole(context.Background(), awseksauth.NewFromConfig(fake.Config()))
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(fake.Calls()).To(Equal(1))
	requests := fake.Requests()
	g.Expect(requests).To(HaveLen(1))
	request := requests[0]
	g.Expect(request.Method).To(Equal(http.MethodPost))
	g.Expect(request.Path).To(Equal("/clusters/" + testClusterName + "/assume-role-for-pod-identity"))
	g.Expect(request.ClusterName).To(Equal(testClusterName))
	g.Expect(request.Token).To(Equal(testToken))
	g.Expect(request.Body).To(MatchJSON(`{"token": "` + testToken + `"}`))
	g.Expect(request.Header.Get("Authorization")).To(HavePrefix("AWS4-HMAC-SHA256 Credential=" + NodeAccessKeyID + "/"))
	g.Expect(request.Header.Get("Authorization")).To(ContainSubstring("/" + Region + "/eks-auth/aws4_request"))

	// Requests hands out copies.
	requests[0].Header.Set("Authorization", "changed")
	requests[0].Body[0] = 'X'
	again := fake.Requests()[0]
	g.Expect(again.Header.Get("Authorization")).ToNot(Equal("changed"))
	g.Expect(again.Body).To(MatchJSON(`{"token": "` + testToken + `"}`))
}

func TestServer_AnswersAnythingElseWith404AndRecordsIt(t *testing.T) {
	g := NewWithT(t)
	fake := New(t)
	// Not parked, even with the gate closed: only the operation is gated.
	fake.Block()
	defer fake.Release()

	for _, request := range []struct{ method, path string }{
		{http.MethodGet, "/clusters/" + testClusterName + "/assume-role-for-pod-identity"},
		{http.MethodPost, "/clusters/" + testClusterName + "/something-else"},
		{http.MethodPost, "/"},
	} {
		req, err := http.NewRequest(request.method, fake.URL+request.path, bytes.NewBufferString(`{"token":"t"}`))
		g.Expect(err).ToNot(HaveOccurred())
		resp, err := http.DefaultClient.Do(req)
		g.Expect(err).ToNot(HaveOccurred())
		_ = resp.Body.Close()
		g.Expect(resp.StatusCode).To(Equal(http.StatusNotFound), "%s %s", request.method, request.path)
	}

	requests := fake.Requests()
	g.Expect(requests).To(HaveLen(3))
	g.Expect(requests[0].Method).To(Equal(http.MethodGet))
	g.Expect(requests[1].Path).To(Equal("/clusters/" + testClusterName + "/something-else"))
	g.Expect(requests[1].ClusterName).To(BeEmpty())
	g.Expect(fake.Blocked()).To(Equal(0))
}

func TestServer_RejectsABodyThatIsNotTheOperationInput(t *testing.T) {
	g := NewWithT(t)
	fake := New(t)

	status, document := rawPost(t, fake.URL, `not json`)
	g.Expect(status).To(Equal(http.StatusBadRequest))
	g.Expect(document).To(HaveKey("message"))
	status, _ = rawPost(t, fake.URL, `{"other":"member"}`)
	g.Expect(status).To(Equal(http.StatusBadRequest))
	g.Expect(fake.Calls()).To(Equal(2))
}

func TestServer_ConfigMakesEveryCallASingleAttempt(t *testing.T) {
	g := NewWithT(t)
	fake := New(t)
	fake.SetError(Throttling())
	cfg := fake.Config()
	g.Expect(cfg.Region).To(Equal(Region))
	g.Expect(aws.ToString(cfg.BaseEndpoint)).To(Equal(fake.URL))
	creds, err := cfg.Credentials.Retrieve(context.Background())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(creds.AccessKeyID).To(Equal(NodeAccessKeyID))

	_, err = assumeRole(context.Background(), awseksauth.NewFromConfig(cfg))
	g.Expect(isA[*types.ThrottlingException](err)).To(BeTrue(), "%v", err)
	g.Expect(fake.Calls()).To(Equal(1))
}

func TestServer_ATestCanOverrideTheRetryer(t *testing.T) {
	g := NewWithT(t)
	fake := New(t)
	var mu sync.Mutex
	calls := 0
	fake.SetFunc(func(Request) (*Session, *APIError) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			return nil, Throttling()
		}
		return nil, nil
	})
	cfg := fake.Config()
	cfg.Retryer = func() aws.Retryer {
		return retry.NewStandard(func(o *retry.StandardOptions) {
			o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
		})
	}

	_, err := assumeRole(context.Background(), awseksauth.NewFromConfig(cfg))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(fake.Calls()).To(Equal(2))
}

func TestServer_BlockParksAnExchangeUntilRelease(t *testing.T) {
	g := NewWithT(t)
	ctx := serverTestContext(t)
	fake := New(t)
	client := awseksauth.NewFromConfig(fake.Config())

	for cycle := 1; cycle <= 2; cycle++ {
		fake.Block()
		first, second := assumeRoleAsync(ctx, client), assumeRoleAsync(ctx, client)
		g.Expect(fake.WaitForBlocked(ctx, 2)).To(Succeed(), "cycle %d", cycle)
		g.Expect(fake.Blocked()).To(Equal(2))
		g.Expect(fake.Calls()).To(Equal(2*cycle), "a parked request is recorded on arrival")
		select {
		case err := <-first:
			t.Fatalf("call returned while parked: %v", err)
		default:
		}

		fake.Release()
		g.Expect(fake.Blocked()).To(Equal(0), "Release settles the count before it returns")
		g.Expect(awaitCall(t, ctx, first)).To(Succeed())
		g.Expect(awaitCall(t, ctx, second)).To(Succeed())
	}
}

func TestServer_AParkedExchangeGivesUpWhenItsCallerDoes(t *testing.T) {
	g := NewWithT(t)
	ctx := serverTestContext(t)
	fake := New(t)
	client := awseksauth.NewFromConfig(fake.Config())
	fake.Block()
	defer fake.Release()

	callCtx, cancel := context.WithCancel(ctx)
	errs := assumeRoleAsync(callCtx, client)
	g.Expect(fake.WaitForBlocked(ctx, 1)).To(Succeed())
	cancel()

	g.Expect(errors.Is(awaitCall(t, ctx, errs), context.Canceled)).To(BeTrue())
	// The server learns of the cancellation when the client closes the
	// connection, which happens after the client's call has returned, so this
	// is the one place the fake has to be watched rather than awaited.
	g.Eventually(fake.Blocked, serverTestTimeout, 5*time.Millisecond).Should(Equal(0))
	g.Expect(fake.Calls()).To(Equal(1), "it was still received")
}

func TestServer_WaitForBlockedReturnsTheContextsError(t *testing.T) {
	g := NewWithT(t)
	fake := New(t)
	done, cancel := context.WithCancel(context.Background())
	cancel()

	g.Expect(fake.WaitForBlocked(done, 0)).To(Succeed())
	g.Expect(fake.WaitForBlocked(done, 1)).To(MatchError(context.Canceled))
}

func TestServer_CloseReleasesParkedExchangesAndTakesTheEndpointAway(t *testing.T) {
	g := NewWithT(t)
	ctx := serverTestContext(t)
	fake := New(t)
	client := awseksauth.NewFromConfig(fake.Config())
	fake.Block()
	errs := assumeRoleAsync(ctx, client)
	g.Expect(fake.WaitForBlocked(ctx, 1)).To(Succeed())

	closed := make(chan struct{})
	go func() {
		fake.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-ctx.Done():
		t.Fatal("Close hung on a parked request")
	}
	g.Expect(awaitCall(t, ctx, errs)).To(Succeed(), "the parked request was answered")

	_, err := assumeRole(ctx, client)
	g.Expect(err).To(HaveOccurred(), "nothing is listening any more")
	fake.Close()
}

func TestServer_IsSafeForConcurrentUse(t *testing.T) {
	g := NewWithT(t)
	ctx := serverTestContext(t)
	fake := New(t)
	client := awseksauth.NewFromConfig(fake.Config())

	const callers, callsEach = 8, 10
	var calls sync.WaitGroup
	for i := 0; i < callers; i++ {
		calls.Add(1)
		go func() {
			defer calls.Done()
			for j := 0; j < callsEach; j++ {
				_, _ = assumeRole(ctx, client)
			}
		}()
	}

	var churn sync.WaitGroup
	churn.Add(1)
	go func() {
		defer churn.Done()
		for i := 0; i < 50; i++ {
			fake.SetSession(EnrolledSession(time.Now().Add(time.Minute)))
			fake.SetError(Throttling())
			fake.SetFunc(func(Request) (*Session, *APIError) { return nil, nil })
			fake.SetRawResponse(http.StatusOK, []byte("{}"))
			fake.Reset()
			fake.Block()
			_ = fake.Blocked()
			_ = fake.Requests()
			_ = fake.Calls()
			fake.Release()
		}
	}()
	churn.Wait()
	fake.Release()
	calls.Wait()

	g.Expect(fake.Calls()).To(Equal(callers * callsEach))
	g.Expect(fake.Blocked()).To(Equal(0))
}
