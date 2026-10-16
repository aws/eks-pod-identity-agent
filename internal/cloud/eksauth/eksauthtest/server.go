// Package eksauthtest is a fake EKS Auth endpoint: an httptest server that
// speaks restJson1 AssumeRoleForPodIdentity well enough for the real SDK
// client, and the agent's clients built on it, to call it unmodified. Tests go
// through the real serializer, signer, retryer and deserializer, and the
// middleware in internal/cloud/eksauth that reads the member the SDK doesn't
// model, instead of a mock that agrees with the code's assumptions.
//
// A test sets the answer (SetSession, SetFunc, SetError, SetRawResponse) and
// when it's sent (Block, Release). Every request is recorded, and every method
// is safe for concurrent use, including while requests are in flight.
package eksauthtest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

const (
	// Region is the region Config sets.
	Region = "us-west-2"
	// NodeAccessKeyID, NodeSecretAccessKey and NodeSessionToken are the static
	// node credentials Config signs with. The access key ID is exported so a
	// test can assert the SigV4 credential scope of a recorded request.
	NodeAccessKeyID     = "AKIAEKSAUTHTESTNODE1"
	NodeSecretAccessKey = "eksauthtest-node-secret-access-key"
	NodeSessionToken    = "eksauthtest-node-session-token"

	// operationPattern is the one route the fake serves, as the SDK serializes
	// it.
	operationPattern = "POST /clusters/{clusterName}/assume-role-for-pod-identity"
	// maxRequestBytes bounds how much of a request body is read. The SDK sends a
	// token of a kilobyte or two.
	maxRequestBytes = 1 << 20
	// workloadIdentityProviderArnMember is EKS Auth's wire name for the member
	// the released SDK doesn't model. It's spelled here, not taken from
	// internal/cloud/eksauth, so a wrong name in the client fails the client's
	// own tests instead of being copied into the fake.
	workloadIdentityProviderArnMember = "workloadIdentityProviderArn"
)

// Server is a fake EKS Auth endpoint. Build it with New. Until a test sets a
// behaviour, it answers every exchange with an EnrolledSession expiring an
// hour after the request. SetSession, SetError, SetFunc and SetRawResponse
// each replace the previous behaviour, and Reset restores the default.
//
// The default subject is default/example-sa whatever the token. A test that
// wants another returns it from SetFunc, matched on Request.Token.
type Server struct {
	// URL is the endpoint's base URL. Config sets it as the BaseEndpoint.
	URL string

	server    *httptest.Server
	gate      gate
	closeOnce sync.Once

	mu        sync.Mutex
	behaviour behaviour
	requests  []Request
}

// behaviour is the answer the fake gives an exchange. At most one field is set;
// none set is the default.
type behaviour struct {
	session *Session
	apiErr  *APIError
	fn      func(Request) (*Session, *APIError)
	raw     *rawResponse
}

type rawResponse struct {
	status int
	body   []byte
}

// Request is one request the fake received.
type Request struct {
	// Method and Path are the request's method and URL path.
	Method string
	Path   string
	// ClusterName is the clusterName path segment, or empty for a request that
	// was not the operation.
	ClusterName string
	// Token is the body's token member, or empty when the body did not decode.
	Token string
	// Header is a copy of the request headers, including the SigV4
	// Authorization header.
	Header http.Header
	// Body is the raw request body.
	Body []byte
}

func (r Request) clone() Request {
	r.Header = r.Header.Clone()
	r.Body = append([]byte(nil), r.Body...)
	return r
}

// New starts a fake EKS Auth endpoint and closes it when the test ends.
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{}
	mux := http.NewServeMux()
	mux.HandleFunc(operationPattern, s.assumeRoleForPodIdentity)
	// Everything else, including another method on the operation's path, falls
	// through to here: the pattern above only matches POST, and a catch-all
	// that also matches the path takes precedence over a 405.
	mux.HandleFunc("/", s.notFound)
	s.server = httptest.NewServer(mux)
	s.URL = s.server.URL
	t.Cleanup(s.Close)
	return s
}

// Close releases any request parked at the gate, which is then answered as if
// Release had been called, and shuts the endpoint down, so a later call to it
// fails to connect. Block has no effect afterwards. New arranges for Close to run
// when the test ends; calling it earlier is how a test takes EKS Auth away. It
// is safe to call more than once.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		// httptest.Server.Close waits for every in-flight handler, so a parked
		// request has to be let go first or the close never returns.
		s.gate.shutdown()
		s.server.Close()
	})
}

// Config is the agent's AWS configuration pointed at the fake: Region, the
// static Node* credentials, and BaseEndpoint set to URL. Its retryer is
// aws.NopRetryer, so the caller sees the fake's failure after one attempt. A
// test that wants the SDK's retries sets Retryer on the returned value. IMDS is
// off, so eksauth.NewService's zone lookup fails at once whatever the host.
func (s *Server) Config() aws.Config {
	return aws.Config{
		Region: Region,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{
				AccessKeyID:     NodeAccessKeyID,
				SecretAccessKey: NodeSecretAccessKey,
				SessionToken:    NodeSessionToken,
				Source:          "eksauthtest",
			}, nil
		}),
		BaseEndpoint:  aws.String(s.URL),
		Retryer:       func() aws.Retryer { return aws.NopRetryer{} },
		ConfigSources: []interface{}{config.LoadOptions{EC2IMDSClientEnableState: imds.ClientDisabled}},
	}
}

// SetSession answers every exchange with session.
func (s *Server) SetSession(session Session) {
	s.setBehaviour(behaviour{session: &session})
}

// SetError answers every exchange with apiErr. A nil apiErr restores the
// default. The value is copied, so changing it afterwards has no effect.
func (s *Server) SetError(apiErr *APIError) {
	if apiErr == nil {
		s.Reset()
		return
	}
	copied := *apiErr
	s.setBehaviour(behaviour{apiErr: &copied})
}

// SetFunc answers every exchange with what fn returns for it: the error when it
// returns one, otherwise the session, otherwise the default session. fn is
// called with a copy of the recorded request, after the gate, from the
// handler's goroutine, and may be called concurrently, so it must be safe for
// that. It may call the Server's other methods. A nil fn restores the default.
func (s *Server) SetFunc(fn func(Request) (*Session, *APIError)) {
	if fn == nil {
		s.Reset()
		return
	}
	s.setBehaviour(behaviour{fn: fn})
}

// SetRawResponse answers every exchange with exactly status and body, as
// application/json. It is for the answers the real service would not give, such
// as a 200 missing its credentials or a body that is not JSON. A zero status is
// sent as 200.
func (s *Server) SetRawResponse(status int, body []byte) {
	if status == 0 {
		status = http.StatusOK
	}
	s.setBehaviour(behaviour{raw: &rawResponse{status: status, body: append([]byte(nil), body...)}})
}

// Reset restores the default behaviour. It does not clear the recorded requests
// or touch the gate.
func (s *Server) Reset() {
	s.setBehaviour(behaviour{})
}

func (s *Server) setBehaviour(b behaviour) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.behaviour = b
}

// Requests returns a copy of every request received so far, in arrival order.
// A request is recorded when it arrives, before the gate, so one that is
// parked, or whose caller gave up while it was parked, is included: EKS Auth did
// receive it.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	requests := make([]Request, len(s.requests))
	for i, r := range s.requests {
		requests[i] = r.clone()
	}
	return requests
}

// Calls reports how many requests have been received, counted as Requests
// counts them.
func (s *Server) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

// Block parks every exchange that arrives afterwards until Release. Exchanges
// already past the gate aren't affected, and a request for anything but the
// operation is answered 404 at once. A parked exchange whose client cancels
// and closes the connection gives up: it leaves the Blocked count and sends
// no answer.
func (s *Server) Block() {
	s.gate.block()
}

// Release wakes every parked exchange and reopens the gate. It's safe to call
// when nothing is parked. A released exchange wins a tie with its context
// ending. Blocked is 0 when Release returns, but a released exchange may not
// have answered yet, so a test asserting on the answer waits for the client's
// call to return.
func (s *Server) Release() {
	s.gate.releaseAll()
}

// Blocked reports how many exchanges are parked at the gate right now.
func (s *Server) Blocked() int {
	return s.gate.blockedCount()
}

// WaitForBlocked returns nil once at least n exchanges are parked at the gate,
// and ctx's error if ctx ends first. It does not poll. The count is checked
// before ctx, so an n already reached returns nil even under a done ctx.
func (s *Server) WaitForBlocked(ctx context.Context, n int) error {
	return s.gate.waitForBlocked(ctx, n)
}

func (s *Server) assumeRoleForPodIdentity(w http.ResponseWriter, r *http.Request) {
	// The body is read to the end before parking: net/http only starts watching
	// for the client going away once the handler has consumed the body, and that
	// is what ends the request context of a parked exchange whose caller
	// cancelled.
	request, requestID, decoded := s.record(r)
	w.Header().Set("X-Amzn-RequestId", requestID)
	if !decoded {
		writeAPIError(w, &APIError{
			Status:  http.StatusBadRequest,
			Code:    "InvalidRequestException",
			Message: "eksauthtest: the request body is not {\"token\": ...}",
		})
		return
	}

	if err := s.gate.enter(r.Context()); err != nil {
		// The caller is gone; there is nobody to answer.
		return
	}

	s.mu.Lock()
	b := s.behaviour
	s.mu.Unlock()

	switch {
	case b.raw != nil:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(b.raw.status)
		_, _ = w.Write(b.raw.body)
		return
	case b.apiErr != nil:
		writeAPIError(w, b.apiErr)
		return
	case b.session != nil:
		writeSession(w, *b.session)
		return
	case b.fn != nil:
		session, apiErr := b.fn(request.clone())
		if apiErr != nil {
			writeAPIError(w, apiErr)
			return
		}
		if session != nil {
			writeSession(w, *session)
			return
		}
	}
	writeSession(w, EnrolledSession(time.Now().Add(time.Hour)))
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	request, requestID, _ := s.record(r)
	w.Header().Set("X-Amzn-RequestId", requestID)
	writeAPIError(w, &APIError{
		Status:  http.StatusNotFound,
		Code:    "UnknownOperationException",
		Message: fmt.Sprintf("eksauthtest: no operation at %s %s", request.Method, request.Path),
	})
}

// record reads the request body and records the request. It returns what it
// recorded, a request ID for the response, and whether the body was the
// operation's input: a JSON object with a string token member.
func (s *Server) record(r *http.Request) (Request, string, bool) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes))
	request := Request{
		Method:      r.Method,
		Path:        r.URL.Path,
		ClusterName: r.PathValue("clusterName"),
		Header:      r.Header.Clone(),
		Body:        body,
	}
	var input struct {
		Token *string `json:"token"`
	}
	decoded := json.Unmarshal(body, &input) == nil && input.Token != nil
	if decoded {
		request.Token = *input.Token
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, request)
	return request.clone(), "eksauthtest-" + strconv.Itoa(len(s.requests)), decoded
}

// The response documents below are the restJson1 shapes the SDK's deserializer
// reads, with its lowerCamel member names.

type assumedRoleUserDocument struct {
	Arn          string `json:"arn"`
	AssumeRoleID string `json:"assumeRoleId"`
}

type credentialsDocument struct {
	AccessKeyID     string      `json:"accessKeyId"`
	SecretAccessKey string      `json:"secretAccessKey"`
	SessionToken    string      `json:"sessionToken"`
	Expiration      json.Number `json:"expiration"`
}

type podIdentityAssociationDocument struct {
	AssociationArn string `json:"associationArn"`
	AssociationID  string `json:"associationId"`
}

type subjectDocument struct {
	Namespace      string `json:"namespace"`
	ServiceAccount string `json:"serviceAccount"`
}

func writeSession(w http.ResponseWriter, session Session) {
	audience := session.Audience
	if audience == "" {
		audience = DefaultAudience
	}
	// A map rather than a struct at the top level, so the unmodelled member is
	// named by workloadIdentityProviderArnMember, which cannot appear in a
	// struct tag, and so it can be left out.
	document := map[string]any{
		"assumedRoleUser": assumedRoleUserDocument{
			Arn:          session.AssumedRoleArn,
			AssumeRoleID: session.AssumeRoleID,
		},
		"audience": audience,
		"credentials": credentialsDocument{
			AccessKeyID:     session.AccessKeyID,
			SecretAccessKey: session.SecretAccessKey,
			SessionToken:    session.SessionToken,
			Expiration:      epochSeconds(session.Expiration),
		},
		"podIdentityAssociation": podIdentityAssociationDocument{
			AssociationArn: session.AssociationArn,
			AssociationID:  session.AssociationID,
		},
		"subject": subjectDocument{
			Namespace:      session.Namespace,
			ServiceAccount: session.ServiceAccount,
		},
	}
	if session.ProviderArn != "" {
		document[workloadIdentityProviderArnMember] = session.ProviderArn
	}
	writeJSON(w, http.StatusOK, document)
}

// writeAPIError sends apiErr the way the SDK's restJson1 error deserializer
// reads it: the code from the X-Amzn-ErrorType header, the message from the
// body's message member.
func writeAPIError(w http.ResponseWriter, apiErr *APIError) {
	status := apiErr.Status
	if status == 0 {
		status = http.StatusBadRequest
	}
	if apiErr.Code != "" {
		w.Header().Set("X-Amzn-ErrorType", apiErr.Code)
	}
	writeJSON(w, status, map[string]string{"message": apiErr.Message})
}

func writeJSON(w http.ResponseWriter, status int, document any) {
	body, err := json.Marshal(document)
	if err != nil {
		// Every document above is maps, strings and numbers.
		panic(fmt.Sprintf("eksauthtest: encoding a response: %v", err))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// epochSeconds renders t as the JSON number of epoch seconds EKS Auth sends for
// credentials.expiration, to the millisecond, which is as much as the SDK keeps.
func epochSeconds(t time.Time) json.Number {
	return json.Number(strconv.FormatFloat(float64(t.UnixMilli())/1e3, 'f', -1, 64))
}
