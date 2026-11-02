package sts

// The shared fixture for this package's tests: a fake STS endpoint that records
// what it is sent, and a check of the wire contract every operation shares, so a
// test for an operation asserts only its own parameters and response.

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
	. "github.com/onsi/gomega"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

const (
	sessionAccessKeyID = "AKIDWORKLOADSESSION"
	sessionToken       = "workload-session-token"
	// signingDate is when pinnedService signs, as X-Amz-Date renders it.
	signingDate = "20261001T110000Z"
)

// sessionCreds stands in for the workload session's credentials each call is
// signed with.
var sessionCreds = aws.Credentials{AccessKeyID: sessionAccessKeyID, SecretAccessKey: "session-secret", SessionToken: sessionToken}

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
		func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.requests = append(f.requests, recordedRequest{method: r.Method, path: r.URL.Path, host: r.Host, header: r.Header.Clone(), body: raw, form: form})
		}()
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

func (f *fakeSTS) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// agentConfig is the agent's own AWS configuration, with no credentials, pointed
// at the fake.
func agentConfig(endpoint string) aws.Config {
	return aws.Config{Region: "us-west-2", BaseEndpoint: aws.String(endpoint)}
}

// pinnedService is a client of the fake whose clock reads signingDate, set in a
// zone other than UTC so a signer that forgets to convert is caught.
func pinnedService(f *fakeSTS) *service {
	svc := NewService(agentConfig(f.server.URL)).(*service)
	svc.now = func() time.Time { return time.Date(2026, 10, 1, 4, 0, 0, 0, time.FixedZone("PDT", -7*3600)) }
	return svc
}

// expectSignedQuery asserts req is the awsQuery POST for operation carrying
// exactly params, SigV4-signed with sessionCreds for STS in us-west-2 at
// signingDate. Every operation's test calls it on its own request.
func expectSignedQuery(g Gomega, req recordedRequest, operation string, params url.Values) {
	g.Expect(req.method).To(Equal(http.MethodPost))
	g.Expect(req.header.Get("Content-Type")).To(HavePrefix("application/x-www-form-urlencoded"))
	form := url.Values{"Action": {operation}, "Version": {"2011-06-15"}}
	for name, values := range params {
		form[name] = values
	}
	g.Expect(req.form).To(Equal(form))

	authorization := req.header.Get("Authorization")
	g.Expect(authorization).To(HavePrefix("AWS4-HMAC-SHA256 "))
	g.Expect(authorization).To(MatchRegexp(`Credential=` + sessionAccessKeyID + `/\d{8}/us-west-2/sts/aws4_request`))
	g.Expect(req.header.Get("X-Amz-Security-Token")).To(Equal(sessionToken))
	g.Expect(req.header.Get("X-Amz-Date")).To(Equal(signingDate))
	g.Expect(req.header.Get("X-Amz-Content-Sha256")).To(BeEmpty(), "STS signs the payload hash without sending it")
	g.Expect(verifySignature(req, sessionCreds, "us-west-2")).To(Succeed())
}

// verifySignature recomputes the SigV4 signature the way STS does: it re-signs
// the headers the Authorization header lists with creds at the request's own
// X-Amz-Date and compares. That catches a wrong payload hash, scope or secret,
// but not a wrong signing time, which the caller checks against X-Amz-Date.
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
