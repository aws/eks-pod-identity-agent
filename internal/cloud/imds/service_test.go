package imds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	testutil "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	"golang.org/x/time/rate"
)

// --- NewService (construction) tests ---

// Verifies NewService builds the namespaceMapping during construction so the
// service is ready to serve credentials immediately.
func TestNewService_BuildsMappingOnConstruction(t *testing.T) {
	ctx, cancel := context.WithCancel(testCtx())
	defer cancel()

	// Create a real service via NewService with a mock that has one namespace/pod.
	svc := NewService(ctx, aws.Config{}, func(o *imds.Options) {
		o.HTTPClient = &mockHTTPClient{handler: func(req *http.Request) (*http.Response, error) {
			path := req.URL.Path
			if strings.HasSuffix(path, "/latest/meta-data/") || strings.HasSuffix(path, "/latest/meta-data") {
				return httpResponse(200, "iam-eks-1"), nil
			}
			if strings.HasSuffix(path, "iam-eks-1/info") {
				return httpResponse(200, infoJSON("pod-a")), nil
			}
			return httpResponse(404, ""), nil
		}}
		o.ClientEnableState = imds.ClientEnabled
	}).(*service)

	// Mapping should be populated immediately after construction.
	_, ok := lookupNamespace(svc, "pod-a")
	assert.True(t, ok, "mapping should be populated after NewService")
}

// Verifies the IMDS service is still created when the initial namespaceMapping
// build fails, and that the mapping is reconciled on a later background refresh.
func TestNewService_InitialBuildFailure_StillCreatesAndRecovers(t *testing.T) {
	ctx, cancel := context.WithCancel(testCtx())
	defer cancel()

	// Root listing fails while IMDS is "down"; the test flips imdsUp to true
	// after construction to simulate IMDS recovering. Using a flag (rather than a
	// call count) keeps the test robust to the SDK's internal request retries.
	var imdsUp atomic.Bool
	handler := func(req *http.Request) (*http.Response, error) {
		path := req.URL.Path
		if strings.HasSuffix(path, "/latest/meta-data/") || strings.HasSuffix(path, "/latest/meta-data") {
			if !imdsUp.Load() {
				return httpResponse(500, "IMDS unavailable"), nil
			}
			return httpResponse(200, "iam-eks-1"), nil
		}
		if strings.HasSuffix(path, "iam-eks-1/info") {
			return httpResponse(200, infoJSON("pod-a")), nil
		}
		return httpResponse(404, ""), nil
	}

	svc := NewService(ctx, aws.Config{}, func(o *imds.Options) {
		o.HTTPClient = &mockHTTPClient{handler: handler}
		o.ClientEnableState = imds.ClientEnabled
	}).(*service)

	// Service is created despite the failed initial build, with an empty mapping.
	require.NotNil(t, svc)
	_, ok := lookupNamespace(svc, "pod-a")
	assert.False(t, ok, "mapping should be empty after a failed initial build")

	// IMDS recovers; a subsequent refresh (as the background goroutine performs)
	// converges the mapping.
	imdsUp.Store(true)
	require.NoError(t, svc.buildNamespaceMapping(ctx))
	_, ok = lookupNamespace(svc, "pod-a")
	assert.True(t, ok, "mapping should converge on the next refresh after IMDS recovers")
}

// Verifies the full path end to end: NewService builds the mapping, then
// GetIamCredentials fetches and returns an IMDS-sourced credential for a mapped pod.
func TestNewService_EndToEnd_GetIamCredentials(t *testing.T) {
	ctx, cancel := context.WithCancel(testCtx())
	defer cancel()

	// Full end-to-end: NewService builds mapping, then GetIamCredentials fetches a credential.
	svc := NewService(ctx, aws.Config{}, func(o *imds.Options) {
		o.HTTPClient = &mockHTTPClient{handler: func(req *http.Request) (*http.Response, error) {
			path := req.URL.Path
			if strings.HasSuffix(path, "/latest/meta-data/") || strings.HasSuffix(path, "/latest/meta-data") {
				return httpResponse(200, "iam-eks-1"), nil
			}
			if strings.HasSuffix(path, "iam-eks-1/info") {
				return httpResponse(200, infoJSON("pod-a")), nil
			}
			if strings.Contains(path, "security-credentials/pod-a") {
				return httpResponse(200, validCredJSON()), nil
			}
			return httpResponse(404, ""), nil
		}}
		o.ClientEnableState = imds.ClientEnabled
	})

	cred, meta, err := svc.GetIamCredentials(testCtx(), fakeRequest(t, "pod-a"))
	require.NoError(t, err)
	assert.Equal(t, "AKIA", cred.AccessKeyId)
	assert.Equal(t, credentials.SourceIMDS, meta.Source())
}

// --- GetIamCredentials (delegate fetch) tests ---

// Verifies the IMDS delegate's fetch behavior: returns a credential when the pod
// is mapped, errors (for chain fallthrough) when the pod is missing or IMDS 404s,
// still returns expired credentials, and tags results with the IMDS source.
func TestGetIamCredentials(t *testing.T) {
	tests := []struct {
		name        string
		mapping     map[string]string
		credBody    string
		credCode    int
		podUID      string
		token       string // if set, overrides fakeRequest
		wantErr     error
		wantErrS    string // substring match when wantErr is nil
		wantKeyId   string
		wantSrc     credentials.CredentialSource
		wantExpired bool // if set, assert the returned credential's expiration is in the past
	}{
		{
			name:      "pod in mapping returns credential",
			mapping:   map[string]string{"pod-1": "1"},
			credBody:  validCredJSON(),
			credCode:  200,
			podUID:    "pod-1",
			wantKeyId: "AKIA",
			wantSrc:   credentials.SourceIMDS,
		},
		{
			name:    "pod not in mapping",
			mapping: map[string]string{},
			podUID:  "pod-missing",
			wantErr: ErrPodNotInMapping,
		},
		{
			name:     "credential not found in IMDS",
			mapping:  map[string]string{"pod-1": "1"},
			credCode: 404,
			podUID:   "pod-1",
			wantErr:  ErrCredentialNotFound,
		},
		{
			name:     "malformed credential JSON returns error",
			mapping:  map[string]string{"pod-1": "1"},
			credBody: "not json",
			credCode: 200,
			podUID:   "pod-1",
			wantErrS: "parsing credential",
		},
		{
			// The delegate performs no expiry checks — it returns whatever IMDS
			// holds. This is what lets the cache honor the static-stability
			// guarantee (expired IMDS creds are still usable during an LSE).
			name:        "expired credential returned without expiry inspection",
			mapping:     map[string]string{"pod-1": "1"},
			credBody:    expiredCredJSON(),
			credCode:    200,
			podUID:      "pod-1",
			wantKeyId:   "AKIA",
			wantSrc:     credentials.SourceIMDS,
			wantExpired: true,
		},
		{
			name:     "invalid token returns error",
			mapping:  map[string]string{},
			token:    "not-a-jwt",
			wantErrS: "IMDS delegate",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock returns the configured credential response for any IMDS request.
			svc := newTestService(func(req *http.Request) (*http.Response, error) {
				return httpResponse(tt.credCode, tt.credBody), nil
			})
			// Pre-populate the namespace mapping (bypasses discovery).
			svc.storeMapping(tt.mapping)

			// Build the request — use raw token if provided, otherwise generate a valid JWT.
			var request *credentials.EksCredentialsRequest
			if tt.token != "" {
				request = &credentials.EksCredentialsRequest{ServiceAccountToken: tt.token, ClusterName: "c"}
			} else {
				request = fakeRequest(t, tt.podUID)
			}

			cred, meta, err := svc.GetIamCredentials(testCtx(), request)

			// Check error cases first.
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}
			if tt.wantErrS != "" {
				assert.ErrorContains(t, err, tt.wantErrS)
				return
			}

			// Verify credential and source metadata on success.
			require.NoError(t, err)
			assert.Equal(t, tt.wantKeyId, cred.AccessKeyId)
			assert.Equal(t, tt.wantSrc, meta.Source())
			if tt.wantExpired {
				// The delegate returned it despite the expiration being in the past,
				// confirming it does not inspect/reject on expiry.
				assert.True(t, cred.Expiration.Time.Before(time.Now()),
					"expected an already-expired credential to be returned")
			}
		})
	}
}

// Verifies IsIrrecoverable's error classification, which drives the cache's
// eviction decision: ErrPodNotInMapping is irrecoverable (pod is gone → evict),
// while ErrCredentialNotFound and any other error are recoverable (transient →
// keep and retry).
func TestIsIrrecoverable(t *testing.T) {
	svc := &service{}
	tests := []struct {
		name            string
		err             error
		wantCode        string
		wantIrrecovable bool
	}{
		{"pod not in mapping is irrecoverable", ErrPodNotInMapping, "PodNotInMapping", true},
		{"credential not found is recoverable", ErrCredentialNotFound, "Unknown", false},
		{"wrapped pod-not-in-mapping is irrecoverable", fmt.Errorf("IMDS delegate: %w", ErrPodNotInMapping), "PodNotInMapping", true},
		{"arbitrary error is recoverable", fmt.Errorf("connection reset"), "Unknown", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, irrecoverable := svc.IsIrrecoverable(tt.err)
			assert.Equal(t, tt.wantCode, code)
			assert.Equal(t, tt.wantIrrecovable, irrecoverable)
		})
	}
}

// --- ProbeIMDS tests ---

// Verifies ProbeIMDS reports IMDS as available on 200 or 429, and unavailable on
// any other HTTP status.
func TestProbeIMDS_HTTPStatus_ReturnsExpectedAvailability(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		wantResult bool
	}{
		{"returns true on 200", http.StatusOK, "i-1234567890abcdef0", true},
		{"returns true on 429", http.StatusTooManyRequests, "", true},
		{"returns false on other error status", http.StatusInternalServerError, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ProbeIMDS(context.Background(), aws.Config{}, func(o *imds.Options) {
				o.HTTPClient = &mockHTTPClient{handler: func(req *http.Request) (*http.Response, error) {
					return httpResponse(tt.status, tt.body), nil
				}}
				o.ClientEnableState = imds.ClientEnabled
			})
			assert.Equal(t, tt.wantResult, result)
		})
	}
}

// Verifies ProbeIMDS reports IMDS as unavailable when the request fails at the
// transport layer (e.g. no IMDS on the node).
func TestProbeIMDS_TransportError_ReturnsFalse(t *testing.T) {
	result := ProbeIMDS(context.Background(), aws.Config{}, func(o *imds.Options) {
		o.HTTPClient = &mockHTTPClient{handler: func(req *http.Request) (*http.Response, error) {
			return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("connection refused")}
		}}
		o.ClientEnableState = imds.ClientEnabled
	})
	assert.False(t, result)
}

// --- Namespace mapping tests ---

// Verifies buildNamespaceMapping assembles the podUID→namespace map across
// namespaces, skipping namespaces whose info read fails, handling non-sequential
// namespace suffixes, and filtering out pods whose info Code is not "Success".
func TestNamespaceMapping_Build(t *testing.T) {
	tests := []struct {
		name        string
		rootListing string
		infoByNS    map[string]func() (*http.Response, error)
		wantPods    int
		wantLookups map[string]string
		wantMissing []string
	}{
		{
			name:        "multiple namespaces",
			rootListing: "iam-eks-1\niam-eks-2",
			infoByNS: map[string]func() (*http.Response, error){
				"1": func() (*http.Response, error) { return httpResponse(200, infoJSON("pod-a", "pod-b")), nil },
				"2": func() (*http.Response, error) { return httpResponse(200, infoJSON("pod-c")), nil },
			},
			wantPods:    3,
			wantLookups: map[string]string{"pod-a": "1", "pod-b": "1", "pod-c": "2"},
			wantMissing: []string{"pod-missing"},
		},
		{
			name:        "partial failure skips failed namespace",
			rootListing: "iam-eks-1\niam-eks-2",
			infoByNS: map[string]func() (*http.Response, error){
				"1": func() (*http.Response, error) { return httpResponse(200, infoJSON("pod-a")), nil },
				"2": func() (*http.Response, error) { return httpResponse(500, "internal error"), nil },
			},
			wantPods:    1,
			wantLookups: map[string]string{"pod-a": "1"},
		},
		{
			name:        "non-sequential namespaces",
			rootListing: "iam-eks-1\niam-eks-3\niam-eks-7",
			infoByNS: map[string]func() (*http.Response, error){
				"1": func() (*http.Response, error) { return httpResponse(200, infoJSON("pod-a")), nil },
				"3": func() (*http.Response, error) { return httpResponse(200, infoJSON("pod-b")), nil },
				"7": func() (*http.Response, error) { return httpResponse(200, infoJSON("pod-c")), nil },
			},
			wantPods:    3,
			wantLookups: map[string]string{"pod-a": "1", "pod-b": "3", "pod-c": "7"},
		},
		{
			name:        "namespace with empty info contributes no pods",
			rootListing: "iam-eks-1\niam-eks-2",
			infoByNS: map[string]func() (*http.Response, error){
				"1": func() (*http.Response, error) { return httpResponse(200, infoJSON("pod-a")), nil },
				"2": func() (*http.Response, error) { return httpResponse(200, infoJSON()), nil }, // empty PodCredentials
			},
			wantPods:    1,
			wantLookups: map[string]string{"pod-a": "1"},
		},
		{
			name:        "no namespaces",
			rootListing: "iam\nplacement",
			infoByNS:    map[string]func() (*http.Response, error){},
			wantPods:    0,
		},
		{
			name:        "filters out non-success pods",
			rootListing: "iam-eks-1",
			infoByNS: map[string]func() (*http.Response, error){
				"1": func() (*http.Response, error) {
					return httpResponse(200, infoJSONWithCodes(map[string]string{
						"pod-ok":     "Success",
						"pod-denied": "access_denied",
						"pod-lower":  "success",
					})), nil
				},
			},
			wantPods:    2,
			wantLookups: map[string]string{"pod-ok": "1", "pod-lower": "1"},
			wantMissing: []string{"pod-denied"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Route IMDS requests: the metadata root returns the namespace listing,
			// each iam-eks-<ns>/info path returns that namespace's canned response,
			// and anything else 404s.
			svc := newTestService(func(req *http.Request) (*http.Response, error) {
				path := req.URL.Path
				if strings.HasSuffix(path, "/latest/meta-data/") || strings.HasSuffix(path, "/latest/meta-data") {
					return httpResponse(200, tt.rootListing), nil
				}
				for ns, fn := range tt.infoByNS {
					if strings.HasSuffix(path, "iam-eks-"+ns+"/info") {
						return fn()
					}
				}
				return httpResponse(404, ""), nil
			})

			require.NoError(t, svc.buildNamespaceMapping(testCtx()))

			// Total map size, then each expected pod resolves to its namespace.
			assert.Len(t, svc.loadMapping(), tt.wantPods)
			for podUID, wantNS := range tt.wantLookups {
				ns, ok := lookupNamespace(svc, podUID)
				assert.True(t, ok, "expected pod %s in mapping", podUID)
				assert.Equal(t, wantNS, ns)
			}
			// Pods from failed/non-success namespaces must be absent.
			for _, podUID := range tt.wantMissing {
				_, ok := lookupNamespace(svc, podUID)
				assert.False(t, ok, "expected pod %s NOT in mapping", podUID)
			}
		})
	}
}

// Verifies the background refresh goroutine reconciles namespaceMapping with new
// pods that IMDS delivers after the service is already running.
func TestNamespaceMapping_BackgroundRefresh_UpdatesMap(t *testing.T) {
	callCount := 0
	// First info call returns one pod; subsequent calls return two (simulating new pod credential delivery).
	svc := newTestService(func(req *http.Request) (*http.Response, error) {
		path := req.URL.Path
		if strings.HasSuffix(path, "/latest/meta-data/") || strings.HasSuffix(path, "/latest/meta-data") {
			return httpResponse(200, "iam-eks-1"), nil
		}
		if strings.HasSuffix(path, "iam-eks-1/info") {
			callCount++
			if callCount <= 1 {
				return httpResponse(200, infoJSON("pod-old")), nil
			}
			return httpResponse(200, infoJSON("pod-old", "pod-new")), nil
		}
		return httpResponse(404, ""), nil
	})

	ctx, cancel := context.WithCancel(testCtx())
	defer cancel()

	// Initial build sees only pod-old.
	require.NoError(t, svc.buildNamespaceMapping(ctx))
	assert.Len(t, svc.loadMapping(), 1)

	// Background refresh picks up pod-new after the ticker fires.
	svc.startBackgroundRefresh(ctx, 50*time.Millisecond)
	time.Sleep(150 * time.Millisecond)
	cancel()

	// Verify the map was updated with the new pod.
	assert.Len(t, svc.loadMapping(), 2)
	_, ok := lookupNamespace(svc, "pod-new")
	assert.True(t, ok)
}

// Verifies the background refresh goroutine stops issuing refreshes once its
// context is cancelled.
func TestNamespaceMapping_Stop_HaltsRefresh(t *testing.T) {
	var refreshes atomic.Int32
	svc := newTestService(func(req *http.Request) (*http.Response, error) {
		// Count root-listing calls — one per buildNamespaceMapping (refresh) cycle.
		path := req.URL.Path
		if strings.HasSuffix(path, "/latest/meta-data/") || strings.HasSuffix(path, "/latest/meta-data") {
			refreshes.Add(1)
		}
		return httpResponse(404, ""), nil
	})

	ctx, cancel := context.WithCancel(testCtx())
	svc.startBackgroundRefresh(ctx, 10*time.Millisecond)

	// Let a few refresh cycles run, then cancel.
	time.Sleep(55 * time.Millisecond)
	cancel()

	// Record the count after cancel, wait well beyond several tick intervals,
	// and confirm no further refreshes occurred — i.e. the goroutine exited.
	countAtCancel := refreshes.Load()
	time.Sleep(60 * time.Millisecond)
	assert.Equal(t, countAtCancel, refreshes.Load(),
		"no refreshes should occur after the context is cancelled")
}

// --- Rate limiter tests ---

// Verifies rateLimitedHTTPClient.Do passes the request through to the wrapped
// client once the limiter admits it.
func TestRateLimitedHTTPClient_Do_PassesThroughWhenAllowed(t *testing.T) {
	var called bool
	rl := &rateLimitedHTTPClient{
		client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return httpResponse(200, "ok"), nil
		})},
		limiter: rate.NewLimiter(imdsRateLimit, imdsRateLimit),
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://imds/latest", nil)
	resp, err := rl.Do(req)
	require.NoError(t, err)
	assert.True(t, called, "wrapped client should be invoked when the limiter allows the request")
	assert.Equal(t, 200, resp.StatusCode)
}

// Verifies rateLimitedHTTPClient.Do fails fast (without calling the wrapped
// client) and wraps the limiter error when the context is already cancelled —
// i.e. requests never bypass the rate limiter.
func TestRateLimitedHTTPClient_Do_CancelledContextErrors(t *testing.T) {
	var called bool
	rl := &rateLimitedHTTPClient{
		client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return httpResponse(200, "ok"), nil
		})},
		// Zero-burst limiter so Wait blocks until the (cancelled) context fires.
		limiter: rate.NewLimiter(rate.Limit(imdsRateLimit), 0),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://imds/latest", nil)

	_, err := rl.Do(req)
	require.Error(t, err)
	assert.ErrorContains(t, err, "IMDS rate limiter")
	assert.False(t, called, "wrapped client must not be called when the limiter rejects the request")
}

// --- Test helpers ---

type mockHTTPClient struct {
	handler func(*http.Request) (*http.Response, error)
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.handler(req)
}

// newTestService creates a bare service with a mock HTTP client, without
// building the namespace mapping or starting background refresh. Use for
// unit tests that need fine-grained control over the service lifecycle.
func newTestService(handler func(*http.Request) (*http.Response, error)) *service {
	mock := &mockHTTPClient{handler: handler}
	imdsClient := imds.New(imds.Options{
		HTTPClient:        mock,
		ClientEnableState: imds.ClientEnabled,
	})
	s := &service{
		imdsClient: imdsClient,
	}
	s.storeMapping(map[string]string{})
	return s
}

func httpResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func validCredJSON() string {
	return `{"AccessKeyId":"AKIA","SecretAccessKey":"secret","Token":"tok","AccountId":"123456789012","Expiration":"2099-01-01T00:00:00Z"}`
}

func expiredCredJSON() string {
	return `{"AccessKeyId":"AKIA","SecretAccessKey":"secret","Token":"tok","AccountId":"123456789012","Expiration":"2020-01-01T00:00:00Z"}`
}

func infoJSON(podUIDs ...string) string {
	pods := make(map[string]credentials.PodCredentialEntry)
	for _, uid := range podUIDs {
		pods[uid] = credentials.PodCredentialEntry{Code: "success", RoleARN: "arn:aws:iam::123456789012:role/R"}
	}
	b, _ := json.Marshal(credentials.NamespaceInfo{Code: "Success", LastUpdated: "2025-03-11T18:58:15Z", PodCredentials: pods})
	return string(b)
}

// infoJSONWithCodes builds a namespace info JSON where each podUID has the given Code.
func infoJSONWithCodes(pods map[string]string) string {
	entries := make(map[string]credentials.PodCredentialEntry)
	for uid, code := range pods {
		entries[uid] = credentials.PodCredentialEntry{Code: code, RoleARN: "arn:aws:iam::123456789012:role/R"}
	}
	b, _ := json.Marshal(credentials.NamespaceInfo{Code: "Success", LastUpdated: "2025-03-11T18:58:15Z", PodCredentials: entries})
	return string(b)
}

func testCtx() context.Context {
	return logger.ContextWithField(context.Background(), "test", "true")
}

func fakeRequest(t *testing.T, podUID string) *credentials.EksCredentialsRequest {
	t.Helper()
	token := testutil.CreateToken(t, testutil.TokenConfig{
		PodUID: podUID,
		Expiry: time.Now().Add(time.Hour),
		Iat:    time.Now(),
		Nbf:    time.Now(),
	})
	return &credentials.EksCredentialsRequest{ServiceAccountToken: token, ClusterName: "test-cluster"}
}

// lookupNamespace reads the podUID→namespace entry from the service's mapping.
// A test-only helper mirroring the inline lookup in GetIamCredentials.
func lookupNamespace(s *service, podUID string) (string, bool) {
	ns, ok := s.loadMapping()[podUID]
	return ns, ok
}

// roundTripFunc adapts a function to http.RoundTripper for test convenience.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
