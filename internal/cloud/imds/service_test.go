package imds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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
	s.nsMapping.Store(map[string]string{})
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

// namespaceHandler returns a mock handler that lists iam-eks-1..n at the
// metadata root and responds 200 for info/credential paths within those namespaces.
func namespaceHandler(n int) func(*http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		path := req.URL.Path
		// Root listing: return all iam-eks-* entries
		if strings.HasSuffix(path, "/latest/meta-data/") || strings.HasSuffix(path, "/latest/meta-data") {
			var entries []string
			for i := 1; i <= n; i++ {
				entries = append(entries, fmt.Sprintf("iam-eks-%d", i))
			}
			return httpResponse(200, strings.Join(entries, "\n")), nil
		}
		return httpResponse(404, ""), nil
	}
}

// --- readCredential tests ---

func TestReadCredential(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		wantErr    string
		wantKeyId  string
	}{
		{
			name:      "valid JSON",
			status:    200,
			body:      validCredJSON(),
			wantKeyId: "AKIA",
		},
		{
			name:    "invalid JSON",
			status:  200,
			body:    "not json",
			wantErr: "parsing credential",
		},
		{
			name:    "not found",
			status:  404,
			body:    "",
			wantErr: "credential not found in IMDS",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock returns the configured status/body for any request.
			svc := newTestService(func(req *http.Request) (*http.Response, error) {
				return httpResponse(tt.status, tt.body), nil
			})

			// Read a credential from namespace "1" for "pod-1".
			cred, err := svc.readCredential(context.Background(), "1", "pod-1")
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				// Verify all credential fields are parsed correctly.
				assert.Equal(t, tt.wantKeyId, cred.AccessKeyId)
				assert.Equal(t, "secret", cred.SecretAccessKey)
				assert.Equal(t, "tok", cred.Token)
				assert.Equal(t, "123456789012", cred.AccountId)
				assert.False(t, cred.Expiration.IsZero())
			}
		})
	}
}

// --- discoverNamespaces tests ---

func TestDiscoverNamespaces(t *testing.T) {
	tests := []struct {
		name      string
		count     int
		wantCount int
	}{
		{"ten namespaces", 10, 10},
		{"five namespaces", 5, 5},
		{"no namespaces", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock returns a root listing with iam-eks-1..count entries.
			svc := newTestService(namespaceHandler(tt.count))
			ns, err := svc.discoverNamespaces(context.Background())
			require.NoError(t, err)
			assert.Len(t, ns, tt.wantCount)
		})
	}

	t.Run("non-sequential namespaces", func(t *testing.T) {
		// Root listing includes non-EKS entries (iam, placement) that should be filtered out.
		svc := newTestService(func(req *http.Request) (*http.Response, error) {
			path := req.URL.Path
			if strings.HasSuffix(path, "/latest/meta-data/") || strings.HasSuffix(path, "/latest/meta-data") {
				return httpResponse(200, "iam-eks-1\niam-eks-3\niam-eks-7\niam\nplacement"), nil
			}
			return httpResponse(404, ""), nil
		})
		ns, err := svc.discoverNamespaces(context.Background())
		require.NoError(t, err)
		assert.Equal(t, []string{"1", "3", "7"}, ns)
	})
}

// --- readNamespaceInfo tests ---

func TestReadNamespaceInfo(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		wantPodUIDs []string
		wantErr     bool
	}{
		{
			name:        "valid response returns pod UIDs",
			status:      200,
			body:        infoJSON("pod-1", "pod-2"),
			wantPodUIDs: []string{"pod-1", "pod-2"},
		},
		{
			name:        "empty pod credentials returns empty map",
			status:      200,
			body:        infoJSON(),
			wantPodUIDs: nil,
		},
		{
			name:    "not found returns error",
			status:  404,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock returns the configured status/body for any request.
			svc := newTestService(func(req *http.Request) (*http.Response, error) {
				return httpResponse(tt.status, tt.body), nil
			})

			// Read the info file for namespace "1".
			info, err := svc.readNamespaceInfo(context.Background(), "1")
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Verify the parsed info contains exactly the expected pod UIDs.
			assert.Len(t, info.PodCredentials, len(tt.wantPodUIDs))
			for _, uid := range tt.wantPodUIDs {
				_, ok := info.PodCredentials[uid]
				assert.True(t, ok, "expected pod UID %s in credentials", uid)
			}
		})
	}
}

// --- Namespace mapping tests ---

func TestNamespaceMapping_Build(t *testing.T) {
	tests := []struct {
		name        string
		rootListing string                                    // newline-delimited IMDS root listing response
		infoByNS    map[string]func() (*http.Response, error) // namespace suffix → HTTP response for its /info file
		wantPods    int                                       // expected total entries in podUID → namespace map
		wantLookups map[string]string                         // podUID → namespace pairs that must exist
		wantMissing []string                                  // podUIDs that must NOT be in the map
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
			name:        "non-sequential with gap and failure",
			rootListing: "iam-eks-2\niam-eks-5\niam-eks-9",
			infoByNS: map[string]func() (*http.Response, error){
				"2": func() (*http.Response, error) { return httpResponse(200, infoJSON("pod-x", "pod-y")), nil },
				"5": func() (*http.Response, error) { return httpResponse(500, "error"), nil },
				"9": func() (*http.Response, error) { return httpResponse(200, infoJSON("pod-z")), nil },
			},
			wantPods:    3,
			wantLookups: map[string]string{"pod-x": "2", "pod-y": "2", "pod-z": "9"},
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
			// Mock routes: root listing, per-namespace info files, 404 for everything else.
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

			// Build the mapping: discover namespaces → read info files → populate podUID map.
			require.NoError(t, svc.buildNamespaceMapping(testCtx()))
			assert.Len(t, svc.nsMapping.Load().(map[string]string), tt.wantPods)

			// Verify expected pods resolve to the correct namespace.
			for podUID, wantNS := range tt.wantLookups {
				ns, ok := svc.lookupNamespace(podUID)
				assert.True(t, ok, "expected pod %s in mapping", podUID)
				assert.Equal(t, wantNS, ns)
			}

			// Verify pods that should be absent are not in the map.
			for _, podUID := range tt.wantMissing {
				_, ok := svc.lookupNamespace(podUID)
				assert.False(t, ok, "expected pod %s NOT in mapping", podUID)
			}
		})
	}
}

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
	assert.Len(t, svc.nsMapping.Load().(map[string]string), 1)

	// Background refresh picks up pod-new after the ticker fires.
	svc.startBackgroundRefresh(ctx, 50*time.Millisecond)
	time.Sleep(150 * time.Millisecond)
	cancel()

	// Verify the map was updated with the new pod.
	assert.Len(t, svc.nsMapping.Load().(map[string]string), 2)
	_, ok := svc.lookupNamespace("pod-new")
	assert.True(t, ok)
}

func TestNamespaceMapping_Stop_HaltsRefresh(t *testing.T) {
	svc := newTestService(func(req *http.Request) (*http.Response, error) {
		return httpResponse(404, ""), nil
	})
	// Start background refresh then immediately cancel — goroutine should exit cleanly.
	ctx, cancel := context.WithCancel(testCtx())
	svc.startBackgroundRefresh(ctx, 10*time.Millisecond)
	cancel()
}

// --- GetIamCredentials tests ---

func TestGetIamCredentials(t *testing.T) {
	tests := []struct {
		name      string
		mapping   map[string]string
		credBody  string
		credCode  int
		podUID    string
		token     string // if set, overrides fakeRequest
		wantErr   error
		wantErrS  string // substring match when wantErr is nil
		wantKeyId string
		wantSrc   credentials.CredentialSource
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
			name:      "expired credential still returned",
			mapping:   map[string]string{"pod-1": "1"},
			credBody:  expiredCredJSON(),
			credCode:  200,
			podUID:    "pod-1",
			wantKeyId: "AKIA",
			wantSrc:   credentials.SourceIMDS,
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
			svc.nsMapping.Store(tt.mapping)

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
		})
	}
}

// --- NewService test ---

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
	_, ok := svc.lookupNamespace("pod-a")
	assert.True(t, ok, "mapping should be populated after NewService")
}

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

// --- Rate limiter test ---

func TestRateLimiter_CancelledContext_ReturnsError(t *testing.T) {
	// Wire up a rate-limited client with a real rate.Limiter (not the test shortcut).
	mock := &rateLimitedHTTPClient{
		client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return httpResponse(200, validCredJSON()), nil
		})},
		limiter: rate.NewLimiter(imdsRateLimit, imdsRateLimit),
	}
	imdsClient := imds.New(imds.Options{
		HTTPClient:        mock,
		ClientEnableState: imds.ClientEnabled,
	})
	svc := &service{imdsClient: imdsClient}
	svc.nsMapping.Store(map[string]string{"pod-1": "1"})

	// Cancel the context before calling — rate limiter's Wait should return context.Canceled.
	ctx, cancel := context.WithCancel(testCtx())
	cancel()

	_, _, err := svc.GetIamCredentials(ctx, fakeRequest(t, "pod-1"))
	assert.ErrorIs(t, err, context.Canceled)
}

// roundTripFunc adapts a function to http.RoundTripper for test convenience.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
