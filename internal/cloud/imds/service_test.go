package imds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
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
	pods := make(map[string]string)
	for _, uid := range podUIDs {
		pods[uid] = credentials.PodCredentialSuccessCode
	}
	b, _ := json.Marshal(credentials.NamespaceInfo{Code: "Success", LastUpdated: "2025-03-11T18:58:15Z", PodCredentials: pods})
	return string(b)
}

// infoJSONWithCodes builds a namespace info JSON where each podUID has the given status code.
func infoJSONWithCodes(pods map[string]string) string {
	b, _ := json.Marshal(credentials.NamespaceInfo{Code: "Success", LastUpdated: "2025-03-11T18:58:15Z", PodCredentials: pods})
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
		name      string
		status    int
		body      string
		wantErr   string
		wantKeyId string
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
		{
			name:    "empty object is rejected",
			status:  200,
			body:    "{}",
			wantErr: ErrInvalidCredential.Error(),
		},
		{
			name:    "expiration-only payload is rejected",
			status:  200,
			body:    `{"Expiration":"2099-01-01T00:00:00Z"}`,
			wantErr: ErrInvalidCredential.Error(),
		},
		{
			name:    "missing secret key is rejected",
			status:  200,
			body:    `{"AccessKeyId":"AKIA","Token":"tok","Expiration":"2099-01-01T00:00:00Z"}`,
			wantErr: ErrInvalidCredential.Error(),
		},
		{
			name:    "missing token is rejected",
			status:  200,
			body:    `{"AccessKeyId":"AKIA","SecretAccessKey":"secret","Expiration":"2099-01-01T00:00:00Z"}`,
			wantErr: ErrInvalidCredential.Error(),
		},
		{
			// Static-stability: a well-formed but expired credential must still pass
			// validation (expiry is enforced by the cache, not readCredential).
			name:      "valid but expired credential is accepted",
			status:    200,
			body:      expiredCredJSON(),
			wantKeyId: "AKIA",
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

// --- getMetadata size-cap tests ---

// TestGetMetadata_SizeCap verifies the maxMetadataBytes read cap: a body that
// reaches the limit is rejected, a smaller one is returned whole.
func TestGetMetadata_SizeCap(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
		wantLen int
	}{
		{
			name:    "oversized body is rejected",
			body:    strings.Repeat("a", 4*maxMetadataBytes),
			wantErr: true,
		},
		{
			name:    "body at the cap is rejected",
			body:    strings.Repeat("a", maxMetadataBytes),
			wantErr: true,
		},
		{
			name:    "body just under the cap is returned whole",
			body:    strings.Repeat("a", maxMetadataBytes-1),
			wantLen: maxMetadataBytes - 1,
		},
		{
			name:    "normal-sized body is returned untouched",
			body:    "iam-eks-1\niam-eks-2",
			wantLen: len("iam-eks-1\niam-eks-2"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(func(req *http.Request) (*http.Response, error) {
				return httpResponse(200, tt.body), nil
			})

			data, err := svc.getMetadata(context.Background(), "")
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "exceeds")
				return
			}
			require.NoError(t, err)
			assert.Len(t, data, tt.wantLen)
			assert.Equal(t, tt.body, string(data))
		})
	}
}

// --- Namespace mapping tests ---

func TestNamespaceMapping_Build(t *testing.T) {
	tests := []struct {
		name        string
		rootListing string                                    // newline-delimited IMDS root listing response
		infoByNS    map[string]func() (*http.Response, error) // namespace suffix → HTTP response for its /info file
		prevMapping map[string]string                         // podUID → namespace map seeded before the build (for salvage cases)
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
			// No previous map, so there is nothing to salvage: a failed namespace
			// simply contributes no pods this cycle.
			name:        "partial failure with no previous map drops failed namespace",
			rootListing: "iam-eks-1\niam-eks-2",
			infoByNS: map[string]func() (*http.Response, error){
				"1": func() (*http.Response, error) { return httpResponse(200, infoJSON("pod-a")), nil },
				"2": func() (*http.Response, error) { return httpResponse(500, "internal error"), nil },
			},
			wantPods:    1,
			wantLookups: map[string]string{"pod-a": "1"},
		},
		{
			// pod-c lives in ns2, ns2 read fails. ns2's pods are salvaged from
			// the previous map so a transient failure does not look like removal.
			name:        "partial failure salvages pods from failed namespace",
			rootListing: "iam-eks-1\niam-eks-2",
			infoByNS: map[string]func() (*http.Response, error){
				"1": func() (*http.Response, error) { return httpResponse(200, infoJSON("pod-a", "pod-b")), nil },
				"2": func() (*http.Response, error) { return httpResponse(500, "internal error"), nil },
			},
			prevMapping: map[string]string{"pod-a": "1", "pod-b": "1", "pod-c": "2"},
			wantPods:    3,
			wantLookups: map[string]string{"pod-a": "1", "pod-b": "1", "pod-c": "2"},
		},
		{
			// pod-a reshuffled ns2→ns1; ns2 (its OLD home) fails. ns1 reads OK
			// and reports pod-a, so the current-cycle namespace (1) wins over the
			// salvaged previous namespace (2).
			name:        "reshuffle beats salvage when new namespace reads successfully",
			rootListing: "iam-eks-1\niam-eks-2",
			infoByNS: map[string]func() (*http.Response, error){
				"1": func() (*http.Response, error) { return httpResponse(200, infoJSON("pod-a")), nil },
				"2": func() (*http.Response, error) { return httpResponse(500, "error"), nil },
			},
			prevMapping: map[string]string{"pod-a": "2"},
			wantPods:    1,
			wantLookups: map[string]string{"pod-a": "1"},
		},
		{
			// pod-a reshuffled ns2→ns1; ns1 (its NEW home) fails. ns2 reads OK
			// and no longer lists pod-a. The agent cannot tell relocation from
			// removal while ns1 is dark, so on a partial scan we retain pod-a with
			// its stale previous namespace (2) rather than evict a possibly-live
			// pod. The stale home self-heals on the next clean scan.
			name:        "partial failure retains pod with stale namespace (reshuffle into failed ns)",
			rootListing: "iam-eks-1\niam-eks-2",
			infoByNS: map[string]func() (*http.Response, error){
				"1": func() (*http.Response, error) { return httpResponse(500, "error"), nil },
				"2": func() (*http.Response, error) { return httpResponse(200, infoJSON()), nil },
			},
			prevMapping: map[string]string{"pod-a": "2"},
			wantPods:    1,
			wantLookups: map[string]string{"pod-a": "2"},
		},
		{
			// Complete scan (no namespace failed): a pod absent from the previous
			// map is a confirmed removal and is NOT salvaged, so it is evicted.
			name:        "complete scan evicts removed pod",
			rootListing: "iam-eks-1\niam-eks-2",
			infoByNS: map[string]func() (*http.Response, error){
				"1": func() (*http.Response, error) { return httpResponse(200, infoJSON("pod-a")), nil },
				"2": func() (*http.Response, error) { return httpResponse(200, infoJSON()), nil },
			},
			prevMapping: map[string]string{"pod-a": "1", "pod-gone": "2"},
			wantPods:    1,
			wantLookups: map[string]string{"pod-a": "1"},
			wantMissing: []string{"pod-gone"},
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
						"pod-ok":      "0",
						"pod-denied":  "AccessDenied",
						"pod-pending": "1",
					})), nil
				},
			},
			wantPods:    1,
			wantLookups: map[string]string{"pod-ok": "1"},
			wantMissing: []string{"pod-denied", "pod-pending"},
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

			// Seed the previous map so salvage-on-partial-scan cases can exercise
			// retention of pods from namespaces that fail to read this cycle.
			if tt.prevMapping != nil {
				svc.storeMapping(tt.prevMapping)
			}

			// Build the mapping: discover namespaces → read info files → populate podUID map.
			require.NoError(t, svc.buildNamespaceMapping(testCtx()))
			assert.Len(t, svc.loadMapping(), tt.wantPods)

			// Verify expected pods resolve to the correct namespace.
			for podUID, wantNS := range tt.wantLookups {
				ns, ok := svc.loadMapping()[podUID]
				assert.True(t, ok, "expected pod %s in mapping", podUID)
				assert.Equal(t, wantNS, ns)
			}

			// Verify pods that should be absent are not in the map.
			for _, podUID := range tt.wantMissing {
				_, ok := svc.loadMapping()[podUID]
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
	assert.Len(t, svc.loadMapping(), 1)

	// Background refresh picks up pod-new after the ticker fires.
	svc.startBackgroundRefresh(ctx, 50*time.Millisecond)
	time.Sleep(150 * time.Millisecond)
	cancel()

	// Verify the map was updated with the new pod.
	assert.Len(t, svc.loadMapping(), 2)
	_, ok := svc.loadMapping()["pod-new"]
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
			name:     "invalid credential payload is rejected",
			mapping:  map[string]string{"pod-1": "1"},
			credBody: "{}",
			credCode: 200,
			podUID:   "pod-1",
			wantErr:  ErrInvalidCredential,
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
	_, ok := svc.loadMapping()["pod-a"]
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
	svc.storeMapping(map[string]string{"pod-1": "1"})

	// Cancel the context before calling — rate limiter's Wait should return context.Canceled.
	ctx, cancel := context.WithCancel(testCtx())
	cancel()

	_, _, err := svc.GetIamCredentials(ctx, fakeRequest(t, "pod-1"))
	assert.ErrorIs(t, err, context.Canceled)
}

// roundTripFunc adapts a function to http.RoundTripper for test convenience.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// --- IsIrrecoverable tests ---

func TestIsIrrecoverable(t *testing.T) {
	svc := &service{}
	tests := []struct {
		name            string
		err             error
		wantCode        string
		wantIrrecovable bool
	}{
		{"pod not in mapping is irrecoverable", ErrPodNotInMapping, "PodNotInMapping", true},
		{"wrapped pod-not-in-mapping is irrecoverable", fmt.Errorf("IMDS delegate: %w", ErrPodNotInMapping), "PodNotInMapping", true},
		{"credential not found is recoverable, surfaces error text", ErrCredentialNotFound, ErrCredentialNotFound.Error(), false},
		{"arbitrary error is recoverable, surfaces error text", fmt.Errorf("connection reset"), "connection reset", false},
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

// --- Operation timeout tests ---

// blockUntilCtxDone returns a handler that blocks until the request context is
// cancelled, then returns its error. It lets a test drive an IMDS call that
// "hangs" so an operation deadline — not the per-attempt HTTP timeout — is what
// ends it.
func blockUntilCtxDone() func(*http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
}

// TestGetIamCredentials_ForegroundTimeout verifies that a slow IMDS read is
// bounded by syncOpTimeout rather than running up to the SDK's much larger
// default, so the chained retriever retains budget for the EKS Auth fallback.
func TestGetIamCredentials_ForegroundTimeout(t *testing.T) {
	svc := newTestService(blockUntilCtxDone())
	svc.storeMapping(map[string]string{"pod-1": "1"})

	start := time.Now()
	_, _, err := svc.GetIamCredentials(testCtx(), fakeRequest(t, "pod-1"))
	elapsed := time.Since(start)

	require.Error(t, err)
	// Must be bounded by our 1s operation budget, well under the SDK default (5s).
	assert.Less(t, elapsed, syncOpTimeout+2*time.Second,
		"foreground read should be bounded by syncOpTimeout, took %v", elapsed)
}

// TestBuildNamespaceMapping_RefreshBudget verifies that a build whose namespace
// read hangs is bounded by refreshOpTimeout rather than blocking indefinitely.
func TestBuildNamespaceMapping_RefreshBudget(t *testing.T) {
	// Root listing returns quickly; the per-namespace info read blocks on context.
	svc := newTestService(func(req *http.Request) (*http.Response, error) {
		path := req.URL.Path
		if strings.HasSuffix(path, "/latest/meta-data/") || strings.HasSuffix(path, "/latest/meta-data") {
			return httpResponse(200, "iam-eks-1"), nil
		}
		<-req.Context().Done()
		return nil, req.Context().Err()
	})

	start := time.Now()
	err := svc.buildNamespaceMapping(testCtx())
	elapsed := time.Since(start)

	// The build still "succeeds" (a failed read is retained, not fatal), but it
	// must return bounded by refreshOpTimeout rather than hanging on the stuck read.
	require.NoError(t, err)
	assert.Less(t, elapsed, refreshOpTimeout+2*time.Second,
		"build should be bounded by refreshOpTimeout, took %v", elapsed)
}
