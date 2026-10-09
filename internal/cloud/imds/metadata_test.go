package imds

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	. "github.com/onsi/gomega"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

const (
	pathZone = "placement/availability-zone-id"
)

// mockIMDSClient implements IMDSClient for testing.
type mockIMDSClient struct {
	responses map[string]mockResponse
	// delay, if set, is applied before returning any response (used to test timeouts).
	delay time.Duration
}

type mockResponse struct {
	body    string
	err     error
	readErr bool // if true, the response body returns an error when read
}

// erroringReader returns an error on Read to simulate an io.ReadAll failure.
type erroringReader struct{}

func (e *erroringReader) Read(p []byte) (int, error) { return 0, fmt.Errorf("simulated read failure") }
func (e *erroringReader) Close() error               { return nil }

func (m *mockIMDSClient) GetMetadata(ctx context.Context, params *imds.GetMetadataInput, optFns ...func(*imds.Options)) (*imds.GetMetadataOutput, error) {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	resp, ok := m.responses[params.Path]
	if !ok {
		return nil, fmt.Errorf("metadata not found: %s", params.Path)
	}
	if resp.err != nil {
		return nil, resp.err
	}
	if resp.readErr {
		return &imds.GetMetadataOutput{Content: &erroringReader{}}, nil
	}
	return &imds.GetMetadataOutput{Content: io.NopCloser(strings.NewReader(resp.body))}, nil
}

func TestFetchNodeMetadata(t *testing.T) {
	testCases := []struct {
		name       string
		responses  map[string]mockResponse
		expectZone string
	}{
		{
			name: "zone success",
			responses: map[string]mockResponse{
				pathZone: {body: "usw2-az1"},
			},
			expectZone: "usw2-az1",
		},
		{
			name: "zone fetch fails",
			responses: map[string]mockResponse{
				pathZone: {err: fmt.Errorf("not available")},
			},
			expectZone: "",
		},
		{
			name: "zone read error",
			responses: map[string]mockResponse{
				pathZone: {readErr: true},
			},
			expectZone: "",
		},
		{
			name: "empty zone body",
			responses: map[string]mockResponse{
				pathZone: {body: ""},
			},
			expectZone: "",
		},
		{
			name:       "zone path not found",
			responses:  map[string]mockResponse{},
			expectZone: "",
		},
		{
			name: "whitespace is trimmed",
			responses: map[string]mockResponse{
				pathZone: {body: "  usw2-az1\n"},
			},
			expectZone: "usw2-az1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			client := &mockIMDSClient{responses: tc.responses}

			metadata := fetchNodeMetadataWithClient(context.Background(), client)

			g.Expect(metadata).NotTo(BeNil())
			g.Expect(metadata.Zone).To(Equal(tc.expectZone))
		})
	}
}

// TestFetchNodeMetadata_TimeoutDoesNotHang verifies that when IMDS is slow, the
// context deadline cancels the calls and fetching returns promptly with empty
// fields rather than hanging agent startup.
func TestFetchNodeMetadata_TimeoutDoesNotHang(t *testing.T) {
	g := NewWithT(t)

	// Client delays far longer than the context deadline.
	client := &mockIMDSClient{
		delay: 5 * time.Second,
		responses: map[string]mockResponse{
			pathZone: {body: "should-not-be-returned"},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	metadata := fetchNodeMetadataWithClient(ctx, client)
	elapsed := time.Since(start)

	// Returns promptly (under the 5s delay) and fails open with empty fields.
	g.Expect(elapsed).To(BeNumerically("<", 1*time.Second))
	g.Expect(metadata).NotTo(BeNil())
	g.Expect(metadata.Zone).To(BeEmpty())
}
