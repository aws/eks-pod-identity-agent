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
	pathHostname   = "hostname"
	pathInstanceID = "instance-id"
	pathZone       = "placement/availability-zone-id"
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
		expectNode string
		expectInst string
		expectZone string
	}{
		{
			name: "all fields success",
			responses: map[string]mockResponse{
				pathHostname:   {body: "ip-10-0-1-42.us-west-2.compute.internal"},
				pathInstanceID: {body: "i-0abc123def456"},
				pathZone:       {body: "usw2-az1"},
			},
			expectNode: "ip-10-0-1-42.us-west-2.compute.internal",
			expectInst: "i-0abc123def456",
			expectZone: "usw2-az1",
		},
		{
			name: "hostname fetch fails",
			responses: map[string]mockResponse{
				pathHostname:   {err: fmt.Errorf("connection refused")},
				pathInstanceID: {body: "i-0abc123def456"},
				pathZone:       {body: "usw2-az1"},
			},
			expectNode: "",
			expectInst: "i-0abc123def456",
			expectZone: "usw2-az1",
		},
		{
			name: "instance-id fetch fails",
			responses: map[string]mockResponse{
				pathHostname:   {body: "ip-10-0-1-42.us-west-2.compute.internal"},
				pathInstanceID: {err: fmt.Errorf("timeout")},
				pathZone:       {body: "usw2-az1"},
			},
			expectNode: "ip-10-0-1-42.us-west-2.compute.internal",
			expectInst: "",
			expectZone: "usw2-az1",
		},
		{
			name: "zone fetch fails",
			responses: map[string]mockResponse{
				pathHostname:   {body: "ip-10-0-1-42.us-west-2.compute.internal"},
				pathInstanceID: {body: "i-0abc123def456"},
				pathZone:       {err: fmt.Errorf("not available")},
			},
			expectNode: "ip-10-0-1-42.us-west-2.compute.internal",
			expectInst: "i-0abc123def456",
			expectZone: "",
		},
		{
			name: "all fields fail",
			responses: map[string]mockResponse{
				pathHostname:   {err: fmt.Errorf("connection refused")},
				pathInstanceID: {err: fmt.Errorf("connection refused")},
				pathZone:       {err: fmt.Errorf("connection refused")},
			},
			expectNode: "",
			expectInst: "",
			expectZone: "",
		},
		{
			name: "read error on hostname",
			responses: map[string]mockResponse{
				pathHostname:   {readErr: true},
				pathInstanceID: {body: "i-0abc123def456"},
				pathZone:       {body: "usw2-az1"},
			},
			expectNode: "",
			expectInst: "i-0abc123def456",
			expectZone: "usw2-az1",
		},
		{
			name: "empty body",
			responses: map[string]mockResponse{
				pathHostname:   {body: ""},
				pathInstanceID: {body: "i-0abc123def456"},
				pathZone:       {body: "usw2-az1"},
			},
			expectNode: "",
			expectInst: "i-0abc123def456",
			expectZone: "usw2-az1",
		},
		{
			name: "path not found (only hostname available)",
			responses: map[string]mockResponse{
				pathHostname: {body: "ip-10-0-1-42.us-west-2.compute.internal"},
			},
			expectNode: "ip-10-0-1-42.us-west-2.compute.internal",
			expectInst: "",
			expectZone: "",
		},
		{
			name: "whitespace is trimmed",
			responses: map[string]mockResponse{
				pathHostname:   {body: "  ip-10-0-1-42.us-west-2.compute.internal  "},
				pathInstanceID: {body: "i-0abc123def456\n"},
				pathZone:       {body: "usw2-az1"},
			},
			expectNode: "ip-10-0-1-42.us-west-2.compute.internal",
			expectInst: "i-0abc123def456",
			expectZone: "usw2-az1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			client := &mockIMDSClient{responses: tc.responses}

			metadata := fetchNodeMetadataWithClient(context.Background(), client)

			g.Expect(metadata).NotTo(BeNil())
			g.Expect(metadata.EksNodeName).To(Equal(tc.expectNode))
			g.Expect(metadata.InstanceId).To(Equal(tc.expectInst))
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
			pathHostname:   {body: "should-not-be-returned"},
			pathInstanceID: {body: "should-not-be-returned"},
			pathZone:       {body: "should-not-be-returned"},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	metadata := fetchNodeMetadataWithClient(ctx, client)
	elapsed := time.Since(start)

	// Returns promptly (well under the 5s delay) and fails open with empty fields.
	g.Expect(elapsed).To(BeNumerically("<", 1*time.Second))
	g.Expect(metadata).NotTo(BeNil())
	g.Expect(metadata.EksNodeName).To(BeEmpty())
	g.Expect(metadata.InstanceId).To(BeEmpty())
	g.Expect(metadata.Zone).To(BeEmpty())
}
