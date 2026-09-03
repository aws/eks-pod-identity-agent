package imds

import (
	"context"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/sirupsen/logrus"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
)

// NodeMetadata holds IMDS-sourced metadata about the EC2 instance
type NodeMetadata struct {
	EksNodeName string
	InstanceId  string
	Zone        string
}

// IMDSClient is an interface for the IMDS operations we use, enabling test mocking.
type IMDSClient interface {
	GetMetadata(ctx context.Context, params *imds.GetMetadataInput, optFns ...func(*imds.Options)) (*imds.GetMetadataOutput, error)
}

// imdsTimeout is the maximum time to wait for all IMDS calls during startup.
const imdsTimeout = 1 * time.Second

// FetchNodeMetadata retrieves node identity information from IMDS.
// Returns a NodeMetadata struct with best-effort fields populated.
// Individual field failures are logged as warnings but do not fail the overall fetch.
// A timeout ensures startup is not blocked if IMDS is slow or unreachable.
func FetchNodeMetadata(ctx context.Context, cfg aws.Config) *NodeMetadata {
	timeoutCtx, cancel := context.WithTimeout(ctx, imdsTimeout)
	defer cancel()

	imdsClient := imds.NewFromConfig(cfg)
	return fetchNodeMetadataWithClient(timeoutCtx, imdsClient)
}

// fetchNodeMetadataWithClient is the internal implementation that accepts an IMDSClient interface.
func fetchNodeMetadataWithClient(ctx context.Context, imdsClient IMDSClient) *NodeMetadata {
	log := logger.FromContext(ctx)

	metadata := &NodeMetadata{
		EksNodeName: fetchField(ctx, imdsClient, log, "hostname", "hostname"),
		InstanceId:  fetchField(ctx, imdsClient, log, "instance-id", "instance-id"),
		Zone:        fetchField(ctx, imdsClient, log, "placement/availability-zone-id", "availability-zone-id"),
	}

	log.WithFields(logrus.Fields{
		"node-name":   metadata.EksNodeName,
		"instance-id": metadata.InstanceId,
		"zone":        metadata.Zone,
	}).Info("Node identity from IMDS")

	return metadata
}

// fetchField retrieves a single metadata field from IMDS at the given path.
// It is best-effort: on a request error, read error, it logs a warning and returns
// an empty string so the caller can proceed with whatever fields are available.
func fetchField(ctx context.Context, imdsClient IMDSClient, log *logrus.Entry, path, fieldName string) string {
	resp, err := imdsClient.GetMetadata(ctx, &imds.GetMetadataInput{Path: path})
	if err != nil {
		log.WithError(err).Warnf("Failed to fetch %s from IMDS", fieldName)
		return ""
	}
	defer resp.Content.Close()

	bytes, readErr := io.ReadAll(resp.Content)
	if readErr != nil {
		log.WithError(readErr).Warnf("Failed to read %s response from IMDS", fieldName)
		return ""
	}
	return strings.TrimSpace(string(bytes))
}
