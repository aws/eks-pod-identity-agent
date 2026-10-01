// Pod credentials can be delivered to EC2 IMDS under numbered namespaces at
// /latest/meta-data/. Each namespace holds up to 200 pods, spread across
// iam-eks-1 .. iam-eks-N:
//
//	/latest/meta-data/
//	├── iam-eks-1/
//	│   ├── info                          # JSON with PodCredentials map (podUID → role/status)
//	│   └── security-credentials/
//	│       ├── <POD-UID-1>               # JSON credential file (AccessKeyId, SecretAccessKey, Token, Expiration)
//	│       └── <POD-UID-2>
//	├── iam-eks-2/
//	│   ├── info
//	│   └── security-credentials/
//	│       └── ...
//	├── iam
//	├── placement
//	└── ...
//
// The number of namespaces is dynamic and pods may be reshuffled across namespaces on each renewal.
package imds

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/sirupsen/logrus"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	"golang.org/x/time/rate"
)

// adds rate limiting to a standard http client
type rateLimitedHTTPClient struct {
	client  *http.Client
	limiter *rate.Limiter
}

func (r *rateLimitedHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if err := r.limiter.Wait(req.Context()); err != nil {
		return nil, fmt.Errorf("IMDS rate limiter: %w", err)
	}
	return r.client.Do(req)
}

type Iface interface {
	// GetIamCredentials fetches a pod's credentials from IMDS
	GetIamCredentials(ctx context.Context,
		request *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error)
	// String returns the delegate's name
	String() string
	// IsIrrecoverable reports whether an error means the credential is gone/invalid
	IsIrrecoverable(err error) (string, bool)
}

const (
	imdsRateLimit          = 20
	defaultRefreshInterval = 60 * time.Second
	// iamEKSPrefix is the IMDS namespace prefix for EKS pod credentials.
	iamEKSPrefix = "iam-eks-"
)

type service struct {
	imdsClient *imds.Client
	// nsMapping maps podUIDs to IMDS namespaces
	nsMapping atomic.Pointer[map[string]string]
}

// loadMapping returns the current podUID→namespace mapping.
func (s *service) loadMapping() map[string]string {
	if m := s.nsMapping.Load(); m != nil {
		return *m
	}
	return nil
}

// storeMapping atomically replaces the podUID→namespace mapping.
func (s *service) storeMapping(m map[string]string) {
	s.nsMapping.Store(&m)
}

func NewService(ctx context.Context, cfg aws.Config, optFns ...func(*imds.Options)) Iface {
	// Set a 1 second timeout per IMDS request, and rate limit to 20 TPS to avoid
	// heavy loads triggering throttling of other node processes that use IMD.
	httpClient := &rateLimitedHTTPClient{
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: 500 * time.Millisecond,
				}).DialContext,
			},
			Timeout: 1000 * time.Millisecond,
		},
		limiter: rate.NewLimiter(imdsRateLimit, imdsRateLimit),
	}
	opts := append([]func(*imds.Options){func(o *imds.Options) {
		o.HTTPClient = httpClient
	}}, optFns...)
	s := &service{
		imdsClient: imds.NewFromConfig(cfg, opts...),
	}
	s.storeMapping(map[string]string{})

	// Build a mapping of pods to namespaces, enabling easy lookup when fetching credentials for a pod.
	// This mapping is refreshed every 60s in the background.
	log := logger.FromContext(ctx)
	if err := s.buildNamespaceMapping(ctx); err != nil {
		log.Warnf("Initial IMDS namespace mapping build failed: %v", err)
	}
	s.startBackgroundRefresh(ctx, defaultRefreshInterval)

	return s
}

// String returns the delegate's name for logging and metrics.
func (s *service) String() string { return "imds" }

// IsIrrecoverable classifies IMDS errors for the cache's eviction decision.
//
// ErrPodNotInMapping (irrecoverable): the pod is absent from the agent's
// namespaceMapping. The mapping is refreshed every 60s in the background,
// and credentials are delivered to IMDS within ~30 minutes of pod creation.
// By the time a cache entry is eligible for refresh (hours), the mapping has
// long since converged. If the pod is absent at refresh time, it has been
// deleted or its association removed — eviction is correct.
//
// ErrCredentialNotFound (recoverable): the pod IS in the mapping but IMDS
// returned 404 for the credential itself. This can happen transiently when
// credentials are reshuffled across IMDS namespaces. The mapping still knows
// about the pod, so a subsequent refresh will succeed — eviction would be
// premature.
//
// All other errors (network timeouts, rate limits, etc.) are transient and
// recoverable by definition.
func (s *service) IsIrrecoverable(err error) (string, bool) {
	if errors.Is(err, ErrPodNotInMapping) {
		return "PodNotInMapping", true
	}
	return "Unknown", false
}

func (s *service) GetIamCredentials(ctx context.Context, request *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
	log := logger.FromContext(ctx)

	podUID, err := credentials.GetPodUIDFromToken(request.ServiceAccountToken)
	if err != nil {
		return nil, nil, fmt.Errorf("IMDS delegate: %w", err)
	}

	// See if the pod has a credential in IMDS
	ns, found := s.loadMapping()[podUID]
	log.WithFields(logrus.Fields{"podUID": podUID, "found": found, "namespace": ns}).Info("IMDS delegate namespace lookup")
	if !found {
		// The namespace mapping only refreshes in the background (every 60s), so a
		// miss is possible even when credentials do exist in IMDS. The race:
		//   t=0  pod receives creds via the sync path
		//   t=1  EKS Auth Service goes down
		//   t=2  agent restarts, clearing its cached creds
		//   t=3  creds are placed in IMDS
		//   t=4  pod requests creds, but the mapping hasn't refreshed yet, so the
		//        agent doesn't see the podUID and returns an error
		//
		// This is unlikely: SDKs refresh credentials close to expiry (hours away),
		// while the mapping converges within a minute. The alternative — refreshing
		// on demand — could overload IMDS under bursty workloads and throttle other
		// critical processes on the node. Behind the chained retriever, this miss
		// simply falls through to EKS Auth.
		return nil, nil, ErrPodNotInMapping
	}

	// If so, get the credential
	cred, err := s.readCredential(ctx, ns, podUID)
	if err != nil {
		return nil, nil, fmt.Errorf("IMDS delegate: %w", err)
	}

	log.WithFields(logrus.Fields{
		"source":    credentials.SourceIMDS,
		"namespace": ns,
	}).Info("Successfully fetched credentials from IMDS")

	return cred, credentials.CredentialMetadata{CredSource: credentials.SourceIMDS}, nil
}

// startBackgroundRefresh starts a goroutine that refreshes the namespace mapping
func (s *service) startBackgroundRefresh(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := s.buildNamespaceMapping(ctx); err != nil {
					log := logger.FromContext(ctx)
					// any failures log a warning but keep the old map
					log.Warnf("IMDS namespace mapping refresh failed, keeping old map: %v", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// buildNamespaceMapping reads all IMDS namespace info files and builds the
// podUID → namespace mapping.
func (s *service) buildNamespaceMapping(ctx context.Context) error {
	log := logger.FromContext(ctx)

	// Determine what namespaces exist (number is not guaranteed)
	namespaces, err := s.discoverNamespaces(ctx)
	if err != nil {
		return fmt.Errorf("building namespace mapping: %w", err)
	}

	// Create the new mapping
	newMap := make(map[string]string)
	for _, ns := range namespaces {
		// Read the info file, which lists the pods in the namespace
		info, err := s.readNamespaceInfo(ctx, ns)
		if err != nil {
			log.WithField("namespace", ns).Warnf("Failed to read namespace info, skipping: %v", err)
			continue
		}
		// Iterate through each pod and map it to the namespace
		for podUID, entry := range info.PodCredentials {
			if !strings.EqualFold(entry.Code, "Success") {
				log.WithFields(logrus.Fields{"namespace": ns, "podUID": podUID, "code": entry.Code}).
					Debug("Skipping pod with non-success code")
				continue
			}
			newMap[podUID] = ns
		}
	}

	s.storeMapping(newMap)
	log.Infof("IMDS namespace mapping refreshed: %d pods across %d namespaces (%v)", len(newMap), len(namespaces), namespaces)
	return nil
}

// maxMetadataBytes caps how much we read from any single IMDS response.
// IMDS info/credential files are a few KB; 1 MiB is generous headroom while
// bounding memory if a misbehaving metadata proxy returns an unbounded body.
const maxMetadataBytes = 1 << 20

// getMetadata fetches a metadata path from IMDS.
func (s *service) getMetadata(ctx context.Context, path string) ([]byte, error) {
	out, err := s.imdsClient.GetMetadata(ctx, &imds.GetMetadataInput{Path: path})
	if err != nil {
		return nil, err
	}
	defer out.Content.Close()
	return io.ReadAll(io.LimitReader(out.Content, maxMetadataBytes))
}

// readNamespaceInfo reads and parses the JSON info file for a given namespace.
func (s *service) readNamespaceInfo(ctx context.Context, namespace string) (*credentials.NamespaceInfo, error) {
	path := iamEKSPrefix + namespace + "/info"
	data, err := s.getMetadata(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("reading namespace info %s: %w", namespace, err)
	}
	var info credentials.NamespaceInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("parsing namespace info %s: %w", namespace, err)
	}
	return &info, nil
}

// readCredential reads and parses a pod's credential file from IMDS.
func (s *service) readCredential(ctx context.Context, namespace, podUID string) (*credentials.EksCredentialsResponse, error) {
	path := iamEKSPrefix + namespace + "/security-credentials/" + podUID
	data, err := s.getMetadata(ctx, path)
	if err != nil {
		if isNotFound(err) {
			return nil, ErrCredentialNotFound
		}
		return nil, fmt.Errorf("reading credential %s/%s: %w", namespace, podUID, err)
	}
	var cred credentials.EksCredentialsResponse
	if err := json.Unmarshal(data, &cred); err != nil {
		return nil, fmt.Errorf("parsing credential %s/%s: %w", namespace, podUID, err)
	}
	return &cred, nil
}

// discoverNamespaces lists the IMDS metadata root and returns the suffix of
// each iam-eks-* namespace (e.g. ["1", "2", "10"]). A single IMDS call
// replaces sequential probing, correctly handling non-sequential namespaces
// and dynamic namespace counts.
func (s *service) discoverNamespaces(ctx context.Context) ([]string, error) {
	data, err := s.getMetadata(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("listing IMDS metadata root: %w", err)
	}
	var namespaces []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		entry := strings.TrimRight(scanner.Text(), "/")
		if strings.HasPrefix(entry, iamEKSPrefix) {
			namespaces = append(namespaces, strings.TrimPrefix(entry, iamEKSPrefix))
		}
	}
	return namespaces, nil
}

// ProbeIMDS checks whether IMDS is available on this node using Option C
// (accept 200 or 429). A 200 means IMDS is healthy; a 429 means IMDS is
// present but throttling. Any other result (transport error, 404 from a
// metadata proxy, etc.) is treated as "IMDS not available."
func ProbeIMDS(ctx context.Context, cfg aws.Config, optFns ...func(*imds.Options)) bool {
	log := logger.FromContext(ctx)

	client := imds.NewFromConfig(cfg, optFns...)
	_, err := client.GetMetadata(ctx, &imds.GetMetadataInput{Path: "instance-id"})

	var respErr *smithyhttp.ResponseError
	available := err == nil ||
		(errors.As(err, &respErr) && respErr.HTTPStatusCode() == http.StatusTooManyRequests)

	if available {
		log.Info("IMDS probe succeeded, IMDS is available on this node")
	} else {
		log.Info("IMDS probe failed, IMDS is not available on this node")
	}
	return available
}
