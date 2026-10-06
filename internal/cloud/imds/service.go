// Package imds implements the IMDS credential delegate for EKS Pod Identity.
//
// Pod credentials are delivered to EC2 IMDS under numbered namespaces at
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
//	├── iam                               # EC2 instance role (not EKS)
//	├── placement
//	└── ...
//
// The number of namespaces is dynamic and pods may be reshuffled across namespaces on each renewal. Namespaces are
// discovered by listing the metadata root and filtering for the iam-eks-* prefix.
package imds

import (
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

// rateLimitedHTTPClient wraps an http.Client with a rate limiter so that all
// IMDS requests are throttled transparently.
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

//go:generate mockgen.sh imds $GOFILE

type Iface interface {
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
	// nsMapping maps podUIDs to IMDS namespaces.
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
	// The IMDS SDK enforces a default 5-second timeout per operation. We tighten
	// this to 1s total / 500ms socket connect to match eksauth's config. The client
	// is rate-limited to 20 TPS to protect other critical processes on the instance
	// that call IMDS.
	// https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/feature/ec2/imds#Options
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
func (s *service) IsIrrecoverable(err error) (string, bool) {
	if errors.Is(err, ErrPodNotInMapping) {
		// ErrPodNotInMapping means the namespace mapping doesn't hold the pod. IMDS
		// creds are delivered every ~30 mins, and by the time the cache tries to refresh (after some hours),
		// the creds will be in IMDS and the mapping. So, credentials won't be prematurely evicted.

		// If a pod is absent from the mapping, the credential has been removed from IMDS and the mapping updated,
		// which means IMDS will no longer hold credentials for the pod.
		return "PodNotInMapping", true
	}
	// Every other error is considered recoverable
	return err.Error(), false
}

func (s *service) GetIamCredentials(ctx context.Context, request *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
	log := logger.FromContext(ctx)

	podUID, err := credentials.GetPodUIDFromToken(request.ServiceAccountToken)
	if err != nil {
		return nil, nil, fmt.Errorf("IMDS delegate: %w", err)
	}

	ns, found := s.loadMapping()[podUID]
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
		// critical processes on the node.
		return nil, nil, ErrPodNotInMapping
	}

	cred, err := s.readCredential(ctx, ns, podUID)
	if err != nil {
		return nil, nil, fmt.Errorf("IMDS delegate: %w", err)
	}

	log.WithFields(logrus.Fields{
		"source":    credentials.SourceIMDS,
		"namespace": ns,
	}).Info("Fetched credentials from IMDS")

	return cred, credentials.CredentialMetadata{CredSource: credentials.SourceIMDS}, nil
}

// startBackgroundRefresh starts a goroutine that refreshes the namespace
// mapping at the given interval. Failures log a warning but keep the old map.
func (s *service) startBackgroundRefresh(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := s.buildNamespaceMapping(ctx); err != nil {
					log := logger.FromContext(ctx)
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

	namespaces, err := s.discoverNamespaces(ctx)
	if err != nil {
		return fmt.Errorf("building namespace mapping: %w", err)
	}

	newMap := make(map[string]string)
	anyFailed := false
	for _, ns := range namespaces {
		info, err := s.readNamespaceInfo(ctx, ns)
		if err != nil {
			log.WithField("namespace", ns).Warnf("Failed to read namespace info, retaining known pods for it: %v", err)
			anyFailed = true
			continue
		}
		for podUID, code := range info.PodCredentials {
			if code != credentials.PodCredentialSuccessCode {
				log.WithFields(logrus.Fields{"namespace": ns, "podUID": podUID, "code": code}).
					Debug("Skipping pod with non-success code")
				continue
			}
			newMap[podUID] = ns
		}
	}

	// If unable to read a namespace, keep pods that weren't found in IMDS. This
	// prevents failed namespace reads from clearing the pod from namespaceMapping,
	// which would evict the pod from the cache. Instead, the background refresh
	// process will try again, and in the meantime failures to get creds from IMDS
	// will fall back to eksauth. Note that this may preserve mappings for deleted pods.
	if anyFailed {
		currentMap := s.loadMapping()
		carryForwardEntries(newMap, currentMap)
	}

	s.storeMapping(newMap)
	log.Infof("IMDS namespace mapping refreshed: %d pods across %d namespaces (completeScan=%v)",
		len(newMap), len(namespaces), !anyFailed)
	return nil
}

// carryForwardEntries carries forward previous-map entries into newMap
func carryForwardEntries(newMap, previousMap map[string]string) {
	for podUID, oldNS := range previousMap {
		if _, seen := newMap[podUID]; seen {
			continue
		}
		newMap[podUID] = oldNS
	}
}

// maxMetadataBytes bounds a single IMDS response.
const maxMetadataBytes = 1 << 20

// getMetadata fetches a metadata path from IMDS.
func (s *service) getMetadata(ctx context.Context, path string) ([]byte, error) {
	out, err := s.imdsClient.GetMetadata(ctx, &imds.GetMetadataInput{Path: path})
	if err != nil {
		return nil, err
	}
	defer out.Content.Close()
	// Bound the read; hitting the limit means the response is too large to trust.
	data, err := io.ReadAll(io.LimitReader(out.Content, maxMetadataBytes))
	if err != nil {
		return nil, err
	}
	if len(data) >= maxMetadataBytes {
		return nil, fmt.Errorf("IMDS response for %q exceeds %d-byte limit", path, maxMetadataBytes)
	}
	return data, nil
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
	for _, entry := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		entry = strings.TrimRight(entry, "/")
		if strings.HasPrefix(entry, iamEKSPrefix) {
			namespaces = append(namespaces, strings.TrimPrefix(entry, iamEKSPrefix))
		}
	}
	return namespaces, nil
}

// ProbeIMDS checks whether IMDS is available on this node. A 200 means IMDS is
// healthy; a 429 means IMDS is present but throttling. Any other result
// (transport error, 404 from a metadata proxy, etc.) is treated as "IMDS not
// available."
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
