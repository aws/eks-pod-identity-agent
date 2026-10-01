// Package sts calls GetTrustBundles, which no released aws-sdk-go-v2 STS client
// carries yet. It builds the call from the SDK's public pieces (the STS client's
// resolved options, the STS endpoint rules, the SigV4 signer and the awsQuery
// error decoder), so partitions, FIPS, dual-stack and AWS_ENDPOINT_URL_STS are
// handled as the SDK handles them. Only the awsQuery request and response bodies
// are written by hand.
//
// Delete it once the SDK releases the operation: the service becomes a call to
// sts.Client.GetTrustBundles and nothing that uses Iface changes.
package sts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsxml "github.com/aws/aws-sdk-go-v2/aws/protocol/xml"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awssts "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	smithyauth "github.com/aws/smithy-go/auth"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
)

//go:generate mockgen.sh mocksts $GOFILE mocksts

// Iface is the set of STS operations the agent calls outside the released SDK.
type Iface interface {
	// GetTrustBundles returns the trust bundles for the named workload
	// identity provider, one entry per trust domain, in response order.
	GetTrustBundles(ctx context.Context, providerArn string) ([]TrustBundle, error)

	// GetWorkloadIdentityCertificate mints an X.509-SVID for the workload
	// identity that creds already carries. Unlike GetTrustBundles it is signed
	// with a workload's session rather than the node role, because STS reads the
	// subject off the caller's session and there is no request input naming it.
	GetWorkloadIdentityCertificate(ctx context.Context, creds aws.Credentials, req CertificateRequest) (*IssuedCertificate, error)
}

// TrustBundle is one entry of a GetTrustBundles response.
type TrustBundle struct {
	// TrustDomain is the SPIFFE trust domain the entry is for.
	TrustDomain string
	// Bundle is the domain's SPIFFE bundle document, an RFC 7517 JWK Set. It is
	// opaque here; the bundle tier parses it.
	Bundle string
}

const (
	// apiVersion is the STS API version every awsQuery request names.
	apiVersion = "2011-06-15"
	// operationGetTrustBundles is the operation name, used as the awsQuery
	// Action and in errors.
	operationGetTrustBundles = "GetTrustBundles"
	// signingName is the SigV4 service name STS signs under.
	signingName = "sts"
	// maxResponseBytes bounds how much of a response body is read. A bundle
	// document is a few kilobytes; this only stops a broken or hostile endpoint
	// from growing the agent's memory.
	maxResponseBytes = 1 << 20
)

type service struct {
	options awssts.Options
	signer  *v4.Signer
	now     func() time.Time
}

// NewService builds the client from cfg, which must be the configuration the
// agent loaded at boot with the node's credentials, never a workload session.
// GetTrustBundles takes the provider ARN as a request input, so the call needs
// nothing else from a workload.
func NewService(cfg aws.Config) Iface {
	return &service{
		// The STS client is built only to resolve its options the way the SDK
		// does, including the service-specific endpoint override. It never makes
		// a call.
		options: awssts.NewFromConfig(cfg).Options(),
		signer:  v4.NewSigner(),
		now:     time.Now,
	}
}

func (s *service) GetTrustBundles(ctx context.Context, providerArn string) ([]TrustBundle, error) {
	body := url.Values{
		"Action":      {operationGetTrustBundles},
		"Version":     {apiVersion},
		"ProviderArn": {providerArn},
	}.Encode()

	var decoded getTrustBundlesResponse
	if err := s.call(ctx, nil, body, &decoded); err != nil {
		return nil, &smithy.OperationError{
			ServiceID:     awssts.ServiceID,
			OperationName: operationGetTrustBundles,
			Err:           err,
		}
	}

	entries := make([]TrustBundle, 0, len(decoded.Result.TrustBundles.Members))
	for _, member := range decoded.Result.TrustBundles.Members {
		entries = append(entries, TrustBundle(member))
	}
	return entries, nil
}

// getTrustBundlesResponse is the awsQuery response shape of GetTrustBundles. A
// list is a sequence of member elements under the list's own element, and the
// output structure sits under the operation's Result element.
type getTrustBundlesResponse struct {
	XMLName xml.Name `xml:"GetTrustBundlesResponse"`
	Result  struct {
		TrustBundles struct {
			Members []struct {
				TrustDomain string `xml:"TrustDomain"`
				Bundle      string `xml:"Bundle"`
			} `xml:"member"`
		} `xml:"TrustBundles"`
	} `xml:"GetTrustBundlesResult"`
}

// call signs and sends one awsQuery request and decodes a successful response
// into out. It makes one attempt. The calling tier owns retrying, on its own
// backoff, and a retry loop here would multiply that against every node's
// schedule during an STS outage.
//
// signWith names the credentials to sign with. Nil means the client's own, which
// is the node role: that is what GetTrustBundles wants, since it names its target
// provider as a request input. An operation whose result depends on who asked,
// GetWorkloadIdentityCertificate being the one, passes a workload's session
// credentials instead.
func (s *service) call(ctx context.Context, signWith *aws.Credentials, body string, out any) error {
	endpoint, signingRegion, err := s.resolveEndpoint(ctx)
	if err != nil {
		return err
	}
	var creds aws.Credentials
	switch {
	case signWith != nil:
		creds = *signWith
	case s.options.Credentials == nil:
		return errors.New("no AWS credentials are configured to sign the request with")
	default:
		if creds, err = s.options.Credentials.Retrieve(ctx); err != nil {
			return fmt.Errorf("retrieving credentials to sign the request: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.URI.String(), strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("building the request: %w", err)
	}
	for name := range endpoint.Headers {
		req.Header.Set(name, endpoint.Headers.Get(name))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("User-Agent", "eks-pod-identity-agent/"+configuration.AgentVersion)

	payloadHash := sha256.Sum256([]byte(body))
	if err := s.signer.SignHTTP(ctx, creds, req, hex.EncodeToString(payloadHash[:]), signingName, signingRegion, s.now().UTC()); err != nil {
		return fmt.Errorf("signing the request: %w", err)
	}

	resp, err := s.options.HTTPClient.Do(req)
	if err != nil {
		return &smithyhttp.RequestSendError{Err: err}
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("reading the response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return responseError(resp, payload)
	}
	if err := xml.Unmarshal(payload, out); err != nil {
		return &smithy.DeserializationError{Err: fmt.Errorf("decoding the response: %w", err), Snapshot: payload}
	}
	return nil
}

// resolveEndpoint runs the STS endpoint rules over the client's options as the
// SDK binds them for an STS operation, and returns the endpoint with its signing
// region. The region comes from the endpoint's auth scheme, since the rules can
// name one other than the client's, as the global endpoint does.
func (s *service) resolveEndpoint(ctx context.Context) (endpoint smithyEndpoint, signingRegion string, err error) {
	params := awssts.EndpointParameters{
		Region:       aws.String(s.options.Region),
		UseDualStack: aws.Bool(s.options.EndpointOptions.UseDualStackEndpoint == aws.DualStackEndpointStateEnabled),
		UseFIPS:      aws.Bool(s.options.EndpointOptions.UseFIPSEndpoint == aws.FIPSEndpointStateEnabled),
		Endpoint:     s.options.BaseEndpoint,
	}
	resolved, err := s.options.EndpointResolverV2.ResolveEndpoint(ctx, params)
	if err != nil {
		return smithyEndpoint{}, "", fmt.Errorf("resolving the STS endpoint: %w", err)
	}

	signingRegion = s.options.Region
	if options, ok := smithyauth.GetAuthOptions(&resolved.Properties); ok {
		for _, option := range options {
			if option.SchemeID != smithyauth.SchemeIDSigV4 {
				continue
			}
			if region, ok := smithyhttp.GetSigV4SigningRegion(&option.SignerProperties); ok && region != "" {
				signingRegion = region
			}
			break
		}
	}
	if signingRegion == "" {
		return smithyEndpoint{}, "", errors.New("no region is configured to sign the request for")
	}
	return smithyEndpoint{URI: resolved.URI, Headers: resolved.Headers}, signingRegion, nil
}

// smithyEndpoint is the part of a resolved endpoint the request is built from.
type smithyEndpoint struct {
	URI     url.URL
	Headers http.Header
}

// responseError decodes an awsQuery error response into the same error chain the
// SDK produces for a released operation: an API error carrying the error code,
// inside a response error carrying the status and request ID. Callers can then
// classify it with errors.As exactly as they would an SDK error.
func responseError(resp *http.Response, payload []byte) error {
	components, err := awsxml.GetErrorResponseComponents(bytes.NewReader(payload), false)
	if err != nil || components.Code == "" {
		components.Code = http.StatusText(resp.StatusCode)
		if components.Code == "" {
			components.Code = "UnknownError"
		}
	}
	if components.RequestID == "" {
		components.RequestID = resp.Header.Get("X-Amzn-RequestId")
	}
	fault := smithy.FaultServer
	if resp.StatusCode < http.StatusInternalServerError {
		fault = smithy.FaultClient
	}
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: resp},
			Err: &smithy.GenericAPIError{
				Code:    components.Code,
				Message: components.Message,
				Fault:   fault,
			},
		},
		RequestID: components.RequestID,
	}
}
