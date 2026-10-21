// Package sts calls the STS operations the agent needs that no released
// aws-sdk-go-v2 client carries yet, one file per operation on a shared awsQuery
// transport. The transport is built from the SDK's public pieces (resolved client
// options, endpoint rules, SigV4 signer, awsQuery error decoder), so partitions,
// FIPS, dual-stack and AWS_ENDPOINT_URL_STS behave as they do in the SDK.
//
// Each call is signed with the credentials it is given and makes one attempt; the
// calling tier owns retries. Once the SDK releases an operation, its method body
// becomes the SDK call and its types and Iface method stay, so callers keep working.
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
	"github.com/aws/aws-sdk-go-v2/aws/protocol/query"
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
	// identity provider, one entry per trust domain, in response order, signing
	// the request with creds.
	GetTrustBundles(ctx context.Context, creds aws.Credentials, providerArn string) ([]TrustBundle, error)

	// GetWorkloadIdentityCertificate mints an X.509-SVID for the workload identity
	// that creds already carries. Unlike GetTrustBundles, which names its provider in
	// the request, this call names no identity: STS takes it from whoever signed, so
	// creds have to be the workload's own.
	GetWorkloadIdentityCertificate(ctx context.Context, creds aws.Credentials, req CertificateRequest) (*IssuedCertificate, error)

	GetWebIdentityToken(ctx context.Context, creds aws.Credentials, req WebIdentityTokenRequest) (*IssuedWebIdentityToken, error)
}

const (
	// apiVersion is the STS API version every awsQuery request names.
	apiVersion = "2011-06-15"
	// signingName is the SigV4 service name STS signs under.
	signingName = "sts"
	// maxResponseBytes bounds how much of a response body is read. A response is
	// a few kilobytes; this only stops a broken or hostile endpoint from growing
	// the agent's memory.
	maxResponseBytes = 1 << 20
)

type service struct {
	options awssts.Options
	signer  *v4.Signer
	now     func() time.Time
}

// NewService builds the client from cfg, taking only its region, endpoint
// settings and HTTP client. Each call is signed with the credentials it is
// given: at launch those are the workload's session, and the client does not
// care whose they are.
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

// invoke makes one awsQuery call to operation, signed with creds, and decodes a
// successful response into out. params, which may be nil, writes the input
// members with the SDK's query encoder; Action and Version are written after it,
// so it cannot override them. Errors come wrapped in a smithy.OperationError.
func (s *service) invoke(ctx context.Context, creds aws.Credentials, operation string, params func(*query.Object), out any) error {
	var body bytes.Buffer
	encoder := query.NewEncoder(&body)
	input := encoder.Object()
	if params != nil {
		params(input)
	}
	input.Key("Action").String(operation)
	input.Key("Version").String(apiVersion)
	err := encoder.Encode()
	if err != nil {
		err = &smithy.SerializationError{Err: err}
	} else {
		err = s.call(ctx, creds, body.String(), out)
	}
	if err != nil {
		return &smithy.OperationError{ServiceID: awssts.ServiceID, OperationName: operation, Err: err}
	}
	return nil
}

// call signs one awsQuery request body with creds, sends it, and decodes a
// successful response into out. It makes one attempt: a retry loop here would
// multiply the calling tier's own backoff during an STS outage.
func (s *service) call(ctx context.Context, creds aws.Credentials, body string, out any) error {
	endpoint, signingRegion, err := s.resolveEndpoint(ctx)
	if err != nil {
		return err
	}
	if !creds.HasKeys() {
		return errors.New("no AWS credentials to sign the request with")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.URI.String(), strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("building the request: %w", err)
	}
	// Headers the endpoint rules require, then the awsQuery content type.
	for name := range endpoint.Headers {
		req.Header.Set(name, endpoint.Headers.Get(name))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("User-Agent", "eks-pod-identity-agent/"+configuration.AgentVersion)

	// SigV4 over the body's hash, scoped to STS in the endpoint's signing region.
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
			// STS's endpoint rules name the scheme in full before sts v1.43.0 and
			// as plain "sigv4" from then on; the SDK accepts both.
			if option.SchemeID != smithyauth.SchemeIDSigV4 && option.SchemeID != "sigv4" {
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
