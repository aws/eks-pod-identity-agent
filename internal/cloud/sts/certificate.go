package sts

// The call that asks STS to sign a certificate for a workload.
//
// Differs from GetTrustBundles only in what the credentials mean. GetTrustBundles
// names its provider in the request and the node role signs it. This call names no
// identity: STS takes the identity for the certificate from whoever signed, so the
// credentials have to be the workload's own and they decide whose certificate comes
// back.

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/protocol/query"
	awssts "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// operationGetWorkloadIdentityCertificate is the operation's awsQuery Action.
const operationGetWorkloadIdentityCertificate = "GetWorkloadIdentityCertificate"

// CertificateRequest is what we send.
type CertificateRequest struct {
	// CertificateSigningRequestPEM is the certificate request as PEM text. STS uses
	// only the public key in it, plus the signature proving we hold the matching
	// private key. Any name inside it is ignored, because STS gets the identity from
	// whoever signed the call. Required.
	CertificateSigningRequestPEM string

	// MaxDuration is how long a certificate we would like. An upper limit: STS can
	// issue less, and sets the start a few minutes in the past, so the real dates come
	// off the response. Zero means no preference, and we take what STS returns.
	//
	// It is not limited by how long our own credentials have left. The comment on
	// workloadIdentityCertificateMaxDurationSecondsType in IAMTokenServiceModel says it
	// is; that is out of date, planned and then dropped, confirmed by STS on 2026-09-30.
	//
	// 1 to 12 hours is accepted, checked at startup against --x509-svid-duration so a bad
	// value stops the agent booting rather than failing every pod.
	MaxDuration time.Duration
}

// IssuedCertificate is the actual certificate issued by STS.
type IssuedCertificate struct {
	// CertificatePEM is the workload's own certificate, as PEM text.
	CertificatePEM string

	// CertificateChainPEM is the certificates that signed it, as PEM text. The root is
	// left out: whoever verifies this workload already has it from the trust bundle.
	CertificateChainPEM string

	// NotBefore and NotAfter are the dates the certificate is actually valid between.
	// The renewal schedule is worked out from these, not from MaxDuration.
	NotBefore time.Time
	NotAfter  time.Time

	// Subject is the identity STS says it put in the certificate, taken from the
	// credentials we signed with. It is here for cross-checking; the identity relied on
	// is the one read out of the certificate.
	Subject string
}

func (s *service) GetWorkloadIdentityCertificate(ctx context.Context, creds aws.Credentials, req CertificateRequest) (*IssuedCertificate, error) {
	var decoded getWorkloadIdentityCertificateResponse
	err := s.invoke(ctx, creds, operationGetWorkloadIdentityCertificate, func(input *query.Object) {
		input.Key("CertificateSigningRequest").String(req.CertificateSigningRequestPEM)
		// Omitted rather than sent as zero, so the service default applies instead of a
		// value the model would reject.
		if req.MaxDuration > 0 {
			input.Key("MaxDurationSeconds").Integer(int32(req.MaxDuration / time.Second))
		}
	}, &decoded)
	if err != nil {
		return nil, err
	}

	issued, err := decoded.Result.toIssuedCertificate()
	if err != nil {
		return nil, &smithy.OperationError{
			ServiceID:     awssts.ServiceID,
			OperationName: operationGetWorkloadIdentityCertificate,
			Err:           &smithy.DeserializationError{Err: err},
		}
	}
	return issued, nil
}

// getWorkloadIdentityCertificateResponse is the awsQuery response shape. The output
// structure sits under the operation's Result element.
type getWorkloadIdentityCertificateResponse struct {
	XMLName xml.Name                    `xml:"GetWorkloadIdentityCertificateResponse"`
	Result  workloadIdentityCertificate `xml:"GetWorkloadIdentityCertificateResult"`
}

// workloadIdentityCertificate is the response as it arrives on the wire. The dates are
// read as plain strings and parsed afterwards, because Go's XML support has no notion
// of a timestamp.
//
// CertificateChain accepts more shapes than it strictly needs to, because the two
// descriptions of this response disagree about it. The API model says it is a single
// block of PEM text; the Java sample in the onboarding guide loops over it as a list.
//
// Read as one string, several certificates would leave only the last, silently dropping
// the intermediates a workload needs to prove its chain. Accepting either shape costs
// nothing.
//
// Subject has the same disagreement, the model's name for it against the sample's
// spiffeId. Nothing depends on it: the identity we use comes out of the certificate,
// and this is only compared against it when STS sends it.
type workloadIdentityCertificate struct {
	Certificate      string            `xml:"Certificate"`
	CertificateChain []certificateList `xml:"CertificateChain"`
	NotBefore        string            `xml:"NotBefore"`
	NotAfter         string            `xml:"NotAfter"`
	Subject          string            `xml:"Subject"`
}

// certificateList is one CertificateChain element. The PEM is either sitting in the
// element directly, or wrapped in the list members AWS sometimes uses.
type certificateList struct {
	Value   string   `xml:",chardata"`
	Members []string `xml:"member"`
}

// pem returns every PEM block this element carries, in order.
func (c certificateList) pem() []string {
	if len(c.Members) > 0 {
		return c.Members
	}
	if strings.TrimSpace(c.Value) == "" {
		return nil
	}
	return []string{c.Value}
}

// toIssuedCertificate checks the response has the parts we cannot do without, and turns
// the dates into real timestamps.
//
// Missing parts are an error rather than zero values, because a zero date reads as long
// expired and would have us replacing the certificate in a loop.
func (c workloadIdentityCertificate) toIssuedCertificate() (*IssuedCertificate, error) {
	if c.Certificate == "" {
		return nil, fmt.Errorf("the response carries no certificate")
	}
	notBefore, err := parseTimestamp("NotBefore", c.NotBefore)
	if err != nil {
		return nil, err
	}
	notAfter, err := parseTimestamp("NotAfter", c.NotAfter)
	if err != nil {
		return nil, err
	}
	if !notAfter.After(notBefore) {
		return nil, fmt.Errorf("the response's validity window ends at or before it starts: NotBefore %s, NotAfter %s", notBefore, notAfter)
	}

	// Joined into one piece of text rather than kept as a list. PEM certificates can be
	// written one after another, and the caller reads certificates out of the text
	// rather than counting fields.
	var chain strings.Builder
	for _, element := range c.CertificateChain {
		for _, block := range element.pem() {
			block = strings.TrimSpace(block)
			if block == "" {
				continue
			}
			chain.WriteString(block)
			chain.WriteString("\n")
		}
	}

	return &IssuedCertificate{
		CertificatePEM:      c.Certificate,
		CertificateChainPEM: chain.String(),
		NotBefore:           notBefore,
		NotAfter:            notAfter,
		Subject:             c.Subject,
	}, nil
}

// parseTimestamp reads one awsQuery ISO 8601 timestamp. Both the fractional and whole
// second forms are accepted, since the model bounds neither and the two are
// interchangeable on the wire.
func parseTimestamp(field, value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("the response carries no %s", field)
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing %s %q: %w", field, value, err)
	}
	return parsed.UTC(), nil
}
