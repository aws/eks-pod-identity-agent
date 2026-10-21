package sts

// The call that asks STS to sign a certificate for a workload.
//
// Differs from GetTrustBundles only in what the credentials mean. That call names its
// provider in the request; this one names no identity, so STS takes it from whoever
// signed and the credentials have to be the workload's own.

import (
	"context"
	"encoding/xml"
	"fmt"
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

	// MaxDuration is the certificate lifetime we request, 1 to 12 hours, checked at
	// startup. Zero means no preference, which STS answers with 12 hours.
	//
	// It is a ceiling, so the issued window comes off the certificate rather than from this
	// value. STS does not reduce it to the signing credentials' remaining life.
	MaxDuration time.Duration
}

// IssuedCertificate is the actual certificate issued by STS.
type IssuedCertificate struct {
	// CertificatePEM is the workload's own certificate, as PEM text.
	CertificatePEM string

	// CertificateChainPEM is the certificates that signed it, as PEM text. The root is
	// left out: whoever verifies this workload already has it from the trust bundle.
	CertificateChainPEM string

	// NotBefore and NotAfter are the window STS reports alongside the certificate. They are
	// parsed so that a response carrying no window, or an inverted one, is rejected. The
	// renewal schedule uses the leaf's own dates rather than these.
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
			input.Key("MaxDurationSeconds").Integer(int32(req.MaxDuration.Seconds()))
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
// strings here and parsed afterwards, because Go's XML support has no notion of a
// timestamp.
//
// CertificateChain is one block of PEM text holding the whole chain, not a list of
// separate certificates. The identity field is Subject.
type workloadIdentityCertificate struct {
	Certificate      string `xml:"Certificate"`
	CertificateChain string `xml:"CertificateChain"`
	NotBefore        string `xml:"NotBefore"`
	NotAfter         string `xml:"NotAfter"`
	Subject          string `xml:"Subject"`
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

	return &IssuedCertificate{
		CertificatePEM:      c.Certificate,
		CertificateChainPEM: c.CertificateChain,
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
