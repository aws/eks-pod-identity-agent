package x509

// Reading what STS sent back.
//
// STS returns the certificate and its issuers as PEM text. We parse both into
// certificates, which is the shape go-spiffe's SVID holds, and read the workload's
// identity out of the leaf. The validity dates are not carried separately: whoever
// needs them reads them off the leaf, so they cannot drift away from the certificate
// they describe.

import (
	cryptox509 "crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// pemTypeCertificate is the label in the "-----BEGIN ...-----" line of a
// certificate. The name is fixed by RFC 7468.
const pemTypeCertificate = "CERTIFICATE"

// parsedChain is one issued certificate after we have read it.
type parsedChain struct {
	// spiffeID is the workload's SPIFFE ID, read from the leaf's URI SAN.
	//
	// Named for the format on purpose. STS calls the same value Subject so they can
	// change identity formats later, but nothing in this tier is format-neutral: it
	// depends on go-spiffe, it enforces the SPIFFE rule of exactly one URI SAN, and it
	// serves the SPIFFE Workload API.
	spiffeID spiffeid.ID

	// certs holds the leaf first, then the certificates that signed it.
	//
	// The root is not among them. STS leaves it out, and whoever verifies this
	// workload takes the root from the trust bundle instead.
	certs []*cryptox509.Certificate
}

// parseChain reads the certificate and its issuers, and finds the workload's identity
// inside the leaf.
func parseChain(leafPEM, chainPEM string) (*parsedChain, error) {
	leaves, err := parseCertificates(leafPEM)
	if err != nil {
		return nil, fmt.Errorf("the leaf certificate: %w", err)
	}
	if len(leaves) != 1 {
		return nil, fmt.Errorf("the leaf certificate: holds %d certificates where there should be one", len(leaves))
	}
	leaf := leaves[0]

	// go-spiffe reads the identity and enforces the rule that an X.509-SVID carries
	// exactly one URI SAN, so we do not write either ourselves. Accepting the first of
	// several would hand out a certificate with an ambiguous identity unnoticed.
	spiffeID, err := x509svid.IDFromCert(leaf)
	if err != nil {
		return nil, fmt.Errorf("reading the identity from the leaf certificate: %w", err)
	}

	// An empty chain is tolerated rather than expected. STS said on 2026-10-02 that a
	// root should never sign leaves directly, so this should not happen, but they were
	// not certain and an empty chain is not a reason to refuse a usable certificate.
	issuers, err := parseCertificates(chainPEM)
	if err != nil {
		return nil, fmt.Errorf("the issuing chain: %w", err)
	}

	certs := make([]*cryptox509.Certificate, 0, 1+len(issuers))
	certs = append(certs, leaf)
	certs = append(certs, issuers...)

	return &parsedChain{spiffeID: spiffeID, certs: certs}, nil
}

// parseCertificates reads every certificate out of PEM text, keeping the order they
// appear in. Empty text is fine and gives back nothing.
//
// Every certificate is parsed, including ones whose bytes we only pass along, so a
// malformed one fails here with a clear error rather than inside the workload.
func parseCertificates(s string) ([]*cryptox509.Certificate, error) {
	var out []*cryptox509.Certificate
	rest := []byte(s)
	for len(trimPEM(rest)) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("holds trailing data that is not a PEM block")
		}
		if block.Type != pemTypeCertificate {
			return nil, fmt.Errorf("holds a %q PEM block rather than a %q block", block.Type, pemTypeCertificate)
		}
		cert, err := cryptox509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing a certificate: %w", err)
		}
		out = append(out, cert)
	}
	return out, nil
}

// trimPEM skips the blank space between PEM blocks, so that a trailing newline at
// the end of the text is not mistaken for another certificate.
func trimPEM(b []byte) []byte {
	for len(b) > 0 {
		switch b[0] {
		case ' ', '\t', '\r', '\n':
			b = b[1:]
		default:
			return b
		}
	}
	return b
}
