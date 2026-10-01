package x509

// Reading what STS sent back.
//
// STS returns certificates as PEM text. The SPIFFE Workload API hands them to the
// workload as raw bytes instead, so we convert, and while we are here we pull out
// the pieces we need to keep: the workload's identity and the dates the certificate
// is valid between.

import (
	cryptox509 "crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// pemTypeCertificate is the label in the "-----BEGIN ...-----" line of a
// certificate. The name is fixed by RFC 7468.
const pemTypeCertificate = "CERTIFICATE"

// parsedChain is one issued certificate after we have read it.
type parsedChain struct {
	// spiffeID is the workload's identity, for example
	// spiffe://example.aws/my-cluster/default/payments. It lives in the certificate
	// as a URI, not as the usual subject name.
	spiffeID string

	// der holds the certificate and the ones that signed it, in bytes, with the
	// workload's own certificate first.
	//
	// The root is left out: whoever verifies this workload already has it, from the
	// trust bundle.
	der [][]byte

	// notBefore and notAfter are the dates the certificate is valid between, read from
	// the certificate rather than the surrounding response, because the replacement
	// schedule is worked out from them.
	notBefore time.Time
	notAfter  time.Time
}

// parseChain reads the certificate and its signers, and finds the workload's
// identity inside it.
//
// Exactly one identity is required, which is what a SPIFFE certificate carries.
// Picking the first of several would hand out a certificate with an ambiguous identity
// and nobody would notice.
func parseChain(leafPEM, chainPEM string) (*parsedChain, error) {
	leafDER, err := decodeOne(leafPEM)
	if err != nil {
		return nil, fmt.Errorf("the leaf certificate: %w", err)
	}
	leaf, err := cryptox509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("parsing the leaf certificate: %w", err)
	}
	if len(leaf.URIs) != 1 {
		return nil, fmt.Errorf("the leaf certificate carries %d URI SANs, and an X.509-SVID carries exactly one", len(leaf.URIs))
	}

	// The list of signers can legitimately be empty, when the customer's certificate
	// authority signs workload certificates directly.
	issuers, err := decodeAll(chainPEM)
	if err != nil {
		return nil, fmt.Errorf("the issuing chain: %w", err)
	}

	der := make([][]byte, 0, 1+len(issuers))
	der = append(der, leafDER)
	der = append(der, issuers...)

	return &parsedChain{
		spiffeID:  leaf.URIs[0].String(),
		der:       der,
		notBefore: leaf.NotBefore.UTC(),
		notAfter:  leaf.NotAfter.UTC(),
	}, nil
}

// decodeOne reads a single certificate out of PEM text, and complains if there is
// more than one or none at all.
func decodeOne(s string) ([]byte, error) {
	block, rest := pem.Decode([]byte(s))
	if block == nil {
		return nil, fmt.Errorf("holds no PEM block")
	}
	if block.Type != pemTypeCertificate {
		return nil, fmt.Errorf("holds a %q PEM block rather than a %q block", block.Type, pemTypeCertificate)
	}
	if len(trimPEM(rest)) != 0 {
		return nil, fmt.Errorf("holds more than one PEM block")
	}
	return block.Bytes, nil
}

// decodeAll reads every certificate in PEM text, keeping the order they appear in.
// Empty text is fine and gives back nothing.
func decodeAll(s string) ([][]byte, error) {
	var out [][]byte
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
		// Parsed and discarded; the bytes pass through untouched. Checking here means a
		// malformed certificate fails with a clear error rather than inside the workload.
		if _, err := cryptox509.ParseCertificate(block.Bytes); err != nil {
			return nil, fmt.Errorf("parsing an issuer certificate: %w", err)
		}
		out = append(out, block.Bytes)
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
