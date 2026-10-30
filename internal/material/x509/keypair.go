package x509

// Making the key pair and the request we send to STS.
//
// The private key stays on the node. It goes to the workload that asked for it, never
// to STS, to disk, or to a log.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptox509 "crypto/x509"
	"encoding/pem"
	"fmt"
)

// pemTypeCertificateRequest is the label in the "-----BEGIN ...-----" line of a
// certificate request. The name is fixed by RFC 7468.
const pemTypeCertificateRequest = "CERTIFICATE REQUEST"

// generateKey creates a new ECDSA P-256 key pair for one certificate. P-256 is the SPIFFE
// default and cheap to generate, which matters because the agent makes a key for every
// pod at every renewal.
//
// It returns a crypto.Signer rather than the key, because a Signer does not expose the
// secret as bytes.
func generateKey() (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating an ECDSA P-256 key: %w", err)
	}
	return key, nil
}

// buildCSR creates the certificate request we send to STS. It carries the public half of
// the key pair and a signature made with the private half, which proves possession.
//
// It names no identity. The SPIFFE ID comes from the attested workload identity in the
// session, never from the request, so the request carries no subject, no SAN and no
// extensions.
func buildCSR(key crypto.Signer) (string, error) {
	der, err := cryptox509.CreateCertificateRequest(rand.Reader, &cryptox509.CertificateRequest{}, key)
	if err != nil {
		return "", fmt.Errorf("building the certificate signing request: %w", err)
	}
	// EncodeToMemory cannot fail here. It returns nil rather than an error, and the only
	// thing that makes it do so is a header key containing a colon; we pass no headers.
	return string(pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificateRequest, Bytes: der})), nil
}
