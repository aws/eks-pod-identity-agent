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
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

// pemTypeCertificateRequest is the label in the "-----BEGIN ...-----" line of a
// certificate request. The name is fixed by RFC 7468.
const pemTypeCertificateRequest = "CERTIFICATE REQUEST"

// keyCurve is the kind of key we generate. P-256 is what SPIFFE tooling uses by
// default, so anything on the other side of a TLS handshake will accept it, and it
// is quick to generate, which matters when we do it once per pod per renewal across
// a whole fleet.
//
// One variable, because the key types STS accepts are unconfirmed: the API leaves
// that to the certificate authority behind it. If P-256 is rejected, change it here.
var keyCurve = elliptic.P256()

// generateKey creates a new key pair for one certificate.
//
// It hands back a crypto.Signer rather than the key itself. A Signer can sign things
// but does not expose the secret as bytes, so there is no easy way for later code to
// copy it somewhere it should not be.
func generateKey() (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(keyCurve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating a %s key: %w", keyCurve.Params().Name, err)
	}
	return key, nil
}

// buildCSR creates the certificate request we send to STS.
//
// The request contains two things: the public half of the key pair, and a signature
// made with the private half. The signature proves we hold the private key.
//
// No name goes in it. STS decides the identity from the credentials the call is signed
// with, and discards anything we put here. Left blank, because a name in this request
// would suggest the agent chooses the workload's identity.
func buildCSR(key crypto.Signer) (string, error) {
	der, err := cryptox509.CreateCertificateRequest(rand.Reader, &cryptox509.CertificateRequest{
		Subject: pkix.Name{},
	}, key)
	if err != nil {
		return "", fmt.Errorf("building the certificate signing request: %w", err)
	}
	// EncodeToMemory cannot fail here. It returns nil rather than an error, and the only
	// thing that makes it do so is a header key containing a colon; we pass no headers.
	return string(pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificateRequest, Bytes: der})), nil
}
