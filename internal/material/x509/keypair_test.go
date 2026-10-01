package x509

import (
	cryptox509 "crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeyIsUsableAndDistinct(t *testing.T) {
	first, err := generateKey()
	require.NoError(t, err)
	require.NotNil(t, first.Public())

	second, err := generateKey()
	require.NoError(t, err)

	assert.NotEqual(t, first.Public(), second.Public(),
		"every issuance has to get its own keypair, so one pod's key is never another's")
}

// TestBuildCSRCarriesNothingButTheKey is the definition-of-done assertion on the
// request: it carries a public key and a proof of possession, and nothing that
// could be read as the agent naming an identity.
func TestBuildCSRCarriesNothingButTheKey(t *testing.T) {
	key, err := generateKey()
	require.NoError(t, err)

	csrPEM, err := buildCSR(key)
	require.NoError(t, err)

	block, rest := pem.Decode([]byte(csrPEM))
	require.NotNil(t, block)
	assert.Equal(t, pemTypeCertificateRequest, block.Type)
	assert.Empty(t, trimPEM(rest), "the request should be exactly one PEM block")

	csr, err := cryptox509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)

	assert.NoError(t, csr.CheckSignature(), "the request has to prove possession of the key")
	assert.Equal(t, key.Public(), csr.PublicKey, "the request has to carry this issuance's public key")

	assert.Empty(t, csr.Subject.String(), "a populated subject would be discarded by STS and would mislead a reader into thinking the agent picks the identity")
	assert.Empty(t, csr.Extensions, "the request carries no extensions")
	assert.Empty(t, csr.ExtraExtensions, "the request carries no extensions")
	assert.Empty(t, csr.DNSNames)
	assert.Empty(t, csr.URIs, "the SPIFFE ID comes from the session, never from the request")
	assert.Empty(t, csr.EmailAddresses)
	assert.Empty(t, csr.IPAddresses)
}
