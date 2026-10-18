package x509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	cryptox509 "crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

func TestGenerateKeyIsUsableAndDistinct(t *testing.T) {
	first, err := generateKey(workloadidentity.DefaultKeyType)
	require.NoError(t, err)
	require.NotNil(t, first.Public())

	second, err := generateKey(workloadidentity.DefaultKeyType)
	require.NoError(t, err)

	assert.NotEqual(t, first.Public(), second.Public(),
		"every issuance has to get its own keypair, so one pod's key is never another's")
}

// TestGenerateKeyCoversEveryConfiguredType checks each name an operator can pass to
// --svid-key-type produces the key that name promises. A name that silently generated
// something else would put a key type on the wire that nobody asked for.
//
// RSA-4096 is left out. It is accepted and it works, but generating one takes long
// enough to slow the suite down noticeably, and the switch arm it exercises is the same
// shape as RSA-2048's.
func TestGenerateKeyCoversEveryConfiguredType(t *testing.T) {
	for _, tc := range []struct {
		kind   workloadidentity.KeyType
		verify func(t *testing.T, key crypto.Signer)
	}{
		{
			kind: workloadidentity.KeyTypeECP256,
			verify: func(t *testing.T, key crypto.Signer) {
				pub, ok := key.Public().(*ecdsa.PublicKey)
				require.True(t, ok, "ec-p256 has to produce an ECDSA key")
				assert.Equal(t, elliptic.P256(), pub.Curve)
			},
		},
		{
			kind: workloadidentity.KeyTypeECP384,
			verify: func(t *testing.T, key crypto.Signer) {
				pub, ok := key.Public().(*ecdsa.PublicKey)
				require.True(t, ok, "ec-p384 has to produce an ECDSA key")
				assert.Equal(t, elliptic.P384(), pub.Curve)
			},
		},
		{
			kind: workloadidentity.KeyTypeRSA2048,
			verify: func(t *testing.T, key crypto.Signer) {
				pub, ok := key.Public().(*rsa.PublicKey)
				require.True(t, ok, "rsa-2048 has to produce an RSA key")
				assert.Equal(t, 2048, pub.N.BitLen())
			},
		},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			key, err := generateKey(tc.kind)
			require.NoError(t, err)
			tc.verify(t, key)

			// Every type has to survive the round trip into a request, because an
			// accepted key type that cannot be signed for is no use.
			csrPEM, err := buildCSR(key)
			require.NoError(t, err)
			block, _ := pem.Decode([]byte(csrPEM))
			require.NotNil(t, block)
			csr, err := cryptox509.ParseCertificateRequest(block.Bytes)
			require.NoError(t, err)
			assert.NoError(t, csr.CheckSignature())
		})
	}
}

// TestGenerateKeyRejectsAnUnknownType covers the arm that cannot be reached through the
// flag, since the flag is validated at startup. It is here so that a caller building the
// tier without that check gets an error rather than a key of some default kind.
func TestGenerateKeyRejectsAnUnknownType(t *testing.T) {
	_, err := generateKey(workloadidentity.KeyType("ed25519"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ed25519")
	assert.Contains(t, err.Error(), string(workloadidentity.KeyTypeECP256),
		"the error has to name the types an operator can choose instead")
}

// TestBuildCSRNamesNoIdentity is the definition-of-done assertion on the request: it
// carries a public key, a proof of possession, and a fixed placeholder subject, and
// nothing that could be read as the agent naming an identity.
func TestBuildCSRNamesNoIdentity(t *testing.T) {
	key, err := generateKey(workloadidentity.DefaultKeyType)
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

	// The subject is the fixed placeholder and nothing else: a blank one is currently
	// rejected by the signer, and a workload-specific one would say the agent picks the
	// identity. Asserting the exact value keeps this pinned to the one string that has
	// to be deleted when STS starts overwriting the subject itself.
	assert.Equal(t, csrSubjectCommonName, csr.Subject.CommonName)
	assert.Equal(t, "CN="+csrSubjectCommonName, csr.Subject.String(),
		"the subject carries the placeholder common name and no other attribute")
	assert.Empty(t, csr.Extensions, "the request carries no extensions")
	assert.Empty(t, csr.ExtraExtensions, "the request carries no extensions")
	assert.Empty(t, csr.DNSNames)
	assert.Empty(t, csr.URIs, "the SPIFFE ID comes from the session, never from the request")
	assert.Empty(t, csr.EmailAddresses)
	assert.Empty(t, csr.IPAddresses)
}
