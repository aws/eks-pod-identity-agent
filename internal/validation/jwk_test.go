package validation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"

	. "github.com/onsi/gomega"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// ecJWK builds a JWK from an ECDSA public key.
func ecJWK(kid string, pub *ecdsa.PublicKey, crv string) JWK {
	return JWK{
		Kty: "EC",
		Kid: kid,
		Crv: crv,
		X:   base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()),
	}
}

func testRSAJWK(kid string, pub *rsa.PublicKey) JWK {
	return JWK{
		Kty: "RSA",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func TestParseRSAKey(t *testing.T) {
	goodKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	good := testRSAJWK("rsa", &goodKey.PublicKey)

	tests := []struct {
		name    string
		jwk     JWK
		wantErr bool
	}{
		{name: "valid key", jwk: good},
		{name: "bad N", jwk: JWK{Kty: "RSA", N: "!!!", E: good.E}, wantErr: true},
		{name: "bad E", jwk: JWK{Kty: "RSA", N: good.N, E: "!!!"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			key, err := parseRSAKey(tc.jwk)
			if tc.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(key.N.Cmp(goodKey.PublicKey.N)).To(Equal(0))
				g.Expect(key.E).To(Equal(goodKey.PublicKey.E))
			}
		})
	}
}

func TestParseECKey(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	good := ecJWK("ec", &ecKey.PublicKey, "P-256")

	tests := []struct {
		name    string
		jwk     JWK
		wantErr bool
	}{
		{name: "valid key", jwk: good},
		{name: "unsupported curve", jwk: JWK{Kty: "EC", Crv: "P-999"}, wantErr: true},
		{name: "bad X", jwk: JWK{Kty: "EC", Crv: "P-256", X: "!!!", Y: good.Y}, wantErr: true},
		{name: "bad Y", jwk: JWK{Kty: "EC", Crv: "P-256", X: good.X, Y: "!!!"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			key, err := parseECKey(tc.jwk)
			if tc.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(key.X.Cmp(ecKey.PublicKey.X)).To(Equal(0))
				g.Expect(key.Y.Cmp(ecKey.PublicKey.Y)).To(Equal(0))
			}
		})
	}
}

func TestParseJWK(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name    string
		jwk     JWK
		wantErr bool
	}{
		{
			name: "RSA key",
			jwk: JWK{
				Kty: "RSA",
				N:   base64.RawURLEncoding.EncodeToString(rsaKey.PublicKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.PublicKey.E)).Bytes()),
			},
		},
		{
			name: "EC key",
			jwk: JWK{
				Kty: "EC",
				Crv: "P-256",
				X:   base64.RawURLEncoding.EncodeToString(ecKey.PublicKey.X.Bytes()),
				Y:   base64.RawURLEncoding.EncodeToString(ecKey.PublicKey.Y.Bytes()),
			},
		},
		{
			name:    "unsupported kty",
			jwk:     JWK{Kty: "OKP"},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			key, err := parseJWK(tc.jwk)
			if tc.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(key).ToNot(BeNil())
			}
		})
	}
}
