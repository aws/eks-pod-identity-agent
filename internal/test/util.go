package test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultKid is the kid header value used in test tokens.
const DefaultKid = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

type TokenConfig struct {
	Expiry    time.Time
	Iat       time.Time
	Nbf       time.Time
	PodUID    string
	Overrides map[string]interface{}
	HeaderOverrides map[string]interface{}
}

func GenerateTestKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test RSA key: %v", err)
	}
	return key
}

func CreateToken(t testing.TB, config TokenConfig) string {
	t.Helper()
	return createToken(t, nil, config)
}

func CreateSignedToken(t testing.TB, key *rsa.PrivateKey, config TokenConfig) string {
	t.Helper()
	return createToken(t, key, config)
}

func createToken(t testing.TB, key *rsa.PrivateKey, config TokenConfig) string {
	t.Helper()

	claims := jwt.MapClaims{
		"exp": jwt.NewNumericDate(config.Expiry).Unix(),
		"iat": jwt.NewNumericDate(config.Iat).Unix(),
		"nbf": jwt.NewNumericDate(config.Nbf).Unix(),
	}

	if config.PodUID != "" {
		claims["kubernetes.io"] = map[string]interface{}{
			"pod": map[string]interface{}{
				"uid": config.PodUID,
			},
		}
	}

	for k, v := range config.Overrides {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = DefaultKid

	for k, v := range config.HeaderOverrides {
		if v == nil {
			delete(token.Header, k)
		} else {
			token.Header[k] = v
		}
	}

	if key == nil {
		unsigned, err := token.SigningString()
		if err != nil {
			t.Fatalf("failed to create unsigned test token: %v", err)
		}
		return unsigned + "."
	}

	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign test token: %v", err)
	}
	return signed
}
