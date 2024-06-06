package test

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

func CreateTokenForTest(expiry time.Time, iat time.Time, nbf time.Time) string {
	someJwtSigningKey := []byte("signingKey")

	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expiry),
		IssuedAt:  jwt.NewNumericDate(iat),
		NotBefore: jwt.NewNumericDate(nbf),
		Issuer:    "some-issuer",
		Subject:   "some-subject",
		Audience:  []string{"some-audience"},
	}).SignedString(someJwtSigningKey)

	return token
}
