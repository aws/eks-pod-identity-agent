package test

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenConfig struct {
	Expiry time.Time
	Iat    time.Time
	Nbf    time.Time
	PodUID string
}

func CreateToken(config TokenConfig) string {
	signingKey := []byte("signingKey")

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

	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(signingKey)
	return token
}
