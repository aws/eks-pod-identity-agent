package validation

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/golang-jwt/jwt/v5"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
)

// jwksProvider abstracts fetching a JWK set, allowing the API client to be
// swapped for testing.
type jwksProvider interface {
	fetchPublicKeys(ctx context.Context) (*JWKSet, error)
}

type keyCache map[string]*cachedKey

// TokenValidator provides deep JWT validation (claims + signature) using
// a persistent public key cache fetched from the kube-apiserver.
type TokenValidator struct {
	keys            atomic.Value // stores keyCache, which maps key IDs (kid) to public keys
	jwksSource      jwksProvider
	refreshInFlight atomic.Bool
}

func NewTokenValidator(ctx context.Context) (*TokenValidator, error) {
	ac, err := newApiserverClient()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize apiserver client: %w", err)
	}
	tv := &TokenValidator{jwksSource: ac}
	tv.keys.Store(make(keyCache))
	go func() {
		// pre-populate the cache, but do not return an error on failure
		// cache misses should trigger a refresh on the next request
		if err := tv.refreshKeys(ctx); err != nil {
			log := logger.FromContext(ctx)
			log.Infof("failed to pre-populate public key cache: %v", err)
		}
	}()
	return tv, nil
}

// RefreshKeys triggers a refresh of the public key cache if the kid
// of the incoming token is not already cached.
func (tv *TokenValidator) RefreshKeys(ctx context.Context, token string) error {
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}
	kid, ok := parsed.Header["kid"].(string)
	if !ok {
		return fmt.Errorf("kid not found in JWT header")
	}
	if _, found := tv.keys.Load().(keyCache)[kid]; !found {
		return tv.refreshKeys(ctx)
	}
	return nil
}

// ValidateToken performs claims validation and cryptographic signature
// verification on the request's service account token.
func (tv *TokenValidator) ValidateToken(ctx context.Context, req *credentials.EksCredentialsRequest) error {
	log := logger.FromContext(ctx)

	if req.ServiceAccountToken == "" {
		return errors.NewRequestValidationError("Service account token cannot be empty")
	}
	
	parsedToken, _, err := jwt.NewParser().ParseUnverified(req.ServiceAccountToken, jwt.MapClaims{})
	if err != nil {
		return errors.NewRequestValidationError(fmt.Sprintf("Service account token cannot be parsed: %v", err))
	}

	if err := ValidateClaims(ctx, parsedToken); err != nil {
		return errors.NewRequestValidationError(fmt.Sprintf("Service account token failed claim validations: %v", err))
	}
	if err := tv.validateSignature(ctx, req.ServiceAccountToken, parsedToken); err != nil {
		return errors.NewRequestValidationError(fmt.Sprintf("JWT signature validation failed: %v", err))
	}

	log.Debug("Token validation passed")
	return nil
}

// refreshKeys fetches JWKS from the API server and refreshes the internal cache.
func (tv *TokenValidator) refreshKeys(ctx context.Context) error {
	if !tv.refreshInFlight.CompareAndSwap(false, true) {
		return fmt.Errorf("key refresh already in progress")
	}
	defer tv.refreshInFlight.Store(false)

	log := logger.FromContext(ctx)
	log.Infof("Public key cache refresh triggered")
	jwks, err := tv.jwksSource.fetchPublicKeys(ctx)
	if err != nil {
		return err
	}
	tv.loadJWKSet(ctx, jwks)
	return nil
}

// loadJWKSet parses a JWKSet and atomically replaces the key cache.
func (tv *TokenValidator) loadJWKSet(ctx context.Context, jwks *JWKSet) {
	log := logger.FromContext(ctx)
	newKeys := make(keyCache)
	for _, k := range jwks.Keys {
		if _, dup := newKeys[k.Kid]; dup {
			continue
		}
		pubKey, err := parseJWK(k)
		if err != nil {
			log.Infof("skipping key %s: %v", k.Kid, err)
			continue
		}
		newKeys[k.Kid] = &cachedKey{key: pubKey, alg: k.Alg}
	}
	tv.keys.Store(newKeys)
	log.Infof("Public key cache refreshed with %d keys", len(newKeys))
}

// validateSignature validates the JWT signature using the cached public keys.
// It accepts the pre-parsed token to extract the kid without re-parsing.
func (tv *TokenValidator) validateSignature(ctx context.Context, tokenString string, parsed *jwt.Token) error {
	log := logger.FromContext(ctx)

	// Parse the token's key id
	kid, ok := parsed.Header["kid"].(string)
	if !ok {
		return fmt.Errorf("cryptographic validation failed: kid not found in JWT header")
	}

	// Refresh keys if the incoming token's key id is not cached
	cached, found := tv.keys.Load().(keyCache)[kid]
	if !found {
		if err := tv.refreshKeys(ctx); err != nil {
			log.Infof("key refresh failed: %v", err)
			return fmt.Errorf("cryptographic validation failed: key refresh failed: %w", err)
		}
		cached, found = tv.keys.Load().(keyCache)[kid]
		if !found {
			return fmt.Errorf("cryptographic validation failed: no matching key found for kid: %s", kid)
		}
	}

	// Attempt to validate the token using the public key
	_, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		tokenAlg, _ := t.Header["alg"].(string)
		if tokenAlg != cached.alg {
			return nil, fmt.Errorf("algorithm mismatch: token uses %q but key declares %q", tokenAlg, cached.alg)
		}
		return cached.key, nil
	})
	if err != nil {
		log.Debugf("validateSignature: FAILED - kid=%s, err=%v", kid, err)
		return fmt.Errorf("cryptographic validation failed: %w", err)
	}

	log.Debugf("validateSignature: PASSED - kid=%s", kid)
	return nil
}
