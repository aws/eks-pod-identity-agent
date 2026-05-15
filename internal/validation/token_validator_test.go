package validation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	. "github.com/onsi/gomega"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
)

// channelJWKSProvider signals on called when fetchPublicKeys is invoked.
type channelJWKSProvider struct {
	called chan struct{}
	jwks   *JWKSet
}

func (c *channelJWKSProvider) fetchPublicKeys(_ context.Context) (*JWKSet, error) {
	c.called <- struct{}{}
	return c.jwks, nil
}

// rsaJWK builds a JWK entry from an RSA public key, used to populate mock JWKS responses.
func rsaJWK(kid string, pub *rsa.PublicKey) JWK {
	return JWK{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// TestRefreshKeys verifies that RefreshKeys fetches JWKS and updates the cache
// when the token's kid is missing, and skips the fetch when it's already cached.
func TestRefreshKeys(t *testing.T) {
	now := time.Now()
	existingKey := test.GenerateTestKey(t)
	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	tests := []struct {
		name        string
		tokenKey    *rsa.PrivateKey  // key used to sign the JWT
		tokenConfig test.TokenConfig // JWT claims and header overrides
		cacheKid    string           // kid pre-populated in the cache (empty = no pre-population)
		jwks        *JWKSet          // what the provider returns on fetch
		wantRefresh bool             // true if we expect fetchPublicKeys to be called
	}{
		{
			// Token's kid is not in the cache, so provider should be called.
			name:     "uncached kid triggers fetch",
			tokenKey: newKey,
			tokenConfig: test.TokenConfig{
				Expiry:          now.Add(time.Hour),
				Iat:             now,
				Nbf:             now,
				HeaderOverrides: map[string]interface{}{"kid": "new-kid"},
			},
			cacheKid:    "",
			jwks:        &JWKSet{Keys: []JWK{rsaJWK("new-kid", &newKey.PublicKey)}},
			wantRefresh: true,
		},
		{
			// Token's kid matches what's already cached, so no fetch needed.
			name:     "cached kid skips fetch",
			tokenKey: existingKey,
			tokenConfig: test.TokenConfig{
				Expiry: now.Add(time.Hour),
				Iat:    now,
				Nbf:    now,
			},
			cacheKid:    test.DefaultKid,
			jwks:        &JWKSet{},
			wantRefresh: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			// Mock a jwks provider that signals on called when fetchPublicKeys is invoked.
			provider := &channelJWKSProvider{
				called: make(chan struct{}, 1),
				jwks:   tc.jwks,
			}
			tv := &TokenValidator{jwksSource: provider}
			tv.keys.Store(keyCache{tc.cacheKid: {key: &existingKey.PublicKey, alg: "RS256"}})

			// Build a signed token and call RefreshKeys
			token := test.CreateSignedToken(t, tc.tokenKey, tc.tokenConfig)
			err := tv.RefreshKeys(context.Background(), token)
			g.Expect(err).ToNot(HaveOccurred())

			// Verify whether a refresh on the jwksprovider was triggered
			select {
			case <-provider.called:
				if !tc.wantRefresh {
					t.Fatal("expected no refresh when kid is already cached")
				}
			default:
				if tc.wantRefresh {
					t.Fatal("expected refresh when kid is not cached")
				}
			}
		})
	}
}

// TestValidateToken verifies that ValidateToken succeeds only when both
// claims and signature are valid, and fails in all other combinations.
func TestValidateToken(t *testing.T) {
	now := time.Now()
	signingKey := test.GenerateTestKey(t)
	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	validClaimsConfig := test.TokenConfig{
		Expiry: now.Add(time.Hour),
		Iat:    now,
		Nbf:    now,
		Overrides: map[string]interface{}{
			"aud":           expectedAudience,
			"sub":           "system:serviceaccount:default:my-sa",
			"kubernetes.io": fullK8sClaim(),
		},
	}
	invalidClaimsConfig := test.TokenConfig{
		Expiry: now.Add(time.Hour),
		Iat:    now,
		Nbf:    now,
		// No kubernetes.io claims -> claims validation fails
	}

	tests := []struct {
		name               string
		token              string
		cacheKey           *rsa.PublicKey // public key cached for signature verification
		endpointOverridden bool
		wantErr            bool
	}{
		{
			name:     "valid claims and valid signature",
			token:    test.CreateSignedToken(t, signingKey, validClaimsConfig),
			cacheKey: &signingKey.PublicKey,
			wantErr:  false,
		},
		{
			name:     "valid claims but invalid signature",
			token:    test.CreateSignedToken(t, signingKey, validClaimsConfig),
			cacheKey: &wrongKey.PublicKey, // wrong public key -> sig fails
			wantErr:  true,
		},
		{
			name:     "invalid claims but valid signature",
			token:    test.CreateSignedToken(t, signingKey, invalidClaimsConfig),
			cacheKey: &signingKey.PublicKey,
			wantErr:  true,
		},
		{
			name:     "invalid claims and invalid signature",
			token:    test.CreateSignedToken(t, signingKey, invalidClaimsConfig),
			cacheKey: &wrongKey.PublicKey,
			wantErr:  true,
		},
		{
			name: "wrong audience rejected",
			token: test.CreateSignedToken(t, signingKey, test.TokenConfig{
				Expiry: now.Add(time.Hour),
				Iat:    now,
				Nbf:    now,
				Overrides: map[string]interface{}{
					"aud":           "wrong.audience.com",
					"sub":           "system:serviceaccount:default:my-sa",
					"kubernetes.io": fullK8sClaim(),
				},
			}),
			cacheKey: &signingKey.PublicKey,
			wantErr:  true,
		},
		{
			name: "wrong audience accepted when endpoint overridden",
			token: test.CreateSignedToken(t, signingKey, test.TokenConfig{
				Expiry: now.Add(time.Hour),
				Iat:    now,
				Nbf:    now,
				Overrides: map[string]interface{}{
					"aud":           "custom.audience.com",
					"sub":           "system:serviceaccount:default:my-sa",
					"kubernetes.io": fullK8sClaim(),
				},
			}),
			cacheKey:           &signingKey.PublicKey,
			endpointOverridden: true,
			wantErr:            false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			tv := &TokenValidator{EndpointOverridden: tc.endpointOverridden}
			tv.keys.Store(keyCache{test.DefaultKid: {key: tc.cacheKey, alg: "RS256"}})

			err := tv.ValidateToken(context.Background(), &credentials.EksCredentialsRequest{
				ServiceAccountToken: tc.token,
			})

			if tc.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
		})
	}
}

// tamperJWTPayload replaces the payload of a signed JWT with modified claims,
// keeping the original header and signature intact.
func tamperJWTPayload(t *testing.T, token string, mutate func(map[string]interface{})) string {
	t.Helper()
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	mutate(claims)
	modified, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(modified)
	return strings.Join(parts, ".")
}

// TestValidateSignature verifies that validateSignature correctly accepts
// tokens signed with the cached key and rejects tokens whose cached public
// key doesn't match, or whose payload has been tampered with after signing.
func TestValidateSignature(t *testing.T) {
	now := time.Now()
	signingKey := test.GenerateTestKey(t)
	validToken := test.CreateSignedToken(t, signingKey, test.TokenConfig{
		Expiry: now.Add(time.Hour),
		Iat:    now,
		Nbf:    now,
	})

	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrongKeyToken := test.CreateSignedToken(t, signingKey, test.TokenConfig{
		Expiry:          now.Add(time.Hour),
		Iat:             now,
		Nbf:             now,
		HeaderOverrides: map[string]interface{}{"kid": "wrong-kid"},
	})

	tamperedToken := tamperJWTPayload(t, validToken, func(claims map[string]interface{}) {
		claims["exp"] = float64(now.Add(24 * time.Hour).Unix())
	})

	tests := []struct {
		name     string
		token    string
		cacheKid string
		cacheKey *rsa.PublicKey
		wantErr  bool
	}{
		{
			name:     "valid signature",
			token:    validToken,
			cacheKid: test.DefaultKid,
			cacheKey: &signingKey.PublicKey,
		},
		{
			name:     "wrong signing key",
			token:    wrongKeyToken,
			cacheKid: "wrong-kid",
			cacheKey: &wrongKey.PublicKey,
			wantErr:  true,
		},
		{
			name:     "tampered payload",
			token:    tamperedToken,
			cacheKid: test.DefaultKid,
			cacheKey: &signingKey.PublicKey,
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			tv := &TokenValidator{}
			tv.keys.Store(keyCache{tc.cacheKid: {key: tc.cacheKey, alg: "RS256"}})

			parsed, _, err := jwt.NewParser().ParseUnverified(tc.token, jwt.MapClaims{})
			g.Expect(err).ToNot(HaveOccurred())

			err = tv.validateSignature(context.Background(), tc.token, parsed)

			if tc.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
		})
	}
}

// TestValidateToken_KeyRefreshOnCacheMiss verifies that during signature
// validation a cache miss triggers a JWKS refresh and the new key ends up in
// the cache, while a cache hit skips the refresh entirely.
func TestValidateToken_KeyRefreshOnCacheMiss(t *testing.T) {
	now := time.Now()

	// kid returns a valid 40-hex-char kid for index i.
	kid := func(i int) string { return fmt.Sprintf("%040x", i) }

	validClaims := map[string]interface{}{
		"aud":           expectedAudience,
		"sub":           "system:serviceaccount:default:my-sa",
		"kubernetes.io": fullK8sClaim(),
	}

	tests := []struct {
		name           string
		initialKids    []string // kids pre-populated in cache
		refreshKids    []string // kids returned by JWKS provider on refresh
		signKid        string   // kid used to sign the token
		wantRefresh    bool
		wantCachedKids []string // kids expected in cache after validation
	}{
		{
			name:           "uncached key triggers refresh and is added to cache",
			initialKids:    []string{kid(0), kid(1), kid(2)},
			refreshKids:    []string{kid(0), kid(1), kid(2), kid(3)},
			signKid:        kid(3),
			wantRefresh:    true,
			wantCachedKids: []string{kid(0), kid(1), kid(2), kid(3)},
		},
		{
			name:           "cached key does not trigger refresh",
			initialKids:    []string{kid(0), kid(1), kid(2)},
			refreshKids:    []string{kid(0), kid(1), kid(2), kid(3)},
			signKid:        kid(0),
			wantRefresh:    false,
			wantCachedKids: []string{kid(0), kid(1), kid(2)},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			// Collect all unique kids and generate a key for each.
			kidSet := make(map[string]struct{})
			for _, k := range tc.initialKids {
				kidSet[k] = struct{}{}
			}
			for _, k := range tc.refreshKids {
				kidSet[k] = struct{}{}
			}
			kidSet[tc.signKid] = struct{}{}

			allKeys := make(map[string]*rsa.PrivateKey, len(kidSet))
			for k := range kidSet {
				allKeys[k] = test.GenerateTestKey(t)
			}

			// Build JWKS response for refresh.
			var jwks JWKSet
			for _, kid := range tc.refreshKids {
				jwks.Keys = append(jwks.Keys, rsaJWK(kid, &allKeys[kid].PublicKey))
			}
			provider := &channelJWKSProvider{
				called: make(chan struct{}, 1),
				jwks:   &jwks,
			}

			tv := &TokenValidator{jwksSource: provider}
			initial := make(keyCache)
			for _, kid := range tc.initialKids {
				initial[kid] = &cachedKey{key: &allKeys[kid].PublicKey, alg: "RS256"}
			}
			tv.keys.Store(initial)

			token := test.CreateSignedToken(t, allKeys[tc.signKid], test.TokenConfig{
				Expiry:          now.Add(time.Hour),
				Iat:             now,
				Nbf:             now,
				HeaderOverrides: map[string]interface{}{"kid": tc.signKid},
				Overrides:       validClaims,
			})

			err := tv.ValidateToken(context.Background(), &credentials.EksCredentialsRequest{
				ServiceAccountToken: token,
			})
			g.Expect(err).ToNot(HaveOccurred())

			select {
			case <-provider.called:
				g.Expect(tc.wantRefresh).To(BeTrue(), "unexpected refresh when key was cached")
			default:
				g.Expect(tc.wantRefresh).To(BeFalse(), "expected refresh on cache miss")
			}

			for _, kid := range tc.wantCachedKids {
				_, found := tv.keys.Load().(keyCache)[kid]
				g.Expect(found).To(BeTrue(), "expected %s in cache after validation", kid)
			}
		})
	}
}

// TestValidateToken_K8sVersionGating verifies that the K8s version determines
// whether local JWT validation can succeed. On < 1.34 the JWKS endpoint is
// unreachable (version check fails), so ValidateToken always fails. On >= 1.34
// keys are fetched and validation succeeds for a correctly signed token.
func TestValidateToken_K8sVersionGating(t *testing.T) {
	signingKey := test.GenerateTestKey(t)
	now := time.Now()

	validToken := test.CreateSignedToken(t, signingKey, test.TokenConfig{
		Expiry: now.Add(time.Hour),
		Iat:    now,
		Nbf:    now,
		Overrides: map[string]interface{}{
			"aud":           expectedAudience,
			"sub":           "system:serviceaccount:default:my-sa",
			"kubernetes.io": fullK8sClaim(),
		},
	})

	jwksResponse := JWKSet{Keys: []JWK{rsaJWK(test.DefaultKid, &signingKey.PublicKey)}}

	tests := []struct {
		name     string
		version  map[string]string
		wantErr  bool
		closeSrv bool
	}{
		{
			name:    "K8s 1.33 rejects — version check fails, no keys loaded",
			version: map[string]string{"major": "1", "minor": "33"},
			wantErr: true,
		},
		{
			name:    "K8s 1.34 succeeds — keys fetched, validation passes",
			version: map[string]string{"major": "1", "minor": "34"},
			wantErr: false,
		},
		{
			name:     "unreachable server — version check fails, no keys loaded",
			closeSrv: true,
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/version":
					json.NewEncoder(w).Encode(tc.version)
				case "/openid/v1/jwks":
					json.NewEncoder(w).Encode(jwksResponse)
				}
			}))
			if tc.closeSrv {
				srv.Close() // make server unreachable
			} else {
				defer srv.Close()
			}

			tv := &TokenValidator{jwksSource: newTestApiserverClient(srv)}
			tv.keys.Store(make(keyCache))

			err := tv.ValidateToken(context.Background(), &credentials.EksCredentialsRequest{
				ServiceAccountToken: validToken,
			})

			if tc.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
		})
	}
}

// failingJWKSProvider always returns an error from fetchPublicKeys,
// simulating an unreachable apiserver.
type failingJWKSProvider struct{}

func (f *failingJWKSProvider) fetchPublicKeys(_ context.Context) (*JWKSet, error) {
	return nil, fmt.Errorf("apiserver unreachable")
}

// TestRefreshKeys_DiskPersistence covers all interactions between refreshKeys and the
// disk cache: persist on success, fallback on failure, graceful handling of write errors.
func TestRefreshKeys_DiskPersistence(t *testing.T) {
	tests := []struct {
		name           string
		providerFails  bool   // whether the jwksProvider returns an error
		preSeedDisk    bool   // whether to write a cache file before calling refreshKeys
		cachePath      string // override cache path ("" = no path, "nested" = subdir, "unwritable" = /proc/fake)
		wantErr        bool
		wantKeysInMem  bool
		wantKeysOnDisk bool
	}{
		{
			name:           "apiserver up, persists to disk",
			providerFails:  false,
			preSeedDisk:    false,
			cachePath:      "normal",
			wantKeysInMem:  true,
			wantKeysOnDisk: true,
		},
		{
			name:           "apiserver up, auto-creates nested directory",
			providerFails:  false,
			preSeedDisk:    false,
			cachePath:      "nested",
			wantKeysInMem:  true,
			wantKeysOnDisk: true,
		},
		{
			name:           "apiserver up, disk write fails, keys still loaded",
			providerFails:  false,
			preSeedDisk:    false,
			cachePath:      "unwritable",
			wantKeysInMem:  true,
			wantKeysOnDisk: false,
		},
		{
			name:           "apiserver down, falls back to disk cache",
			providerFails:  true,
			preSeedDisk:    true,
			cachePath:      "normal",
			wantKeysInMem:  true,
			wantKeysOnDisk: true, // already on disk from pre-seed
		},
		{
			name:          "apiserver down, no disk cache, returns error",
			providerFails: true,
			preSeedDisk:   false,
			cachePath:     "normal",
			wantErr:       true,
			wantKeysInMem: false,
		},
		{
			name:          "apiserver down, no cache path configured, returns error",
			providerFails: true,
			preSeedDisk:   false,
			cachePath:     "",
			wantErr:       true,
			wantKeysInMem: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			key := test.GenerateTestKey(t)
			jwks := &JWKSet{Keys: []JWK{rsaJWK("kid-1", &key.PublicKey)}}

			// Resolve the cache path
			var path string
			switch tt.cachePath {
			case "normal":
				path = filepath.Join(t.TempDir(), "jwks-cache.json")
			case "nested":
				path = filepath.Join(t.TempDir(), "sub", "dir", "jwks-cache.json")
			case "unwritable":
				path = "/proc/fake/jwks-cache.json"
			case "":
				path = ""
			}

			// Pre-seed disk if needed
			if tt.preSeedDisk && path != "" {
				g.Expect(writeJWKCache(path, jwks)).To(Succeed())
			}

			// Set up provider
			var source jwksProvider
			if tt.providerFails {
				source = &failingJWKSProvider{}
			} else {
				source = &channelJWKSProvider{called: make(chan struct{}, 1), jwks: jwks}
			}

			tv := &TokenValidator{jwksSource: source, jwkCachePath: path}
			tv.keys.Store(make(keyCache))

			err := tv.refreshKeys(context.Background())

			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}

			// Check in-memory keys
			cache := tv.keys.Load().(keyCache)
			if tt.wantKeysInMem {
				g.Expect(cache).To(HaveKey("kid-1"))
			} else {
				g.Expect(cache).To(BeEmpty())
			}

			// Check disk keys
			if tt.wantKeysOnDisk && path != "" {
				got, err := readJWKCache(path)
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(got.Keys).To(HaveLen(1))
			}
		})
	}
}

// TestRefreshKeys_AlreadyInFlight verifies that concurrent refresh attempts
// are rejected with an error rather than blocking or double-fetching.
func TestRefreshKeys_AlreadyInFlight(t *testing.T) {
	g := NewWithT(t)
	tv := &TokenValidator{}
	tv.keys.Store(make(keyCache))
	tv.refreshInFlight.Store(true)

	err := tv.refreshKeys(context.Background())
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("already in progress"))
}

// TestIntegration_AgentRestart_ApiserverDown_ValidatesFromDiskCache simulates a full
// agent lifecycle: fetch keys → persist to disk → restart with apiserver down →
// validate a token using only the disk-cached keys.
func TestIntegration_AgentRestart_ApiserverDown_ValidatesFromDiskCache(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	kid := "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
	signingKey := test.GenerateTestKey(t)
	jwks := &JWKSet{Keys: []JWK{rsaJWK(kid, &signingKey.PublicKey)}}
	cachePath := filepath.Join(t.TempDir(), "jwks-cache.json")

	// --- First boot: apiserver is up, keys fetched and persisted ---
	provider := &channelJWKSProvider{called: make(chan struct{}, 1), jwks: jwks}
	tv1 := &TokenValidator{jwksSource: provider, jwkCachePath: cachePath}
	tv1.keys.Store(make(keyCache))

	err := tv1.refreshKeys(ctx)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(tv1.keys.Load().(keyCache)).To(HaveKey(kid))

	// --- Simulate restart: new validator, apiserver is down ---
	tv2 := &TokenValidator{jwksSource: &failingJWKSProvider{}, jwkCachePath: cachePath}
	tv2.keys.Store(make(keyCache))

	err = tv2.refreshKeys(ctx)
	g.Expect(err).ToNot(HaveOccurred())

	// --- Validate a token signed with the original key ---
	now := time.Now()
	token := test.CreateSignedToken(t, signingKey, test.TokenConfig{
		Expiry: now.Add(time.Hour),
		Iat:    now,
		Nbf:    now,
		Overrides: map[string]interface{}{
			"aud": expectedAudience,
			"sub": "system:serviceaccount:default:my-sa",
			"kubernetes.io": map[string]interface{}{
				"namespace": "default",
				"pod": map[string]interface{}{
					"name": "my-pod",
					"uid":  "pod-uid",
				},
				"serviceaccount": map[string]interface{}{
					"name": "my-sa",
					"uid":  "sa-uid",
				},
			},
		},
		HeaderOverrides: map[string]interface{}{"kid": kid},
	})

	// Full ValidateToken: claims + signature verification using disk-cached keys
	err = tv2.ValidateToken(ctx, &credentials.EksCredentialsRequest{
		ServiceAccountToken: token,
	})
	g.Expect(err).ToNot(HaveOccurred())
}
