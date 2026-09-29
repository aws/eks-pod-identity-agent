package bundle

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// domainBundle is one trust domain's parsed authorities, in the forms the tier
// serves them. It is immutable once built, which is what lets a snapshot be read
// without a lock.
type domainBundle struct {
	// x509 holds the x509-svid authorities as DER, sorted and without duplicates,
	// so the same set always serves the same bytes and two sets compare as
	// slices. Order means nothing to a verifier.
	x509 [][]byte
	// jwt holds the jwt-svid authorities by key ID.
	jwt *jwtbundle.Bundle
	// jwks is the standard JWK Set FetchJWTBundles serves; see jwtSet.
	jwks []byte
	// refreshHint is the document's spiffe_refresh_hint, zero when absent or
	// not positive.
	refreshHint time.Duration
}

// parseDocument parses one SPIFFE bundle document with go-spiffe, and refuses one
// with no authority, which would leave workloads an empty trust store, or with a
// JWT authority that is not an RSA or ECDSA public key: go-jose parses a JWK with
// private members as the private key, which the tier would serve to every pod.
func parseDocument(trustDomain spiffeid.TrustDomain, document string) (*domainBundle, error) {
	parsed, err := spiffebundle.Parse(trustDomain, []byte(document))
	if err != nil {
		return nil, err
	}

	jwt := parsed.JWTBundle()
	authorities := jwt.JWTAuthorities()
	certificates := parsed.X509Authorities()
	if len(certificates) == 0 && len(authorities) == 0 {
		return nil, errors.New("bundle document holds no x509-svid or jwt-svid authority")
	}
	for keyID, authority := range authorities {
		if !isPublicKey(authority) {
			return nil, fmt.Errorf("jwt-svid authority %q is %T, not an RSA or ECDSA public key", keyID, authority)
		}
	}

	jwks, err := jwtSet(authorities)
	if err != nil {
		return nil, err
	}
	out := &domainBundle{jwt: jwt, jwks: jwks}
	for _, certificate := range certificates {
		out.x509 = append(out.x509, certificate.Raw)
	}
	slices.SortFunc(out.x509, bytes.Compare)
	if hint, ok := parsed.RefreshHint(); ok && hint > 0 {
		out.refreshHint = hint
	}
	return out, nil
}

// isPublicKey reports whether a parsed JWT authority is a public key of a type a
// JWT-SVID can be signed with.
func isPublicKey(key crypto.PublicKey) bool {
	switch key.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
		return true
	}
	return false
}

// jwtSet builds the JWK Set FetchJWTBundles serves: the jwt-svid authorities
// rebuilt from the parsed keys, ordered by key ID, with no use member. Serving
// the document itself would break go-spiffe's jwtbundle.Parse, which treats
// every key as a JWT authority, so an x509-svid key without a kid fails it.
func jwtSet(authorities map[string]crypto.PublicKey) ([]byte, error) {
	set := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(authorities))}
	for keyID, authority := range authorities {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: authority, KeyID: keyID})
	}
	slices.SortFunc(set.Keys, func(a, b jose.JSONWebKey) int { return strings.Compare(a.KeyID, b.KeyID) })
	out, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("encoding the jwt-svid key set: %w", err)
	}
	return out, nil
}

// sameAuthorities reports whether two parsed domains hold the same authority set,
// ignoring key order, whitespace and the refresh hint. go-spiffe compares JWT
// authorities as a set, and the X.509 ones are sorted at parse time, so both
// comparisons are set comparisons.
func (d *domainBundle) sameAuthorities(other *domainBundle) bool {
	return d.jwt.Equal(other.jwt) && slices.EqualFunc(d.x509, other.x509, bytes.Equal)
}
