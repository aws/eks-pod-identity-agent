package bundle

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// domainBundle is one trust domain's parsed authorities, in the forms the tier
// serves them. It is immutable once built, which is what lets a snapshot be read
// without a lock.
type domainBundle struct {
	// x509Authorities holds the x509-svid authorities sorted by DER and without
	// duplicates, so the same set always serves the same bytes and go-spiffe's
	// order-sensitive Equal compares two as sets. Order means nothing to a
	// verifier. It is never nil, and a reader gets a Clone, never this bundle.
	x509Authorities *x509bundle.Bundle
	// jwtAuthorities holds the jwt-svid authorities by key ID.
	jwtAuthorities *jwtbundle.Bundle
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
	// spiffebundle.Parse has already dropped a repeated certificate.
	slices.SortFunc(certificates, func(a, b *x509.Certificate) int { return bytes.Compare(a.Raw, b.Raw) })
	out := &domainBundle{
		x509Authorities: x509bundle.FromX509Authorities(trustDomain, certificates),
		jwtAuthorities:  jwt,
		jwks:            jwks,
	}
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

// jwtSet builds the JWK Set FetchJWTBundles serves: only the jwt-svid keys, with
// no use member, because go-spiffe's jwtbundle.Parse reads every key in a set as
// a JWT authority. Keys are ordered by key ID so the same set always encodes to
// the same bytes, which lets a stream skip resending an unchanged bundle.
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

// sameX509Authorities reports whether two parsed domains hold the same x509-svid
// authorities. They are sorted at parse time, so this is a set comparison. A nil
// domain holds none.
func (d *domainBundle) sameX509Authorities(other *domainBundle) bool {
	if d.noX509() || other.noX509() {
		return d.noX509() == other.noX509()
	}
	return d.x509Authorities.Equal(other.x509Authorities)
}

// sameJWTAuthorities reports whether two parsed domains hold the same jwt-svid
// authorities, which go-spiffe compares as a set. A nil domain holds none.
func (d *domainBundle) sameJWTAuthorities(other *domainBundle) bool {
	if d.noJWT() || other.noJWT() {
		return d.noJWT() == other.noJWT()
	}
	return d.jwtAuthorities.Equal(other.jwtAuthorities)
}

func (d *domainBundle) noX509() bool {
	return d == nil || d.x509Authorities.Empty()
}

func (d *domainBundle) noJWT() bool {
	return d == nil || d.jwtAuthorities.Empty()
}
