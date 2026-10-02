package bundle

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	. "github.com/onsi/gomega"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
)

// with returns a copy of key with member set to value, or removed when value is
// nil.
func with(key map[string]any, member string, value any) map[string]any {
	out := map[string]any{}
	for k, v := range key {
		out[k] = v
	}
	if value == nil {
		delete(out, member)
	} else {
		out[member] = value
	}
	return out
}

// TestParseResponse_MalformedMaterial_IsRefusedWhole covers the refusals at the
// tier's boundary. Where the rule is go-spiffe's or go-jose's the case only
// asserts the document is refused; where the rule is the tier's own, it asserts
// the tier's reason.
func TestParseResponse_MalformedMaterial_IsRefusedWhole(t *testing.T) {
	ca, other := newAuthority(t, "ca"), newAuthority(t, "other")
	good := jwtECKey(t, "good", newECKey(t))
	private := jwkMembers(jose.JSONWebKey{Key: newECKey(t), KeyID: "leaked", Use: useJWTSVID})
	symmetric := jwkMembers(jose.JSONWebKey{Key: []byte("0123456789abcdef0123456789abcdef"), KeyID: "hmac", Use: useJWTSVID})
	_, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateEd := jwkMembers(jose.JSONWebKey{Key: edPrivate, KeyID: "leaked-ed", Use: useJWTSVID})
	publicEd := jwkMembers(jose.JSONWebKey{Key: edPrivate.Public(), KeyID: "ed", Use: useJWTSVID})

	for name, tc := range map[string]struct {
		entries []sts.TrustBundle
		reason  string
	}{
		"no entries":            {nil, "no trust bundle"},
		"empty trust domain":    {[]sts.TrustBundle{{TrustDomain: "", Bundle: bundleDoc(t, 0, good)}}, "trust domain"},
		"invalid trust domain":  {[]sts.TrustBundle{{TrustDomain: "Example.ORG", Bundle: bundleDoc(t, 0, good)}}, "trust domain"},
		"repeated trust domain": {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, good)}, {TrustDomain: testDomain, Bundle: bundleDoc(t, 0, good)}}, "repeats trust domain"},
		"empty document":        {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: ""}}, ""},
		"not JSON":              {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: "<keys/>"}}, ""},
		"no keys member":        {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: `{"spiffe_refresh_hint":300}`}}, ""},
		"malformed hint":        {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: strings.Replace(bundleDoc(t, 0, good), `{"keys"`, `{"spiffe_refresh_hint":"soon","keys"`, 1)}}, ""},
		"empty key set":         {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: `{"keys":[]}`}}, "no x509-svid or jwt-svid authority"},
		"only unknown uses":     {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, with(good, "use", "sig"))}}, "no x509-svid or jwt-svid authority"},
		"a second bad domain":   {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, good)}, {TrustDomain: peerDomain, Bundle: `{"keys":[]}`}}, peerDomain},
		"x5c missing":           {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, with(x509Key(t, ca), "x5c", nil))}}, ""},
		"x5c with two certificates": {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, with(x509Key(t, ca), "x5c", []string{
			base64.StdEncoding.EncodeToString(ca.der), base64.StdEncoding.EncodeToString(other.der),
		}))}}, ""},
		"x5c not a certificate":    {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, with(x509Key(t, ca), "x5c", []string{"AAAA"}))}}, ""},
		"x5c not the key's cert":   {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, with(x509Key(t, ca), "x5c", []string{base64.StdEncoding.EncodeToString(other.der)}))}}, ""},
		"jwt-svid without kid":     {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, with(good, "kid", nil))}}, ""},
		"jwt-svid malformed point": {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, with(good, "y", "!!!"))}}, ""},
		"jwt-svid private EC key":  {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, private)}}, "not an RSA or ECDSA public key"},
		"jwt-svid private Ed25519": {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, privateEd)}}, "not an RSA or ECDSA public key"},
		"jwt-svid symmetric key":   {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, symmetric)}}, "not an RSA or ECDSA public key"},
		"jwt-svid Ed25519 key":     {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, publicEd)}}, "not an RSA or ECDSA public key"},
		// go-jose before v4.1.5 padded or truncated a malformed x into a 32-byte
		// key, the identity point among them, which accepts forged signatures
		"jwt-svid Ed25519 identity x": {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, with(publicEd, "x", "AQ"))}}, ""},
		"jwt-svid Ed25519 empty x":    {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, with(publicEd, "x", ""))}}, ""},
		"jwt-svid Ed25519 seed as x":  {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, with(publicEd, "x", base64.RawURLEncoding.EncodeToString(edPrivate)))}}, ""},
		"a good key beside a bad":     {[]sts.TrustBundle{{TrustDomain: testDomain, Bundle: bundleDoc(t, 0, good, with(x509Key(t, ca), "x5c", nil))}}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)

			parsed, err := parseResponse(tc.entries)

			g.Expect(parsed).To(BeNil())
			g.Expect(err).To(HaveOccurred())
			g.Expect(err.Error()).To(ContainSubstring(tc.reason))
		})
	}
}

// TestParseDocument_ServedMaterial_IsWhatGoSpiffeParses runs what the tier
// serves through the parsers a Go workload uses on the other end of
// FetchJWTBundles and FetchX509Bundles.
func TestParseDocument_ServedMaterial_IsWhatGoSpiffeParses(t *testing.T) {
	g := NewWithT(t)
	caA, caB := newAuthority(t, "a"), newAuthority(t, "b")
	ecKey, rsaKey := newECKey(t), newRSAKey(t)
	unknownUse := jwtECKey(t, "wit-1", newECKey(t))
	unknownUse["use"] = "wit-svid"
	withAlg := jwtECKey(t, "ec-1", ecKey)
	withAlg["alg"] = "ES256"
	trustDomain := spiffeid.RequireTrustDomainFromString(testDomain)

	parsed, err := parseDocument(trustDomain, bundleDoc(t, 0, x509Key(t, caA), withAlg, x509Key(t, caB), jwtRSAKey("rsa-1", rsaKey), unknownUse))
	g.Expect(err).ToNot(HaveOccurred())

	jwt, err := jwtbundle.Parse(trustDomain, parsed.jwks)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(jwt.JWTAuthorities()).To(HaveLen(2))
	g.Expect(jwt.Equal(parsed.jwtAuthorities)).To(BeTrue(), "a workload trusts exactly the keys the agent trusts")
	var rawDER []byte
	for _, der := range parsed.x509Authorities {
		rawDER = append(rawDER, der...)
	}
	x509Authorities, err := x509bundle.ParseRaw(trustDomain, rawDER)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(x509Authorities.X509Authorities()).To(HaveLen(2))
	g.Expect(parsed.x509Authorities).To(Equal(sortedDER(caA.der, caB.der)), "every authority, sorted")

	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	g.Expect(json.Unmarshal(parsed.jwks, &set)).To(Succeed())
	g.Expect(set.Keys).To(HaveLen(2))
	g.Expect(set.Keys[0]).To(HaveKeyWithValue("kid", "ec-1"), "ordered by key ID")
	g.Expect(set.Keys[1]).To(HaveKeyWithValue("kid", "rsa-1"))
	for _, key := range set.Keys {
		g.Expect(key).ToNot(HaveKey("use"), "jwt-svid is not an RFC 7517 use value, so it is not served")
		g.Expect(key).ToNot(HaveKey("x5c"))
		g.Expect(key).ToNot(HaveKey("alg"), "the set is rebuilt from the parsed keys, not copied")
	}
}

func TestParseDocument_SameSetInAnyOrder_ServesTheSameBytes(t *testing.T) {
	g := NewWithT(t)
	k1, k2, k3 := jwtECKey(t, "k1", newECKey(t)), jwtRSAKey("k2", newRSAKey(t)), jwtECKey(t, "k3", newECKey(t))
	trustDomain := spiffeid.RequireTrustDomainFromString(testDomain)

	first, err := parseDocument(trustDomain, bundleDoc(t, 0, k1, k2, k3))
	g.Expect(err).ToNot(HaveOccurred())
	second, err := parseDocument(trustDomain, indentedBundleDoc(t, 60, k3, k1, k2))
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(second.jwks).To(Equal(first.jwks))
	g.Expect(second.sameX509Authorities(first)).To(BeTrue())
	g.Expect(second.sameJWTAuthorities(first)).To(BeTrue())
}

func TestParseDocument_SameX509SetInAnyOrder_ServesTheSameBytes(t *testing.T) {
	g := NewWithT(t)
	a, b, c := newAuthority(t, "a"), newAuthority(t, "b"), newAuthority(t, "c")
	trustDomain := spiffeid.RequireTrustDomainFromString(testDomain)

	first, err := parseDocument(trustDomain, bundleDoc(t, 0, x509Key(t, a), x509Key(t, b), x509Key(t, c)))
	g.Expect(err).ToNot(HaveOccurred())
	second, err := parseDocument(trustDomain, bundleDoc(t, 0, x509Key(t, c), x509Key(t, a), x509Key(t, b)))
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(first.x509Authorities).To(Equal(sortedDER(a.der, b.der, c.der)))
	g.Expect(second.x509Authorities).To(Equal(first.x509Authorities))
	g.Expect(second.sameX509Authorities(first)).To(BeTrue())
	g.Expect(second.sameJWTAuthorities(first)).To(BeTrue())
}

func TestJWTSet_IsOrderedByKeyID(t *testing.T) {
	g := NewWithT(t)
	authorities := map[string]crypto.PublicKey{}
	for i := 9; i >= 0; i-- {
		authorities[fmt.Sprintf("k%02d", i)] = &newECKey(t).PublicKey
	}

	served, err := jwtSet(authorities)
	g.Expect(err).ToNot(HaveOccurred())

	var set struct {
		Keys []struct {
			KeyID string `json:"kid"`
		} `json:"keys"`
	}
	g.Expect(json.Unmarshal(served, &set)).To(Succeed())
	var order []string
	for _, key := range set.Keys {
		order = append(order, key.KeyID)
	}
	g.Expect(order).To(Equal([]string{"k00", "k01", "k02", "k03", "k04", "k05", "k06", "k07", "k08", "k09"}))
}

func TestParseDocument_X509KeyCarryingAKid_IsNotAJWTAuthority(t *testing.T) {
	g := NewWithT(t)
	x509Authority := x509Key(t, newAuthority(t, "ca"))
	x509Authority["kid"] = "ca-kid"

	parsed, err := parseDocument(spiffeid.RequireTrustDomainFromString(testDomain), bundleDoc(t, 0, x509Authority, jwtECKey(t, "k1", newECKey(t))))

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(parsed.jwtAuthorities.HasJWTAuthority("ca-kid")).To(BeFalse())
	g.Expect(string(parsed.jwks)).ToNot(ContainSubstring("ca-kid"))
}

func TestParseDocument_RepeatedX509Authority_IsServedOnce(t *testing.T) {
	g := NewWithT(t)
	ca := newAuthority(t, "ca")

	parsed, err := parseDocument(spiffeid.RequireTrustDomainFromString(testDomain), bundleDoc(t, 0, x509Key(t, ca), x509Key(t, ca)))

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(parsed.x509Authorities).To(Equal([][]byte{ca.der}))
}

func TestParseDocument_OnlyX509Keys_ServesAnEmptyJWTSet(t *testing.T) {
	g := NewWithT(t)

	parsed, err := parseDocument(spiffeid.RequireTrustDomainFromString(testDomain), bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca"))))

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(parsed.jwtAuthorities.Empty()).To(BeTrue())
	g.Expect(string(parsed.jwks)).To(Equal(`{"keys":[]}`))
}

func TestParseDocument_RefreshHint_OnlyAPositiveHintIsKept(t *testing.T) {
	for name, tc := range map[string]struct {
		hintSeconds int
		expected    time.Duration
	}{
		"hint":          {300, 300 * time.Second},
		"no hint":       {0, 0},
		"negative hint": {-5, 0},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)

			parsed, err := parseDocument(spiffeid.RequireTrustDomainFromString(testDomain), bundleDoc(t, tc.hintSeconds, x509Key(t, newAuthority(t, "ca"))))

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(parsed.refreshHint).To(Equal(tc.expected))
		})
	}
}

func TestParseResponse_TrustDomainGivenAsASPIFFEID_IsKeyedByItsName(t *testing.T) {
	g := NewWithT(t)

	parsed, err := parseResponse([]sts.TrustBundle{{TrustDomain: "spiffe://" + testDomain, Bundle: bundleDoc(t, 0, x509Key(t, newAuthority(t, "ca")))}})

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(parsed.ownDomain).To(Equal(testDomain))
	g.Expect(parsed.domains).To(HaveKey(testDomain))
}
