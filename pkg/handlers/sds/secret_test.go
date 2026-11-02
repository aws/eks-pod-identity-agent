package sds

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	. "github.com/onsi/gomega"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/protobuf/types/known/anypb"
)

// testCertificate is a self-signed certificate and its key, standing in for an
// issued SVID or an authority. It holds the parsed certificate, which is what the
// tiers now hand over, with the DER reachable as cert.Raw.
type testCertificate struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// newTestCertificate issues a self-signed certificate under the given common
// name.
func newTestCertificate(t *testing.T, commonName string) testCertificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the certificate just created: %v", err)
	}

	return testCertificate{cert: cert, key: key}
}

// newTestSVID builds an X.509-SVID carrying one self-signed certificate.
func newTestSVID(t *testing.T, spiffeID string) *x509svid.SVID {
	t.Helper()

	issued := newTestCertificate(t, spiffeID)

	return &x509svid.SVID{
		ID:           spiffeid.RequireFromString(spiffeID),
		Certificates: []*x509.Certificate{issued.cert},
		PrivateKey:   issued.key,
	}
}

// testBundle is one trust domain's authorities, as the bundle tier holds them.
func testBundle(t *testing.T, trustDomain string, authorities ...testCertificate) *x509bundle.Bundle {
	t.Helper()

	bundle := x509bundle.New(spiffeid.RequireTrustDomainFromString(trustDomain))
	for _, authority := range authorities {
		bundle.AddX509Authority(authority.cert)
	}
	return bundle
}

// TestSecretTypeURL_MatchesWhatEnvoyExpects is the compatibility pin the
// definition of done asks for. The URL is produced by anypb from the generated
// descriptor, so a go-control-plane upgrade that renamed the message would be
// invisible in this package and fatal in the field: Envoy would reject every
// response for a type it does not recognise.
func TestSecretTypeURL_MatchesWhatEnvoyExpects(t *testing.T) {
	g := NewWithT(t)

	packed, err := anypb.New(&tlsv3.Secret{Name: ResourceNameTLSCertificate})
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(packed.GetTypeUrl()).To(Equal("type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"))
	g.Expect(packed.GetTypeUrl()).To(Equal(SecretTypeURL))
}

// TestResourceNames_AreTheNamesIstioGenerates pins the customer-visible contract.
// Istio hardcodes these two in the sidecar bootstrap it writes, so a change here
// means no Istio sidecar can use this agent.
func TestResourceNames_AreTheNamesIstioGenerates(t *testing.T) {
	g := NewWithT(t)

	g.Expect(ResourceNameTLSCertificate).To(Equal("default"))
	g.Expect(ResourceNameOwnValidationContext).To(Equal("ROOTCA"))
	g.Expect(TrustDomainPrefix).To(Equal("spiffe://"))
}

func TestParseResourceName(t *testing.T) {
	for _, tc := range []struct {
		name            string
		input           string
		wantKind        secretKind
		wantTrustDomain string
	}{
		{"the certificate", "default", kindTLSCertificate, ""},
		{"the caller's own anchors", "ROOTCA", kindValidationContext, ""},
		{"a named trust domain", "spiffe://example.org", kindValidationContext, "example.org"},
		{"a named trust domain with dots and dashes", "spiffe://prod-cluster.acme.example", kindValidationContext, "prod-cluster.acme.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			r, err := parseResourceName(tc.input)

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(r.kind).To(Equal(tc.wantKind))
			// The zero TrustDomain, whose Name is empty, is the caller's own
			// domain, resolved against the bundle tier rather than here.
			g.Expect(r.trustDomain.Name()).To(Equal(tc.wantTrustDomain))
			// The name is echoed verbatim because Envoy rejects an update whose
			// secret name is not the one it subscribed to.
			g.Expect(r.name).To(Equal(tc.input))
		})
	}
}

func TestParseResourceName_Refusals(t *testing.T) {
	for _, tc := range []struct {
		name        string
		input       string
		wantMessage string
	}{
		// SPIRE serves ALL; this agent deliberately does not, because federation
		// is outside the launch scope. Pinned so dropping it stays a decision.
		{"SPIRE's ALL is not served", "ALL", "unknown resource name"},
		{"an unknown name", "my-cert", "unknown resource name"},
		{"the empty name", "", "unknown resource name"},
		{"a scheme with no domain", "spiffe://", "names no trust domain"},
		// Truncating to the trust domain would answer a question that was not
		// asked, so it is refused with the name that would have worked.
		{"a SPIFFE ID rather than a domain", "spiffe://example.org/workload", "names a SPIFFE ID"},
		{"case matters on ROOTCA", "rootca", "unknown resource name"},
		// Rejected by go-spiffe rather than by the prefix check, which is the
		// point: the name has to be a trust domain the tier could key on.
		{"a domain go-spiffe will not parse", "spiffe://EXAMPLE.ORG", "invalid trust domain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			_, err := parseResourceName(tc.input)

			g.Expect(err).To(HaveOccurred())
			g.Expect(err.Error()).To(ContainSubstring(tc.wantMessage))
		})
	}
}

// TestParseResourceName_SpiffeIDNamesTheWorkingAlternative pins that the refusal
// tells the operator what to write instead, since the name came out of their own
// Envoy configuration.
func TestParseResourceName_SpiffeIDNamesTheWorkingAlternative(t *testing.T) {
	g := NewWithT(t)

	_, err := parseResourceName("spiffe://example.org/ns/default/sa/web")

	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("spiffe://example.org"))
}

// TestTLSCertificateSecret_IsPEMEnvoyCanParse asserts the shape rather than the
// bytes: Envoy parses PEM out of the inline DataSource, so what matters is that
// the blocks decode and carry the certificate and the key.
func TestTLSCertificateSecret_IsPEMEnvoyCanParse(t *testing.T) {
	g := NewWithT(t)

	svid := newTestSVID(t, "spiffe://example.org/workload")

	secret, err := tlsCertificateSecret(ResourceNameTLSCertificate, svid)
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(secret.GetName()).To(Equal(ResourceNameTLSCertificate))

	tlsCert := secret.GetTlsCertificate()
	g.Expect(tlsCert).ToNot(BeNil())

	chainBlock, rest := pem.Decode(tlsCert.GetCertificateChain().GetInlineBytes())
	g.Expect(chainBlock).ToNot(BeNil())
	g.Expect(chainBlock.Type).To(Equal("CERTIFICATE"))
	g.Expect(rest).To(BeEmpty())
	g.Expect(chainBlock.Bytes).To(Equal(svid.Certificates[0].Raw))

	keyBlock, rest := pem.Decode(tlsCert.GetPrivateKey().GetInlineBytes())
	g.Expect(keyBlock).ToNot(BeNil())
	// PKCS#8, so the block type is the generic one rather than "EC PRIVATE KEY".
	g.Expect(keyBlock.Type).To(Equal("PRIVATE KEY"))
	g.Expect(rest).To(BeEmpty())

	// The key round-trips to the one that signs for the leaf, which is the
	// property Envoy depends on and the one a wrong PKCS#8 marshal would break.
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	g.Expect(err).ToNot(HaveOccurred())
	parsedKey, ok := parsed.(*ecdsa.PrivateKey)
	g.Expect(ok).To(BeTrue())
	g.Expect(parsedKey.Equal(svid.PrivateKey)).To(BeTrue())
}

// TestTLSCertificateSecret_PreservesChainOrder pins leaf-first, which is the
// order Envoy expects and the order x509svid.SVID.Certificates documents.
func TestTLSCertificateSecret_PreservesChainOrder(t *testing.T) {
	g := NewWithT(t)

	leaf := newTestCertificate(t, "spiffe://example.org/workload")
	intermediate := newTestCertificate(t, "intermediate")

	svid := &x509svid.SVID{
		ID:           spiffeid.RequireFromString("spiffe://example.org/workload"),
		Certificates: []*x509.Certificate{leaf.cert, intermediate.cert},
		PrivateKey:   leaf.key,
	}

	secret, err := tlsCertificateSecret(ResourceNameTLSCertificate, svid)
	g.Expect(err).ToNot(HaveOccurred())

	var order [][]byte
	rest := secret.GetTlsCertificate().GetCertificateChain().GetInlineBytes()
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		order = append(order, block.Bytes)
	}

	g.Expect(order).To(HaveLen(2))
	g.Expect(order[0]).To(Equal(leaf.cert.Raw))
	g.Expect(order[1]).To(Equal(intermediate.cert.Raw))
}

// TestTLSCertificateSecret_Refusals covers what the tier can still hand over
// wrongly. There is no malformed-DER case any more: the tier yields parsed
// *x509.Certificates, so a corrupt certificate cannot reach this far.
func TestTLSCertificateSecret_Refusals(t *testing.T) {
	leaf := newTestCertificate(t, "spiffe://example.org/workload")

	for _, tc := range []struct {
		name        string
		svid        *x509svid.SVID
		wantMessage string
	}{
		{"no SVID at all", nil, "no X.509-SVID"},
		{
			"an SVID with no certificate",
			&x509svid.SVID{PrivateKey: leaf.key},
			"carries no certificate",
		},
		{
			"an SVID with no key",
			&x509svid.SVID{Certificates: []*x509.Certificate{leaf.cert}},
			"carries no private key",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			_, err := tlsCertificateSecret(ResourceNameTLSCertificate, tc.svid)

			g.Expect(err).To(HaveOccurred())
			g.Expect(err.Error()).To(ContainSubstring(tc.wantMessage))
		})
	}
}

// TestValidationContextSecret_IsPEMEnvoyCanParse covers the anchors, which are
// the resource a one-way-TLS Envoy asks for and the only one it asks for.
func TestValidationContextSecret_IsPEMEnvoyCanParse(t *testing.T) {
	g := NewWithT(t)

	first := newTestCertificate(t, "authority-one")
	second := newTestCertificate(t, "authority-two")

	secret, err := validationContextSecret(ResourceNameOwnValidationContext,
		testBundle(t, "example.org", first, second))
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(secret.GetName()).To(Equal(ResourceNameOwnValidationContext))

	validation := secret.GetValidationContext()
	g.Expect(validation).ToNot(BeNil())

	var anchors [][]byte
	rest := validation.GetTrustedCa().GetInlineBytes()
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		g.Expect(block.Type).To(Equal("CERTIFICATE"))
		anchors = append(anchors, block.Bytes)
	}

	g.Expect(anchors).To(Equal([][]byte{first.cert.Raw, second.cert.Raw}))
}

// TestValidationContextSecret_IsStableForUnchangedAnchors is what makes the
// handler's dedupe work. The same anchors have to encode to identical bytes, or
// proto.Equal would report a change on every wake and Envoy would be handed a new
// version for nothing.
func TestValidationContextSecret_IsStableForUnchangedAnchors(t *testing.T) {
	g := NewWithT(t)

	anchor := newTestCertificate(t, "authority")

	first, err := validationContextSecret(ResourceNameOwnValidationContext,
		testBundle(t, "example.org", anchor))
	g.Expect(err).ToNot(HaveOccurred())

	second, err := validationContextSecret(ResourceNameOwnValidationContext,
		testBundle(t, "example.org", anchor))
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(first.GetValidationContext().GetTrustedCa().GetInlineBytes()).
		To(Equal(second.GetValidationContext().GetTrustedCa().GetInlineBytes()))
}

// TestValidationContextSecret_Refusals covers an empty bundle and a missing one.
// A malformed authority is no longer reachable, for the same reason as on the
// certificate: the tier holds parsed certificates.
func TestValidationContextSecret_Refusals(t *testing.T) {
	for _, tc := range []struct {
		name        string
		bundle      *x509bundle.Bundle
		wantMessage string
	}{
		{"no bundle at all", nil, "no trust anchors"},
		{"a bundle with no authorities", testBundle(t, "example.org"), "no trust anchors"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			_, err := validationContextSecret(ResourceNameOwnValidationContext, tc.bundle)

			g.Expect(err).To(HaveOccurred())
			g.Expect(err.Error()).To(ContainSubstring(tc.wantMessage))
		})
	}
}
