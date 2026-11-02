// Package sds serves the Envoy Secret Discovery Service on the workload identity
// socket, so a sidecar fetches its certificate and trust anchors over SDS rather
// than from disk. Where a choice is Envoy's or Istio's, the comment says so.
package sds

import (
	"fmt"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// Resource names Envoy may ask for. They appear in the customer's bootstrap, so
// renaming one breaks every deployed sidecar. Istio hardcodes the first two
// (istio/istio#41414); SPIRE serves them too, but configurably.
const (
	// ResourceNameTLSCertificate is the workload's own X.509-SVID: the chain and
	// private key Envoy presents in a handshake.
	ResourceNameTLSCertificate = "default"

	// ResourceNameOwnValidationContext is the trust anchors of the caller's own
	// trust domain. Sugar for the TrustDomainPrefix form naming that domain.
	ResourceNameOwnValidationContext = "ROOTCA"

	// TrustDomainPrefix prefixes a name selecting one trust domain's anchors, as
	// in spiffe://example.org.
	TrustDomainPrefix = "spiffe://"
)

// SPIRE's "ALL" is not served: federation is out of scope, so there is no second
// domain to return. Additive, so adding it later breaks nothing.

// SecretTypeURL is the type URL Envoy expects on each resource. Declared so a
// test can pin it, since anypb derives it from the generated descriptor and a
// module upgrade that moved it would be invisible here.
const SecretTypeURL = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"

// secretKind is which of the two secret kinds a resource name selects.
type secretKind int

const (
	// kindTLSCertificate is a TlsCertificate: the workload's own identity.
	kindTLSCertificate secretKind = iota + 1

	// kindValidationContext is a CertificateValidationContext: the anchors a
	// peer is verified against.
	kindValidationContext
)

// resource is a parsed resource name.
type resource struct {
	// name is verbatim as Envoy wrote it: it rejects an update whose secret name
	// is not the one it asked for.
	name string

	// kind is which secret kind to build.
	kind secretKind

	// trustDomain is whose anchors are wanted. Zero means the caller's own
	// domain, the ROOTCA case, resolved against the bundle tier.
	trustDomain spiffeid.TrustDomain
}

// parseResourceName resolves one name Envoy asked for. An unrecognised name is
// an error, so a sidecar is not left waiting on a secret that never comes.
func parseResourceName(name string) (resource, error) {
	switch {
	case name == ResourceNameTLSCertificate:
		return resource{name: name, kind: kindTLSCertificate}, nil

	case name == ResourceNameOwnValidationContext:
		return resource{name: name, kind: kindValidationContext}, nil

	case strings.HasPrefix(name, TrustDomainPrefix):
		domain := strings.TrimPrefix(name, TrustDomainPrefix)
		if domain == "" {
			return resource{}, fmt.Errorf("resource name %q names no trust domain", name)
		}
		// Refused rather than truncated. Before TrustDomainFromString, which
		// would accept a full SPIFFE ID and silently return its domain.
		if strings.Contains(domain, "/") {
			return resource{}, fmt.Errorf("resource name %q names a SPIFFE ID, but a validation context is per trust domain: use %s%s",
				name, TrustDomainPrefix, strings.SplitN(domain, "/", 2)[0])
		}
		trustDomain, err := spiffeid.TrustDomainFromString(domain)
		if err != nil {
			return resource{}, fmt.Errorf("resource name %q names an invalid trust domain: %w", name, err)
		}
		return resource{name: name, kind: kindValidationContext, trustDomain: trustDomain}, nil

	default:
		return resource{}, fmt.Errorf("unknown resource name %q: this agent serves %q, %q and %s<trust-domain>",
			name, ResourceNameTLSCertificate, ResourceNameOwnValidationContext, TrustDomainPrefix)
	}
}

// tlsCertificateSecret builds the TlsCertificate secret for svid. Envoy wants
// PEM in both fields, which is what Marshal returns; the Workload API handler
// calls MarshalRaw instead, for DER.
func tlsCertificateSecret(name string, svid *x509svid.SVID) (*tlsv3.Secret, error) {
	if svid == nil {
		return nil, fmt.Errorf("no X.509-SVID to serve as %q", name)
	}
	if len(svid.Certificates) == 0 {
		return nil, fmt.Errorf("the X.509-SVID for %q carries no certificate", name)
	}
	if svid.PrivateKey == nil {
		return nil, fmt.Errorf("the X.509-SVID for %q carries no private key", name)
	}

	chain, key, err := svid.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshalling the X.509-SVID for %q: %w", name, err)
	}

	return &tlsv3.Secret{
		Name: name,
		Type: &tlsv3.Secret_TlsCertificate{
			TlsCertificate: &tlsv3.TlsCertificate{
				CertificateChain: inlineBytes(chain),
				PrivateKey:       inlineBytes(key),
			},
		},
	}, nil
}

// validationContextSecret builds the CertificateValidationContext secret holding
// bundle's authorities. Only TrustedCa is set, since federation is out of scope.
// Marshal walks the authorities in bundle order, so an unchanged set encodes to
// identical bytes and the dedupe sees no change.
func validationContextSecret(name string, bundle *x509bundle.Bundle) (*tlsv3.Secret, error) {
	if bundle == nil || len(bundle.X509Authorities()) == 0 {
		return nil, fmt.Errorf("no trust anchors to serve as %q", name)
	}

	trusted, err := bundle.Marshal()
	if err != nil {
		return nil, fmt.Errorf("encoding the trust anchors for %q: %w", name, err)
	}

	return &tlsv3.Secret{
		Name: name,
		Type: &tlsv3.Secret_ValidationContext{
			ValidationContext: &tlsv3.CertificateValidationContext{
				TrustedCa: inlineBytes(trusted),
			},
		},
	}, nil
}

// inlineBytes wraps b as an inline DataSource. Inline rather than Filename so
// the key is never written to the pod's filesystem.
func inlineBytes(b []byte) *corev3.DataSource {
	return &corev3.DataSource{
		Specifier: &corev3.DataSource_InlineBytes{InlineBytes: b},
	}
}
