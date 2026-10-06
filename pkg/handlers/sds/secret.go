// Package sds serves the Envoy Secret Discovery Service on the workload identity
// socket. It is the second launch interface and the one that carries the service
// mesh story: an Istio sidecar fetches its certificate and its trust anchors over
// SDS rather than reading them from disk, and pointing that sidecar at the Pod
// Identity Agent is what replaces a self-managed SPIRE deployment.
//
// Envoy is a third-party consumer that we do not control and cannot patch, so its
// expectations are the specification. Where a choice here is dictated by Envoy or
// by Istio rather than preferred by us, the comment says which.
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

// Resource names Envoy may ask for on this socket.
//
// These are a contract with the customer's Envoy configuration, not an internal
// choice: the names appear in their bootstrap, so changing one breaks every
// deployed sidecar. Taken from Istio and SPIRE rather than invented.
//
// Istio hardcodes "default" and "ROOTCA" in the bootstrap it generates
// (istio/istio#41414), so any other choice would mean patching Istio. SPIRE
// serves the same two, as its default_svid_name and default_bundle_name, plus
// trust-domain URIs: see SDS Configuration in
// https://github.com/spiffe/spire/blob/main/doc/spire_agent.md
//
// They are configurable in SPIRE and fixed here, so a migrating customer who
// overrode one has to rename the resource.
const (
	// ResourceNameTLSCertificate is the workload's own X.509-SVID: the chain and
	// private key Envoy presents in a handshake.
	ResourceNameTLSCertificate = "default"

	// ResourceNameOwnValidationContext is the trust anchors of the caller's own
	// trust domain, which is its provider's. It is sugar for the
	// TrustDomainPrefix form naming the caller's own domain.
	ResourceNameOwnValidationContext = "ROOTCA"

	// TrustDomainPrefix prefixes a resource name that selects one trust domain's
	// anchors explicitly, as in spiffe://example.org. The suffix is looked up in
	// the provider's X.509 authorities by trust domain.
	TrustDomainPrefix = "spiffe://"
)

// SPIRE also serves "ALL", its default_all_bundles_name, which packs the agent's
// own trust domain's authorities together with every federated one into a single
// resource. Deliberately not served here: federation is outside the launch scope,
// so there is no second trust domain for it to return. It is additive, so adding
// it later breaks no deployed configuration. Note that "ALL" additionally needs
// the SPIFFE Certificate Validator extension and Envoy 1.18 or newer, so it is
// not a name every sidecar could consume anyway. Same reference as above:
// https://github.com/spiffe/spire/blob/main/doc/spire_agent.md

// SecretTypeURL is the type URL Envoy expects on each resource in a
// DiscoveryResponse. Declared so a test can pin it against a literal: the value
// is produced by anypb from the generated descriptor, so a module upgrade that
// moved it would otherwise be invisible here and fatal in the field.
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
	// name is the name as Envoy wrote it, which is echoed back on the secret.
	// Envoy's own SDS subscription rejects an update whose secret name is not
	// the one it asked for, so this has to be preserved verbatim rather than
	// normalised.
	name string

	// kind is which secret kind to build.
	kind secretKind

	// trustDomain names the domain whose anchors are wanted, for a
	// kindValidationContext resource. The zero TrustDomain means the caller's own
	// domain, which is the ROOTCA case and is resolved against the bundle tier at
	// build time rather than here.
	trustDomain spiffeid.TrustDomain
}

// parseResourceName resolves one name Envoy asked for.
//
// An unrecognised name is an error rather than an empty response, because Envoy
// subscribing to a name this agent will never serve is a configuration mistake
// that should be visible. Answering silently would leave the sidecar waiting on a
// secret that is never coming, with nothing on either side saying why.
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
		// A SPIFFE ID rather than a trust domain name, such as
		// spiffe://example.org/workload. Refused rather than truncated to its
		// domain, since a configuration asking for one is not asking for what
		// truncation would return.
		//
		// Checked before TrustDomainFromString, which would accept the ID and
		// return its domain, so the refusal is ours to word rather than a
		// silent truncation.
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

// tlsCertificateSecret builds the TlsCertificate secret for svid.
//
// Envoy wants PEM in both DataSource fields, which is exactly what go-spiffe's
// Marshal returns: the chain as concatenated CERTIFICATE blocks, leaf first, and
// the key as an unencrypted PKCS#8 PRIVATE KEY block. The Workload API handler
// calls MarshalRaw beside this for the DER the SPIFFE wire format carries, so the
// two interfaces differ only in which of the pair they call.
//
// Nothing re-parses the chain here. The tier hands over parsed
// *x509.Certificates, so a malformed certificate cannot reach this far; it would
// have failed where it was parsed, which is where the error belongs.
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
// bundle's authorities.
//
// Only TrustedCa is set. SPIRE additionally offers a SPIFFE-aware custom
// validator, which matters when one context has to verify peers from several
// trust domains; with federation out of scope there is only ever one domain's
// anchors here, and Istio's generated configuration combines an SDS-provided
// trusted_ca with its own default validation context.
//
// Bundle.Marshal is the PEM Envoy wants, and walks the authorities in the order
// the bundle holds them, so an unchanged set encodes to identical bytes and the
// dedupe does not see a reordering as a change.
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

// inlineBytes wraps b as an inline DataSource.
//
// Inline rather than Filename: the agent holds this material in memory and never
// writes it to the pod's filesystem, which is the property that makes a private
// key served over SDS better than one mounted as a file.
func inlineBytes(b []byte) *corev3.DataSource {
	return &corev3.DataSource{
		Specifier: &corev3.DataSource_InlineBytes{InlineBytes: b},
	}
}
