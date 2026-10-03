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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// Resource names Envoy may ask for on this socket.
//
// These are a contract with the customer's Envoy configuration, not an internal
// choice: the names appear in their bootstrap, so changing one breaks every
// deployed sidecar. They are taken from Istio and SPIRE rather than invented.
//
// Istio generates a sidecar bootstrap that names "default" for the certificate
// and "ROOTCA" for the validation context, and those names are hardcoded rather
// than configurable (istio/istio#41414). Any other choice would mean no Istio
// sidecar could use this agent without patching Istio. SPIRE serves the same two
// names plus trust-domain URIs, so a customer migrating off self-managed SPIRE
// keeps their existing Envoy configuration unchanged, which is the point of
// serving SDS at all.
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

// SPIRE also serves "ALL", every federated bundle packed into one resource.
// Deliberately not served here: federation is outside the launch scope, so there
// is no second trust domain for it to return. It is additive, so adding it later
// breaks no deployed configuration.

// SecretTypeURL is the type URL Envoy expects on each resource in a
// DiscoveryResponse. Declared so a test can pin it against a literal: the value
// is produced by anypb from the generated descriptor, so a module upgrade that
// moved it would otherwise be invisible here and fatal in the field.
const SecretTypeURL = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"

// PEM block types. Envoy parses both from the DataSource bytes.
const (
	// pemBlockCertificate is the block type for a certificate, leaf or anchor.
	pemBlockCertificate = "CERTIFICATE"

	// pemBlockPrivateKey is the block type for an unencrypted PKCS#8 key, which
	// is what MarshalPKCS8PrivateKey produces. "PRIVATE KEY" rather than "RSA
	// PRIVATE KEY" or "EC PRIVATE KEY", since those name the older
	// algorithm-specific encodings and would not match the bytes.
	pemBlockPrivateKey = "PRIVATE KEY"
)

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
	// kindValidationContext resource. Empty means the caller's own domain, which
	// is the ROOTCA case and is resolved against the bundle tier at build time
	// rather than here.
	trustDomain string
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
		if strings.Contains(domain, "/") {
			return resource{}, fmt.Errorf("resource name %q names a SPIFFE ID, but a validation context is per trust domain: use %s%s",
				name, TrustDomainPrefix, strings.SplitN(domain, "/", 2)[0])
		}
		return resource{name: name, kind: kindValidationContext, trustDomain: domain}, nil

	default:
		return resource{}, fmt.Errorf("unknown resource name %q: this agent serves %q, %q and %s<trust-domain>",
			name, ResourceNameTLSCertificate, ResourceNameOwnValidationContext, TrustDomainPrefix)
	}
}

// tlsCertificateSecret builds the TlsCertificate secret for svid.
//
// Envoy wants PEM in both DataSource fields, and the agent holds the chain as DER
// and the key as a crypto.Signer, so the marshalling happens here at the edge. The
// key is marshalled rather than carried as bytes through the agent, which is why
// X509SVID holds a Signer in the first place.
func tlsCertificateSecret(name string, svid *workloadidentity.X509SVID) (*tlsv3.Secret, error) {
	if svid == nil {
		return nil, fmt.Errorf("no X.509-SVID to serve as %q", name)
	}
	if len(svid.Certificates) == 0 {
		return nil, fmt.Errorf("the X.509-SVID for %q carries no certificate", name)
	}
	if svid.PrivateKey == nil {
		return nil, fmt.Errorf("the X.509-SVID for %q carries no private key", name)
	}

	chain, err := certificateChainPEM(svid.Certificates)
	if err != nil {
		return nil, fmt.Errorf("encoding the certificate chain for %q: %w", name, err)
	}

	key, err := privateKeyPEM(svid.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("encoding the private key for %q: %w", name, err)
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
// anchors.
//
// Only TrustedCa is set. SPIRE additionally offers a SPIFFE-aware custom
// validator, which matters when one context has to verify peers from several
// trust domains; with federation out of scope there is only ever one domain's
// anchors here, and Istio's generated configuration combines an SDS-provided
// trusted_ca with its own default validation context.
func validationContextSecret(name string, anchors [][]byte) (*tlsv3.Secret, error) {
	if len(anchors) == 0 {
		return nil, fmt.Errorf("no trust anchors to serve as %q", name)
	}

	trusted, err := certificateChainPEM(anchors)
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

// certificateChainPEM concatenates DER certificates into one PEM document, in the
// order given. For a chain that is leaf first, which is what X509SVID.Certificates
// holds and what Envoy expects; for anchors the order is immaterial to Envoy but
// is preserved anyway, so that an unchanged authority set encodes to identical
// bytes and the handler's dedupe does not see a change that is only a reordering.
//
// Each certificate is parsed before it is encoded. Nothing downstream would catch
// a malformed one: PEM encoding is just base64 with a header, so a corrupt DER
// would reach Envoy as a well-formed document it then rejects, and the failure
// would surface as a handshake error in the customer's mesh rather than as an
// error from this agent.
func certificateChainPEM(der [][]byte) ([]byte, error) {
	var out []byte

	for i, certificate := range der {
		if _, err := x509.ParseCertificate(certificate); err != nil {
			return nil, fmt.Errorf("certificate %d of %d is not valid DER: %w", i+1, len(der), err)
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{
			Type:  pemBlockCertificate,
			Bytes: certificate,
		})...)
	}

	return out, nil
}

// privateKeyPEM marshals signer as an unencrypted PKCS#8 PEM document.
//
// PKCS#8 covers RSA and ECDSA with one encoding, so this does not branch on the
// key type, and it is what the Workload API carries too, so both interfaces
// marshal the same bytes and differ only in the PEM wrapper.
func privateKeyPEM(signer crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, fmt.Errorf("marshalling the private key as PKCS#8: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  pemBlockPrivateKey,
		Bytes: der,
	}), nil
}
