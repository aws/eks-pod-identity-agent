// Package workloadidentity declares the interface seams and domain types of the
// workload identity path: attestation, token minting, AWS session exchange,
// SVID issuance, trust bundle distribution, and change notification.
//
// The shapes deliberately track the SPIFFE Workload API rather than being
// invented. Where the API returns a repeated field, so does the interface, even
// where the agent only ever produces one entry at launch. Where the API carries
// a field the agent does not use yet, such as Hint, it is present rather than
// dropped. The gRPC handlers are a thin adapter onto these types, and every
// place the internal shape diverges from the wire shape becomes a translation in
// the handler and a reshaping later.
//
// This package holds no behaviour: no methods, no constructors, no state. The
// one function it declares, MetricNames in metrics.go, returns the list of
// declared metric names so callers can enumerate it.
package workloadidentity

import (
	"context"
	"crypto"
	"net"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// Workload is an attested caller. Every field is established by the agent,
// never supplied by the caller.
type Workload struct {
	// PodUID is the Kubernetes UID of the calling pod.
	PodUID string
	// PodName is the name of the calling pod.
	PodName string
	// Namespace is the namespace of the calling pod.
	Namespace string
	// ServiceAccount is the name of the pod's ServiceAccount.
	ServiceAccount string
	// NodeName is the node the pod is scheduled on, which is always the node
	// the agent runs on.
	NodeName string
}

// Attestor resolves the process on the other end of an accepted connection to a
// Workload. It returns ErrUnattestable if the caller cannot be identified.
//
// Attest takes the conn rather than a PID because the PID alone is not safe to
// act on. SO_PEERCRED reports who connected, and that process can exit before
// the agent finishes resolving it, leaving the agent reading /proc for whatever
// process inherited the number. Guarding against that needs a handle opened at
// accept time and rechecked after resolution, and the conn is what scopes that
// handle's lifetime. Passing a PID pushes the race onto every caller.
//
// The parameter is net.Conn rather than *net.UnixConn so a fake can ignore the
// argument. The implementation does the type assertion and returns
// ErrUnattestable for anything that is not a Unix socket, which also rejects a
// caller reaching the handler over TCP.
type Attestor interface {
	// Attest identifies the workload behind conn.
	Attest(ctx context.Context, conn net.Conn) (*Workload, error)
}

// TokenMinter obtains a pod-bound ServiceAccount token for an attested
// workload.
type TokenMinter interface {
	// Mint returns a projected ServiceAccount token bound to the workload's
	// pod.
	Mint(ctx context.Context, w *Workload) (*ProjectedToken, error)
}

// ProjectedToken is a pod-bound ServiceAccount token and its expiry.
type ProjectedToken struct {
	// Token is the serialized ServiceAccount token.
	Token string
	// ExpiresAt is when the token stops being accepted.
	ExpiresAt time.Time
}

// SessionProvider exchanges a projected token for a decorated AWS session.
type SessionProvider interface {
	// Session returns an AWS session for the workload.
	Session(ctx context.Context, w *Workload) (*WorkloadSession, error)
	// Invalidate drops any cached session for the workload.
	Invalidate(podUID string)
}

// WorkloadSession is an AWS session issued for one attested workload, together
// with the identity it was issued against.
type WorkloadSession struct {
	// Credentials are the AWS credentials for the session.
	Credentials aws.Credentials
	// ProviderArn identifies the identity provider that vended the session.
	ProviderArn string
	// ExpiresAt is when the credentials stop being accepted.
	ExpiresAt time.Time
}

// CertSource yields every X.509-SVID a workload is entitled to, minting or
// renewing as needed. It is plural because FetchX509SVID returns a repeated
// svids field, so the handler emits a list either way.
//
// The slice will always hold exactly one element. WISE issues one SVID per
// workload, so there is nothing to select among and no selection logic is
// needed anywhere.
type CertSource interface {
	// X509SVIDs returns the workload's X.509-SVIDs.
	X509SVIDs(ctx context.Context, w *Workload) ([]*X509SVID, error)
}

// X509SVID tracks the Workload API X509SVID message. The API carries the key as
// PKCS#8 DER bytes; this holds a crypto.Signer instead and marshals at the edge,
// so the private key is not copied through the agent as a byte slice. Envoy
// wants PEM and the Workload API wants DER, so a marshal happens in the handler
// either way.
type X509SVID struct {
	// SpiffeID is the SPIFFE ID asserted by the leaf certificate.
	SpiffeID string
	// Certificates is the certificate chain as DER, leaf first.
	Certificates [][]byte
	// PrivateKey signs for the leaf certificate.
	PrivateKey crypto.Signer
	// Hint is on the wire and nothing populates it. WISE issues one SVID per
	// workload, so there is never a set to disambiguate. It is present so the
	// handler does not need changing if that ever stops being true.
	Hint string
	// NotBefore is agent-internal and not on the wire. It is parsed off the
	// leaf and used to schedule renewal. Derive it from the issued
	// certificate, never from what was requested.
	NotBefore time.Time
	// NotAfter is agent-internal and not on the wire. It is parsed off the
	// leaf and used to schedule renewal. Derive it from the issued
	// certificate, never from what was requested.
	NotAfter time.Time
}

// TokenSource yields JWT-SVIDs for a workload. Audiences is plural because
// FetchJWTSVID takes a repeated audience field.
//
// The STS call underneath also takes a list but permits only one entry, so an
// implementation fans out: one call per requested audience, and one cache entry
// each. A caller asking for three audiences costs three issuances.
type TokenSource interface {
	// JWTSVIDs returns one JWT-SVID per requested audience.
	JWTSVIDs(ctx context.Context, w *Workload, audiences []string) ([]*JWTSVID, error)
}

// JWTSVID tracks the Workload API JWTSVID message.
type JWTSVID struct {
	// SpiffeID is the SPIFFE ID asserted by the token's subject.
	SpiffeID string
	// Token is the serialized JWT-SVID.
	Token string
	// Hint is on the wire and nothing populates it, for the same reason as on
	// X509SVID: WISE issues one SVID per workload, so there is never a set to
	// disambiguate.
	Hint string
	// ExpiresAt is agent-internal, parsed from the token's exp claim and used
	// to schedule renewal.
	ExpiresAt time.Time
}

// BundleSource yields trust material per workload identity provider, not per
// workload. Callers pass the provider ARN from the workload's WorkloadSession;
// an implementation fetches with the node's own credentials, never that session.
//
// The methods split by format to mirror FetchX509Bundles and FetchJWTBundles,
// but one GetTrustBundles fetch and one cache back all of them. There is no
// generation number: change is signalled through Subscriber. A stream holds a
// Lease on its provider for as long as it is open.
type BundleSource interface {
	// Lease keeps the provider's bundles cached and refreshed until release is
	// called or ctx ends, whichever comes first; releasing twice is harmless. A
	// stream takes one when it opens. An empty ARN is ErrNotEnrolled.
	Lease(ctx context.Context, providerArn string) (release func(), err error)

	// OwnTrustDomain is the provider's own domain, which is the workload's. The
	// Workload API presents its authorities inline on each X509SVID and every
	// other entry under federated_bundles, so the handler has to know which is
	// which.
	OwnTrustDomain(providerArn string) string

	// X509Bundles mirrors FetchX509Bundles: authorities as DER, keyed by trust
	// domain, decoded from each JWK's x5c member. Envoy wants these
	// PEM-encoded, which the SDS handler does at the edge.
	X509Bundles(ctx context.Context, providerArn string) (map[string][][]byte, error)

	// JWTBundles mirrors FetchJWTBundles: per trust domain, a JWK Set of the
	// jwt-svid keys only, which the RPC returns as is. x509-svid entries are
	// left out because go-spiffe treats every key in the set as a JWT authority.
	JWTBundles(ctx context.Context, providerArn string) (map[string][]byte, error)

	// JWTAuthority resolves one verification key for ValidateJWTSVID. It is a
	// lookup rather than a map so the implementation can parse lazily and
	// cache, and so an unknown key ID is an error at the point it matters.
	JWTAuthority(providerArn, trustDomain, keyID string) (crypto.PublicKey, error)
}

// Subscriber delivers change notifications to an open stream.
type Subscriber interface {
	// Subscribe returns a channel signalled on every change relevant to the
	// workload, and a cancel function that releases the subscription.
	Subscribe(ctx context.Context, w *Workload) (<-chan struct{}, func())
	// BroadcastBundleChange notifies every open subscription.
	BroadcastBundleChange()
}
