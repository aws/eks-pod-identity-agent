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
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
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

// ProviderArnResolver names an attested workload's identity provider. A workload
// with none is ErrNotEnrolled, never an empty ARN. At launch the ARN comes from
// the workload's session (SessionProviderArns); post-GA it can come from the
// credentials cache instead.
type ProviderArnResolver interface {
	ProviderArn(ctx context.Context, w *Workload) (string, error)
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
// workload. Every method takes the attested workload, so where the provider ARN
// comes from and whose credentials sign sts:GetTrustBundles can change without
// the interface changing.
//
// The methods split by format to mirror FetchX509Bundles and FetchJWTBundles,
// but one fetch and one cache back all of them. There is no generation number:
// each changed authority set is signalled through BundleNotifier. A stream holds
// a Lease on its provider for as long as it is open.
type BundleSource interface {
	// Lease keeps the workload's provider cached and refreshed until release is
	// called or ctx ends, whichever comes first; releasing twice is harmless. A
	// stream takes one when it opens.
	Lease(ctx context.Context, w *Workload) (release func(), err error)

	// OwnTrustDomain is the provider's own domain, which is the workload's. The
	// Workload API presents its authorities inline on each X509SVID and every
	// other entry under federated_bundles, so the handler has to know which.
	OwnTrustDomain(ctx context.Context, w *Workload) (string, error)

	// X509Bundles mirrors FetchX509Bundles: authorities as DER, keyed by trust
	// domain, decoded from each JWK's x5c member. Envoy wants these
	// PEM-encoded, which the SDS handler does at the edge.
	X509Bundles(ctx context.Context, w *Workload) (map[string][][]byte, error)

	// JWTBundles mirrors FetchJWTBundles: per trust domain, a JWK Set of the
	// jwt-svid keys only, which the RPC returns as is. x509-svid entries are
	// left out because go-spiffe treats every key in the set as a JWT authority.
	JWTBundles(ctx context.Context, w *Workload) (map[string][]byte, error)

	// JWTSource returns the provider's JWT authorities as a point-in-time
	// source that go-spiffe's jwtsvid.ParseAndValidate reads directly, so
	// ValidateJWTSVID parses nothing itself.
	JWTSource(ctx context.Context, w *Workload) (jwtbundle.Source, error)
}

// Subscriber is the read side of the notification tier: a handler can learn that
// its own material changed and cannot make anything change for anybody else.
// Publishing lives on BundleNotifier and WorkloadNotifier. One implementation
// satisfies all three, and each caller is handed only the side it needs.
//
// One method per kind of stream rather than one method and a set of interests,
// because only three combinations exist and they are stable. Nothing wants both
// authority sets, so no call has to express a combination.
//
// Every method takes the provider ARN from the caller's WorkloadSession, so a
// rotation in one provider's bundles does not wake another provider's streams. An
// empty ARN is reached by no bundle change, which a caller should have refused
// with ErrNotEnrolled before subscribing.
//
// No method carries the RPC it subscribes for, even though the subscription
// metrics are labelled by RPC; the implementation takes that label at wiring time.
//
// On every method: the channel arrives with one signal pending, so a handler's
// loop is wait-then-send and its first pass is the initial response. Release is
// idempotent and the subscription also ends with ctx, so a handler that returns
// without releasing does not leak. Nothing is required to observe a signal.
type Subscriber interface {
	// SubscribeToWorkloadMaterial is signalled when the workload's own
	// credentials change and when its provider's X.509 authorities do.
	//
	// It is for the streams serving an SVID together with the material to verify
	// peers: FetchX509SVID, whose response embeds the bundle, and Envoy SDS,
	// which serves both as secrets on one stream. Both reasons to wake arrive on
	// one channel, so a handler never selects across two.
	SubscribeToWorkloadMaterial(ctx context.Context, w *Workload, providerArn string) (<-chan struct{}, func())

	// SubscribeToCertBundles is signalled only by the provider's X.509
	// authorities changing. For FetchX509Bundles, which has a workload and
	// deliberately does not pass it: a renewed SVID is not something a bundle
	// stream can act on.
	SubscribeToCertBundles(ctx context.Context, providerArn string) (<-chan struct{}, func())

	// SubscribeToJWTBundles is signalled only by the provider's JWT authorities
	// changing. For FetchJWTBundles.
	//
	// Separate from SubscribeToCertBundles because the two sets rotate
	// independently: a JWT signing key typically rolls more often than a
	// certificate authority, and a shared signal would wake every SVID stream on
	// the node for a key roll none of them can observe.
	SubscribeToJWTBundles(ctx context.Context, providerArn string) (<-chan struct{}, func())
}

// BundleNotifier is how the trust bundle tier reports a rotation, one method per
// authority set. Separate from Subscriber so only the tiers entitled to wake
// another pod's stream hold the methods that do it.
//
// Both name a provider, since a node hosts workloads of several and a rotation in
// one is not news to the others. One fetch can change both sets, in which case
// the publisher calls both; no stream subscribes to both, so neither call reaches
// the other's audience.
type BundleNotifier interface {
	// NotifyCertBundleChange signals the provider's subscriptions that take
	// X.509 authorities: workload material and cert bundle streams.
	NotifyCertBundleChange(providerArn string)

	// NotifyJWTBundleChange signals the provider's JWT bundle subscriptions.
	NotifyJWTBundleChange(providerArn string)
}

// WorkloadNotifier is how a per-pod material tier reports that one workload's
// credentials changed, so only that pod's streams are woken.
type WorkloadNotifier interface {
	// NotifyWorkloadChange signals the pod's workload material subscriptions and
	// nothing else. A pod with no open stream is not an error.
	//
	// It must not block: a renewal loop stalling on one slow subscriber would
	// stall renewals for the whole node.
	NotifyWorkloadChange(podUID string)
}
