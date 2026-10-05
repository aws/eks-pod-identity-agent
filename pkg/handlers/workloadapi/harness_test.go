package workloadapi

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"k8s.io/apimachinery/pkg/util/wait"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test" // initializes the package logger
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity/fake"
)

// The harness serves a Handler over a real Unix socket through grpcserver, so the
// accepted connection reaches the handler the way it does in production, with a
// pkg/workloadidentity/fake for every tier. A test picks which attested workload
// it is by sending podHeader; the fake attestor reads it off the RPC's metadata.

const (
	// testTrustDomain is the trust domain of the default provider.
	testTrustDomain = "example.org"
	// federatedTrustDomain is a second trust domain the default provider's
	// bundles carry, which FetchX509SVID serves under federated_bundles.
	federatedTrustDomain = "federated.example"
	// providerA and providerB are the two providers the fake resolver names.
	providerA = "arn:aws:iam::111122223333:workload-identity-provider/a"
	providerB = "arn:aws:iam::111122223333:workload-identity-provider/b"
	// podHeader carries the test pod's UID to the fake attestor.
	podHeader = "x-test-pod-uid"
	// jwtKeyID is the key ID the test JWT authority is published under.
	jwtKeyID = "test-key-1"
)

var (
	// podA is the default caller, enrolled with providerA.
	podA = &workloadidentity.Workload{PodUID: "uid-a", PodName: "pod-a", Namespace: "ns", ServiceAccount: "sa-a", NodeName: "node-1"}
	// podB is a second caller, enrolled with providerB.
	podB = &workloadidentity.Workload{PodUID: "uid-b", PodName: "pod-b", Namespace: "ns", ServiceAccount: "sa-b", NodeName: "node-1"}
	// podUnenrolled is attestable but its provider resolution is ErrNotEnrolled.
	podUnenrolled = &workloadidentity.Workload{PodUID: "uid-none", PodName: "pod-none", Namespace: "ns", ServiceAccount: "sa-none", NodeName: "node-1"}
)

// testBackoff keeps a blocked stream's retries in milliseconds.
var testBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 2, Steps: 1 << 30, Cap: 10 * time.Millisecond}

// harness is one served Handler, its fakes and a client. Every fake is set up by
// newHarness with a working default; a test adjusts them in the configure func,
// before the server starts, or through the fakes' setters afterwards. The default
// attestor answers through its Func, which wins over its canned Result and Err, so
// a test that wants a different answer replaces the Func.
type harness struct {
	t *testing.T

	attestor  *fake.Attestor
	certs     *fake.CertSource
	tokens    *fake.TokenSource
	bundles   *fake.BundleSource
	providers *fake.ProviderArnResolver
	// subs is the one fake Subscriber every stream subscribes through, unless
	// configure sets a per-RPC field to a fake of its own.
	subs            *fake.Subscriber
	x509SVIDSubs    workloadidentity.Subscriber
	x509BundlesSubs workloadidentity.Subscriber
	jwtBundlesSubs  workloadidentity.Subscriber

	// pki is providerA's X.509 authority, fed is federatedTrustDomain's, and jwt
	// is providerA's JWT authority.
	pki *testCA
	fed *testCA
	jwt *testJWTAuthority
	// svidA is the X.509-SVID the default CertSource serves podA.
	svidA *x509svid.SVID

	handler *Handler
	path    string
	conn    *grpc.ClientConn
	client  workload.SpiffeWorkloadAPIClient
	// ended counts streaming handlers that have returned, which a client cannot
	// observe: it reports a cancel as Canceled without waiting for the server.
	ended atomic.Int64
}

// newHarness builds the fakes, lets configure adjust them, then serves the handler
// and dials it. Everything is torn down by t.Cleanup.
func newHarness(t *testing.T, configure ...func(*harness)) *harness {
	t.Helper()

	h := &harness{t: t}
	h.pki = newTestCA(t, testTrustDomain)
	h.fed = newTestCA(t, federatedTrustDomain)
	h.jwt = newTestJWTAuthority(t, testTrustDomain, jwtKeyID)
	h.svidA = h.pki.issue(t, "spiffe://"+testTrustDomain+"/ns/ns/sa/sa-a")

	pods := map[string]*workloadidentity.Workload{podA.PodUID: podA, podB.PodUID: podB, podUnenrolled.PodUID: podUnenrolled}
	h.attestor = &fake.Attestor{Func: func(ctx context.Context, _ net.Conn) (*workloadidentity.Workload, error) {
		return podFromMetadata(ctx, pods), nil
	}}
	h.providers = &fake.ProviderArnResolver{Arns: map[string]string{podA.PodUID: providerA, podB.PodUID: providerB}}
	h.subs = &fake.Subscriber{Providers: h.providers}
	h.certs = &fake.CertSource{Result: []*x509svid.SVID{h.svidA}}
	h.tokens = &fake.TokenSource{}
	h.bundles = &fake.BundleSource{
		TrustDomain:     h.pki.trustDomain,
		X509:            x509Set(h.pki, h.fed),
		JWT:             map[string][]byte{testTrustDomain: h.jwt.jwks(t)},
		JWTSourceResult: h.jwt.bundle,
	}

	for _, c := range configure {
		c(h)
	}
	for _, field := range []*workloadidentity.Subscriber{&h.x509SVIDSubs, &h.x509BundlesSubs, &h.jwtBundlesSubs} {
		if *field == nil {
			*field = h.subs
		}
	}

	h.handler = New(Opts{
		Attestor:              h.attestor,
		Certs:                 h.certs,
		Tokens:                h.tokens,
		Bundles:               h.bundles,
		X509SVIDSubscriber:    h.x509SVIDSubs,
		X509BundlesSubscriber: h.x509BundlesSubs,
		JWTBundlesSubscriber:  h.jwtBundlesSubs,
	})
	h.handler.backoff = testBackoff
	h.serve()
	h.conn = h.dial()
	h.client = workload.NewSpiffeWorkloadAPIClient(h.conn)
	return h
}

// serve binds a socket in a short temporary directory, since a Unix socket path
// is capped near 108 bytes, and serves the handler until the test ends.
func (h *harness) serve() {
	h.t.Helper()

	dir, err := os.MkdirTemp("", "wlapi")
	if err != nil {
		h.t.Fatalf("creating a socket directory: %v", err)
	}
	h.t.Cleanup(func() { _ = os.RemoveAll(dir) })
	h.path = filepath.Join(dir, "agent.sock")

	srv, err := grpcserver.New(grpcserver.Opts{
		SocketPath:     h.path,
		ShutdownWait:   time.Second,
		Register:       h.handler.Register,
		RequestLimiter: rate.NewLimiter(rate.Inf, 0),
		ServerOptions: []grpc.ServerOption{grpc.ChainStreamInterceptor(
			func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
				defer h.ended.Add(1)
				return handler(srv, ss)
			})},
	})
	if err != nil {
		h.t.Fatalf("binding the socket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		srv.ListenUntilContextCancelled(ctx)
	}()
	h.t.Cleanup(func() {
		cancel()
		<-stopped
	})
}

// streamsEnded reports how many streaming handlers have returned.
func (h *harness) streamsEnded() int64 {
	return h.ended.Load()
}

// dial opens a new client connection to the socket, closed when the test ends.
func (h *harness) dial() *grpc.ClientConn {
	h.t.Helper()

	conn, err := grpc.NewClient("unix://"+h.path, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		h.t.Fatalf("dialling the socket: %v", err)
	}
	h.t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// ctxFor returns a context carrying the SPIFFE header the server's gate requires
// and the pod header the fake attestor reads, bounded so a hung call fails the
// test rather than the suite.
func (h *harness) ctxFor(pod *workloadidentity.Workload) context.Context {
	h.t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	h.t.Cleanup(cancel)
	return withPod(ctx, pod)
}

// withPod adds the SPIFFE header and pod's UID to ctx's outgoing metadata.
func withPod(ctx context.Context, pod *workloadidentity.Workload) context.Context {
	return metadata.AppendToOutgoingContext(ctx,
		grpcserver.SpiffeSecurityHeader, grpcserver.SpiffeSecurityHeaderValue,
		podHeader, pod.PodUID)
}

// podFromMetadata is the fake attestor's answer: the pod whose UID the caller sent
// in podHeader, podA when it sent none, which is what a go-spiffe client does, and
// nil, which the handler refuses as unattestable, for a UID it does not know.
func podFromMetadata(ctx context.Context, pods map[string]*workloadidentity.Workload) *workloadidentity.Workload {
	md, _ := metadata.FromIncomingContext(ctx)
	uids := md.Get(podHeader)
	if len(uids) == 0 {
		return podA
	}
	return pods[uids[0]]
}

// testCA is a self-signed X.509 authority for one trust domain.
type testCA struct {
	trustDomain spiffeid.TrustDomain
	cert        *x509.Certificate
	key         *ecdsa.PrivateKey
}

// newTestCA creates an authority whose certificate carries the trust domain's
// SPIFFE ID as its URI SAN, as a SPIFFE CA does.
func newTestCA(t *testing.T, trustDomain string) *testCA {
	t.Helper()

	td := spiffeid.RequireTrustDomainFromString(trustDomain)
	key := newECKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          newSerial(t),
		Subject:               pkix.Name{CommonName: trustDomain + " CA"},
		URIs:                  []*url.URL{td.ID().URL()},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return &testCA{trustDomain: td, cert: createCert(t, tmpl, tmpl, key.Public(), key), key: key}
}

// issue signs a fresh leaf X.509-SVID for spiffeID under the authority, with a
// new key each time, so two issues for the same ID differ as a renewal does.
func (ca *testCA) issue(t *testing.T, spiffeID string) *x509svid.SVID {
	t.Helper()

	id := spiffeid.RequireFromString(spiffeID)
	key := newECKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: newSerial(t),
		URIs:         []*url.URL{id.URL()},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	leaf := createCert(t, tmpl, ca.cert, key.Public(), ca.key)
	return &x509svid.SVID{ID: id, Certificates: []*x509.Certificate{leaf}, PrivateKey: key}
}

// x509Set is the bundle set of the given authorities, one bundle per authority's
// trust domain, as the bundle tier serves X509Bundles.
func x509Set(cas ...*testCA) *x509bundle.Set {
	set := x509bundle.NewSet()
	for _, ca := range cas {
		bundle, ok := set.Get(ca.trustDomain)
		if !ok {
			bundle = x509bundle.New(ca.trustDomain)
			set.Add(bundle)
		}
		bundle.AddX509Authority(ca.cert)
	}
	return set
}

// chainDER is an SVID's certificate chain as the wire carries it.
func chainDER(svid *x509svid.SVID) []byte {
	var der []byte
	for _, cert := range svid.Certificates {
		der = append(der, cert.Raw...)
	}
	return der
}

// testJWTAuthority is one trust domain's JWT signing key, published under a key
// ID in a jwtbundle.Bundle.
type testJWTAuthority struct {
	keyID  string
	key    *ecdsa.PrivateKey
	bundle *jwtbundle.Bundle
}

// newTestJWTAuthority creates a P-384 key, the ES384 key type STS signs with.
func newTestJWTAuthority(t *testing.T, trustDomain, keyID string) *testJWTAuthority {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a JWT key: %v", err)
	}
	bundle := jwtbundle.New(spiffeid.RequireTrustDomainFromString(trustDomain))
	if err := bundle.AddJWTAuthority(keyID, key.Public()); err != nil {
		t.Fatalf("adding the JWT authority: %v", err)
	}
	return &testJWTAuthority{keyID: keyID, key: key, bundle: bundle}
}

// jwks is the authority's JWK Set, as the bundle tier serves FetchJWTBundles.
func (a *testJWTAuthority) jwks(t *testing.T) []byte {
	t.Helper()

	raw, err := a.bundle.Marshal()
	if err != nil {
		t.Fatalf("marshalling the JWK Set: %v", err)
	}
	return raw
}

// sign issues a JWT-SVID for subject and audience, expiring at expiry.
func (a *testJWTAuthority) sign(t *testing.T, subject string, audience []string, expiry time.Time) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: a.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), a.keyID))
	if err != nil {
		t.Fatalf("building a JWT signer: %v", err)
	}
	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Subject:  subject,
		Audience: audience,
		Expiry:   jwt.NewNumericDate(expiry),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}).Serialize()
	if err != nil {
		t.Fatalf("signing a JWT: %v", err)
	}
	return token
}

// svid signs a JWT-SVID for subject and audience, valid for an hour, and parses it
// as the token tier hands it over. go-spiffe keeps the serialized token unexported,
// so a test JWT-SVID has to come from a real token.
func (a *testJWTAuthority) svid(t *testing.T, subject string, audience ...string) *jwtsvid.SVID {
	t.Helper()
	return parseJWTSVID(t, a.sign(t, subject, audience, time.Now().Add(time.Hour)), audience)
}

// parseJWTSVID parses token without verifying it, failing the test if it is not a
// JWT-SVID for audience.
func parseJWTSVID(t *testing.T, token string, audience []string) *jwtsvid.SVID {
	t.Helper()

	svid, err := jwtsvid.ParseInsecure(token, audience)
	if err != nil {
		t.Fatalf("parsing a test JWT-SVID: %v", err)
	}
	return svid
}

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	return key
}

func newSerial(t *testing.T) *big.Int {
	t.Helper()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("generating a serial: %v", err)
	}
	return serial
}

func createCert(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing a certificate: %v", err)
	}
	return cert
}
