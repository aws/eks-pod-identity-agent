package workloadapi

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	spiffeworkloadapi "github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// These tests drive the handler with go-spiffe's own client instead of a
// hand-written one, so they check what a SPIFFE library nobody here wrote
// accepts: the PKCS#8 key, the trust domain keys on the bundle maps, the JWK Set,
// and a stream that blocks through a cold start rather than failing it.

// conformanceLogger records what go-spiffe's client logs at warning and error
// level. The client logs every failed stream there before it quietly retries,
// so an empty log is how a test knows the library never saw a stream fail.
type conformanceLogger struct {
	mu      sync.Mutex
	entries []string
}

func (l *conformanceLogger) Debugf(string, ...any) {}
func (l *conformanceLogger) Infof(string, ...any)  {}
func (l *conformanceLogger) Warnf(format string, args ...any) {
	l.record("WARN "+format, args...)
}
func (l *conformanceLogger) Errorf(format string, args ...any) {
	l.record("ERROR "+format, args...)
}

func (l *conformanceLogger) record(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, fmt.Sprintf(format, args...))
}

// failures returns a copy of what was logged, safe to read while the client's
// watch goroutine is still running.
func (l *conformanceLogger) failures() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.entries...)
}

// conformanceCtx bounds one go-spiffe call so a hung stream fails the test rather
// than the suite. go-spiffe replaces the outgoing metadata with its own header,
// so the fake attestor answers podA for every call the library makes.
func conformanceCtx(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// conformanceClientOptions points go-spiffe at the harness socket the way
// SPIFFE_ENDPOINT_SOCKET would, and routes its logs to log.
func conformanceClientOptions(h *harness, log *conformanceLogger) []spiffeworkloadapi.ClientOption {
	return []spiffeworkloadapi.ClientOption{
		spiffeworkloadapi.WithAddr("unix://" + h.path),
		spiffeworkloadapi.WithLogger(log),
	}
}

// conformanceClient opens a go-spiffe Workload API client, closed when the test
// ends, before the harness stops serving.
func conformanceClient(t *testing.T, h *harness, log *conformanceLogger) *spiffeworkloadapi.Client {
	t.Helper()

	client, err := spiffeworkloadapi.New(conformanceCtx(t), conformanceClientOptions(h, log)...)
	if err != nil {
		t.Fatalf("opening a go-spiffe client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// conformanceX509Source opens a go-spiffe X509Source, which returns only once
// the stream has delivered its first response. Close is idempotent, so a test
// may close it early and the cleanup still runs.
func conformanceX509Source(t *testing.T, h *harness, log *conformanceLogger) (*spiffeworkloadapi.X509Source, error) {
	t.Helper()

	source, err := spiffeworkloadapi.NewX509Source(conformanceCtx(t),
		spiffeworkloadapi.WithClientOptions(conformanceClientOptions(h, log)...))
	if err == nil {
		t.Cleanup(func() { _ = source.Close() })
	}
	return source, err
}

// conformancePeer issues an X.509-SVID for id under ca, parsed back through
// go-spiffe so it is validated, to stand in for the workload on the other end of a
// handshake.
func conformancePeer(t *testing.T, ca *testCA, id string) *x509svid.SVID {
	t.Helper()

	chain, key, err := ca.issue(t, id).MarshalRaw()
	if err != nil {
		t.Fatalf("marshalling the peer SVID: %v", err)
	}
	svid, err := x509svid.ParseRaw(chain, key)
	if err != nil {
		t.Fatalf("parsing the peer SVID: %v", err)
	}
	return svid
}

// conformanceHandshake runs one TLS handshake over loopback TCP and returns each
// side's error. The server then writes a byte for the client to read, because a
// TLS 1.3 client finishes before the server has checked its certificate and only
// hears a refusal on its next read. Loopback rather than net.Pipe, whose
// unbuffered writes can leave both sides blocked sending alerts.
func conformanceHandshake(t *testing.T, serverConfig, clientConfig *tls.Config) (serverErr, clientErr error) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on loopback: %v", err)
	}
	defer func() { _ = ln.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()

	type result struct {
		conn net.Conn
		err  error
	}
	serverDone := make(chan result, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			serverDone <- result{err: err}
			return
		}
		_ = raw.SetDeadline(deadline)
		conn := tls.Server(raw, serverConfig)
		err = conn.HandshakeContext(ctx)
		if err == nil {
			_, err = conn.Write([]byte{1})
		}
		serverDone <- result{conn: raw, err: err}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dialling loopback: %v", err)
	}
	_ = raw.SetDeadline(deadline)
	conn := tls.Client(raw, clientConfig)
	clientErr = conn.HandshakeContext(ctx)
	if clientErr == nil {
		_, clientErr = io.ReadFull(conn, make([]byte, 1))
	}
	// The raw conns are closed rather than the TLS ones, so neither side sends a
	// close_notify the other is no longer reading.
	_ = raw.Close()

	server := <-serverDone
	if server.conn != nil {
		_ = server.conn.Close()
	}
	return server.err, clientErr
}

func TestFetchX509SVID_GoSpiffeVerifiesPeerWithBundleFromSameResponse(t *testing.T) {
	g := NewWithT(t)
	h := newHarness(t)
	client := conformanceClient(t, h, &conformanceLogger{})

	x509Ctx, err := client.FetchX509Context(conformanceCtx(t))
	g.Expect(err).NotTo(HaveOccurred())

	g.Expect(x509Ctx.SVIDs).To(HaveLen(1))
	svid := x509Ctx.DefaultSVID()
	g.Expect(svid.ID.String()).To(Equal(h.svidA.ID.String()))
	g.Expect(svid.Certificates).To(HaveLen(1))
	g.Expect(svid.Certificates[0].Raw).To(Equal(h.svidA.Certificates[0].Raw))
	pub, ok := svid.PrivateKey.Public().(interface{ Equal(crypto.PublicKey) bool })
	g.Expect(ok).To(BeTrue(), "the parsed private key has no comparable public key")
	g.Expect(pub.Equal(svid.Certificates[0].PublicKey)).To(BeTrue(), "the private key does not match the leaf")
	g.Expect(pub.Equal(h.svidA.PrivateKey.Public())).To(BeTrue(), "the private key is not the one the cert tier holds")

	own := spiffeid.RequireTrustDomainFromString(testTrustDomain)
	federated := spiffeid.RequireTrustDomainFromString(federatedTrustDomain)
	g.Expect(x509Ctx.Bundles.Len()).To(Equal(2))
	ownBundle, ok := x509Ctx.Bundles.Get(own)
	g.Expect(ok).To(BeTrue(), "no bundle for the SVID's own trust domain")
	g.Expect(ownBundle.X509Authorities()).To(HaveLen(1))
	g.Expect(ownBundle.HasX509Authority(h.pki.cert)).To(BeTrue())
	fedBundle, ok := x509Ctx.Bundles.Get(federated)
	g.Expect(ok).To(BeTrue(), "no bundle for the federated trust domain")
	g.Expect(fedBundle.X509Authorities()).To(HaveLen(1))
	g.Expect(fedBundle.HasX509Authority(h.fed.cert)).To(BeTrue())

	// What the peer trusts to verify the fetched SVID. The fetched side trusts
	// nothing but x509Ctx.Bundles, so every accept and reject below is the
	// response's own bundle at work.
	peerTrust := x509bundle.FromX509Authorities(own, []*x509.Certificate{h.pki.cert})
	cases := []struct {
		name     string
		peer     *x509svid.SVID
		accepted bool
	}{
		{name: "same trust domain", peer: conformancePeer(t, h.pki, "spiffe://"+testTrustDomain+"/ns/ns/sa/peer"), accepted: true},
		{name: "federated trust domain", peer: conformancePeer(t, h.fed, "spiffe://"+federatedTrustDomain+"/peer"), accepted: true},
		{name: "unrelated CA claiming the same trust domain", peer: conformancePeer(t, newTestCA(t, testTrustDomain), "spiffe://"+testTrustDomain+"/ns/ns/sa/peer")},
		{name: "trust domain the response has no bundle for", peer: conformancePeer(t, newTestCA(t, "other.example"), "spiffe://other.example/peer")},
	}
	for _, tc := range cases {
		for _, fetchedIsServer := range []bool{true, false} {
			role := "fetched SVID dials"
			if fetchedIsServer {
				role = "fetched SVID serves"
			}
			t.Run(tc.name+"/"+role, func(t *testing.T) {
				g := NewWithT(t)

				var serverConfig, clientConfig *tls.Config
				if fetchedIsServer {
					serverConfig = tlsconfig.MTLSServerConfig(svid, x509Ctx.Bundles, tlsconfig.AuthorizeID(tc.peer.ID))
					clientConfig = tlsconfig.MTLSClientConfig(tc.peer, peerTrust, tlsconfig.AuthorizeID(svid.ID))
				} else {
					serverConfig = tlsconfig.MTLSServerConfig(tc.peer, peerTrust, tlsconfig.AuthorizeID(svid.ID))
					clientConfig = tlsconfig.MTLSClientConfig(svid, x509Ctx.Bundles, tlsconfig.AuthorizeID(tc.peer.ID))
				}
				serverErr, clientErr := conformanceHandshake(t, serverConfig, clientConfig)
				fetchedErr, peerErr := serverErr, clientErr
				if !fetchedIsServer {
					fetchedErr, peerErr = clientErr, serverErr
				}

				if tc.accepted {
					g.Expect(fetchedErr).NotTo(HaveOccurred())
					g.Expect(peerErr).NotTo(HaveOccurred())
					return
				}
				// The fetched side is the one that refuses, on the chain and not
				// on the authorizer, which names the peer's ID exactly.
				g.Expect(fetchedErr).To(MatchError(ContainSubstring("x509svid:")))
				g.Expect(peerErr).To(HaveOccurred())
			})
		}
	}
}

func TestFetchX509SVID_GoSpiffeSourceReceivesRenewalOnOpenStream(t *testing.T) {
	g := NewWithT(t)
	h := newHarness(t)
	log := &conformanceLogger{}
	source, err := conformanceX509Source(t, h, log)
	g.Expect(err).NotTo(HaveOccurred())

	initial, err := source.GetX509SVID()
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(initial.Certificates[0].Raw).To(Equal(h.svidA.Certificates[0].Raw))
	g.Expect(h.attestor.Calls()).To(Equal(1))
	g.Expect(h.subs.Subscriptions()).To(HaveLen(1))

	renewed := h.pki.issue(t, h.svidA.ID.String())
	h.certs.SetResult([]*x509svid.SVID{renewed}, nil)
	g.Expect(h.subs.NotifyWorkload(podA.PodUID)).To(Equal(1))

	g.Eventually(func() []byte {
		svid, err := source.GetX509SVID()
		if err != nil {
			return nil
		}
		return svid.Certificates[0].Raw
	}).WithTimeout(5 * time.Second).Should(Equal(renewed.Certificates[0].Raw))
	current, err := source.GetX509SVID()
	g.Expect(err).NotTo(HaveOccurred())
	pub, ok := current.PrivateKey.Public().(interface{ Equal(crypto.PublicKey) bool })
	g.Expect(ok).To(BeTrue())
	g.Expect(pub.Equal(renewed.PrivateKey.Public())).To(BeTrue(), "the renewed SVID came with a stale key")

	// One attestation and one subscription: the renewal rode the stream the
	// source opened, and the library saw no failure to reconnect after.
	g.Expect(h.attestor.Calls()).To(Equal(1))
	g.Expect(h.subs.Subscriptions()).To(HaveLen(1))
	g.Expect(h.subs.Subscriptions()[0].Live()).To(BeTrue())
	g.Expect(log.failures()).To(BeEmpty())

	g.Expect(source.Close()).To(Succeed())
	g.Eventually(h.subs.LiveSubscriptions).WithTimeout(5 * time.Second).Should(BeZero())
	g.Eventually(h.bundles.LiveLeases).WithTimeout(5 * time.Second).Should(BeZero())
}

func TestFetchX509Bundles_GoSpiffeReceivesProviderTrustDomains(t *testing.T) {
	g := NewWithT(t)
	h := newHarness(t)
	client := conformanceClient(t, h, &conformanceLogger{})

	set, err := client.FetchX509Bundles(conformanceCtx(t))
	g.Expect(err).NotTo(HaveOccurred())

	g.Expect(set.Len()).To(Equal(2))
	own, ok := set.Get(spiffeid.RequireTrustDomainFromString(testTrustDomain))
	g.Expect(ok).To(BeTrue(), "no bundle for the provider's own trust domain")
	g.Expect(own.X509Authorities()).To(HaveLen(1))
	g.Expect(own.HasX509Authority(h.pki.cert)).To(BeTrue())
	fed, ok := set.Get(spiffeid.RequireTrustDomainFromString(federatedTrustDomain))
	g.Expect(ok).To(BeTrue(), "no bundle for the federated trust domain")
	g.Expect(fed.X509Authorities()).To(HaveLen(1))
	g.Expect(fed.HasX509Authority(h.fed.cert)).To(BeTrue())

	// go-spiffe's one-shot fetch cancels the stream after one response, which
	// must release what the stream held.
	g.Eventually(h.subs.LiveSubscriptions).WithTimeout(5 * time.Second).Should(BeZero())
	g.Eventually(h.bundles.LiveLeases).WithTimeout(5 * time.Second).Should(BeZero())
}

func TestFetchJWTBundles_GoSpiffeReceivesProviderAuthorities(t *testing.T) {
	g := NewWithT(t)
	h := newHarness(t)
	client := conformanceClient(t, h, &conformanceLogger{})

	set, err := client.FetchJWTBundles(conformanceCtx(t))
	g.Expect(err).NotTo(HaveOccurred())

	g.Expect(set.Len()).To(Equal(1))
	bundle, ok := set.Get(spiffeid.RequireTrustDomainFromString(testTrustDomain))
	g.Expect(ok).To(BeTrue(), "no JWT bundle for the provider's trust domain")
	g.Expect(bundle.JWTAuthorities()).To(HaveLen(1))
	key, ok := bundle.FindJWTAuthority(jwtKeyID)
	g.Expect(ok).To(BeTrue(), "no JWT authority under %q", jwtKeyID)
	pub, ok := key.(interface{ Equal(crypto.PublicKey) bool })
	g.Expect(ok).To(BeTrue())
	g.Expect(pub.Equal(h.jwt.key.Public())).To(BeTrue(), "the JWT authority is not the provider's key")

	g.Eventually(h.subs.LiveSubscriptions).WithTimeout(5 * time.Second).Should(BeZero())
	g.Eventually(h.bundles.LiveLeases).WithTimeout(5 * time.Second).Should(BeZero())
}

// conformanceJWTHarness serves tokens signed by the harness's JWT authority for
// svidA, one per audience set in conformanceAudienceSets, each carrying the whole
// set as T8 issues them. They are minted up front on the test goroutine, since
// the signer fails the test through t. It returns the tokens by joined set.
func conformanceJWTHarness(t *testing.T) (*harness, map[string]string) {
	t.Helper()

	tokens := map[string]string{}
	h := newHarness(t, func(h *harness) {
		expiry := time.Now().Add(time.Hour)
		parsed := map[string]*jwtsvid.SVID{}
		for _, set := range conformanceAudienceSets {
			key := strings.Join(set, " ")
			tokens[key] = h.jwt.sign(t, h.svidA.ID.String(), set, expiry)
			parsed[key] = parseJWTSVID(t, tokens[key], set)
		}
		h.tokens.Func = func(_ context.Context, _ *workloadidentity.Workload, audiences []string) ([]*jwtsvid.SVID, error) {
			svid, ok := parsed[strings.Join(audiences, " ")]
			if !ok {
				return nil, wierrors.ErrInvalidAudience.Wrapf(nil, "the test mints no token for %q", audiences)
			}
			return []*jwtsvid.SVID{svid}, nil
		}
	})
	return h, tokens
}

// conformanceAudienceSets are the audience sets conformanceJWTHarness mints
// tokens for, in the order go-spiffe sends them.
var conformanceAudienceSets = [][]string{{"aud-1"}, {"aud-2"}, {"aud-1", "aud-2"}}

func TestFetchJWTSVID_GoSpiffeFetchesATokenForItsAudiences(t *testing.T) {
	g := NewWithT(t)
	h, tokens := conformanceJWTHarness(t)
	client := conformanceClient(t, h, &conformanceLogger{})
	ctx := conformanceCtx(t)

	first, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "aud-1"})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(first.ID.String()).To(Equal(h.svidA.ID.String()))
	g.Expect(first.Audience).To(Equal([]string{"aud-1"}))
	g.Expect(first.Marshal()).To(Equal(tokens["aud-1"]))

	second, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "aud-2"})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(second.ID.String()).To(Equal(h.svidA.ID.String()))
	g.Expect(second.Audience).To(Equal([]string{"aud-2"}))
	g.Expect(second.Marshal()).NotTo(Equal(first.Marshal()))

	// go-spiffe sends the subject as the request's spiffe_id filter.
	bySubject, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "aud-1", Subject: first.ID})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(bySubject.Marshal()).To(Equal(tokens["aud-1"]))

	// ExtraAudiences go in the same request, and the one token carries them all,
	// which is what a relying party for either audience checks.
	both, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "aud-1", ExtraAudiences: []string{"aud-2"}})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(both.Audience).To(ConsistOf("aud-1", "aud-2"))
	g.Expect(both.Marshal()).To(Equal(tokens["aud-1 aud-2"]))

	requests := h.tokens.Requests()
	g.Expect(requests).To(HaveLen(4))
	for i, want := range [][]string{{"aud-1"}, {"aud-2"}, {"aud-1"}, {"aud-1", "aud-2"}} {
		g.Expect(requests[i].Workload).To(BeIdenticalTo(podA))
		g.Expect(requests[i].Audiences).To(Equal(want))
	}
}

func TestValidateJWTSVID_GoSpiffeChecksAudienceAndAuthority(t *testing.T) {
	g := NewWithT(t)
	h, _ := conformanceJWTHarness(t)
	client := conformanceClient(t, h, &conformanceLogger{})
	ctx := conformanceCtx(t)

	fetched, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "aud-1"})
	g.Expect(err).NotTo(HaveOccurred())
	token := fetched.Marshal()

	validated, err := client.ValidateJWTSVID(ctx, token, "aud-1")
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(validated.ID.String()).To(Equal(h.svidA.ID.String()))
	g.Expect(validated.Audience).To(Equal([]string{"aud-1"}))

	_, err = client.ValidateJWTSVID(ctx, token, "aud-2")
	g.Expect(status.Code(err)).To(Equal(codes.InvalidArgument), "a token for another audience: %v", err)

	// Same trust domain and key ID, different key: only the signature can fail.
	forged := newTestJWTAuthority(t, testTrustDomain, jwtKeyID).sign(t, h.svidA.ID.String(), []string{"aud-1"}, time.Now().Add(time.Hour))
	_, err = client.ValidateJWTSVID(ctx, forged, "aud-1")
	g.Expect(status.Code(err)).To(Equal(codes.InvalidArgument), "a token signed outside the bundle: %v", err)
}

func TestFetchX509SVID_GoSpiffeSourceWaitsOutColdStart(t *testing.T) {
	const notYetMinted = 5

	g := NewWithT(t)
	var calls atomic.Int32
	h := newHarness(t, func(h *harness) {
		svid := h.svidA
		h.certs.Func = func(context.Context, *workloadidentity.Workload) ([]*x509svid.SVID, error) {
			if calls.Add(1) <= notYetMinted {
				return nil, wierrors.ErrIssuanceFailed.Wrapf(nil, "the SVID is not minted yet")
			}
			return []*x509svid.SVID{svid}, nil
		}
	})
	log := &conformanceLogger{}

	source, err := conformanceX509Source(t, h, log)
	g.Expect(err).NotTo(HaveOccurred())
	svid, err := source.GetX509SVID()
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(svid.ID.String()).To(Equal(h.svidA.ID.String()))
	g.Expect(svid.Certificates[0].Raw).To(Equal(h.svidA.Certificates[0].Raw))

	// The stream waited out every refusal itself: one attestation means go-spiffe
	// never reopened it, and an empty log means it never saw it fail. A server
	// that answered Unavailable would pass the constructor on a retry and fail
	// both of these.
	g.Expect(calls.Load()).To(BeNumerically("==", notYetMinted+1))
	g.Expect(h.attestor.Calls()).To(Equal(1))
	g.Expect(log.failures()).To(BeEmpty())
}
