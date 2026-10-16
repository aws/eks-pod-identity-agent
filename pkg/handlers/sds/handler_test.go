package sds

import (
	"context"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	. "github.com/onsi/gomega"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/util/wait"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	pkgerrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/grpcserver"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity/fake"
)

const (
	testProviderArn      = "arn:aws:eks:us-west-2:111122223333:podidentityprovider/one"
	testOtherProviderArn = "arn:aws:eks:us-west-2:111122223333:podidentityprovider/two"
	testTrustDomain      = "example.org"
	testOtherTrustDomain = "other.example"
)

// The same two domains as go-spiffe values, which is what the bundle tier and the
// parsed resource names carry.
var (
	testTrustDomainID      = spiffeid.RequireTrustDomainFromString(testTrustDomain)
	testOtherTrustDomainID = spiffeid.RequireTrustDomainFromString(testOtherTrustDomain)
)

// bundleSet builds what the bundle tier serves from X509Bundles: one bundle per
// trust domain, each holding the given authority.
func bundleSet(t *testing.T, authorities map[string]testCertificate) *x509bundle.Set {
	t.Helper()

	set := x509bundle.NewSet()
	for domain, authority := range authorities {
		set.Add(testBundle(t, domain, authority))
	}
	return set
}

// settleFor is how long an assertion that nothing happens waits. Long enough that
// a send the handler was going to make would have arrived, short enough not to
// dominate the suite.
const settleFor = 250 * time.Millisecond

// harness is a Handler served over a real Unix socket with a real gRPC client in
// front of it, so the acknowledgement protocol is exercised over the wire rather
// than by calling methods directly. The client is the generated SDS stub, which
// is the same code an Envoy-side control plane library would use.
type harness struct {
	attestor *fake.Attestor
	certs    *fake.CertSource
	bundles  *fake.BundleSource
	subs     *fake.Subscriber

	// providers is the subscriber's resolver, which is where a provider ARN now
	// comes from and where the enrollment refusal originates. The handler no
	// longer reads a session, so this is the only thing that names a provider.
	providers *fake.ProviderArnResolver

	// handler is kept so a test can shorten the retry backoff before it opens a
	// stream. Each stream copies the handler's backoff when it starts, so a test
	// that writes it after opening one would not affect that stream.
	handler *Handler

	client secretv3.SecretDiscoveryServiceClient
}

// testBackoff paces the retries in tests. Short enough that a test waiting out
// one step does not dominate the suite, and still a real wait, so a retry loop
// that spun would show up as a flake rather than passing.
var testBackoff = wait.Backoff{
	Duration: 5 * time.Millisecond,
	Factor:   1,
	Steps:    1 << 30,
	Cap:      5 * time.Millisecond,
}

// newHarness serves a Handler over a socket in the test's temp dir, wired to
// fakes that answer a single enrolled workload by default.
func newHarness(t *testing.T) *harness {
	t.Helper()

	anchor := newTestCertificate(t, "authority")

	h := &harness{
		attestor:  &fake.Attestor{Result: testWorkload("pod-one")},
		certs:     &fake.CertSource{Result: []*x509svid.SVID{newTestSVID(t, "spiffe://example.org/workload")}},
		bundles:   &fake.BundleSource{},
		providers: &fake.ProviderArnResolver{Arn: testProviderArn},
	}
	h.subs = &fake.Subscriber{Providers: h.providers}

	h.bundles.SetTrustDomain(testTrustDomainID, nil)
	h.bundles.SetX509Bundles(bundleSet(t, map[string]testCertificate{testTrustDomain: anchor}), nil)

	h.handler = New(Opts{
		Attestor:                h.attestor,
		Certs:                   h.certs,
		Bundles:                 h.bundles,
		StreamSecretsSubscriber: h.subs,
	})
	h.handler.backoff = testBackoff

	h.client = serve(t, h.handler)

	return h
}

// serve starts the handler on a Unix socket and returns a client for it. Built
// with grpcserver.NewPeerCredentials and nothing else, since those credentials
// put the caller's pinned Peer on the context, the only route to attestation. The
// rest of the interceptor chain is grpcserver's own to test.
func serve(t *testing.T, handler *Handler) secretv3.SecretDiscoveryServiceClient {
	t.Helper()

	// EvalSymlinks because a Unix socket address is capped near 108 bytes and the
	// temp dir can be a symlink to a longer real path.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolving the temp dir: %v", err)
	}
	socketPath := filepath.Join(dir, "sds.sock")

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listening on %s: %v", socketPath, err)
	}

	server := grpc.NewServer(grpc.Creds(grpcserver.NewPeerCredentials()))
	handler.Register(server)

	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = server.Serve(lis)
	}()

	conn, err := grpc.NewClient("unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dialling %s: %v", socketPath, err)
	}

	t.Cleanup(func() {
		_ = conn.Close()
		server.Stop()
		<-served
	})

	return secretv3.NewSecretDiscoveryServiceClient(conn)
}

func testWorkload(podUID string) *workloadidentity.Workload {
	return &workloadidentity.Workload{
		PodUID:         podUID,
		PodName:        "web-" + podUID,
		Namespace:      "default",
		ServiceAccount: "web",
		NodeName:       "node-one",
	}
}

// testStream is an open StreamSecrets with its receive side drained onto a
// channel, so a test can assert that a response arrived or that none did.
type testStream struct {
	stream    secretv3.SecretDiscoveryService_StreamSecretsClient
	responses chan *discoveryv3.DiscoveryResponse
	errs      chan error
	cancel    context.CancelFunc
}

// open starts a stream and begins draining it.
func (h *harness) open(t *testing.T) *testStream {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	stream, err := h.client.StreamSecrets(ctx)
	if err != nil {
		cancel()
		t.Fatalf("opening StreamSecrets: %v", err)
	}

	ts := &testStream{
		stream:    stream,
		responses: make(chan *discoveryv3.DiscoveryResponse, 16),
		errs:      make(chan error, 1),
		cancel:    cancel,
	}

	go func() {
		for {
			response, err := stream.Recv()
			if err != nil {
				ts.errs <- err
				return
			}
			ts.responses <- response
		}
	}()

	t.Cleanup(cancel)

	return ts
}

// request sends one DiscoveryRequest naming names and echoing nonce.
func (ts *testStream) request(t *testing.T, names []string, nonce string) {
	t.Helper()

	err := ts.stream.Send(&discoveryv3.DiscoveryRequest{
		ResourceNames: names,
		TypeUrl:       SecretTypeURL,
		ResponseNonce: nonce,
	})

	// io.EOF means the handler has already ended the stream, which is what a
	// refusal taken before the first read looks like from here: the handler
	// attests and reads the session before it reads anything off the stream, so a
	// refused caller races this send. Swallowed rather than fatal, so the
	// assertion that follows reports the refusal's own status instead of this.
	if err != nil && err != io.EOF {
		t.Fatalf("sending a DiscoveryRequest: %v", err)
	}
}

// reject sends a request carrying an error detail, which is how Envoy reports
// that it refused a version.
func (ts *testStream) reject(t *testing.T, names []string, nonce, message string) {
	t.Helper()

	if err := ts.stream.Send(&discoveryv3.DiscoveryRequest{
		ResourceNames: names,
		TypeUrl:       SecretTypeURL,
		ResponseNonce: nonce,
		// The same google.rpc.Status Envoy puts on a rejection.
		ErrorDetail: status.New(codes.InvalidArgument, message).Proto(),
	}); err != nil {
		t.Fatalf("sending a rejection: %v", err)
	}
}

// nextResponse waits for one response.
func (ts *testStream) nextResponse(t *testing.T) *discoveryv3.DiscoveryResponse {
	t.Helper()

	select {
	case response := <-ts.responses:
		return response
	case err := <-ts.errs:
		t.Fatalf("expected a response, the stream ended: %v", err)
		return nil
	case <-time.After(5 * time.Second):
		t.Fatal("expected a response, nothing arrived")
		return nil
	}
}

// expectNoResponse asserts the handler stays quiet, which is what dedupe and the
// stale-nonce rule are for.
func (ts *testStream) expectNoResponse(t *testing.T) {
	t.Helper()

	select {
	case response := <-ts.responses:
		t.Fatalf("expected no response, got version %s for %v",
			response.GetVersionInfo(), resourceNamesOf(response))
	case err := <-ts.errs:
		t.Fatalf("expected no response, the stream ended: %v", err)
	case <-time.After(settleFor):
	}
}

// streamError waits for the stream to end and returns why.
func (ts *testStream) streamError(t *testing.T) error {
	t.Helper()

	select {
	case err := <-ts.errs:
		return err
	case response := <-ts.responses:
		t.Fatalf("expected the stream to end, got version %s", response.GetVersionInfo())
		return nil
	case <-time.After(5 * time.Second):
		t.Fatal("expected the stream to end, it stayed open")
		return nil
	}
}

// secretIn unpacks the single secret a response carries, asserting the
// one-resource-per-response shape Envoy's SdsApi requires.
func secretIn(t *testing.T, response *discoveryv3.DiscoveryResponse) *tlsv3.Secret {
	t.Helper()

	g := NewWithT(t)

	// Envoy's SdsApi reads only resources[0] and rejects an update that is not
	// exactly one resource, so this is the contract rather than a preference.
	g.Expect(response.GetResources()).To(HaveLen(1))
	g.Expect(response.GetTypeUrl()).To(Equal(SecretTypeURL))
	g.Expect(response.GetNonce()).ToNot(BeEmpty())

	packed := response.GetResources()[0]
	g.Expect(packed.GetTypeUrl()).To(Equal(SecretTypeURL))

	secret := &tlsv3.Secret{}
	g.Expect(packed.UnmarshalTo(secret)).To(Succeed())

	return secret
}

// resourceNamesOf names what a response carries, for failure messages.
func resourceNamesOf(response *discoveryv3.DiscoveryResponse) []string {
	names := make([]string, 0, len(response.GetResources()))
	for _, packed := range response.GetResources() {
		secret := &tlsv3.Secret{}
		if err := packed.UnmarshalTo(secret); err != nil {
			names = append(names, "<unparseable>")
			continue
		}
		names = append(names, secret.GetName())
	}
	return names
}

// TestStreamSecrets_ServesBothSecretKinds is the headline definition-of-done
// item: a client obtains a TlsCertificate and a CertificateValidationContext over
// the socket, one resource per response.
func TestStreamSecrets_ServesBothSecretKinds(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	ts := h.open(t)

	ts.request(t, []string{ResourceNameTLSCertificate, ResourceNameOwnValidationContext}, "")

	first := secretIn(t, ts.nextResponse(t))
	g.Expect(first.GetName()).To(Equal(ResourceNameTLSCertificate))
	g.Expect(first.GetTlsCertificate()).ToNot(BeNil())
	g.Expect(first.GetTlsCertificate().GetCertificateChain().GetInlineBytes()).ToNot(BeEmpty())
	g.Expect(first.GetTlsCertificate().GetPrivateKey().GetInlineBytes()).ToNot(BeEmpty())

	second := secretIn(t, ts.nextResponse(t))
	g.Expect(second.GetName()).To(Equal(ResourceNameOwnValidationContext))
	g.Expect(second.GetValidationContext()).ToNot(BeNil())
	g.Expect(second.GetValidationContext().GetTrustedCa().GetInlineBytes()).ToNot(BeEmpty())

	// Nothing further without a change.
	ts.expectNoResponse(t)
}

// TestStreamSecrets_ValidationContextOnly covers the one-way-TLS Envoy, which
// asks only for anchors and never holds a certificate. SPIRE serves this case
// with no identity gate at all; here the caller still needs a session, but it
// must not need a certificate.
func TestStreamSecrets_ValidationContextOnly(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	// No certificate is obtainable at all, to prove none is consulted.
	h.certs.SetResult(nil, pkgerrors.ErrIssuanceFailed)

	ts := h.open(t)
	ts.request(t, []string{ResourceNameOwnValidationContext}, "")

	secret := secretIn(t, ts.nextResponse(t))
	g.Expect(secret.GetName()).To(Equal(ResourceNameOwnValidationContext))
	g.Expect(secret.GetValidationContext()).ToNot(BeNil())

	g.Expect(h.certs.Calls()).To(BeZero(), "a validation context must not read the certificate source")
}

// TestStreamSecrets_NotEnrolledIsRefused pins the enrollment refusal on SPIRE's
// PermissionDenied, as the Workload API uses. It arrives from the subscription,
// which resolves the caller's provider, so this is the gate FetchX509SVID passes
// through too.
func TestStreamSecrets_NotEnrolledIsRefused(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	h.providers.Err = pkgerrors.ErrNotEnrolled

	ts := h.open(t)
	ts.request(t, []string{ResourceNameOwnValidationContext}, "")

	g.Expect(status.Code(ts.streamError(t))).To(Equal(codes.PermissionDenied))
}

// TestStreamSecrets_UnknownResourceNameIsNotFound pins that a name this agent
// will never serve ends the stream rather than leaving the sidecar waiting. SPIRE
// serves "ALL"; this agent does not, and that is the case most likely to arrive
// from a migrated configuration.
func TestStreamSecrets_UnknownResourceNameIsNotFound(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	ts := h.open(t)

	ts.request(t, []string{"ALL"}, "")

	err := ts.streamError(t)
	g.Expect(status.Code(err)).To(Equal(codes.NotFound))
	g.Expect(status.Convert(err).Message()).To(ContainSubstring("unknown resource name"))
}

// TestStreamSecrets_ColdStartBlocksThenServes pins the window before any bundle
// has been fetched: the tier reports a zero own trust domain and a lease does not
// wait for a fetch, so the stream holds the request open rather than making Envoy
// come back. The refusal underneath is ErrBundleUnavailable, which is what makes
// it retryable; a status built in the handler would read as permanent.
func TestStreamSecrets_ColdStartBlocksThenServes(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	h.bundles.SetTrustDomain(spiffeid.TrustDomain{}, nil)

	ts := h.open(t)
	ts.request(t, []string{ResourceNameOwnValidationContext}, "")

	// Nothing is served and, crucially, nothing is refused: no Unavailable
	// reaches Envoy for a condition the agent is about to resolve itself.
	ts.expectNoResponse(t)

	// The first fetch lands, which is what the lease started.
	h.bundles.SetTrustDomain(testTrustDomainID, nil)

	served := secretIn(t, ts.nextResponse(t))
	g.Expect(served.GetName()).To(Equal(ResourceNameOwnValidationContext))
	g.Expect(served.GetValidationContext()).ToNot(BeNil())
}

// TestStreamSecrets_NamedTrustDomain covers the spiffe://<trust-domain> form,
// which is how SPIRE's existing consumers name anchors explicitly.
func TestStreamSecrets_NamedTrustDomain(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	ts := h.open(t)

	name := TrustDomainPrefix + testTrustDomain
	ts.request(t, []string{name}, "")

	secret := secretIn(t, ts.nextResponse(t))
	g.Expect(secret.GetName()).To(Equal(name))
	g.Expect(secret.GetValidationContext()).ToNot(BeNil())
}

// TestStreamSecrets_UnfederatedTrustDomainIsNotFound pins that a domain the
// provider has no anchors for is NotFound rather than Unavailable: no retry
// produces a federation that does not exist.
func TestStreamSecrets_UnfederatedTrustDomainIsNotFound(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	ts := h.open(t)

	ts.request(t, []string{TrustDomainPrefix + "nobody.example"}, "")

	err := ts.streamError(t)
	g.Expect(status.Code(err)).To(Equal(codes.NotFound))
	g.Expect(status.Convert(err).Message()).To(ContainSubstring("no trust anchors"))
}

// TestStreamSecrets_CertificateRenewalIsPushed is the push-on-rotation item. The
// version increments and the validation context is not re-sent, because it did
// not change.
func TestStreamSecrets_CertificateRenewalIsPushed(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	ts := h.open(t)

	ts.request(t, []string{ResourceNameTLSCertificate, ResourceNameOwnValidationContext}, "")

	certResponse := ts.nextResponse(t)
	g.Expect(secretIn(t, certResponse).GetName()).To(Equal(ResourceNameTLSCertificate))
	contextResponse := ts.nextResponse(t)
	g.Expect(secretIn(t, contextResponse).GetName()).To(Equal(ResourceNameOwnValidationContext))

	// A renewal in the certificate tier, then the notification that tier would
	// publish.
	h.certs.SetResult([]*x509svid.SVID{newTestSVID(t, "spiffe://example.org/workload")}, nil)
	g.Eventually(func() int {
		return h.subs.NotifyWorkload("pod-one")
	}).Should(Equal(1))

	renewed := ts.nextResponse(t)
	g.Expect(secretIn(t, renewed).GetName()).To(Equal(ResourceNameTLSCertificate))
	g.Expect(renewed.GetVersionInfo()).ToNot(Equal(certResponse.GetVersionInfo()))
	g.Expect(renewed.GetNonce()).ToNot(Equal(certResponse.GetNonce()))

	// The anchors did not change, so the dedupe keeps them off the stream.
	ts.expectNoResponse(t)
}

// TestStreamSecrets_CertificateAddedMidStreamIsThenPushed is the second half of
// the push item: a resource Envoy adds to an already-open stream is served, and
// its later renewals reach the stream. This is why the handler subscribes to
// workload material even on a stream that opened asking only for anchors.
func TestStreamSecrets_CertificateAddedMidStreamIsThenPushed(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	ts := h.open(t)

	// Opens asking only for anchors.
	ts.request(t, []string{ResourceNameOwnValidationContext}, "")
	contextResponse := ts.nextResponse(t)
	g.Expect(secretIn(t, contextResponse).GetName()).To(Equal(ResourceNameOwnValidationContext))

	// Envoy adds the certificate to the same stream, acknowledging what it has.
	ts.request(t, []string{ResourceNameOwnValidationContext, ResourceNameTLSCertificate}, contextResponse.GetNonce())

	added := ts.nextResponse(t)
	g.Expect(secretIn(t, added).GetName()).To(Equal(ResourceNameTLSCertificate),
		"the anchors were unchanged, so only the newly named resource should be sent")

	// And that certificate's renewals now reach this stream.
	h.certs.SetResult([]*x509svid.SVID{newTestSVID(t, "spiffe://example.org/workload")}, nil)
	g.Eventually(func() int {
		return h.subs.NotifyWorkload("pod-one")
	}).Should(Equal(1))

	renewed := ts.nextResponse(t)
	g.Expect(secretIn(t, renewed).GetName()).To(Equal(ResourceNameTLSCertificate))
	g.Expect(renewed.GetVersionInfo()).ToNot(Equal(added.GetVersionInfo()))
}

// TestStreamSecrets_StaleNonceIsIgnored pins the acknowledgement rule. A late
// acknowledgement must not be read as a new subscription, or every ack would
// re-send everything.
func TestStreamSecrets_StaleNonceIsIgnored(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	ts := h.open(t)

	names := []string{ResourceNameTLSCertificate, ResourceNameOwnValidationContext}
	ts.request(t, names, "")

	first := ts.nextResponse(t)
	second := ts.nextResponse(t)
	g.Expect(second.GetNonce()).ToNot(Equal(first.GetNonce()))

	// Acknowledging the first response after the second has been sent: stale,
	// and the named set is unchanged, so there is nothing to do.
	ts.request(t, names, first.GetNonce())
	ts.expectNoResponse(t)

	// And no second subscription was taken out.
	g.Expect(h.subs.SubscribeCalls()).To(Equal(1))
	g.Expect(h.subs.LiveSubscriptions()).To(Equal(1))
}

// TestStreamSecrets_StaleNonceStillHonoursAnInterestChange is the other side of
// that rule, and the reason it is scoped to an unchanged named set. One resource
// per response means more than one response can be in flight, so an interest
// change can legitimately carry an older nonce. Dropping it would leave a
// resource Envoy asked for unserved forever.
func TestStreamSecrets_StaleNonceStillHonoursAnInterestChange(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	ts := h.open(t)

	ts.request(t, []string{ResourceNameTLSCertificate, ResourceNameOwnValidationContext}, "")
	first := ts.nextResponse(t)
	_ = ts.nextResponse(t)

	// Adds a resource while echoing the older of the two nonces.
	ts.request(t, []string{
		ResourceNameTLSCertificate,
		ResourceNameOwnValidationContext,
		TrustDomainPrefix + testTrustDomain,
	}, first.GetNonce())

	added := secretIn(t, ts.nextResponse(t))
	g.Expect(added.GetName()).To(Equal(TrustDomainPrefix + testTrustDomain))
}

// TestStreamSecrets_RejectionIsLoggedAndTheStreamContinues pins that a NACK does
// not end the stream and does not roll anything back. Rolling back would re-send
// material Envoy just refused.
func TestStreamSecrets_RejectionIsLoggedAndTheStreamContinues(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	ts := h.open(t)

	ts.request(t, []string{ResourceNameOwnValidationContext}, "")
	served := ts.nextResponse(t)

	ts.reject(t, []string{ResourceNameOwnValidationContext}, served.GetNonce(), "it did not like the anchors")

	// Nothing is re-sent in response to the rejection itself.
	ts.expectNoResponse(t)

	// And the stream still serves: a bundle change reaches it.
	anchor := newTestCertificate(t, "rolled-authority")
	h.bundles.SetX509Bundles(bundleSet(t, map[string]testCertificate{testTrustDomain: anchor}), nil)
	g.Eventually(func() int {
		return h.subs.NotifyCertBundles(testProviderArn)
	}).Should(Equal(1))

	rolled := secretIn(t, ts.nextResponse(t))
	g.Expect(rolled.GetName()).To(Equal(ResourceNameOwnValidationContext))
}

// TestStreamSecrets_LeaseIsHeldForExactlyTheStreamsLife pins the lease lifecycle.
// Without it the bundle tier would evict a provider whose only reader is parked
// on a signal, and the stream would miss the next rotation.
func TestStreamSecrets_LeaseIsHeldForExactlyTheStreamsLife(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)

	g.Expect(h.bundles.LiveLeases()).To(BeZero())

	ts := h.open(t)
	ts.request(t, []string{ResourceNameOwnValidationContext}, "")
	_ = ts.nextResponse(t)

	g.Expect(h.bundles.LiveLeases()).To(Equal(1))
	g.Expect(h.bundles.Released()).To(BeZero())

	// An abrupt client disconnect, which is how a sidecar going away with its
	// pod arrives.
	ts.cancel()

	g.Eventually(h.bundles.Released).Should(Equal(1))
	g.Eventually(h.bundles.LiveLeases).Should(BeZero())
	g.Eventually(h.subs.LiveSubscriptions).Should(BeZero())
}

// TestStreamSecrets_LeaseAndReadsUseTheCallersOwnWorkload pins that the provider
// is never a parameter the caller supplies. Every BundleSource method takes the
// attested workload, and the tier resolves the provider from it, so two callers
// cannot be served each other's anchors.
func TestStreamSecrets_LeaseAndReadsUseTheCallersOwnWorkload(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	ts := h.open(t)

	ts.request(t, []string{ResourceNameOwnValidationContext}, "")
	_ = ts.nextResponse(t)

	g.Expect(h.bundles.LeaseCalls()).To(Equal(1))

	requested := h.bundles.WorkloadRequests()
	g.Expect(requested).ToNot(BeEmpty())
	for _, w := range requested {
		g.Expect(w.PodUID).To(Equal("pod-one"))
	}
}

// TestStreamSecrets_BundleChangeWakesOnlyTheChangedProvider is the routing item.
// Two callers whose providers differ open streams; a rotation in one provider
// reaches only its own stream, and the other keeps its version.
func TestStreamSecrets_BundleChangeWakesOnlyTheChangedProvider(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)

	// Two callers, distinguished by attestation order, each with its own
	// provider. The named trust domain form is used rather than ROOTCA because
	// the fake bundle source has one own-trust-domain for all callers.
	var mu sync.Mutex
	attested := 0
	h.attestor.Func = func(context.Context, workloadidentity.Peer) (*workloadidentity.Workload, error) {
		mu.Lock()
		defer mu.Unlock()
		attested++
		return testWorkload(fmt.Sprintf("pod-%d", attested)), nil
	}
	// pod-1's provider is named explicitly and every other pod falls to Arn, which
	// is the fake resolver's stand-in for "the rest".
	h.providers.Arns = map[string]string{"pod-1": testProviderArn}
	h.providers.Arn = testOtherProviderArn

	anchor := newTestCertificate(t, "authority")
	otherAnchor := newTestCertificate(t, "other-authority")
	h.bundles.SetX509Bundles(bundleSet(t, map[string]testCertificate{
		testTrustDomain:      anchor,
		testOtherTrustDomain: otherAnchor,
	}), nil)

	first := h.open(t)
	first.request(t, []string{TrustDomainPrefix + testTrustDomain}, "")
	firstServed := first.nextResponse(t)

	second := h.open(t)
	second.request(t, []string{TrustDomainPrefix + testOtherTrustDomain}, "")
	secondServed := second.nextResponse(t)

	// Both subscriptions name their own caller's provider.
	g.Eventually(func() []string {
		var arns []string
		for _, sub := range h.subs.Subscriptions() {
			arns = append(arns, sub.ProviderArn)
		}
		return arns
	}).Should(ConsistOf(testProviderArn, testOtherProviderArn))

	// The first provider's authorities roll.
	rolled := newTestCertificate(t, "rolled-authority")
	h.bundles.SetX509Bundles(bundleSet(t, map[string]testCertificate{
		testTrustDomain:      rolled,
		testOtherTrustDomain: otherAnchor,
	}), nil)
	g.Expect(h.subs.NotifyCertBundles(testProviderArn)).To(Equal(1),
		"only the changed provider's subscription should be signalled")

	pushed := first.nextResponse(t)
	g.Expect(secretIn(t, pushed).GetName()).To(Equal(TrustDomainPrefix + testTrustDomain))
	g.Expect(pushed.GetVersionInfo()).ToNot(Equal(firstServed.GetVersionInfo()))

	// The other provider's stream sends nothing and keeps its version.
	second.expectNoResponse(t)
	g.Expect(secondServed.GetVersionInfo()).To(Equal("1"))
}

// TestStreamSecrets_JWTBundlesAreNeverSubscribed pins that a JWT key roll does
// not wake an SDS stream. Envoy never consumes JWT authorities, so waking for one
// would be pure cost on every stream on the node.
func TestStreamSecrets_JWTBundlesAreNeverSubscribed(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	ts := h.open(t)

	ts.request(t, []string{ResourceNameTLSCertificate, ResourceNameOwnValidationContext}, "")
	_ = ts.nextResponse(t)
	_ = ts.nextResponse(t)

	for _, sub := range h.subs.Subscriptions() {
		g.Expect(sub.Kind).To(Equal(fake.KindWorkloadMaterial))
	}

	// A JWT key roll reaches nobody here.
	g.Expect(h.subs.NotifyJWTBundles(testProviderArn)).To(BeZero())
	ts.expectNoResponse(t)
}

// TestStreamSecrets_SpuriousSignalSendsNothing pins the dedupe against the
// notification tier's own contract: its signals may be spurious, and it leaves
// dedupe to its handlers.
func TestStreamSecrets_SpuriousSignalSendsNothing(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	ts := h.open(t)

	ts.request(t, []string{ResourceNameTLSCertificate, ResourceNameOwnValidationContext}, "")
	_ = ts.nextResponse(t)
	_ = ts.nextResponse(t)

	// Nothing changed in either tier.
	g.Eventually(func() int {
		return h.subs.NotifyWorkload("pod-one")
	}).Should(Equal(1))

	ts.expectNoResponse(t)
}

// TestStreamSecrets_TeardownLeavesNoGoroutine pins that the receive goroutine the
// handler starts per stream ends with the stream. Envoy sidecars come and go with
// pods, so this path runs constantly and a leak here would accumulate for the
// life of the agent.
func TestStreamSecrets_TeardownLeavesNoGoroutine(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)

	// One cycle first, so the client's own connection machinery is already up and
	// is not counted as growth.
	warmup := h.open(t)
	warmup.request(t, []string{ResourceNameOwnValidationContext}, "")
	_ = warmup.nextResponse(t)
	warmup.cancel()
	g.Eventually(h.subs.LiveSubscriptions).Should(BeZero())

	before := runtime.NumGoroutine()

	for range 20 {
		ts := h.open(t)
		ts.request(t, []string{ResourceNameTLSCertificate, ResourceNameOwnValidationContext}, "")
		_ = ts.nextResponse(t)
		_ = ts.nextResponse(t)
		ts.cancel()
	}

	g.Eventually(h.subs.LiveSubscriptions, 5*time.Second).Should(BeZero())
	g.Eventually(h.bundles.LiveLeases, 5*time.Second).Should(BeZero())

	// A small allowance for gRPC's own transient goroutines, well under the 40
	// that twenty leaked streams would leave.
	g.Eventually(runtime.NumGoroutine, 5*time.Second).Should(BeNumerically("<=", before+5))
}

// TestStreamSecrets_DuplicateResourceNamesAreServedOnce pins that a request
// naming the same resource twice produces one response, not two nonces for one
// subscription.
func TestStreamSecrets_DuplicateResourceNamesAreServedOnce(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	ts := h.open(t)

	ts.request(t, []string{ResourceNameOwnValidationContext, ResourceNameOwnValidationContext}, "")

	served := secretIn(t, ts.nextResponse(t))
	g.Expect(served.GetName()).To(Equal(ResourceNameOwnValidationContext))

	ts.expectNoResponse(t)
}

// TestStreamSecrets_SignalBeforeTheFirstRequestReadsNothing pins that the primed
// signal the subscription arrives with does not cause a read. Envoy has named
// nothing yet, so there is nothing to re-read, and the first request is answered
// from a fresh read of what it names.
func TestStreamSecrets_SignalBeforeTheFirstRequestReadsNothing(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	ts := h.open(t)

	// Wait for the subscription to exist, then signal before any request.
	g.Eventually(h.subs.LiveSubscriptions).Should(Equal(1))
	g.Eventually(func() int {
		return h.subs.NotifyWorkload("pod-one")
	}).Should(Equal(1))

	ts.expectNoResponse(t)
	g.Expect(h.certs.Calls()).To(BeZero())

	// And the first request is still answered normally.
	ts.request(t, []string{ResourceNameTLSCertificate}, "")
	g.Expect(secretIn(t, ts.nextResponse(t)).GetName()).To(Equal(ResourceNameTLSCertificate))
}

// secretsIn unpacks every secret a unary response carries, keyed by name.
//
// Deliberately not secretIn: the one-resource-per-response shape that helper
// asserts is Envoy's SdsApi constraint on the stream, and a unary fetch answers
// the whole named set in one response.
func secretsIn(t *testing.T, response *discoveryv3.DiscoveryResponse) map[string]*tlsv3.Secret {
	t.Helper()

	g := NewWithT(t)

	g.Expect(response.GetTypeUrl()).To(Equal(SecretTypeURL))

	secrets := make(map[string]*tlsv3.Secret, len(response.GetResources()))
	for _, packed := range response.GetResources() {
		g.Expect(packed.GetTypeUrl()).To(Equal(SecretTypeURL))

		secret := &tlsv3.Secret{}
		g.Expect(packed.UnmarshalTo(secret)).To(Succeed())
		secrets[secret.GetName()] = secret
	}

	g.Expect(secrets).To(HaveLen(len(response.GetResources())), "a name was served twice")

	return secrets
}

// TestFetchSecrets_ServesBothSecretKindsInOneResponse is the unary counterpart of
// TestStreamSecrets_ServesBothSecretKinds. The shape is the difference that
// matters: one response carrying the whole named set, because there is no
// singleton watch on the other end to read only the first resource.
func TestFetchSecrets_ServesBothSecretKindsInOneResponse(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)

	response, err := h.client.FetchSecrets(context.Background(), &discoveryv3.DiscoveryRequest{
		TypeUrl:       SecretTypeURL,
		ResourceNames: []string{ResourceNameTLSCertificate, ResourceNameOwnValidationContext},
	})
	g.Expect(err).ToNot(HaveOccurred())

	secrets := secretsIn(t, response)
	g.Expect(secrets).To(HaveLen(2))

	certificate := secrets[ResourceNameTLSCertificate]
	g.Expect(certificate.GetTlsCertificate().GetCertificateChain().GetInlineBytes()).ToNot(BeEmpty())
	g.Expect(certificate.GetTlsCertificate().GetPrivateKey().GetInlineBytes()).ToNot(BeEmpty())

	validation := secrets[ResourceNameOwnValidationContext]
	g.Expect(validation.GetValidationContext().GetTrustedCa().GetInlineBytes()).ToNot(BeEmpty())

	// Neither belongs to an acknowledgement protocol that exists here, and a
	// nonce echoed onto a stream later would be one that stream never issued.
	g.Expect(response.GetVersionInfo()).To(BeEmpty())
	g.Expect(response.GetNonce()).To(BeEmpty())
}

// TestFetchSecrets_NamingNothingServesTheWildcardSet pins the xDS rule that an
// empty resource list means everything, as SPIRE applies on this method, with an
// empty string dropped before the count. The stream does not share the rule: its
// first request routinely names nothing, and answering that with a private key
// the sidecar never asked for would be wrong.
func TestFetchSecrets_NamingNothingServesTheWildcardSet(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)

	for _, names := range [][]string{nil, {""}} {
		response, err := h.client.FetchSecrets(context.Background(), &discoveryv3.DiscoveryRequest{
			TypeUrl:       SecretTypeURL,
			ResourceNames: names,
		})
		g.Expect(err).ToNot(HaveOccurred())

		secrets := secretsIn(t, response)
		g.Expect(secrets).To(HaveKey(ResourceNameTLSCertificate))
		g.Expect(secrets).To(HaveKey(ResourceNameOwnValidationContext))

		// Not the spiffe://<own domain> form as well: it would repeat ROOTCA's
		// bytes under a second name.
		g.Expect(secrets).To(HaveLen(2))
	}
}

// TestFetchSecrets_NamedTrustDomain covers the spiffe://<trust-domain> form on the
// unary method. The resolution is shared with the stream, which has its own test
// for it, but nothing exercised it here and the unary path reaches it through a
// different entry point.
func TestFetchSecrets_NamedTrustDomain(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	name := TrustDomainPrefix + testTrustDomain

	response, err := h.client.FetchSecrets(context.Background(), &discoveryv3.DiscoveryRequest{
		TypeUrl:       SecretTypeURL,
		ResourceNames: []string{name},
	})
	g.Expect(err).ToNot(HaveOccurred())

	secrets := secretsIn(t, response)
	g.Expect(secrets).To(HaveLen(1))
	g.Expect(secrets[name].GetValidationContext().GetTrustedCa().GetInlineBytes()).ToNot(BeEmpty())

	// The certificate source is never consulted for a validation context, the
	// same as on the stream.
	g.Expect(h.certs.Calls()).To(BeZero())
}

// TestFetchSecrets_UnfederatedTrustDomainIsNotFound pairs with it: a domain the
// provider has no anchors for is NotFound on this method too. Worth pinning
// because federation is out of scope at launch, so the only trust domain in the
// set is the caller's own and every other name a customer writes lands here.
func TestFetchSecrets_UnfederatedTrustDomainIsNotFound(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)

	_, err := h.client.FetchSecrets(context.Background(), &discoveryv3.DiscoveryRequest{
		TypeUrl:       SecretTypeURL,
		ResourceNames: []string{TrustDomainPrefix + "nobody.example"},
	})

	g.Expect(status.Code(err)).To(Equal(codes.NotFound))
	g.Expect(status.Convert(err).Message()).To(ContainSubstring("no trust anchors"))
}

// TestFetchSecrets_UnknownResourceNameIsNotFound pins that the two methods answer
// one bad name with one code. SPIRE answers InvalidArgument here; matching its
// own stream matters more, since a caller cannot be asked to branch on which
// method it used.
func TestFetchSecrets_UnknownResourceNameIsNotFound(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)

	_, err := h.client.FetchSecrets(context.Background(), &discoveryv3.DiscoveryRequest{
		TypeUrl:       SecretTypeURL,
		ResourceNames: []string{"ALL"},
	})

	g.Expect(status.Code(err)).To(Equal(codes.NotFound))
	g.Expect(status.Convert(err).Message()).To(ContainSubstring("unknown resource name"))
}

// TestFetchSecrets_NotEnrolledIsRefused pins that the unary method is not a way
// around enrollment. It takes no subscription, so the refusal has to come from
// the lease, which is the other place the caller's provider gets resolved.
func TestFetchSecrets_NotEnrolledIsRefused(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	h.bundles.SetLease(pkgerrors.ErrNotEnrolled)

	_, err := h.client.FetchSecrets(context.Background(), &discoveryv3.DiscoveryRequest{
		TypeUrl:       SecretTypeURL,
		ResourceNames: []string{ResourceNameOwnValidationContext},
	})

	g.Expect(status.Code(err)).To(Equal(codes.PermissionDenied))
}

// TestFetchSecrets_LeasesWithoutSubscribing pins the two halves of the one-shot
// contract. The lease is taken, because a cold provider has to start being
// fetched for a retry to ever answer, and released before the call returns rather
// than left for the context. Nothing is subscribed: there is no stream to wake, so
// a subscription here would be a leak that the notification tier would then fan
// out to.
func TestFetchSecrets_LeasesWithoutSubscribing(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)

	_, err := h.client.FetchSecrets(context.Background(), &discoveryv3.DiscoveryRequest{
		TypeUrl:       SecretTypeURL,
		ResourceNames: []string{ResourceNameOwnValidationContext},
	})
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(h.bundles.LeaseCalls()).To(Equal(1))
	g.Expect(h.bundles.ReleaseCalls()).To(Equal(1), "the lease must be released by the handler, not left to the RPC's context")
	g.Expect(h.bundles.LiveLeases()).To(BeZero())
	g.Expect(h.subs.SubscribeCalls()).To(BeZero())
}

// TestFetchSecrets_WithoutConnCredentialsIsRefused is the unary half of the
// wiring guard: gRPC serves an RPC with a nil AuthInfo quite happily, so a server
// built without the conn-carrying credentials would otherwise answer a caller it
// cannot attest.
func TestFetchSecrets_WithoutConnCredentialsIsRefused(t *testing.T) {
	g := NewWithT(t)

	client := serveWithoutConnCredentials(t)

	_, err := client.FetchSecrets(context.Background(), &discoveryv3.DiscoveryRequest{
		TypeUrl:       SecretTypeURL,
		ResourceNames: []string{ResourceNameTLSCertificate},
	})

	g.Expect(status.Code(err)).To(Equal(codes.PermissionDenied))
}

// TestDeltaSecrets_IsUnimplementedAndNamesTheFix is the one that matters
// operationally: DELTA_GRPC is valid Envoy configuration, so a sidecar set that
// way would otherwise sit without a certificate and nothing would say why.
func TestDeltaSecrets_IsUnimplementedAndNamesTheFix(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)

	stream, err := h.client.DeltaSecrets(context.Background())
	g.Expect(err).ToNot(HaveOccurred())

	// The send is expected to race the refusal: the handler returns before
	// reading anything, so this is EOF as often as it is nil. Either way the
	// status arrives on the receive.
	_ = stream.Send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: SecretTypeURL})

	_, err = stream.Recv()

	g.Expect(status.Code(err)).To(Equal(codes.Unimplemented))
	g.Expect(status.Convert(err).Message()).To(ContainSubstring("DELTA_GRPC"))
	g.Expect(status.Convert(err).Message()).To(ContainSubstring("GRPC"))
}

// TestStreamSecrets_WithoutConnCredentialsIsRefused pins the wiring guard. gRPC
// permits a nil AuthInfo and serves the RPC anyway, so a server built without the
// conn-carrying credentials has no caller information and nothing else would
// notice.
func TestStreamSecrets_WithoutConnCredentialsIsRefused(t *testing.T) {
	g := NewWithT(t)

	client := serveWithoutConnCredentials(t)

	stream, err := client.StreamSecrets(context.Background())
	g.Expect(err).ToNot(HaveOccurred())

	// Races the refusal, which is taken before the handler reads anything.
	_ = stream.Send(&discoveryv3.DiscoveryRequest{ResourceNames: []string{ResourceNameTLSCertificate}})

	_, err = stream.Recv()
	g.Expect(status.Code(err)).To(Equal(codes.PermissionDenied))
}

// serveWithoutConnCredentials serves a fully wired Handler on a server built with
// no grpc.Creds at all, which is the one wiring mistake that leaves a handler
// with no caller to attest. Shared by both methods' guards: the refusal has to
// hold on each of them independently, since each reads the conn for itself.
func serveWithoutConnCredentials(t *testing.T) secretv3.SecretDiscoveryServiceClient {
	t.Helper()

	g := NewWithT(t)

	anchor := newTestCertificate(t, "authority")
	bundles := &fake.BundleSource{}
	bundles.SetTrustDomain(testTrustDomainID, nil)
	bundles.SetX509Bundles(bundleSet(t, map[string]testCertificate{testTrustDomain: anchor}), nil)

	handler := New(Opts{
		Attestor:                &fake.Attestor{Result: testWorkload("pod-one")},
		Certs:                   &fake.CertSource{},
		Bundles:                 bundles,
		StreamSecretsSubscriber: &fake.Subscriber{Providers: &fake.ProviderArnResolver{Arn: testProviderArn}},
	})

	dir, err := filepath.EvalSymlinks(t.TempDir())
	g.Expect(err).ToNot(HaveOccurred())
	socketPath := filepath.Join(dir, "sds.sock")

	lis, err := net.Listen("unix", socketPath)
	g.Expect(err).ToNot(HaveOccurred())

	// Deliberately no grpc.Creds.
	server := grpc.NewServer()
	handler.Register(server)
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient("unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	g.Expect(err).ToNot(HaveOccurred())
	t.Cleanup(func() { _ = conn.Close() })

	return secretv3.NewSecretDiscoveryServiceClient(conn)
}

// TestStreamSecrets_RetriesARetryableTierFailure is the decision in one test: a
// transient tier failure is waited out inside the agent, not handed to Envoy. The
// agent knows the failure is transient, and all Envoy would learn is that its
// stream broke.
func TestStreamSecrets_RetriesARetryableTierFailure(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)

	// Fails the first two reads, then succeeds, as an STS blip would.
	svid := newTestSVID(t, "spiffe://example.org/workload")
	var mu sync.Mutex
	attempts := 0
	h.certs.Func = func(context.Context, *workloadidentity.Workload) ([]*x509svid.SVID, error) {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts <= 2 {
			return nil, pkgerrors.ErrIssuanceFailed
		}
		return []*x509svid.SVID{svid}, nil
	}

	ts := h.open(t)
	ts.request(t, []string{ResourceNameTLSCertificate}, "")

	// The stream stays open across the failures and then answers.
	served := secretIn(t, ts.nextResponse(t))
	g.Expect(served.GetName()).To(Equal(ResourceNameTLSCertificate))
	g.Expect(served.GetTlsCertificate()).ToNot(BeNil())

	mu.Lock()
	defer mu.Unlock()
	g.Expect(attempts).To(BeNumerically(">=", 3), "the read should have been retried, not abandoned")
}

// TestStreamSecrets_ThrottledIssuanceIsRetriedNotReturned covers the throttling
// case specifically, because it is the one the taxonomy keeps apart from a plain
// failure. Retried here rather than returned as ResourceExhausted, which is the
// cost of the agent-retries-first decision and is recorded as such.
func TestStreamSecrets_ThrottledIssuanceIsRetriedNotReturned(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)

	svid := newTestSVID(t, "spiffe://example.org/workload")
	var mu sync.Mutex
	throttled := true
	h.certs.Func = func(context.Context, *workloadidentity.Workload) ([]*x509svid.SVID, error) {
		mu.Lock()
		defer mu.Unlock()
		if throttled {
			throttled = false
			return nil, pkgerrors.ErrIssuanceThrottled
		}
		return []*x509svid.SVID{svid}, nil
	}

	ts := h.open(t)
	ts.request(t, []string{ResourceNameTLSCertificate}, "")

	g.Expect(secretIn(t, ts.nextResponse(t)).GetName()).To(Equal(ResourceNameTLSCertificate))
}

// TestStreamSecrets_NonRetryableTierFailureEndsTheStream is the other half: a
// failure no retry can fix is handed to Envoy immediately, which is what leaves
// it free to reconnect or to surface the condition. Blocking on one of these
// would be a stream that never answers and never says why.
func TestStreamSecrets_NonRetryableTierFailureEndsTheStream(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	h.certs.SetResult(nil, pkgerrors.ErrSessionRefused)

	ts := h.open(t)
	ts.request(t, []string{ResourceNameTLSCertificate}, "")

	err := ts.streamError(t)
	g.Expect(status.Code(err)).To(Equal(codes.PermissionDenied))
}

// TestStreamSecrets_RetryEndsWhenTheClientLeaves pins the bound on a retry loop
// that never succeeds. The retry is unbounded by design, as workloadapi's is, so
// the only thing that stops it is the workload going away, and it has to stop
// cleanly: the lease and the subscription both have to come back.
func TestStreamSecrets_RetryEndsWhenTheClientLeaves(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	// Never comes good.
	h.certs.SetResult(nil, pkgerrors.ErrIssuanceFailed)

	ts := h.open(t)
	ts.request(t, []string{ResourceNameTLSCertificate}, "")

	// Retrying, so nothing is served and nothing is refused.
	ts.expectNoResponse(t)
	g.Expect(h.bundles.LiveLeases()).To(Equal(1))

	ts.cancel()

	g.Eventually(h.bundles.Released).Should(Equal(1))
	g.Eventually(h.subs.LiveSubscriptions).Should(BeZero())
}

// TestStreamSecrets_RetryIsCutShortByASignal pins that a stream parked between
// retries does not sit out its backoff when there is news. A rotation published
// while it waits should be picked up at once, since the wait had nothing left to
// wait for.
func TestStreamSecrets_RetryIsCutShortByASignal(t *testing.T) {
	g := NewWithT(t)

	h := newHarness(t)
	// A long backoff, so a test that passes can only have been woken by the
	// signal rather than by the timer.
	h.handler.backoff = wait.Backoff{Duration: time.Hour, Factor: 1, Steps: 1 << 30, Cap: time.Hour}

	svid := newTestSVID(t, "spiffe://example.org/workload")
	var mu sync.Mutex
	failing := true
	h.certs.Func = func(context.Context, *workloadidentity.Workload) ([]*x509svid.SVID, error) {
		mu.Lock()
		defer mu.Unlock()
		if failing {
			return nil, pkgerrors.ErrIssuanceFailed
		}
		return []*x509svid.SVID{svid}, nil
	}

	ts := h.open(t)
	ts.request(t, []string{ResourceNameTLSCertificate}, "")
	ts.expectNoResponse(t)

	// The tier comes good and says so, while the stream is parked on an hour.
	mu.Lock()
	failing = false
	mu.Unlock()
	g.Eventually(func() int {
		return h.subs.NotifyWorkload("pod-one")
	}).Should(Equal(1))

	g.Expect(secretIn(t, ts.nextResponse(t)).GetName()).To(Equal(ResourceNameTLSCertificate))
}
