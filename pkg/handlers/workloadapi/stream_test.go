package workloadapi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/util/wait"

	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity/fake"
)

// These tests drive the three streams through the raw generated client, so what
// they observe is exactly what reaches a SPIFFE library on the socket.

const (
	// streamWait bounds every wait for a response or a stream's end.
	streamWait = 5 * time.Second
	// streamQuietWindow is how long a test watches for a response that must not
	// come.
	streamQuietWindow = 200 * time.Millisecond
	// streamTDID is the default provider's trust domain as the wire keys it.
	streamTDID = "spiffe://" + testTrustDomain
	// streamFedID is the federated trust domain as the wire keys it.
	streamFedID = "spiffe://" + federatedTrustDomain
	// streamSPIFFEIDA is the SPIFFE ID the harness issues podA's SVIDs for.
	streamSPIFFEIDA = "spiffe://" + testTrustDomain + "/ns/ns/sa/sa-a"
)

// streamHourBackoff keeps a blocked stream waiting for an hour between retries,
// so only a signal or the end of the stream can end the wait inside a test.
var streamHourBackoff = wait.Backoff{Duration: time.Hour, Factor: 1, Steps: 1 << 30, Cap: time.Hour}

// streamTap reads one client stream on its own goroutine, so a test can wait for
// the next response with a timeout and assert that nothing more arrives.
type streamTap struct {
	msgs chan proto.Message
	// end holds the error Recv ended the stream with.
	end chan error
	// done is closed when the reading goroutine has returned.
	done   chan struct{}
	cancel context.CancelFunc
}

// streamPump starts reading recv until it fails. The stream is cancelled and its
// reader waited for when the test ends, so no tap outlives its test.
func streamPump(t *testing.T, ctx context.Context, cancel context.CancelFunc, recv func() (proto.Message, error)) *streamTap {
	tap := &streamTap{msgs: make(chan proto.Message, 64), end: make(chan error, 1), done: make(chan struct{}), cancel: cancel}
	go func() {
		defer close(tap.done)
		for {
			msg, err := recv()
			if err != nil {
				tap.end <- err
				return
			}
			select {
			case tap.msgs <- msg:
			case <-ctx.Done():
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-tap.done
	})
	return tap
}

// next returns the stream's next response, failing the test if the stream ends
// first or nothing arrives within streamWait.
func (tap *streamTap) next(t *testing.T) proto.Message {
	t.Helper()
	select {
	case msg := <-tap.msgs:
		return msg
	case err := <-tap.end:
		tap.end <- err
		// A response sent before the end is still the next one.
		select {
		case msg := <-tap.msgs:
			return msg
		default:
		}
		t.Fatalf("the stream ended before its next response: %v", err)
	case <-time.After(streamWait):
		t.Fatalf("no response within %s", streamWait)
	}
	return nil
}

// ended waits for the stream to end and returns the error Recv ended it with.
func (tap *streamTap) ended(t *testing.T) error {
	t.Helper()
	select {
	case err := <-tap.end:
		tap.end <- err
		return err
	case <-time.After(streamWait):
		t.Fatalf("the stream did not end within %s", streamWait)
	}
	return nil
}

// close cancels the stream from the client side and returns the error it ended with.
func (tap *streamTap) close(t *testing.T) error {
	t.Helper()
	tap.cancel()
	return tap.ended(t)
}

func streamOpenX509SVID(t *testing.T, h *harness, pod *workloadidentity.Workload) *streamTap {
	t.Helper()
	ctx, cancel := context.WithCancel(h.ctxFor(pod))
	stream, err := h.client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		cancel()
		t.Fatalf("opening FetchX509SVID: %v", err)
	}
	return streamPump(t, ctx, cancel, func() (proto.Message, error) { return stream.Recv() })
}

func streamOpenX509Bundles(t *testing.T, h *harness, pod *workloadidentity.Workload) *streamTap {
	t.Helper()
	ctx, cancel := context.WithCancel(h.ctxFor(pod))
	stream, err := h.client.FetchX509Bundles(ctx, &workload.X509BundlesRequest{})
	if err != nil {
		cancel()
		t.Fatalf("opening FetchX509Bundles: %v", err)
	}
	return streamPump(t, ctx, cancel, func() (proto.Message, error) { return stream.Recv() })
}

func streamOpenJWTBundles(t *testing.T, h *harness, pod *workloadidentity.Workload) *streamTap {
	t.Helper()
	ctx, cancel := context.WithCancel(h.ctxFor(pod))
	stream, err := h.client.FetchJWTBundles(ctx, &workload.JWTBundlesRequest{})
	if err != nil {
		cancel()
		t.Fatalf("opening FetchJWTBundles: %v", err)
	}
	return streamPump(t, ctx, cancel, func() (proto.Message, error) { return stream.Recv() })
}

// streamRPC is one of the three streams and the levers a test pulls on it, so the
// same steps run against each. Every lever acts on podA's provider, providerA.
type streamRPC struct {
	name string
	kind fake.SubscriptionKind
	open func(t *testing.T, h *harness, pod *workloadidentity.Workload) *streamTap
	// gate parks the stream's reads. reads counts its first read on every pass,
	// and failReads makes that read fail with err.
	gate      func(h *harness) *fake.Gate
	reads     func(h *harness) int
	failReads func(h *harness, err error)
	// change moves what the stream serves to a new state and returns the bytes
	// identifying it on the wire; served reads those bytes off a response.
	change func(t *testing.T, h *harness) []byte
	served func(msg proto.Message) []byte
	// initial is what served reads off a response before any change.
	initial func(t *testing.T, h *harness) []byte
	// notify publishes the change that wakes this stream for podA.
	notify func(h *harness) int
	// failFirst makes the read fail with err n times, then answer as the harness
	// set it up. It sets a Func, so it must run in newHarness's configure.
	failFirst func(h *harness, n int32, err error)
}

func streamRPCs() []streamRPC {
	return []streamRPC{
		{
			name:      "FetchX509SVID",
			kind:      fake.KindWorkloadMaterial,
			open:      streamOpenX509SVID,
			gate:      func(h *harness) *fake.Gate { return &h.certs.Gate },
			reads:     func(h *harness) int { return h.certs.Calls() },
			failReads: func(h *harness, err error) { h.certs.SetResult(nil, err) },
			change:    streamRenew,
			served:    streamLeaf,
			initial:   func(_ *testing.T, h *harness) []byte { return chainDER(h.svidA) },
			notify:    func(h *harness) int { return h.subs.NotifyWorkload(podA.PodUID) },
			failFirst: func(h *harness, n int32, err error) {
				var calls atomic.Int32
				svids := h.certs.Result
				h.certs.Func = func(context.Context, *workloadidentity.Workload) ([]*x509svid.SVID, error) {
					if calls.Add(1) <= n {
						return nil, err
					}
					return svids, nil
				}
			},
		},
		{
			name:      "FetchX509Bundles",
			kind:      fake.KindCertBundles,
			open:      streamOpenX509Bundles,
			gate:      func(h *harness) *fake.Gate { return &h.bundles.Gate },
			reads:     func(h *harness) int { return h.bundles.X509BundlesCalls() },
			failReads: func(h *harness, err error) { h.bundles.SetX509Bundles(nil, err) },
			change:    streamRotateX509,
			served: func(msg proto.Message) []byte {
				return msg.(*workload.X509BundlesResponse).GetBundles()[streamTDID]
			},
			initial: func(_ *testing.T, h *harness) []byte { return h.pki.cert.Raw },
			notify:  func(h *harness) int { return h.subs.NotifyCertBundles(providerA) },
			failFirst: func(h *harness, n int32, err error) {
				var calls atomic.Int32
				bundles := h.bundles.X509
				h.bundles.X509Func = func(context.Context, *workloadidentity.Workload) (*x509bundle.Set, error) {
					if calls.Add(1) <= n {
						return nil, err
					}
					return bundles, nil
				}
			},
		},
		{
			name:      "FetchJWTBundles",
			kind:      fake.KindJWTBundles,
			open:      streamOpenJWTBundles,
			gate:      func(h *harness) *fake.Gate { return &h.bundles.Gate },
			reads:     func(h *harness) int { return h.bundles.JWTBundlesCalls() },
			failReads: func(h *harness, err error) { h.bundles.SetJWTBundles(nil, err) },
			change:    streamRotateJWT,
			served: func(msg proto.Message) []byte {
				return msg.(*workload.JWTBundlesResponse).GetBundles()[streamTDID]
			},
			initial: func(t *testing.T, h *harness) []byte { return h.jwt.jwks(t) },
			notify:  func(h *harness) int { return h.subs.NotifyJWTBundles(providerA) },
			failFirst: func(h *harness, n int32, err error) {
				var calls atomic.Int32
				bundles := h.bundles.JWT
				h.bundles.JWTFunc = func(context.Context, *workloadidentity.Workload) (map[string][]byte, error) {
					if calls.Add(1) <= n {
						return nil, err
					}
					return bundles, nil
				}
			},
		},
	}
}

// streamRenew issues podA a fresh SVID under the same authority, as a renewal does,
// and returns its leaf.
func streamRenew(t *testing.T, h *harness) []byte {
	t.Helper()
	renewed := h.pki.issue(t, streamSPIFFEIDA)
	h.certs.SetResult([]*x509svid.SVID{renewed}, nil)
	return chainDER(renewed)
}

// streamRotateX509 adds a fresh authority to the default trust domain's X.509
// bundle and returns that bundle as the wire carries it.
func streamRotateX509(t *testing.T, h *harness) []byte {
	t.Helper()
	next := newTestCA(t, testTrustDomain)
	h.bundles.SetX509Bundles(x509Set(h.pki, next, h.fed), nil)
	return bytes.Join([][]byte{h.pki.cert.Raw, next.cert.Raw}, nil)
}

// streamJWTKeys numbers the key IDs streamRotateJWT publishes, so every rotation
// is a new JWK Set.
var streamJWTKeys atomic.Int32

// streamRotateJWT replaces the default trust domain's JWT authority and returns
// the new JWK Set.
func streamRotateJWT(t *testing.T, h *harness) []byte {
	t.Helper()
	jwks := newTestJWTAuthority(t, testTrustDomain, fmt.Sprintf("rotated-%d", streamJWTKeys.Add(1))).jwks(t)
	h.bundles.SetJWTBundles(map[string][]byte{testTrustDomain: jwks}, nil)
	return jwks
}

// streamLeaf is the first SVID's certificate chain in an X.509-SVID response.
func streamLeaf(msg proto.Message) []byte {
	svids := msg.(*workload.X509SVIDResponse).GetSvids()
	if len(svids) == 0 {
		return nil
	}
	return svids[0].GetX509Svid()
}

// streamBundle is the first SVID's own trust domain bundle in an X.509-SVID
// response.
func streamBundle(msg proto.Message) []byte {
	svids := msg.(*workload.X509SVIDResponse).GetSvids()
	if len(svids) == 0 {
		return nil
	}
	return svids[0].GetBundle()
}

// streamQuiet asserts that none of taps receives a response, or ends, within
// streamQuietWindow.
func streamQuiet(g Gomega, taps ...*streamTap) {
	g.Consistently(func() int {
		n := 0
		for _, tap := range taps {
			n += len(tap.msgs) + len(tap.end)
		}
		return n
	}, streamQuietWindow, 10*time.Millisecond).Should(BeZero(), "a stream sent a response or ended when it should have stayed quiet")
}

// streamWaitCtx bounds a WaitForBlocked call.
func streamWaitCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), streamWait)
	t.Cleanup(cancel)
	return ctx
}

// streamSlowRetries makes a blocked stream wait an hour between retries. It must
// run before the test opens a stream, since each stream copies the backoff when it
// opens.
func streamSlowRetries(h *harness) {
	h.handler.backoff = streamHourBackoff
}

func TestStreams_SubscribeWithTheCallersWorkloadThroughTheirOwnSubscriber(t *testing.T) {
	g := NewWithT(t)
	subs := map[fake.SubscriptionKind]*fake.Subscriber{}
	h := newHarness(t, func(h *harness) {
		for _, kind := range []fake.SubscriptionKind{fake.KindWorkloadMaterial, fake.KindCertBundles, fake.KindJWTBundles} {
			subs[kind] = &fake.Subscriber{Providers: h.providers}
		}
		h.x509SVIDSubs = subs[fake.KindWorkloadMaterial]
		h.x509BundlesSubs = subs[fake.KindCertBundles]
		h.jwtBundlesSubs = subs[fake.KindJWTBundles]
	})

	for _, pod := range []*workloadidentity.Workload{podA, podB} {
		for _, rpc := range streamRPCs() {
			rpc.open(t, h, pod).next(t)
		}
	}

	for _, rpc := range streamRPCs() {
		got := subs[rpc.kind].Subscriptions()
		g.Expect(got).To(HaveLen(2), "%s subscribed through another RPC's Subscriber", rpc.name)
		for i, want := range []struct {
			pod      *workloadidentity.Workload
			provider string
		}{{podA, providerA}, {podB, providerB}} {
			g.Expect(got[i].Kind).To(Equal(rpc.kind), "%s subscribed with the wrong method", rpc.name)
			g.Expect(got[i].Workload).To(BeIdenticalTo(want.pod), "%s subscribed with another caller's workload", rpc.name)
			g.Expect(got[i].ProviderArn).To(Equal(want.provider))
		}
	}
}

func TestStreams_RenewalWakesOnlyTheX509SVIDStream(t *testing.T) {
	g := NewWithT(t)
	h := newHarness(t)
	svid := streamOpenX509SVID(t, h, podA)
	x509Bundles := streamOpenX509Bundles(t, h, podA)
	jwtBundles := streamOpenJWTBundles(t, h, podA)
	for _, tap := range []*streamTap{svid, x509Bundles, jwtBundles} {
		tap.next(t)
	}
	x509Reads, jwtReads := h.bundles.X509BundlesCalls(), h.bundles.JWTBundlesCalls()

	leaf := streamRenew(t, h)
	g.Expect(h.subs.NotifyWorkload(podA.PodUID)).To(Equal(1), "the renewal reached a stream other than FetchX509SVID")
	g.Expect(streamLeaf(svid.next(t))).To(Equal(leaf))

	// The SVID stream's own pass reads the X.509 bundles once; a bundle stream
	// the renewal woke would read again.
	g.Consistently(h.bundles.X509BundlesCalls, streamQuietWindow).Should(Equal(x509Reads + 1))
	g.Consistently(h.bundles.JWTBundlesCalls, streamQuietWindow).Should(Equal(jwtReads))
	streamQuiet(g, x509Bundles, jwtBundles)
}

func TestFetchX509SVID_RenewalSendsAFreshResponseOnTheOpenStream(t *testing.T) {
	g := NewWithT(t)
	h := newHarness(t)
	tap := streamOpenX509SVID(t, h, podA)
	g.Expect(streamLeaf(tap.next(t))).To(Equal(chainDER(h.svidA)))

	renewed := h.pki.issue(t, streamSPIFFEIDA)
	h.certs.SetResult([]*x509svid.SVID{renewed}, nil)
	g.Expect(h.subs.NotifyWorkload(podA.PodUID)).To(Equal(1))

	resp := tap.next(t).(*workload.X509SVIDResponse)
	g.Expect(resp.GetSvids()).To(HaveLen(1))
	got := resp.GetSvids()[0]
	g.Expect(got.GetSpiffeId()).To(Equal(streamSPIFFEIDA))
	g.Expect(got.GetX509Svid()).To(Equal(chainDER(renewed)))
	g.Expect(got.GetBundle()).To(Equal(h.pki.cert.Raw))
	key, err := x509.ParsePKCS8PrivateKey(got.GetX509SvidKey())
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(key.(crypto.Signer).Public()).To(Equal(renewed.PrivateKey.Public()), "the fresh response carries the old key")

	// The same stream served both: the client never reconnected.
	g.Expect(h.attestor.Calls()).To(Equal(1))
	g.Expect(h.subs.SubscribeCalls()).To(Equal(1))
	g.Expect(h.bundles.LeaseCalls()).To(Equal(1))
}

func TestStreams_BundleChangeReachesOnlyTheChangedProvidersStreamsThatServeIt(t *testing.T) {
	g := NewWithT(t)
	h := newHarness(t)
	open := func(pod *workloadidentity.Workload) (svid, x509Bundles, jwtBundles *streamTap) {
		svid, x509Bundles, jwtBundles = streamOpenX509SVID(t, h, pod), streamOpenX509Bundles(t, h, pod), streamOpenJWTBundles(t, h, pod)
		for _, tap := range []*streamTap{svid, x509Bundles, jwtBundles} {
			tap.next(t)
		}
		return svid, x509Bundles, jwtBundles
	}
	svidA, x509A, jwtA := open(podA)
	svidB, x509B, jwtB := open(podB)

	// An X.509 change reaches the SVID and X.509 bundle streams of providerA.
	jwtReads := h.bundles.JWTBundlesCalls()
	bundle := streamRotateX509(t, h)
	g.Expect(h.subs.NotifyCertBundles(providerA)).To(Equal(2))
	g.Expect(streamBundle(svidA.next(t))).To(Equal(bundle))
	g.Expect(x509A.next(t).(*workload.X509BundlesResponse).GetBundles()).To(Equal(map[string][]byte{
		streamTDID:  bundle,
		streamFedID: h.fed.cert.Raw,
	}))
	g.Consistently(h.bundles.JWTBundlesCalls, streamQuietWindow).Should(Equal(jwtReads), "an X.509 change woke a JWT bundle stream")
	streamQuiet(g, jwtA, svidB, x509B, jwtB)

	// A JWT change reaches the JWT bundle stream of providerA only.
	certReads, x509Reads := h.certs.Calls(), h.bundles.X509BundlesCalls()
	jwks := streamRotateJWT(t, h)
	g.Expect(h.subs.NotifyJWTBundles(providerA)).To(Equal(1))
	g.Expect(jwtA.next(t).(*workload.JWTBundlesResponse).GetBundles()).To(Equal(map[string][]byte{streamTDID: jwks}))
	g.Consistently(h.certs.Calls, streamQuietWindow).Should(Equal(certReads), "a JWT change woke an SVID stream")
	g.Consistently(h.bundles.X509BundlesCalls, streamQuietWindow).Should(Equal(x509Reads), "a JWT change woke an X.509 stream")
	streamQuiet(g, svidA, x509A, svidB, x509B, jwtB)

	// providerB's change reaches podB's streams and none of podA's.
	bundle = streamRotateX509(t, h)
	g.Expect(h.subs.NotifyCertBundles(providerB)).To(Equal(2))
	g.Expect(streamBundle(svidB.next(t))).To(Equal(bundle))
	g.Expect(x509B.next(t).(*workload.X509BundlesResponse).GetBundles()).To(HaveKeyWithValue(streamTDID, bundle))
	streamQuiet(g, svidA, x509A, jwtA, jwtB)
}

func TestStreams_SlowReaderGetsTheNewestStateNotAQueue(t *testing.T) {
	for _, rpc := range streamRPCs() {
		t.Run(rpc.name, func(t *testing.T) {
			g := NewWithT(t)
			h := newHarness(t)
			tap := rpc.open(t, h, podA)
			tap.next(t)

			// Park the stream's re-read, then let several changes pile up behind it.
			gate := rpc.gate(h)
			gate.Block()
			g.Expect(rpc.notify(h)).To(Equal(1))
			g.Expect(gate.WaitForBlocked(streamWaitCtx(t), 1)).To(Succeed())
			var states [][]byte
			for range 3 {
				states = append(states, rpc.change(t, h))
				rpc.notify(h)
			}
			gate.Release()

			g.Expect(rpc.served(tap.next(t))).To(Equal(states[len(states)-1]), "the first response after the stall is not the newest state")
			streamQuiet(g, tap)
		})
	}
}

func TestStreams_WakeWithNothingNewSendsNothing(t *testing.T) {
	g := NewWithT(t)
	h := newHarness(t)
	svid := streamOpenX509SVID(t, h, podA)
	x509Bundles := streamOpenX509Bundles(t, h, podA)
	jwtBundles := streamOpenJWTBundles(t, h, podA)
	for _, tap := range []*streamTap{svid, x509Bundles, jwtBundles} {
		tap.next(t)
	}
	certReads, x509Reads, jwtReads := h.certs.Calls(), h.bundles.X509BundlesCalls(), h.bundles.JWTBundlesCalls()

	// Wake every stream with nothing changed, and wait until each has re-read, so
	// the quiet window below covers its decision not to send.
	g.Expect(h.subs.NotifyWorkload(podA.PodUID)).To(Equal(1))
	g.Eventually(h.bundles.X509BundlesCalls, streamWait).Should(Equal(x509Reads + 1))
	g.Expect(h.subs.NotifyCertBundles(providerA)).To(Equal(2))
	g.Eventually(h.bundles.X509BundlesCalls, streamWait).Should(Equal(x509Reads + 3))
	g.Expect(h.certs.Calls()).To(Equal(certReads + 2))
	g.Expect(h.subs.NotifyJWTBundles(providerA)).To(Equal(1))
	g.Eventually(h.bundles.JWTBundlesCalls, streamWait).Should(Equal(jwtReads + 1))
	streamQuiet(g, svid, x509Bundles, jwtBundles)

	// Responses arrive in order, so had a wake above sent an unchanged response,
	// it would be received ahead of the changed one.
	leaf := streamRenew(t, h)
	h.subs.NotifyWorkload(podA.PodUID)
	g.Expect(streamLeaf(svid.next(t))).To(Equal(leaf))

	bundle := streamRotateX509(t, h)
	h.subs.NotifyCertBundles(providerA)
	g.Expect(streamBundle(svid.next(t))).To(Equal(bundle))
	g.Expect(x509Bundles.next(t).(*workload.X509BundlesResponse).GetBundles()).To(HaveKeyWithValue(streamTDID, bundle))

	jwks := streamRotateJWT(t, h)
	h.subs.NotifyJWTBundles(providerA)
	g.Expect(jwtBundles.next(t).(*workload.JWTBundlesResponse).GetBundles()).To(HaveKeyWithValue(streamTDID, jwks))
	streamQuiet(g, svid, x509Bundles, jwtBundles)
}

func TestFetchX509SVID_DedupeIgnoresThePrivateKey(t *testing.T) {
	g := NewWithT(t)
	h := newHarness(t)
	tap := streamOpenX509SVID(t, h, podA)
	tap.next(t)

	rekeyed := *h.svidA
	rekeyed.PrivateKey = newECKey(t)
	h.certs.SetResult([]*x509svid.SVID{&rekeyed}, nil)
	x509Reads := h.bundles.X509BundlesCalls()
	g.Expect(h.subs.NotifyWorkload(podA.PodUID)).To(Equal(1))
	g.Eventually(h.bundles.X509BundlesCalls, streamWait).Should(Equal(x509Reads + 1))
	streamQuiet(g, tap)

	leaf := streamRenew(t, h)
	h.subs.NotifyWorkload(podA.PodUID)
	g.Expect(streamLeaf(tap.next(t))).To(Equal(leaf))
}

func TestX509SVIDView_ComparesEverythingButThePrivateKey(t *testing.T) {
	g := NewWithT(t)
	resp := &workload.X509SVIDResponse{
		Svids: []*workload.X509SVID{{
			SpiffeId:    streamSPIFFEIDA,
			X509Svid:    []byte("leaf"),
			X509SvidKey: []byte("key"),
			Bundle:      []byte("bundle"),
			Hint:        "hint",
		}},
		FederatedBundles: map[string][]byte{streamFedID: []byte("federated")},
		Crl:              [][]byte{[]byte("crl")},
	}

	view := x509SVIDView(resp).(*workload.X509SVIDResponse)
	g.Expect(view.GetSvids()).To(HaveLen(1))
	g.Expect(view.GetSvids()[0].GetX509SvidKey()).To(BeEmpty(), "the view keeps a copy of the private key")
	g.Expect(resp.GetSvids()[0].GetX509SvidKey()).To(Equal([]byte("key")), "the view stripped the key off the response itself")

	rekeyed := proto.Clone(resp).(*workload.X509SVIDResponse)
	rekeyed.Svids[0].X509SvidKey = []byte("another key")
	g.Expect(proto.Equal(x509SVIDView(resp), x509SVIDView(rekeyed))).To(BeTrue())

	for name, change := range map[string]func(*workload.X509SVIDResponse){
		"SPIFFE ID":         func(r *workload.X509SVIDResponse) { r.Svids[0].SpiffeId = streamSPIFFEIDA + "-2" },
		"certificates":      func(r *workload.X509SVIDResponse) { r.Svids[0].X509Svid = []byte("renewed leaf") },
		"bundle":            func(r *workload.X509SVIDResponse) { r.Svids[0].Bundle = []byte("rotated bundle") },
		"hint":              func(r *workload.X509SVIDResponse) { r.Svids[0].Hint = "another hint" },
		"federated bundles": func(r *workload.X509SVIDResponse) { r.FederatedBundles[streamFedID] = []byte("rotated") },
		"CRL":               func(r *workload.X509SVIDResponse) { r.Crl = nil },
		"SVID list": func(r *workload.X509SVIDResponse) {
			r.Svids = append(r.Svids, &workload.X509SVID{SpiffeId: streamSPIFFEIDA, X509Svid: []byte("leaf")})
		},
	} {
		changed := proto.Clone(resp).(*workload.X509SVIDResponse)
		change(changed)
		g.Expect(proto.Equal(x509SVIDView(resp), x509SVIDView(changed))).To(BeFalse(), "a change to the %s is deduped away", name)
	}
}

func TestStreams_FirstCallerBlocksThroughRetryableReadFailures(t *testing.T) {
	retryable := []*wierrors.WorkloadIdentityError{
		wierrors.ErrIssuanceFailed, wierrors.ErrIssuanceThrottled, wierrors.ErrBundleUnavailable, wierrors.ErrSessionUnavailable,
	}
	for _, rpc := range streamRPCs() {
		for _, sentinel := range retryable {
			t.Run(rpc.name+"/"+wierrors.MetricLabel(sentinel), func(t *testing.T) {
				g := NewWithT(t)
				h := newHarness(t, func(h *harness) { rpc.failFirst(h, 3, sentinel.Wrapf(nil, "not minted yet")) })
				tap := rpc.open(t, h, podA)

				g.Expect(rpc.served(tap.next(t))).To(Equal(rpc.initial(t, h)))
				g.Expect(rpc.reads(h)).To(Equal(4), "the stream answered before its read succeeded")
				g.Expect(h.subs.LiveSubscriptions()).To(Equal(1))
				g.Expect(h.bundles.LiveLeases()).To(Equal(1))
			})
		}
	}
}

func TestStreams_FirstCallerBlocksThroughARetryableSubscribeFailure(t *testing.T) {
	for _, rpc := range streamRPCs() {
		t.Run(rpc.name, func(t *testing.T) {
			g := NewWithT(t)
			var resolutions atomic.Int32
			h := newHarness(t, func(h *harness) {
				h.providers.Func = func(context.Context, *workloadidentity.Workload) (string, error) {
					if resolutions.Add(1) <= 3 {
						return "", wierrors.ErrSessionUnavailable.Wrapf(nil, "EKS Auth is unreachable")
					}
					return providerA, nil
				}
			})
			tap := rpc.open(t, h, podA)

			g.Expect(rpc.served(tap.next(t))).To(Equal(rpc.initial(t, h)))
			g.Expect(h.subs.SubscribeCalls()).To(Equal(4))
			subs := h.subs.Subscriptions()
			g.Expect(subs).To(HaveLen(1))
			g.Expect(subs[0].Kind).To(Equal(rpc.kind))
			g.Expect(subs[0].Workload).To(BeIdenticalTo(podA))
			g.Expect(subs[0].ProviderArn).To(Equal(providerA))
		})
	}
}

func TestStreams_FirstCallerBlocksThroughARetryableLeaseFailure(t *testing.T) {
	for _, rpc := range streamRPCs() {
		t.Run(rpc.name, func(t *testing.T) {
			g := NewWithT(t)
			var attempts, released atomic.Int32
			h := newHarness(t, func(h *harness) {
				h.bundles.LeaseFunc = func(context.Context, *workloadidentity.Workload) (func(), error) {
					if attempts.Add(1) <= 3 {
						return nil, wierrors.ErrSessionUnavailable.Wrapf(nil, "EKS Auth is unreachable")
					}
					return func() { released.Add(1) }, nil
				}
			})
			tap := rpc.open(t, h, podA)

			g.Expect(rpc.served(tap.next(t))).To(Equal(rpc.initial(t, h)))
			g.Expect(h.bundles.LeaseCalls()).To(Equal(4))
			g.Expect(h.subs.LiveSubscriptions()).To(Equal(1), "a failed lease left a subscription behind")
			g.Expect(released.Load()).To(BeZero(), "the lease was released while its stream is open")

			g.Expect(status.Code(tap.close(t))).To(Equal(codes.Canceled))
			g.Eventually(released.Load, streamWait).Should(Equal(int32(1)))
		})
	}
}

func TestStreams_SignalCutsTheRetryBackoffShort(t *testing.T) {
	for _, rpc := range streamRPCs() {
		t.Run(rpc.name, func(t *testing.T) {
			g := NewWithT(t)
			h := newHarness(t, func(h *harness) { rpc.failFirst(h, 1, wierrors.ErrBundleUnavailable) })
			streamSlowRetries(h)
			tap := rpc.open(t, h, podA)
			g.Eventually(func() int { return rpc.reads(h) }, streamWait).Should(Equal(1))

			// The retry is an hour away, so only the signal can bring the response.
			g.Expect(rpc.notify(h)).To(Equal(1))
			g.Expect(rpc.served(tap.next(t))).To(Equal(rpc.initial(t, h)))
			g.Expect(rpc.reads(h)).To(Equal(2))
		})
	}
}

func TestStreams_NonRetryableErrorEndsTheStreamWithItsMappedCode(t *testing.T) {
	notEnrolled := wierrors.ErrNotEnrolled.Wrapf(nil, "the session names no provider")
	steps := []struct {
		name      string
		pod       *workloadidentity.Workload
		configure func(h *harness, rpc streamRPC)
		// calls counts the failing step, which must not be retried.
		calls func(h *harness, rpc streamRPC) int
		code  codes.Code
	}{
		{
			name: "attest unattestable",
			pod:  podA,
			configure: func(h *harness, _ streamRPC) {
				h.attestor.Func = func(context.Context, workloadidentity.Peer) (*workloadidentity.Workload, error) {
					return nil, wierrors.ErrUnattestable.Wrapf(nil, "no pod owns the caller")
				}
			},
			calls: func(h *harness, _ streamRPC) int { return h.attestor.Calls() },
			code:  codes.PermissionDenied,
		},
		{
			// The fake resolver names no provider for podUnenrolled.
			name:      "subscribe not enrolled",
			pod:       podUnenrolled,
			configure: func(*harness, streamRPC) {},
			calls:     func(h *harness, _ streamRPC) int { return h.subs.SubscribeCalls() },
			code:      codes.PermissionDenied,
		},
		{
			name:      "lease not enrolled",
			pod:       podA,
			configure: func(h *harness, _ streamRPC) { h.bundles.LeaseErr = notEnrolled },
			calls:     func(h *harness, _ streamRPC) int { return h.bundles.LeaseCalls() },
			code:      codes.PermissionDenied,
		},
		{
			name:      "read not enrolled",
			pod:       podA,
			configure: func(h *harness, rpc streamRPC) { rpc.failReads(h, notEnrolled) },
			calls:     func(h *harness, rpc streamRPC) int { return rpc.reads(h) },
			code:      codes.PermissionDenied,
		},
		{
			name: "read refused",
			pod:  podA,
			configure: func(h *harness, rpc streamRPC) {
				rpc.failReads(h, wierrors.ErrBundleRefused.Wrapf(nil, "the role lacks sts:GetTrustBundles"))
			},
			calls: func(h *harness, rpc streamRPC) int { return rpc.reads(h) },
			code:  codes.PermissionDenied,
		},
		{
			name:      "read unclassified",
			pod:       podA,
			configure: func(h *harness, rpc streamRPC) { rpc.failReads(h, errors.New("something unexpected")) },
			calls:     func(h *harness, rpc streamRPC) int { return rpc.reads(h) },
			code:      codes.Internal,
		},
	}
	for _, rpc := range streamRPCs() {
		for _, step := range steps {
			t.Run(rpc.name+"/"+step.name, func(t *testing.T) {
				g := NewWithT(t)
				h := newHarness(t, func(h *harness) { step.configure(h, rpc) })
				tap := rpc.open(t, h, step.pod)

				err := tap.ended(t)
				g.Expect(status.Code(err)).To(Equal(step.code), "the stream ended with %v", err)
				g.Expect(tap.msgs).To(BeEmpty(), "the stream answered before it failed")
				g.Expect(step.calls(h, rpc)).To(Equal(1), "a non-retryable error was retried")
				g.Eventually(h.subs.LiveSubscriptions, streamWait).Should(BeZero())
				g.Eventually(h.bundles.LiveLeases, streamWait).Should(BeZero())
			})
		}
	}
}

func TestStreams_BundleOnlyRPCsServeACallerThatNeverFetchedAnSVID(t *testing.T) {
	g := NewWithT(t)
	h := newHarness(t)
	x509Bundles := streamOpenX509Bundles(t, h, podB)
	jwtBundles := streamOpenJWTBundles(t, h, podB)

	g.Expect(x509Bundles.next(t).(*workload.X509BundlesResponse).GetBundles()).To(Equal(map[string][]byte{
		streamTDID:  h.pki.cert.Raw,
		streamFedID: h.fed.cert.Raw,
	}))
	g.Expect(jwtBundles.next(t).(*workload.JWTBundlesResponse).GetBundles()).To(Equal(map[string][]byte{
		streamTDID: h.jwt.jwks(t),
	}))
	g.Expect(h.certs.Calls()).To(BeZero())
	g.Expect(h.bundles.WorkloadRequests()).To(HaveEach(BeIdenticalTo(podB)))
}

func TestStreams_HoldALeaseForExactlyTheStreamsLife(t *testing.T) {
	for _, rpc := range streamRPCs() {
		t.Run(rpc.name+"/client cancel", func(t *testing.T) {
			g := NewWithT(t)
			h := newHarness(t)
			first := rpc.open(t, h, podA)
			first.next(t)
			g.Expect(h.bundles.LiveLeases()).To(Equal(1))
			second := rpc.open(t, h, podB)
			second.next(t)
			g.Expect(h.bundles.LiveLeases()).To(Equal(2))
			g.Expect(h.bundles.Released()).To(BeZero())

			g.Expect(status.Code(first.close(t))).To(Equal(codes.Canceled))
			g.Eventually(h.bundles.Released, streamWait).Should(Equal(1))
			g.Expect(h.bundles.LiveLeases()).To(Equal(1))

			g.Expect(status.Code(second.close(t))).To(Equal(codes.Canceled))
			g.Eventually(h.bundles.Released, streamWait).Should(Equal(2))
			g.Expect(h.bundles.LiveLeases()).To(BeZero())
			g.Expect(h.bundles.LeaseCalls()).To(Equal(2))
		})

		t.Run(rpc.name+"/handler returns", func(t *testing.T) {
			g := NewWithT(t)
			h := newHarness(t)
			tap := rpc.open(t, h, podA)
			tap.next(t)
			g.Expect(h.bundles.LiveLeases()).To(Equal(1))

			rpc.failReads(h, wierrors.ErrBundleRefused.Wrapf(nil, "the role lacks sts:GetTrustBundles"))
			g.Expect(rpc.notify(h)).To(Equal(1))
			g.Expect(status.Code(tap.ended(t))).To(Equal(codes.PermissionDenied))
			g.Eventually(h.bundles.Released, streamWait).Should(Equal(1))
			g.Expect(h.bundles.LiveLeases()).To(BeZero())
			g.Expect(h.bundles.LeaseCalls()).To(Equal(1))
		})
	}
}

func TestStreams_GatedBundleReadDoesNotHoldTheLeaseBack(t *testing.T) {
	for _, rpc := range streamRPCs() {
		t.Run(rpc.name, func(t *testing.T) {
			g := NewWithT(t)
			h := newHarness(t)
			h.bundles.Block()
			t.Cleanup(h.bundles.Release)
			tap := rpc.open(t, h, podA)

			g.Expect(h.bundles.WaitForBlocked(streamWaitCtx(t), 1)).To(Succeed())
			g.Expect(h.bundles.LiveLeases()).To(Equal(1), "the lease waited on the bundle read")

			h.bundles.Release()
			g.Expect(rpc.served(tap.next(t))).To(Equal(rpc.initial(t, h)))
			g.Expect(h.bundles.LiveLeases()).To(Equal(1))

			g.Expect(status.Code(tap.close(t))).To(Equal(codes.Canceled))
			g.Eventually(h.bundles.Released, streamWait).Should(Equal(1))
			g.Expect(h.bundles.LiveLeases()).To(BeZero())
		})
	}
}

func TestStreams_TeardownLeavesNoGoroutineBehind(t *testing.T) {
	const cycles = 50
	// slack absorbs runtime goroutines that come and go; a leak of one per stream
	// would overshoot it by two orders of magnitude.
	const slack = 5
	for _, closeOnCancel := range []bool{false, true} {
		t.Run(fmt.Sprintf("CloseOnCancel=%t", closeOnCancel), func(t *testing.T) {
			g := NewWithT(t)
			h := newHarness(t, func(h *harness) { h.subs.CloseOnCancel = closeOnCancel })
			cycle := func(rpc streamRPC) {
				tap := rpc.open(t, h, podA)
				tap.next(t)
				g.Expect(status.Code(tap.close(t))).To(Equal(codes.Canceled))
			}

			// The first stream dials the connection, whose goroutines live as long
			// as the test, so the baseline is taken after one cycle of each.
			for _, rpc := range streamRPCs() {
				cycle(rpc)
			}
			g.Eventually(h.subs.CancelCalls, streamWait).Should(Equal(3))
			g.Eventually(h.bundles.Released, streamWait).Should(Equal(3))
			baseline := runtime.NumGoroutine()

			for range cycles {
				for _, rpc := range streamRPCs() {
					cycle(rpc)
				}
			}

			total := 3 * (cycles + 1)
			g.Eventually(h.subs.CancelCalls, streamWait).Should(Equal(total))
			g.Eventually(h.bundles.Released, streamWait).Should(Equal(total))
			g.Expect(h.subs.LiveSubscriptions()).To(BeZero())
			g.Expect(h.bundles.LiveLeases()).To(BeZero())
			g.Eventually(runtime.NumGoroutine, streamWait).Should(BeNumerically("<=", baseline+slack))

			// A handler looping on a closed channel would keep reading after its
			// stream ended.
			reads := func() int {
				return h.certs.Calls() + h.bundles.X509BundlesCalls() + h.bundles.JWTBundlesCalls()
			}
			g.Consistently(reads, streamQuietWindow).Should(Equal(reads()))
		})
	}
}

func TestStreams_ClientCancelEndsTheStreamAndReleasesTheSubscriptionPromptly(t *testing.T) {
	// promptly is well short of the hour a blocked stream waits between retries.
	const promptly = 2 * time.Second
	released := func(g Gomega, h *harness) {
		g.Eventually(h.subs.CancelCalls, promptly).Should(Equal(1), "the subscription was not released")
		g.Expect(h.subs.LiveSubscriptions()).To(BeZero())
		g.Eventually(h.bundles.LiveLeases, promptly).Should(BeZero(), "the lease was not released")
	}
	for _, rpc := range streamRPCs() {
		t.Run(rpc.name+"/after a response", func(t *testing.T) {
			g := NewWithT(t)
			h := newHarness(t)
			tap := rpc.open(t, h, podA)
			tap.next(t)
			g.Expect(h.subs.CancelCalls()).To(BeZero())

			g.Expect(status.Code(tap.close(t))).To(Equal(codes.Canceled))
			released(g, h)
		})

		t.Run(rpc.name+"/parked in a read", func(t *testing.T) {
			g := NewWithT(t)
			h := newHarness(t)
			gate := rpc.gate(h)
			gate.Block()
			t.Cleanup(gate.Release)
			tap := rpc.open(t, h, podA)
			g.Expect(gate.WaitForBlocked(streamWaitCtx(t), 1)).To(Succeed())

			g.Expect(status.Code(tap.close(t))).To(Equal(codes.Canceled))
			released(g, h)
		})

		t.Run(rpc.name+"/waiting out a retry", func(t *testing.T) {
			g := NewWithT(t)
			h := newHarness(t, func(h *harness) { rpc.failFirst(h, math.MaxInt32, wierrors.ErrBundleUnavailable) })
			streamSlowRetries(h)
			tap := rpc.open(t, h, podA)
			g.Eventually(func() int { return rpc.reads(h) }, streamWait).Should(Equal(1))

			g.Expect(status.Code(tap.close(t))).To(Equal(codes.Canceled))
			released(g, h)
			g.Expect(rpc.reads(h)).To(Equal(1))
		})
	}
}

// streamRPCLabels are the metric labels of the three streams, by streamRPC name.
var streamRPCLabels = map[string]string{
	"FetchX509SVID":    workloadidentity.RPCFetchX509SVID,
	"FetchX509Bundles": workloadidentity.RPCFetchX509Bundles,
	"FetchJWTBundles":  workloadidentity.RPCFetchJWTBundles,
}

// A stream that has answered keeps its client on the last response through a
// retryable failure, as through an EKS Auth outage, and picks up the next state on
// the same stream. A non-retryable failure ends it, and neither counts it again.
func TestStreams_AnErrorAfterTheFirstResponse(t *testing.T) {
	for _, rpc := range streamRPCs() {
		t.Run(rpc.name+"/retryable keeps the stream open", func(t *testing.T) {
			g := NewWithT(t)
			h := newHarness(t)
			tap := rpc.open(t, h, podA)
			tap.next(t)
			before := errsRPCMetrics(g, streamRPCLabels[rpc.name])

			rpc.failReads(h, wierrors.ErrSessionUnavailable)
			reads := rpc.reads(h)
			g.Expect(rpc.notify(h)).To(Equal(1))
			g.Eventually(func() int { return rpc.reads(h) }, streamWait).Should(BeNumerically(">=", reads+3),
				"the stream is not retrying its read")
			streamQuiet(g, tap)

			want := rpc.change(t, h)
			g.Expect(rpc.served(tap.next(t))).To(Equal(want))
			g.Expect(h.attestor.Calls()).To(Equal(1), "the stream was reopened")
			g.Expect(h.subs.SubscribeCalls()).To(Equal(1), "the stream was reopened")
			g.Expect(errsRPCMetrics(g, streamRPCLabels[rpc.name]).since(before)).To(Equal(errsNothing()))
		})

		t.Run(rpc.name+"/non-retryable ends the stream", func(t *testing.T) {
			g := NewWithT(t)
			h := newHarness(t)
			tap := rpc.open(t, h, podA)
			tap.next(t)
			before := errsRPCMetrics(g, streamRPCLabels[rpc.name])

			rpc.failReads(h, wierrors.ErrNotEnrolled)
			g.Expect(rpc.notify(h)).To(Equal(1))
			g.Expect(status.Code(tap.ended(t))).To(Equal(codes.PermissionDenied))
			g.Eventually(h.streamsEnded, streamWait).Should(BeEquivalentTo(1))
			g.Expect(errsRPCMetrics(g, streamRPCLabels[rpc.name]).since(before)).To(Equal(errsNothing()),
				"a stream that already answered was counted again")
		})
	}
}

// An SVID whose own trust domain has no X.509 authorities is not served, since
// nothing could verify it: the stream waits, and the bundle that arrives with the
// next rotation is sent on the same stream.
func TestFetchX509SVID_WaitsForABundleCarryingTheSVIDsTrustDomain(t *testing.T) {
	g := NewWithT(t)
	h := newHarness(t, func(h *harness) {
		h.bundles.X509 = x509Set(h.fed)
	})
	streamSlowRetries(h)
	tap := streamOpenX509SVID(t, h, podA)

	g.Eventually(h.bundles.X509BundlesCalls, streamWait).Should(Equal(1))
	streamQuiet(g, tap)

	h.bundles.SetX509Bundles(x509Set(h.pki, h.fed), nil)
	g.Expect(h.subs.NotifyCertBundles(providerA)).To(Equal(1))
	resp := tap.next(t).(*workload.X509SVIDResponse)
	g.Expect(streamBundle(resp)).To(Equal(h.pki.cert.Raw))
	g.Expect(resp.GetFederatedBundles()).To(HaveKeyWithValue(streamFedID, h.fed.cert.Raw))
	g.Expect(h.subs.SubscribeCalls()).To(Equal(1), "the stream was reopened")
}

// A cert tier answering with no SVID and no error leaves the caller with no
// identity, which is SPIRE's "no identity issued", counted once under no_identity.
func TestFetchX509SVID_AnEmptySVIDListIsNoIdentityIssued(t *testing.T) {
	g := NewWithT(t)
	h := newHarness(t, func(h *harness) { h.certs.Result = []*x509svid.SVID{} })
	before := errsRPCMetrics(g, workloadidentity.RPCFetchX509SVID)

	err := streamOpenX509SVID(t, h, podA).ended(t)
	g.Expect(status.Code(err)).To(Equal(codes.PermissionDenied), "%v", err)
	g.Expect(status.Convert(err).Message()).To(Equal("no identity issued"))
	g.Eventually(h.streamsEnded, streamWait).Should(BeEquivalentTo(1))
	g.Expect(errsRPCMetrics(g, workloadidentity.RPCFetchX509SVID).since(before)).
		To(Equal(errsCounted(workloadidentity.OutcomeFailure, wierrors.ErrNoIdentity.MetricLabel())))
}

// A client that stops reading stalls the handler in Send once gRPC's flow-control
// window is full. The changes that land meanwhile coalesce: when the client reads
// again it gets what was already sent and then the newest state, and never the
// state superseded while it was not reading.
func TestFetchX509Bundles_AClientThatStopsReadingGetsTheNewestStateNotAQueue(t *testing.T) {
	g := NewWithT(t)
	// Each response is larger than the window the client grants, so a response the
	// client does not read holds the next Send back.
	state := func(b byte) *x509bundle.Set {
		// The handler sends authorities' raw bytes as they are, so a blob that is
		// no certificate stands in for a large bundle.
		blob := &x509.Certificate{Raw: bytes.Repeat([]byte{b}, 256<<10)}
		return x509bundle.NewSet(x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString(testTrustDomain), []*x509.Certificate{blob}))
	}
	h := newHarness(t, func(h *harness) { h.bundles.X509 = state(0) })

	conn, err := grpc.NewClient("unix://"+h.path,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithInitialWindowSize(1<<16), grpc.WithInitialConnWindowSize(1<<16))
	g.Expect(err).ToNot(HaveOccurred())
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithCancel(h.ctxFor(podA))
	defer cancel()
	stream, err := workload.NewSpiffeWorkloadAPIClient(conn).FetchX509Bundles(ctx, &workload.X509BundlesRequest{})
	g.Expect(err).ToNot(HaveOccurred())
	servedState := func(resp *workload.X509BundlesResponse) byte { return resp.GetBundles()[streamTDID][0] }

	first, err := stream.Recv()
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(servedState(first)).To(Equal(byte(0)))

	// Publish one change at a time until the handler stops reading them, which is
	// when it is held in Send. read is the last state it read.
	var read, unread byte
	for next := byte(1); next < 16; next++ {
		h.bundles.SetX509Bundles(state(next), nil)
		h.subs.NotifyCertBundles(providerA)
		advanced := func(context.Context) (bool, error) { return h.bundles.X509BundlesCalls() == int(next)+1, nil }
		if wait.PollUntilContextTimeout(ctx, 5*time.Millisecond, 500*time.Millisecond, true, advanced) != nil {
			unread = next
			break
		}
		read = next
	}
	g.Expect(unread).ToNot(BeZero(), "the handler never stalled in Send")
	newest := unread + 1
	h.bundles.SetX509Bundles(state(newest), nil)
	h.subs.NotifyCertBundles(providerA)
	g.Consistently(h.bundles.X509BundlesCalls, streamQuietWindow).Should(Equal(int(read)+1),
		"the handler read again while it was held in Send")

	received := make(chan *workload.X509BundlesResponse, 32)
	go func() {
		for {
			resp, err := stream.Recv()
			if err != nil {
				return
			}
			received <- resp
		}
	}()
	var got []byte
	for b := byte(1); b <= read; b++ {
		var resp *workload.X509BundlesResponse
		g.Eventually(received, streamWait).Should(Receive(&resp))
		got = append(got, servedState(resp))
	}
	var resp *workload.X509BundlesResponse
	g.Eventually(received, streamWait).Should(Receive(&resp))
	got = append(got, servedState(resp))

	want := []byte{}
	for b := byte(1); b <= read; b++ {
		want = append(want, b)
	}
	g.Expect(got).To(Equal(append(want, newest)), "the client was handed a superseded state")
	g.Consistently(received, streamQuietWindow).ShouldNot(Receive())
}
