package workloadapi

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

const (
	// unaryAudience1 and unaryAudience2 are the audiences the JWT tests ask for.
	unaryAudience1 = "audience-one"
	unaryAudience2 = "audience-two"
	// unaryPeerID is the subject of a token the caller presents for validation,
	// someone else's identity in the caller's own trust domain.
	unaryPeerID = "spiffe://" + testTrustDomain + "/ns/ns/sa/peer"
)

// unaryIDFor is the SPIFFE ID the fake token source mints w under.
func unaryIDFor(w *workloadidentity.Workload) string {
	return "spiffe://" + testTrustDomain + "/ns/" + w.Namespace + "/sa/" + w.ServiceAccount
}

// unaryTokenKey names one pre-signed token: a pod and its audience set, sorted.
type unaryTokenKey struct {
	podUID, audiences string
}

func unaryKey(podUID string, audiences []string) unaryTokenKey {
	sorted := slices.Sorted(slices.Values(audiences))
	return unaryTokenKey{podUID, strings.Join(sorted, " ")}
}

// unaryMintTokens points h.tokens at a func returning one JWT-SVID carrying every
// requested audience, as T8 issues them, signed by h.jwt. Every token is signed
// here, on the test goroutine, so the fake only looks them up and never calls
// t.Fatalf off it.
func unaryMintTokens(h *harness) map[unaryTokenKey]string {
	minted := map[unaryTokenKey]string{}
	parsed := map[unaryTokenKey]*jwtsvid.SVID{}
	for _, pod := range []*workloadidentity.Workload{podA, podB} {
		for _, set := range [][]string{{unaryAudience1}, {unaryAudience2}, {unaryAudience1, unaryAudience2}} {
			svid := h.jwt.svid(h.t, unaryIDFor(pod), set...)
			minted[unaryKey(pod.PodUID, set)] = svid.Marshal()
			parsed[unaryKey(pod.PodUID, set)] = svid
		}
	}
	h.tokens.Func = func(_ context.Context, w *workloadidentity.Workload, audiences []string) ([]*jwtsvid.SVID, error) {
		svid, ok := parsed[unaryKey(w.PodUID, audiences)]
		if !ok {
			return nil, fmt.Errorf("the test minted no token for pod %s and audiences %q", w.PodUID, audiences)
		}
		return []*jwtsvid.SVID{svid}, nil
	}
	return minted
}

// unaryAudiences reads a token's aud claim, which a single audience serializes
// as a string and several as a list.
func unaryAudiences(claims *structpb.Struct) []string {
	aud := claims.GetFields()["aud"]
	if list := aud.GetListValue(); list != nil {
		var out []string
		for _, v := range list.GetValues() {
			out = append(out, v.GetStringValue())
		}
		return out
	}
	return []string{aud.GetStringValue()}
}

func TestFetchJWTSVID_ReturnsATokenForTheRequestedAudience(t *testing.T) {
	g := NewWithT(t)
	var minted map[unaryTokenKey]string
	h := newHarness(t, func(h *harness) { minted = unaryMintTokens(h) })

	tokens := map[string]string{}
	for _, aud := range []string{unaryAudience1, unaryAudience2} {
		resp, err := h.client.FetchJWTSVID(h.ctxFor(podA), &workload.JWTSVIDRequest{Audience: []string{aud}})
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(resp.GetSvids()).To(HaveLen(1))

		svid := resp.GetSvids()[0]
		g.Expect(svid.GetSpiffeId()).To(Equal(unaryIDFor(podA)))
		g.Expect(svid.GetSvid()).To(Equal(minted[unaryKey(podA.PodUID, []string{aud})]))
		parsed, err := jwtsvid.ParseAndValidate(svid.GetSvid(), h.jwt.bundle, []string{aud})
		g.Expect(err).ToNot(HaveOccurred(), "the token is valid for the audience it was asked for")
		g.Expect(parsed.Audience).To(Equal([]string{aud}))
		tokens[aud] = svid.GetSvid()
	}
	g.Expect(tokens[unaryAudience1]).ToNot(Equal(tokens[unaryAudience2]), "two audiences get two tokens")
}

// Two audiences in one request get one SVID carrying both, so a relying party
// for either accepts the same token.
func TestFetchJWTSVID_TwoAudiencesYieldOneSVIDCarryingBoth(t *testing.T) {
	g := NewWithT(t)
	h := newHarness(t, func(h *harness) { unaryMintTokens(h) })

	resp, err := h.client.FetchJWTSVID(h.ctxFor(podB), &workload.JWTSVIDRequest{Audience: []string{unaryAudience1, unaryAudience2}})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp.GetSvids()).To(HaveLen(1))

	svid := resp.GetSvids()[0]
	g.Expect(svid.GetSpiffeId()).To(Equal(unaryIDFor(podB)))
	for _, aud := range []string{unaryAudience1, unaryAudience2} {
		parsed, err := jwtsvid.ParseAndValidate(svid.GetSvid(), h.jwt.bundle, []string{aud})
		g.Expect(err).ToNot(HaveOccurred(), "the token is valid for %s", aud)
		g.Expect(parsed.Audience).To(ConsistOf(unaryAudience1, unaryAudience2))
	}
}

// The handler hands the token source the workload its attestor returned and the
// audiences as asked, so a caller cannot get a token minted for another pod.
func TestFetchJWTSVID_PassesTheAttestedWorkloadAndAudiences(t *testing.T) {
	g := NewWithT(t)
	h := newHarness(t, func(h *harness) { unaryMintTokens(h) })

	_, err := h.client.FetchJWTSVID(h.ctxFor(podA), &workload.JWTSVIDRequest{Audience: []string{unaryAudience1}})
	g.Expect(err).ToNot(HaveOccurred())
	_, err = h.client.FetchJWTSVID(h.ctxFor(podB), &workload.JWTSVIDRequest{Audience: []string{unaryAudience2, unaryAudience1}})
	g.Expect(err).ToNot(HaveOccurred())

	requests := h.tokens.Requests()
	g.Expect(requests).To(HaveLen(2))
	g.Expect(requests[0].Workload).To(BeIdenticalTo(podA))
	g.Expect(requests[0].Audiences).To(Equal([]string{unaryAudience1}))
	g.Expect(requests[1].Workload).To(BeIdenticalTo(podB))
	g.Expect(requests[1].Audiences).To(Equal([]string{unaryAudience2, unaryAudience1}))
}

func TestFetchJWTSVID_RejectsAMissingOrEmptyAudience(t *testing.T) {
	h := newHarness(t, func(h *harness) { unaryMintTokens(h) })

	for name, audiences := range map[string][]string{
		"no audience field":          nil,
		"an empty audience list":     {},
		"an empty-string audience":   {""},
		"one of two audiences empty": {unaryAudience1, ""},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			_, err := h.client.FetchJWTSVID(h.ctxFor(podA), &workload.JWTSVIDRequest{Audience: audiences})
			g.Expect(status.Code(err)).To(Equal(codes.InvalidArgument), "%v", err)
		})
	}
}

func TestFetchJWTSVID_FiltersByTheRequestedSpiffeID(t *testing.T) {
	g := NewWithT(t)
	h := newHarness(t, func(h *harness) { unaryMintTokens(h) })
	audiences := []string{unaryAudience1, unaryAudience2}

	resp, err := h.client.FetchJWTSVID(h.ctxFor(podA), &workload.JWTSVIDRequest{Audience: audiences, SpiffeId: unaryIDFor(podA)})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp.GetSvids()).To(HaveLen(1), "the SVID for the requested SPIFFE ID is kept")
	g.Expect(resp.GetSvids()[0].GetSpiffeId()).To(Equal(unaryIDFor(podA)))

	_, err = h.client.FetchJWTSVID(h.ctxFor(podA), &workload.JWTSVIDRequest{Audience: audiences, SpiffeId: unaryPeerID})
	g.Expect(status.Code(err)).To(Equal(codes.PermissionDenied), "%v", err)
	g.Expect(status.Convert(err).Message()).To(ContainSubstring("no identity issued"))

	for _, malformed := range []string{"not-a-spiffe-id", "spiffe://", "https://example.org/ns/ns/sa/sa-a"} {
		_, err = h.client.FetchJWTSVID(h.ctxFor(podA), &workload.JWTSVIDRequest{Audience: audiences, SpiffeId: malformed})
		g.Expect(status.Code(err)).To(Equal(codes.InvalidArgument), "spiffe_id %q: %v", malformed, err)
	}
}

// With SVIDs for two identities, the filter keeps only the requested one's.
func TestFetchJWTSVID_FilterDropsOtherIdentities(t *testing.T) {
	g := NewWithT(t)
	var peer *jwtsvid.SVID
	h := newHarness(t, func(h *harness) {
		peer = h.jwt.svid(t, unaryPeerID, unaryAudience1)
		h.tokens.Result = []*jwtsvid.SVID{h.jwt.svid(t, unaryIDFor(podA), unaryAudience1), peer}
	})

	resp, err := h.client.FetchJWTSVID(h.ctxFor(podA), &workload.JWTSVIDRequest{Audience: []string{unaryAudience1}, SpiffeId: unaryPeerID})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp.GetSvids()).To(HaveLen(1))
	g.Expect(resp.GetSvids()[0].GetSpiffeId()).To(Equal(unaryPeerID))
	g.Expect(resp.GetSvids()[0].GetSvid()).To(Equal(peer.Marshal()))
}

// FetchJWTSVID reads no bundle, so it has nothing to lease and no stream to keep
// current.
func TestFetchJWTSVID_TakesNoLeaseAndSubscribesToNothing(t *testing.T) {
	g := NewWithT(t)
	h := newHarness(t, func(h *harness) { unaryMintTokens(h) })

	_, err := h.client.FetchJWTSVID(h.ctxFor(podA), &workload.JWTSVIDRequest{Audience: []string{unaryAudience1, unaryAudience2}})
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(h.bundles.LeaseCalls()).To(BeZero())
	g.Expect(h.subs.SubscribeCalls()).To(BeZero())
	g.Expect(h.bundles.WorkloadRequests()).To(BeEmpty(), "FetchJWTSVID reads no bundle")
}

// unaryNoSVIDs makes the caller's own credentials unobtainable, so a validation
// that needed one would fail.
func unaryNoSVIDs(h *harness) {
	h.certs.Err = wierrors.ErrIssuanceFailed.Wrapf(nil, "the caller holds no X.509-SVID")
	h.tokens.Err = wierrors.ErrIssuanceFailed.Wrapf(nil, "the caller holds no JWT-SVID")
}

func TestValidateJWTSVID_AcceptsATokenSignedByAnAuthorityInTheBundle(t *testing.T) {
	g := NewWithT(t)
	h := newHarness(t, unaryNoSVIDs)
	token := h.jwt.sign(t, unaryPeerID, []string{unaryAudience1}, time.Now().Add(time.Hour))

	resp, err := h.client.ValidateJWTSVID(h.ctxFor(podA), &workload.ValidateJWTSVIDRequest{Audience: unaryAudience1, Svid: token})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp.GetSpiffeId()).To(Equal(unaryPeerID))
	g.Expect(resp.GetClaims().GetFields()["sub"].GetStringValue()).To(Equal(unaryPeerID))
	g.Expect(unaryAudiences(resp.GetClaims())).To(ContainElement(unaryAudience1))
	g.Expect(resp.GetClaims().GetFields()).To(HaveKey("exp"))

	g.Expect(h.certs.Calls()).To(BeZero(), "validation needs no X.509-SVID of the caller's")
	g.Expect(h.tokens.Calls()).To(BeZero(), "validation needs no JWT-SVID of the caller's")
	g.Expect(h.bundles.LeaseCalls()).To(BeZero())
	g.Expect(h.bundles.JWTSourceCalls()).To(Equal(1))
	g.Expect(h.bundles.WorkloadRequests()).To(HaveExactElements(BeIdenticalTo(podA)))
}

func TestValidateJWTSVID_RejectsATokenTheBundleDoesNotVouchFor(t *testing.T) {
	h := newHarness(t, unaryNoSVIDs)
	hour := time.Hour
	sameKid := newTestJWTAuthority(t, testTrustDomain, jwtKeyID)
	unknownKid := newTestJWTAuthority(t, testTrustDomain, "unknown-kid")
	otherDomain := newTestJWTAuthority(t, "other.example", jwtKeyID)
	otherID := "spiffe://other.example/ns/ns/sa/peer"

	for name, token := range map[string]string{
		"signed by another key with the same kid": sameKid.sign(t, unaryPeerID, []string{unaryAudience1}, time.Now().Add(hour)),
		"an unknown kid":                       unknownKid.sign(t, unaryPeerID, []string{unaryAudience1}, time.Now().Add(hour)),
		"another trust domain's own authority": otherDomain.sign(t, otherID, []string{unaryAudience1}, time.Now().Add(hour)),
		// Signed by the bundle's own key: only the subject's trust domain is wrong,
		// so a handler matching the kid across trust domains would accept it.
		"another trust domain, the bundle's key": h.jwt.sign(t, otherID, []string{unaryAudience1}, time.Now().Add(hour)),
		"the wrong audience":                     h.jwt.sign(t, unaryPeerID, []string{"another-audience"}, time.Now().Add(hour)),
		"expired":                                h.jwt.sign(t, unaryPeerID, []string{unaryAudience1}, time.Now().Add(-hour)),
		"not a JWT":                              "not.a.jwt",
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			leases := h.bundles.LeaseCalls()

			_, err := h.client.ValidateJWTSVID(h.ctxFor(podA), &workload.ValidateJWTSVIDRequest{Audience: unaryAudience1, Svid: token})
			g.Expect(status.Code(err)).To(Equal(codes.InvalidArgument), "%v", err)
			g.Expect(h.bundles.LeaseCalls()).To(Equal(leases))
		})
	}
	g := NewWithT(t)
	g.Expect(h.certs.Calls()).To(BeZero())
	g.Expect(h.tokens.Calls()).To(BeZero())
}

// The source is taken before the token is parsed, so an STS outage reads as
// Unavailable rather than as a bad token, and the same token validates once the
// bundle is back.
func TestValidateJWTSVID_BundleUnavailableIsUnavailableNotInvalid(t *testing.T) {
	g := NewWithT(t)
	h := newHarness(t, func(h *harness) {
		h.bundles.JWTSourceErr = wierrors.ErrBundleUnavailable.Wrapf(nil, "sts:GetTrustBundles timed out")
	})
	token := h.jwt.sign(t, unaryPeerID, []string{unaryAudience1}, time.Now().Add(time.Hour))
	req := &workload.ValidateJWTSVIDRequest{Audience: unaryAudience1, Svid: token}

	_, err := h.client.ValidateJWTSVID(h.ctxFor(podA), req)
	g.Expect(status.Code(err)).To(Equal(codes.Unavailable), "%v", err)
	g.Expect(status.Convert(err).Message()).To(ContainSubstring("sts:GetTrustBundles timed out"))
	g.Expect(status.Convert(err).Message()).ToNot(ContainSubstring("jwtsvid"), "the token is not reported as invalid")
	g.Expect(h.bundles.LeaseCalls()).To(BeZero())

	h.bundles.SetJWTSource(h.jwt.bundle, nil)
	resp, err := h.client.ValidateJWTSVID(h.ctxFor(podA), req)
	g.Expect(err).ToNot(HaveOccurred(), "the same token validates once the bundle is back")
	g.Expect(resp.GetSpiffeId()).To(Equal(unaryPeerID))
}

// The source resolves the caller's provider as T6 does, so an unenrolled caller is
// refused with the Not enrolled code and an enrolled one is served.
func TestValidateJWTSVID_NotEnrolledCallerIsPermissionDenied(t *testing.T) {
	g := NewWithT(t)
	h := newHarness(t, func(h *harness) {
		h.bundles.JWTSourceFunc = func(ctx context.Context, w *workloadidentity.Workload) (jwtbundle.Source, error) {
			if _, err := h.providers.ProviderArn(ctx, w); err != nil {
				return nil, err
			}
			return h.jwt.bundle, nil
		}
	})
	token := h.jwt.sign(t, unaryPeerID, []string{unaryAudience1}, time.Now().Add(time.Hour))
	req := &workload.ValidateJWTSVIDRequest{Audience: unaryAudience1, Svid: token}

	_, err := h.client.ValidateJWTSVID(h.ctxFor(podUnenrolled), req)
	g.Expect(status.Code(err)).To(Equal(codes.PermissionDenied), "%v", err)

	_, err = h.client.ValidateJWTSVID(h.ctxFor(podA), req)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(h.bundles.LeaseCalls()).To(BeZero())
}

func TestValidateJWTSVID_RejectsAMissingAudienceOrSVID(t *testing.T) {
	h := newHarness(t)
	token := h.jwt.sign(t, unaryPeerID, []string{unaryAudience1}, time.Now().Add(time.Hour))

	for name, req := range map[string]*workload.ValidateJWTSVIDRequest{
		"no audience": {Svid: token},
		"no svid":     {Audience: unaryAudience1},
		"neither":     {},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			_, err := h.client.ValidateJWTSVID(h.ctxFor(podA), req)
			g.Expect(status.Code(err)).To(Equal(codes.InvalidArgument), "%v", err)
			g.Expect(h.bundles.LeaseCalls()).To(BeZero())
		})
	}
}

// unaryCallerOp is one RPC that reads bundles, run as a caller until the handler
// has finished with it, and what it should have read.
type unaryCallerOp struct {
	name string
	// stream ops open, receive the first response and cancel; the run returns once
	// the handler's deferred releases have run.
	stream bool
	run    func(g Gomega, ctx context.Context)
	// reads reports how many times the op's own bundle read ran so far.
	reads func() int
}

// Every BundleSource call carries the caller's attested workload, on every RPC
// that reads bundles and on every stream's Lease. One harness serves both callers
// in turn, so a handler reusing one caller's workload for the next, or passing
// nil, leaves a wrong pointer in the second caller's window.
func TestWorkloadAPI_EveryBundleSourceCallCarriesTheAttestedCaller(t *testing.T) {
	g := NewWithT(t)
	h := newHarness(t)
	token := h.jwt.sign(t, unaryPeerID, []string{unaryAudience1}, time.Now().Add(time.Hour))

	ops := []unaryCallerOp{
		{name: "FetchX509SVID", stream: true, reads: h.bundles.X509BundlesCalls, run: func(g Gomega, ctx context.Context) {
			s, err := h.client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
			g.Expect(err).ToNot(HaveOccurred())
			_, err = s.Recv()
			g.Expect(err).ToNot(HaveOccurred())
		}},
		{name: "FetchX509Bundles", stream: true, reads: h.bundles.X509BundlesCalls, run: func(g Gomega, ctx context.Context) {
			s, err := h.client.FetchX509Bundles(ctx, &workload.X509BundlesRequest{})
			g.Expect(err).ToNot(HaveOccurred())
			_, err = s.Recv()
			g.Expect(err).ToNot(HaveOccurred())
		}},
		{name: "FetchJWTBundles", stream: true, reads: h.bundles.JWTBundlesCalls, run: func(g Gomega, ctx context.Context) {
			s, err := h.client.FetchJWTBundles(ctx, &workload.JWTBundlesRequest{})
			g.Expect(err).ToNot(HaveOccurred())
			_, err = s.Recv()
			g.Expect(err).ToNot(HaveOccurred())
		}},
		{name: "ValidateJWTSVID", reads: h.bundles.JWTSourceCalls, run: func(g Gomega, ctx context.Context) {
			_, err := h.client.ValidateJWTSVID(ctx, &workload.ValidateJWTSVIDRequest{Audience: unaryAudience1, Svid: token})
			g.Expect(err).ToNot(HaveOccurred())
		}},
	}

	for _, caller := range []*workloadidentity.Workload{podA, podB} {
		for _, op := range ops {
			before := len(h.bundles.WorkloadRequests())
			leases, reads, cancels := h.bundles.LeaseCalls(), op.reads(), h.subs.CancelCalls()

			ctx, cancel := context.WithCancel(h.ctxFor(caller))
			op.run(g, ctx)
			cancel()
			if op.stream {
				// The handler releases its subscription in a defer, after the lease's,
				// so once it has run the stream has made its last BundleSource call.
				g.Eventually(h.subs.CancelCalls, 5*time.Second, time.Millisecond).Should(Equal(cancels+1), "%s as %s", op.name, caller.PodName)
			}

			window := h.bundles.WorkloadRequests()[before:]
			g.Expect(window).To(HaveEach(BeIdenticalTo(caller)),
				"%s as %s: every BundleSource call carries the attested caller, never nil or another pod", op.name, caller.PodName)
			g.Expect(op.reads()).To(BeNumerically(">", reads), "%s as %s read its bundles", op.name, caller.PodName)
			if op.stream {
				g.Expect(h.bundles.LeaseCalls()).To(Equal(leases+1), "%s as %s took one lease", op.name, caller.PodName)
			} else {
				g.Expect(h.bundles.LeaseCalls()).To(Equal(leases), "%s as %s took no lease", op.name, caller.PodName)
			}
		}
	}
	g.Expect(h.bundles.LiveLeases()).To(BeZero())
}

// A rejected token reaches neither the caller's status message nor the agent's
// log, whichever way it is rejected. The payload and signature segments are
// checked as well, since either half of a token is enough to leak it.
func TestValidateJWTSVID_NeverLogsOrEchoesTheToken(t *testing.T) {
	g := NewWithT(t)
	hook := logtest.NewLocal(logger.FromContext(context.Background()).Logger)
	t.Cleanup(hook.Reset)
	h := newHarness(t)
	other := newTestJWTAuthority(t, testTrustDomain, jwtKeyID)

	cases := []struct {
		name  string
		token string
		code  codes.Code
		// unavailable fails the bundle read first, so the token never reaches
		// ParseAndValidate.
		unavailable bool
	}{
		{name: "wrong audience", token: h.jwt.sign(t, unaryPeerID, []string{"another-audience"}, time.Now().Add(time.Hour)), code: codes.InvalidArgument},
		{name: "another key", token: other.sign(t, unaryPeerID, []string{unaryAudience1}, time.Now().Add(time.Hour)), code: codes.InvalidArgument},
		{name: "expired", token: h.jwt.sign(t, unaryPeerID, []string{unaryAudience1}, time.Now().Add(-time.Hour)), code: codes.InvalidArgument},
		{name: "another trust domain", token: h.jwt.sign(t, "spiffe://other.example/ns/ns/sa/peer", []string{unaryAudience1}, time.Now().Add(time.Hour)), code: codes.InvalidArgument},
		{name: "bundle unavailable", token: h.jwt.sign(t, unaryPeerID, []string{unaryAudience1}, time.Now().Add(time.Hour)), code: codes.Unavailable, unavailable: true},
	}
	var secrets []string
	for _, c := range cases {
		parts := strings.Split(c.token, ".")
		g.Expect(parts).To(HaveLen(3))
		secrets = append(secrets, c.token, parts[1], parts[2])

		if c.unavailable {
			h.bundles.SetJWTSource(nil, wierrors.ErrBundleUnavailable.Wrapf(nil, "sts:GetTrustBundles timed out"))
		} else {
			h.bundles.SetJWTSource(h.jwt.bundle, nil)
		}
		_, err := h.client.ValidateJWTSVID(h.ctxFor(podA), &workload.ValidateJWTSVIDRequest{Audience: unaryAudience1, Svid: c.token})
		g.Expect(status.Code(err)).To(Equal(c.code), "%s: %v", c.name, err)
		for _, secret := range parts[1:] {
			g.Expect(err.Error()).ToNot(ContainSubstring(secret), "%s: the status message carries the token", c.name)
		}
		g.Expect(err.Error()).ToNot(ContainSubstring(c.token), "%s: the status message carries the token", c.name)
	}

	// Without this the test would pass on a hook that captured nothing.
	refusals := 0
	for _, entry := range hook.AllEntries() {
		if entry.Data["rpc"] == workloadidentity.RPCValidateJWTSVID {
			refusals++
		}
		text := entry.Message
		for key, value := range entry.Data {
			text += fmt.Sprintf(" %s=%v", key, value)
		}
		for _, secret := range secrets {
			g.Expect(text).ToNot(ContainSubstring(secret), "a log entry carries a token: %q", entry.Message)
		}
	}
	g.Expect(refusals).To(BeNumerically(">=", len(cases)), "every refusal is logged, so the scan above saw them")
}
