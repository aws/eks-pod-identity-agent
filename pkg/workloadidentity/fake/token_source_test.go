package fake

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	. "github.com/onsi/gomega"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// tokenSourceTestTimeout bounds every wait in this file, so a fake that never
// releases a parked call fails the test instead of hanging the suite.
const tokenSourceTestTimeout = 2 * time.Second

// tokenSourceTestWorkload is the attested caller the canned JWT-SVIDs are
// issued for.
var tokenSourceTestWorkload = &workloadidentity.Workload{
	PodUID:         "pod-uid-1",
	PodName:        "my-pod",
	Namespace:      "my-namespace",
	ServiceAccount: "my-service-account",
	NodeName:       "my-node",
}

// tokenSourceJWTSVIDResult is what a JWTSVIDs call running in another goroutine
// hands back to the test.
type tokenSourceJWTSVIDResult struct {
	svids []*jwtsvid.SVID
	err   error
}

// tokenSourceSVID builds a fully populated JWT-SVID, so every field is available
// to assert on. It signs a real token and parses it, because a jwtsvid.SVID
// literal has no token and would make the token assertion vacuous.
func tokenSourceSVID(t *testing.T, audience string) *jwtsvid.SVID {
	t.Helper()
	g := NewWithT(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	g.Expect(err).To(Not(HaveOccurred()))
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"))
	g.Expect(err).To(Not(HaveOccurred()))
	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Subject:  "spiffe://example.org/my-pod",
		Audience: jwt.Audience{audience},
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).Serialize()
	g.Expect(err).To(Not(HaveOccurred()))
	svid, err := jwtsvid.ParseInsecure(token, []string{audience})
	g.Expect(err).To(Not(HaveOccurred()))
	svid.Hint = "hint-for-" + audience
	return svid
}

// tokenSourceExpectSVID asserts every field of a returned JWT-SVID.
func tokenSourceExpectSVID(g *WithT, got, want *jwtsvid.SVID) {
	g.Expect(got).To(Not(BeNil()))
	g.Expect(got.ID).To(Equal(want.ID))
	g.Expect(got.Marshal()).To(Not(BeEmpty()))
	g.Expect(got.Marshal()).To(Equal(want.Marshal()))
	g.Expect(got.Audience).To(Equal(want.Audience))
	g.Expect(got.Expiry).To(Equal(want.Expiry))
	g.Expect(got.Claims).To(Equal(want.Claims))
	g.Expect(got.Hint).To(Equal(want.Hint))
}

func TestTokenSourceJWTSVIDs_CannedBehaviour_ReturnsThatBehaviour(t *testing.T) {
	cannedErr := errors.New("jwt issuance failed")
	first := tokenSourceSVID(t, "aud-1")
	second := tokenSourceSVID(t, "aud-2")
	byAudience := map[string]*jwtsvid.SVID{"aud-1": first, "aud-2": second}

	testCases := []struct {
		name        string
		source      *TokenSource
		audiences   []string
		expected    []*jwtsvid.SVID
		expectedErr error
	}{
		{
			name:      "zero value returns no svids and no error",
			source:    &TokenSource{},
			audiences: []string{"aud-1"},
			expected:  nil,
		},
		{
			name:      "canned result is returned for one audience",
			source:    &TokenSource{Result: []*jwtsvid.SVID{first}},
			audiences: []string{"aud-1"},
			expected:  []*jwtsvid.SVID{first},
		},
		{
			name:      "canned result is returned unchanged for several audiences",
			source:    &TokenSource{Result: []*jwtsvid.SVID{first, second}},
			audiences: []string{"aud-1", "aud-2", "aud-3"},
			expected:  []*jwtsvid.SVID{first, second},
		},
		{
			name:        "canned error wins over canned result",
			source:      &TokenSource{Result: []*jwtsvid.SVID{first}, Err: cannedErr},
			audiences:   []string{"aud-1"},
			expectedErr: cannedErr,
		},
		{
			name: "func wins over canned result and canned error",
			source: &TokenSource{
				Result: []*jwtsvid.SVID{first},
				Err:    cannedErr,
				Func: func(_ context.Context, _ *workloadidentity.Workload, audiences []string) ([]*jwtsvid.SVID, error) {
					svids := make([]*jwtsvid.SVID, 0, len(audiences))
					for _, audience := range audiences {
						svids = append(svids, byAudience[audience])
					}
					return svids, nil
				},
			},
			audiences: []string{"aud-1", "aud-2"},
			expected:  []*jwtsvid.SVID{first, second},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := tc.source.JWTSVIDs(context.Background(), tokenSourceTestWorkload, tc.audiences)

			if tc.expectedErr != nil {
				g.Expect(err).To(MatchError(tc.expectedErr))
				g.Expect(got).To(BeNil())
			} else {
				g.Expect(err).To(Not(HaveOccurred()))
				g.Expect(got).To(HaveLen(len(tc.expected)))
				for i := range tc.expected {
					tokenSourceExpectSVID(g, got[i], tc.expected[i])
				}
			}
			g.Expect(tc.source.Calls()).To(Equal(1))
			g.Expect(tc.source.Requests()).To(Equal([]JWTSVIDRequest{{
				Workload:  tokenSourceTestWorkload,
				Audiences: tc.audiences,
			}}))
			g.Expect(tc.source.Blocked()).To(Equal(0))
		})
	}
}

func TestTokenSourceJWTSVIDs_CalledRepeatedly_CountsCallsAndRecordsRequests(t *testing.T) {
	g := NewWithT(t)

	other := &workloadidentity.Workload{
		PodUID:         "pod-uid-2",
		PodName:        "other-pod",
		Namespace:      "other-namespace",
		ServiceAccount: "other-service-account",
		NodeName:       "my-node",
	}
	source := &TokenSource{Result: []*jwtsvid.SVID{tokenSourceSVID(t, "aud-1")}}

	g.Expect(source.Calls()).To(Equal(0))
	g.Expect(source.Requests()).To(BeEmpty())

	_, err := source.JWTSVIDs(context.Background(), tokenSourceTestWorkload, []string{"aud-1"})
	g.Expect(err).To(Not(HaveOccurred()))
	_, err = source.JWTSVIDs(context.Background(), other, []string{"aud-2", "aud-3"})
	g.Expect(err).To(Not(HaveOccurred()))
	_, err = source.JWTSVIDs(context.Background(), tokenSourceTestWorkload, nil)
	g.Expect(err).To(Not(HaveOccurred()))

	g.Expect(source.Calls()).To(Equal(3))

	requests := source.Requests()
	g.Expect(requests).To(HaveLen(3))
	g.Expect(requests[0].Workload).To(BeIdenticalTo(tokenSourceTestWorkload))
	g.Expect(*requests[0].Workload).To(Equal(*tokenSourceTestWorkload))
	g.Expect(requests[0].Audiences).To(Equal([]string{"aud-1"}))
	g.Expect(requests[1].Workload).To(BeIdenticalTo(other))
	g.Expect(*requests[1].Workload).To(Equal(*other))
	g.Expect(requests[1].Audiences).To(Equal([]string{"aud-2", "aud-3"}))
	g.Expect(requests[2].Workload).To(BeIdenticalTo(tokenSourceTestWorkload))
	g.Expect(requests[2].Audiences).To(BeNil())

	// Requests hands back a copy of the outer slice, so a test mutating it
	// cannot rewrite the record.
	requests[0] = JWTSVIDRequest{}
	g.Expect(source.Requests()[0].Workload).To(BeIdenticalTo(tokenSourceTestWorkload))
	g.Expect(source.Requests()[0].Audiences).To(Equal([]string{"aud-1"}))
}

func TestTokenSourceJWTSVIDs_CallerMutatesAudiences_RecordedAudiencesUnaffected(t *testing.T) {
	g := NewWithT(t)

	source := &TokenSource{Result: []*jwtsvid.SVID{tokenSourceSVID(t, "aud-1")}}
	audiences := []string{"aud-1", "aud-2"}

	_, err := source.JWTSVIDs(context.Background(), tokenSourceTestWorkload, audiences)
	g.Expect(err).To(Not(HaveOccurred()))

	audiences[0] = "mutated"

	g.Expect(source.Requests()).To(Equal([]JWTSVIDRequest{{
		Workload:  tokenSourceTestWorkload,
		Audiences: []string{"aud-1", "aud-2"},
	}}))
}

func TestTokenSourceJWTSVIDs_FuncSet_ReceivesCallersAudiencesNotTheRecordedCopy(t *testing.T) {
	g := NewWithT(t)

	var seen []string
	source := &TokenSource{
		Func: func(_ context.Context, _ *workloadidentity.Workload, audiences []string) ([]*jwtsvid.SVID, error) {
			seen = audiences
			return nil, nil
		},
	}
	audiences := []string{"aud-1"}

	_, err := source.JWTSVIDs(context.Background(), tokenSourceTestWorkload, audiences)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(seen).To(Equal([]string{"aud-1"}))

	// Func was handed the caller's own slice, so mutating it is visible through
	// seen, while the recorded copy keeps what the caller originally asked for.
	audiences[0] = "mutated"

	g.Expect(seen).To(Equal([]string{"mutated"}))
	g.Expect(source.Requests()).To(Equal([]JWTSVIDRequest{{
		Workload:  tokenSourceTestWorkload,
		Audiences: []string{"aud-1"},
	}}))
}

func TestTokenSourceJWTSVIDs_ReturnedSliceMutated_NextCallIsUnaffected(t *testing.T) {
	g := NewWithT(t)

	canned := tokenSourceSVID(t, "aud-1")
	source := &TokenSource{Result: []*jwtsvid.SVID{canned}}

	got, err := source.JWTSVIDs(context.Background(), tokenSourceTestWorkload, []string{"aud-1"})
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(HaveLen(1))
	tokenSourceExpectSVID(g, got[0], canned)

	got[0] = tokenSourceSVID(t, "mutated")

	again, err := source.JWTSVIDs(context.Background(), tokenSourceTestWorkload, []string{"aud-1"})
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(again).To(HaveLen(1))
	tokenSourceExpectSVID(g, again[0], canned)
	g.Expect(again[0]).To(BeIdenticalTo(canned))
	g.Expect(source.Calls()).To(Equal(2))
}

func TestTokenSourceSetResult_CalledWhileLive_ReplacesCannedBehaviour(t *testing.T) {
	g := NewWithT(t)

	first := tokenSourceSVID(t, "aud-1")
	second := tokenSourceSVID(t, "aud-2")
	cannedErr := errors.New("jwt issuance failed")
	source := &TokenSource{Result: []*jwtsvid.SVID{first}}

	got, err := source.JWTSVIDs(context.Background(), tokenSourceTestWorkload, []string{"aud-1"})
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(HaveLen(1))
	tokenSourceExpectSVID(g, got[0], first)

	source.SetResult([]*jwtsvid.SVID{second}, nil)
	got, err = source.JWTSVIDs(context.Background(), tokenSourceTestWorkload, []string{"aud-2"})
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(HaveLen(1))
	tokenSourceExpectSVID(g, got[0], second)

	source.SetResult(nil, cannedErr)
	got, err = source.JWTSVIDs(context.Background(), tokenSourceTestWorkload, []string{"aud-2"})
	g.Expect(err).To(MatchError(cannedErr))
	g.Expect(got).To(BeNil())

	g.Expect(source.Calls()).To(Equal(3))
}

func TestTokenSourceJWTSVIDs_GateBlocked_ReturnsCannedResultAfterRelease(t *testing.T) {
	g := NewWithT(t)

	canned := tokenSourceSVID(t, "aud-1")
	source := &TokenSource{Result: []*jwtsvid.SVID{canned}}
	source.Block()

	ctx, cancel := context.WithTimeout(context.Background(), tokenSourceTestTimeout)
	t.Cleanup(cancel)

	done := make(chan tokenSourceJWTSVIDResult, 1)
	go func() {
		svids, err := source.JWTSVIDs(ctx, tokenSourceTestWorkload, []string{"aud-1"})
		done <- tokenSourceJWTSVIDResult{svids: svids, err: err}
	}()

	g.Expect(source.WaitForBlocked(ctx, 1)).To(Succeed())
	g.Expect(source.Blocked()).To(Equal(1))
	g.Expect(done).To(Not(Receive()))
	g.Expect(source.Calls()).To(Equal(0))
	g.Expect(source.Requests()).To(BeEmpty())

	source.Release()

	var got tokenSourceJWTSVIDResult
	select {
	case got = <-done:
	case <-ctx.Done():
		t.Fatalf("JWTSVIDs did not return after Release: %v", ctx.Err())
	}

	g.Expect(got.err).To(Not(HaveOccurred()))
	g.Expect(got.svids).To(HaveLen(1))
	tokenSourceExpectSVID(g, got.svids[0], canned)
	g.Expect(source.Calls()).To(Equal(1))
	g.Expect(source.Requests()).To(Equal([]JWTSVIDRequest{{
		Workload:  tokenSourceTestWorkload,
		Audiences: []string{"aud-1"},
	}}))
	g.Expect(source.Blocked()).To(Equal(0))
}

func TestTokenSourceJWTSVIDs_ParkedCallContextCancelled_ReturnsContextError(t *testing.T) {
	g := NewWithT(t)

	source := &TokenSource{Result: []*jwtsvid.SVID{tokenSourceSVID(t, "aud-1")}}
	source.Block()

	waitCtx, cancelWait := context.WithTimeout(context.Background(), tokenSourceTestTimeout)
	t.Cleanup(cancelWait)
	callCtx, cancelCall := context.WithCancel(context.Background())
	t.Cleanup(cancelCall)

	done := make(chan tokenSourceJWTSVIDResult, 1)
	go func() {
		svids, err := source.JWTSVIDs(callCtx, tokenSourceTestWorkload, []string{"aud-1"})
		done <- tokenSourceJWTSVIDResult{svids: svids, err: err}
	}()

	g.Expect(source.WaitForBlocked(waitCtx, 1)).To(Succeed())
	cancelCall()

	var got tokenSourceJWTSVIDResult
	select {
	case got = <-done:
	case <-waitCtx.Done():
		t.Fatalf("JWTSVIDs did not return after its context was cancelled: %v", waitCtx.Err())
	}

	g.Expect(got.err).To(MatchError(context.Canceled))
	g.Expect(got.svids).To(BeNil())
	g.Expect(source.Calls()).To(Equal(0))
	g.Expect(source.Requests()).To(BeEmpty())
	g.Expect(source.Blocked()).To(Equal(0))
}

func TestTokenSourceJWTSVIDs_ContextAlreadyDone_ReturnsContextErrorWithoutParking(t *testing.T) {
	g := NewWithT(t)

	source := &TokenSource{Result: []*jwtsvid.SVID{tokenSourceSVID(t, "aud-1")}}
	source.Block()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := source.JWTSVIDs(ctx, tokenSourceTestWorkload, []string{"aud-1"})

	g.Expect(err).To(MatchError(context.Canceled))
	g.Expect(got).To(BeNil())
	g.Expect(source.Calls()).To(Equal(0))
	g.Expect(source.Requests()).To(BeEmpty())
	g.Expect(source.Blocked()).To(Equal(0))
}
