package fake

import (
	"context"
	"crypto/ed25519"
	cryptox509 "crypto/x509"
	"errors"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// certSourceTestTimeout bounds every wait in this file, so a fake that never
// releases a parked call fails the test instead of hanging the suite.
const certSourceTestTimeout = 2 * time.Second

// certSourceTestKey is a deterministic signer for the canned X.509-SVIDs, so an
// assertion on the PrivateKey field compares equal across calls.
var certSourceTestKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

// certSourceTestWorkload is the attested caller the canned SVIDs are issued for.
var certSourceTestWorkload = &workloadidentity.Workload{
	PodUID:         "pod-uid-1",
	PodName:        "my-pod",
	Namespace:      "my-namespace",
	ServiceAccount: "my-service-account",
	NodeName:       "my-node",
}

// certSourceX509SVIDResult is what a X509SVIDs call running in another goroutine
// hands back to the test.
type certSourceX509SVIDResult struct {
	svids []*x509svid.SVID
	err   error
}

// certSourceSVID builds a fully populated X.509-SVID, so every field is
// available to assert on.
//
// The certificates are placeholders rather than signed ones. This fake only passes
// values through, so nothing here parses them, and the validity window the real tier
// reads off a leaf is tested where that happens instead.
func certSourceSVID(id string) *x509svid.SVID {
	return &x509svid.SVID{
		ID: spiffeid.RequireFromString(id),
		Certificates: []*cryptox509.Certificate{
			{Raw: []byte(id + "/leaf-der")},
			{Raw: []byte(id + "/intermediate-der")},
		},
		PrivateKey: certSourceTestKey,
		Hint:       id + "/hint",
	}
}

// certSourceExpectSVID asserts every field of a returned X.509-SVID.
func certSourceExpectSVID(g *WithT, got, want *x509svid.SVID) {
	g.Expect(got).To(Not(BeNil()))
	g.Expect(got.ID).To(Equal(want.ID))
	g.Expect(got.Certificates).To(Equal(want.Certificates))
	g.Expect(got.PrivateKey).To(Equal(want.PrivateKey))
	g.Expect(got.Hint).To(Equal(want.Hint))
}

func TestCertSourceX509SVIDs_CannedBehaviour_ReturnsThatBehaviour(t *testing.T) {
	cannedErr := errors.New("cert source unavailable")
	first := certSourceSVID("spiffe://example.org/first")
	second := certSourceSVID("spiffe://example.org/second")

	testCases := []struct {
		name        string
		source      *CertSource
		expected    []*x509svid.SVID
		expectedErr error
	}{
		{
			name:     "zero value returns no svids and no error",
			source:   &CertSource{},
			expected: nil,
		},
		{
			name:     "canned result is returned",
			source:   &CertSource{Result: []*x509svid.SVID{first, second}},
			expected: []*x509svid.SVID{first, second},
		},
		{
			name:        "canned error wins over canned result",
			source:      &CertSource{Result: []*x509svid.SVID{first}, Err: cannedErr},
			expectedErr: cannedErr,
		},
		{
			name: "func wins over canned result and canned error",
			source: &CertSource{
				Result: []*x509svid.SVID{first},
				Err:    cannedErr,
				Func: func(_ context.Context, _ *workloadidentity.Workload) ([]*x509svid.SVID, error) {
					return []*x509svid.SVID{second}, nil
				},
			},
			expected: []*x509svid.SVID{second},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := tc.source.X509SVIDs(context.Background(), certSourceTestWorkload)

			if tc.expectedErr != nil {
				g.Expect(err).To(MatchError(tc.expectedErr))
				g.Expect(got).To(BeNil())
			} else {
				g.Expect(err).To(Not(HaveOccurred()))
				g.Expect(got).To(HaveLen(len(tc.expected)))
				for i := range tc.expected {
					certSourceExpectSVID(g, got[i], tc.expected[i])
					g.Expect(got[i]).To(BeIdenticalTo(tc.expected[i]))
				}
			}
			g.Expect(tc.source.Calls()).To(Equal(1))
			g.Expect(tc.source.Workloads()).To(Equal([]*workloadidentity.Workload{certSourceTestWorkload}))
			g.Expect(tc.source.Blocked()).To(Equal(0))
		})
	}
}

func TestCertSourceX509SVIDs_CalledRepeatedly_CountsCallsAndRecordsWorkloads(t *testing.T) {
	g := NewWithT(t)

	other := &workloadidentity.Workload{
		PodUID:         "pod-uid-2",
		PodName:        "other-pod",
		Namespace:      "other-namespace",
		ServiceAccount: "other-service-account",
		NodeName:       "my-node",
	}
	source := &CertSource{Result: []*x509svid.SVID{certSourceSVID("spiffe://example.org/first")}}

	g.Expect(source.Calls()).To(Equal(0))
	g.Expect(source.Workloads()).To(BeEmpty())

	for _, w := range []*workloadidentity.Workload{certSourceTestWorkload, other, certSourceTestWorkload} {
		_, err := source.X509SVIDs(context.Background(), w)
		g.Expect(err).To(Not(HaveOccurred()))
	}

	g.Expect(source.Calls()).To(Equal(3))
	g.Expect(source.Workloads()).To(Equal([]*workloadidentity.Workload{certSourceTestWorkload, other, certSourceTestWorkload}))

	// Workloads hands back a copy, so a test mutating it cannot rewrite the record.
	recorded := source.Workloads()
	recorded[0] = nil
	g.Expect(source.Workloads()[0]).To(BeIdenticalTo(certSourceTestWorkload))
}

func TestCertSourceX509SVIDs_ReturnedSliceMutated_NextCallIsUnaffected(t *testing.T) {
	g := NewWithT(t)

	canned := certSourceSVID("spiffe://example.org/first")
	source := &CertSource{Result: []*x509svid.SVID{canned}}

	got, err := source.X509SVIDs(context.Background(), certSourceTestWorkload)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(HaveLen(1))
	certSourceExpectSVID(g, got[0], canned)

	got[0] = certSourceSVID("spiffe://example.org/mutated")

	again, err := source.X509SVIDs(context.Background(), certSourceTestWorkload)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(again).To(HaveLen(1))
	certSourceExpectSVID(g, again[0], canned)
	g.Expect(again[0]).To(BeIdenticalTo(canned))
	g.Expect(source.Calls()).To(Equal(2))
}

func TestCertSourceSetResult_CalledWhileLive_ReplacesCannedBehaviour(t *testing.T) {
	g := NewWithT(t)

	first := certSourceSVID("spiffe://example.org/first")
	second := certSourceSVID("spiffe://example.org/second")
	cannedErr := errors.New("cert source unavailable")
	source := &CertSource{Result: []*x509svid.SVID{first}}

	got, err := source.X509SVIDs(context.Background(), certSourceTestWorkload)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(HaveLen(1))
	certSourceExpectSVID(g, got[0], first)

	source.SetResult([]*x509svid.SVID{second}, nil)
	got, err = source.X509SVIDs(context.Background(), certSourceTestWorkload)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(HaveLen(1))
	certSourceExpectSVID(g, got[0], second)

	source.SetResult(nil, cannedErr)
	got, err = source.X509SVIDs(context.Background(), certSourceTestWorkload)
	g.Expect(err).To(MatchError(cannedErr))
	g.Expect(got).To(BeNil())

	g.Expect(source.Calls()).To(Equal(3))
}

func TestCertSourceX509SVIDs_GateBlocked_ReturnsCannedResultAfterRelease(t *testing.T) {
	g := NewWithT(t)

	canned := certSourceSVID("spiffe://example.org/first")
	source := &CertSource{Result: []*x509svid.SVID{canned}}
	source.Block()

	ctx, cancel := context.WithTimeout(context.Background(), certSourceTestTimeout)
	t.Cleanup(cancel)

	done := make(chan certSourceX509SVIDResult, 1)
	go func() {
		svids, err := source.X509SVIDs(ctx, certSourceTestWorkload)
		done <- certSourceX509SVIDResult{svids: svids, err: err}
	}()

	g.Expect(source.WaitForBlocked(ctx, 1)).To(Succeed())
	g.Expect(source.Blocked()).To(Equal(1))
	g.Expect(done).To(Not(Receive()))
	g.Expect(source.Calls()).To(Equal(0))
	g.Expect(source.Workloads()).To(BeEmpty())

	source.Release()

	var got certSourceX509SVIDResult
	select {
	case got = <-done:
	case <-ctx.Done():
		t.Fatalf("X509SVIDs did not return after Release: %v", ctx.Err())
	}

	g.Expect(got.err).To(Not(HaveOccurred()))
	g.Expect(got.svids).To(HaveLen(1))
	certSourceExpectSVID(g, got.svids[0], canned)
	g.Expect(source.Calls()).To(Equal(1))
	g.Expect(source.Workloads()).To(Equal([]*workloadidentity.Workload{certSourceTestWorkload}))
	g.Expect(source.Blocked()).To(Equal(0))
}

func TestCertSourceX509SVIDs_ParkedCallContextCancelled_ReturnsContextError(t *testing.T) {
	g := NewWithT(t)

	source := &CertSource{Result: []*x509svid.SVID{certSourceSVID("spiffe://example.org/first")}}
	source.Block()

	waitCtx, cancelWait := context.WithTimeout(context.Background(), certSourceTestTimeout)
	t.Cleanup(cancelWait)
	callCtx, cancelCall := context.WithCancel(context.Background())
	t.Cleanup(cancelCall)

	done := make(chan certSourceX509SVIDResult, 1)
	go func() {
		svids, err := source.X509SVIDs(callCtx, certSourceTestWorkload)
		done <- certSourceX509SVIDResult{svids: svids, err: err}
	}()

	g.Expect(source.WaitForBlocked(waitCtx, 1)).To(Succeed())
	cancelCall()

	var got certSourceX509SVIDResult
	select {
	case got = <-done:
	case <-waitCtx.Done():
		t.Fatalf("X509SVIDs did not return after its context was cancelled: %v", waitCtx.Err())
	}

	g.Expect(got.err).To(MatchError(context.Canceled))
	g.Expect(got.svids).To(BeNil())
	g.Expect(source.Calls()).To(Equal(0))
	g.Expect(source.Workloads()).To(BeEmpty())
	g.Expect(source.Blocked()).To(Equal(0))
}

func TestCertSourceX509SVIDs_ContextAlreadyDone_ReturnsContextErrorWithoutParking(t *testing.T) {
	g := NewWithT(t)

	source := &CertSource{Result: []*x509svid.SVID{certSourceSVID("spiffe://example.org/first")}}
	source.Block()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := source.X509SVIDs(ctx, certSourceTestWorkload)

	g.Expect(err).To(MatchError(context.Canceled))
	g.Expect(got).To(BeNil())
	g.Expect(source.Calls()).To(Equal(0))
	g.Expect(source.Workloads()).To(BeEmpty())
	g.Expect(source.Blocked()).To(Equal(0))
}
