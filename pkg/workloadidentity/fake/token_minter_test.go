package fake

import (
	"context"
	"errors"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// tokenMinterGateTimeout bounds every wait in this file, so a fake that never
// wakes a parked call fails the test instead of hanging the suite.
const tokenMinterGateTimeout = 2 * time.Second

// mintResult is one returned pair from a Mint call made on another goroutine.
type mintResult struct {
	token *workloadidentity.ProjectedToken
	err   error
}

// expectProjectedTokenEqual asserts every field of got against want.
func expectProjectedTokenEqual(g *WithT, got, want *workloadidentity.ProjectedToken) {
	g.Expect(got).To(Not(BeNil()))
	g.Expect(got.Token).To(Equal(want.Token))
	g.Expect(got.ExpiresAt).To(Equal(want.ExpiresAt))
}

func TestTokenMinterMint_CannedFields_ReturnsTokenOrError(t *testing.T) {
	var (
		expiresAt = time.Date(1996, 3, 27, 7, 45, 23, 123_456_789, time.UTC)
		token     = &workloadidentity.ProjectedToken{
			Token:     "some-projected-token",
			ExpiresAt: expiresAt,
		}
		funcToken = &workloadidentity.ProjectedToken{
			Token:     "some-func-token",
			ExpiresAt: expiresAt.Add(time.Hour),
		}
		mintErr = errors.New("some mint error")
		funcErr = errors.New("some func error")
	)

	testCases := []struct {
		name      string
		minter    *TokenMinter
		wantToken *workloadidentity.ProjectedToken
		wantErr   error
	}{
		{
			name:      "canned token",
			minter:    &TokenMinter{Result: token},
			wantToken: token,
		},
		{
			name:    "canned error wins over canned token",
			minter:  &TokenMinter{Result: token, Err: mintErr},
			wantErr: mintErr,
		},
		{
			name: "func wins over canned token and error",
			minter: &TokenMinter{
				Result: token,
				Err:    mintErr,
				Func: func(ctx context.Context, w *workloadidentity.Workload) (*workloadidentity.ProjectedToken, error) {
					return funcToken, nil
				},
			},
			wantToken: funcToken,
		},
		{
			name: "func error",
			minter: &TokenMinter{
				Result: token,
				Func: func(ctx context.Context, w *workloadidentity.Workload) (*workloadidentity.ProjectedToken, error) {
					return nil, funcErr
				},
			},
			wantErr: funcErr,
		},
		{
			name:   "zero value returns nothing",
			minter: &TokenMinter{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			ctx, cancel := context.WithTimeout(context.Background(), tokenMinterGateTimeout)
			t.Cleanup(cancel)
			w := &workloadidentity.Workload{
				PodUID:         "some-pod-uid",
				PodName:        "some-pod",
				Namespace:      "some-namespace",
				ServiceAccount: "some-service-account",
				NodeName:       "some-node",
			}

			got, err := tc.minter.Mint(ctx, w)

			if tc.wantErr != nil {
				g.Expect(err).To(MatchError(tc.wantErr))
				g.Expect(got).To(BeNil())
			} else {
				g.Expect(err).To(Not(HaveOccurred()))
				if tc.wantToken == nil {
					g.Expect(got).To(BeNil())
				} else {
					g.Expect(got).To(BeIdenticalTo(tc.wantToken))
					expectProjectedTokenEqual(g, got, tc.wantToken)
				}
			}
			g.Expect(tc.minter.Calls()).To(Equal(1))
			g.Expect(tc.minter.Workloads()).To(Equal([]*workloadidentity.Workload{w}))
		})
	}
}

func TestTokenMinterMint_ThreeCalls_CountsAndRecordsWorkloadsInCallOrder(t *testing.T) {
	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), tokenMinterGateTimeout)
	t.Cleanup(cancel)

	minter := &TokenMinter{Result: &workloadidentity.ProjectedToken{
		Token:     "some-projected-token",
		ExpiresAt: time.Date(1996, 3, 27, 7, 45, 23, 0, time.UTC),
	}}
	workloads := []*workloadidentity.Workload{
		{PodUID: "uid-1", PodName: "pod-1", Namespace: "ns-1", ServiceAccount: "sa-1", NodeName: "node-1"},
		{PodUID: "uid-2", PodName: "pod-2", Namespace: "ns-2", ServiceAccount: "sa-2", NodeName: "node-1"},
		{PodUID: "uid-3", PodName: "pod-3", Namespace: "ns-3", ServiceAccount: "sa-3", NodeName: "node-1"},
	}

	g.Expect(minter.Calls()).To(Equal(0))
	g.Expect(minter.Workloads()).To(BeEmpty())

	for _, w := range workloads {
		got, err := minter.Mint(ctx, w)
		g.Expect(err).To(Not(HaveOccurred()))
		expectProjectedTokenEqual(g, got, minter.Result)
	}

	g.Expect(minter.Calls()).To(Equal(3))
	recorded := minter.Workloads()
	g.Expect(recorded).To(HaveLen(3))
	for i, w := range workloads {
		g.Expect(recorded[i]).To(BeIdenticalTo(w))
		g.Expect(*recorded[i]).To(Equal(*w))
	}

	// The recorded slice is a copy, so mutating it cannot rewrite the fake.
	recorded[0] = nil
	g.Expect(minter.Workloads()[0]).To(BeIdenticalTo(workloads[0]))
}

func TestTokenMinterSetResult_WhileLive_ChangesLaterCalls(t *testing.T) {
	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), tokenMinterGateTimeout)
	t.Cleanup(cancel)

	var (
		first = &workloadidentity.ProjectedToken{
			Token:     "first-token",
			ExpiresAt: time.Date(1996, 3, 27, 7, 45, 23, 0, time.UTC),
		}
		second = &workloadidentity.ProjectedToken{
			Token:     "second-token",
			ExpiresAt: time.Date(1996, 3, 27, 8, 45, 23, 0, time.UTC),
		}
		mintErr = errors.New("some mint error")
	)
	minter := &TokenMinter{Result: first}
	w := &workloadidentity.Workload{PodUID: "some-pod-uid", PodName: "some-pod"}

	got, err := minter.Mint(ctx, w)
	g.Expect(err).To(Not(HaveOccurred()))
	expectProjectedTokenEqual(g, got, first)

	minter.SetResult(second, nil)
	got, err = minter.Mint(ctx, w)
	g.Expect(err).To(Not(HaveOccurred()))
	expectProjectedTokenEqual(g, got, second)

	minter.SetResult(nil, mintErr)
	got, err = minter.Mint(ctx, w)
	g.Expect(err).To(MatchError(mintErr))
	g.Expect(got).To(BeNil())

	g.Expect(minter.Calls()).To(Equal(3))
}

func TestTokenMinterMint_DoneContext_ReturnsContextErrorAndCountsNothing(t *testing.T) {
	g := NewWithT(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	minter := &TokenMinter{Result: &workloadidentity.ProjectedToken{Token: "some-projected-token"}}

	got, err := minter.Mint(ctx, &workloadidentity.Workload{PodUID: "some-pod-uid"})

	g.Expect(err).To(MatchError(context.Canceled))
	g.Expect(got).To(BeNil())
	g.Expect(minter.Calls()).To(Equal(0))
	g.Expect(minter.Workloads()).To(BeEmpty())
	g.Expect(minter.Blocked()).To(Equal(0))
}

func TestTokenMinterMint_GateBlocked_ParksUntilReleased(t *testing.T) {
	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), tokenMinterGateTimeout)
	t.Cleanup(cancel)

	want := &workloadidentity.ProjectedToken{
		Token:     "parked-token",
		ExpiresAt: time.Date(1996, 3, 27, 7, 45, 23, 0, time.UTC),
	}
	minter := &TokenMinter{Result: want}
	w := &workloadidentity.Workload{PodUID: "some-pod-uid", PodName: "some-pod"}
	minter.Block()

	done := make(chan mintResult, 1)
	go func() {
		token, err := minter.Mint(ctx, w)
		done <- mintResult{token: token, err: err}
	}()

	g.Expect(minter.WaitForBlocked(ctx, 1)).To(Succeed())
	g.Expect(minter.Blocked()).To(Equal(1))
	g.Expect(minter.Calls()).To(Equal(0))
	g.Expect(minter.Workloads()).To(BeEmpty())

	// The call is parked at the gate, so it cannot have returned yet.
	select {
	case got := <-done:
		t.Fatalf("Mint returned while the gate was closed: %+v, %v", got.token, got.err)
	default:
	}

	minter.Release()

	var got mintResult
	select {
	case got = <-done:
	case <-ctx.Done():
		t.Fatal("Mint did not return after Release")
	}

	g.Expect(got.err).To(Not(HaveOccurred()))
	g.Expect(got.token).To(BeIdenticalTo(want))
	expectProjectedTokenEqual(g, got.token, want)
	g.Expect(minter.Calls()).To(Equal(1))
	g.Expect(minter.Workloads()).To(Equal([]*workloadidentity.Workload{w}))
	g.Expect(minter.Blocked()).To(Equal(0))
}

func TestTokenMinterMint_ParkedCallCancelled_ReturnsContextError(t *testing.T) {
	g := NewWithT(t)
	waitCtx, waitCancel := context.WithTimeout(context.Background(), tokenMinterGateTimeout)
	t.Cleanup(waitCancel)
	callCtx, callCancel := context.WithCancel(context.Background())
	t.Cleanup(callCancel)

	minter := &TokenMinter{Result: &workloadidentity.ProjectedToken{Token: "parked-token"}}
	minter.Block()

	done := make(chan mintResult, 1)
	go func() {
		token, err := minter.Mint(callCtx, &workloadidentity.Workload{PodUID: "some-pod-uid"})
		done <- mintResult{token: token, err: err}
	}()

	g.Expect(minter.WaitForBlocked(waitCtx, 1)).To(Succeed())
	callCancel()

	var got mintResult
	select {
	case got = <-done:
	case <-waitCtx.Done():
		t.Fatal("Mint stayed parked after its context was cancelled")
	}

	g.Expect(got.err).To(MatchError(context.Canceled))
	g.Expect(got.token).To(BeNil())
	g.Expect(minter.Blocked()).To(Equal(0))
	g.Expect(minter.Calls()).To(Equal(0))
	g.Expect(minter.Workloads()).To(BeEmpty())
}

func TestTokenMinterMint_FiveParkedCalls_AllReturnCannedTokenAfterRelease(t *testing.T) {
	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), tokenMinterGateTimeout)
	t.Cleanup(cancel)

	const callers = 5
	want := &workloadidentity.ProjectedToken{
		Token:     "shared-token",
		ExpiresAt: time.Date(1996, 3, 27, 7, 45, 23, 0, time.UTC),
	}
	minter := &TokenMinter{Result: want}
	minter.Block()

	done := make(chan mintResult, callers)
	for i := 0; i < callers; i++ {
		go func() {
			token, err := minter.Mint(ctx, &workloadidentity.Workload{PodUID: "some-pod-uid"})
			done <- mintResult{token: token, err: err}
		}()
	}

	g.Expect(minter.WaitForBlocked(ctx, callers)).To(Succeed())
	g.Expect(minter.Calls()).To(Equal(0))

	minter.Release()

	for i := 0; i < callers; i++ {
		var got mintResult
		select {
		case got = <-done:
		case <-ctx.Done():
			t.Fatalf("only %d of %d parked Mint calls returned after Release", i, callers)
		}
		g.Expect(got.err).To(Not(HaveOccurred()))
		g.Expect(got.token).To(BeIdenticalTo(want))
		expectProjectedTokenEqual(g, got.token, want)
	}

	g.Expect(minter.Calls()).To(Equal(callers))
	g.Expect(minter.Workloads()).To(HaveLen(callers))
	g.Expect(minter.Blocked()).To(Equal(0))
}
