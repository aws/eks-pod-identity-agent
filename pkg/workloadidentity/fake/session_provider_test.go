package fake

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	. "github.com/onsi/gomega"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// sessionProviderGateTimeout bounds every wait in this file, so a fake that
// never wakes a parked call fails the test instead of hanging the suite.
const sessionProviderGateTimeout = 2 * time.Second

// sessionResult is one returned pair from a Session call made on another
// goroutine.
type sessionResult struct {
	session *workloadidentity.WorkloadSession
	err     error
}

// expectWorkloadSessionEqual asserts every field of got against want, including
// every field of the embedded AWS credentials.
func expectWorkloadSessionEqual(g *WithT, got, want *workloadidentity.WorkloadSession) {
	g.Expect(got).To(Not(BeNil()))
	g.Expect(got.Credentials.AccessKeyID).To(Equal(want.Credentials.AccessKeyID))
	g.Expect(got.Credentials.SecretAccessKey).To(Equal(want.Credentials.SecretAccessKey))
	g.Expect(got.Credentials.SessionToken).To(Equal(want.Credentials.SessionToken))
	g.Expect(got.Credentials.Source).To(Equal(want.Credentials.Source))
	g.Expect(got.Credentials.CanExpire).To(Equal(want.Credentials.CanExpire))
	g.Expect(got.Credentials.Expires).To(Equal(want.Credentials.Expires))
	g.Expect(got.Credentials.AccountID).To(Equal(want.Credentials.AccountID))
	g.Expect(got.ProviderArn).To(Equal(want.ProviderArn))
	g.Expect(got.ExpiresAt).To(Equal(want.ExpiresAt))
}

// newTestWorkloadSession builds a fully populated session, so a test asserting
// every field has a value in every field to assert.
func newTestWorkloadSession(accessKeyID string, expiresAt time.Time) *workloadidentity.WorkloadSession {
	return &workloadidentity.WorkloadSession{
		Credentials: aws.Credentials{
			AccessKeyID:     accessKeyID,
			SecretAccessKey: "some-secret-key",
			SessionToken:    "some-session-token",
			Source:          "some-source",
			CanExpire:       true,
			Expires:         expiresAt,
			AccountID:       "some-account-id",
		},
		ProviderArn: "arn:aws:eks:us-west-2:000000000000:podidentityassociation/some-cluster/some-association",
		ExpiresAt:   expiresAt,
	}
}

func TestSessionProviderSession_CannedFields_ReturnsSessionOrError(t *testing.T) {
	var (
		expiresAt   = time.Date(1996, 3, 27, 7, 45, 23, 123_456_789, time.UTC)
		session     = newTestWorkloadSession("AKIACANNED", expiresAt)
		funcSession = newTestWorkloadSession("AKIAFUNC", expiresAt.Add(time.Hour))
		sessionErr  = errors.New("some session error")
		funcErr     = errors.New("some func error")
	)

	testCases := []struct {
		name        string
		provider    *SessionProvider
		wantSession *workloadidentity.WorkloadSession
		wantErr     error
	}{
		{
			name:        "canned session",
			provider:    &SessionProvider{Result: session},
			wantSession: session,
		},
		{
			name:     "canned error wins over canned session",
			provider: &SessionProvider{Result: session, Err: sessionErr},
			wantErr:  sessionErr,
		},
		{
			name: "func wins over canned session and error",
			provider: &SessionProvider{
				Result: session,
				Err:    sessionErr,
				Func: func(ctx context.Context, w *workloadidentity.Workload) (*workloadidentity.WorkloadSession, error) {
					return funcSession, nil
				},
			},
			wantSession: funcSession,
		},
		{
			name: "func error",
			provider: &SessionProvider{
				Result: session,
				Func: func(ctx context.Context, w *workloadidentity.Workload) (*workloadidentity.WorkloadSession, error) {
					return nil, funcErr
				},
			},
			wantErr: funcErr,
		},
		{
			name:     "zero value returns nothing",
			provider: &SessionProvider{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			ctx, cancel := context.WithTimeout(context.Background(), sessionProviderGateTimeout)
			t.Cleanup(cancel)
			w := &workloadidentity.Workload{
				PodUID:         "some-pod-uid",
				PodName:        "some-pod",
				Namespace:      "some-namespace",
				ServiceAccount: "some-service-account",
				NodeName:       "some-node",
			}

			got, err := tc.provider.Session(ctx, w)

			if tc.wantErr != nil {
				g.Expect(err).To(MatchError(tc.wantErr))
				g.Expect(got).To(BeNil())
			} else {
				g.Expect(err).To(Not(HaveOccurred()))
				if tc.wantSession == nil {
					g.Expect(got).To(BeNil())
				} else {
					g.Expect(got).To(BeIdenticalTo(tc.wantSession))
					expectWorkloadSessionEqual(g, got, tc.wantSession)
				}
			}
			g.Expect(tc.provider.Calls()).To(Equal(1))
			g.Expect(tc.provider.Workloads()).To(Equal([]*workloadidentity.Workload{w}))
			g.Expect(tc.provider.InvalidateCalls()).To(Equal(0))
			g.Expect(tc.provider.Invalidated()).To(BeEmpty())
		})
	}
}

func TestSessionProviderSession_ThreeCalls_CountsAndRecordsWorkloadsInCallOrder(t *testing.T) {
	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), sessionProviderGateTimeout)
	t.Cleanup(cancel)

	want := newTestWorkloadSession("AKIACANNED",
		time.Date(1996, 3, 27, 7, 45, 23, 0, time.UTC))
	provider := &SessionProvider{Result: want}
	workloads := []*workloadidentity.Workload{
		{PodUID: "uid-1", PodName: "pod-1", Namespace: "ns-1", ServiceAccount: "sa-1", NodeName: "node-1"},
		{PodUID: "uid-2", PodName: "pod-2", Namespace: "ns-2", ServiceAccount: "sa-2", NodeName: "node-1"},
		{PodUID: "uid-3", PodName: "pod-3", Namespace: "ns-3", ServiceAccount: "sa-3", NodeName: "node-1"},
	}

	g.Expect(provider.Calls()).To(Equal(0))
	g.Expect(provider.Workloads()).To(BeEmpty())

	for _, w := range workloads {
		got, err := provider.Session(ctx, w)
		g.Expect(err).To(Not(HaveOccurred()))
		expectWorkloadSessionEqual(g, got, want)
	}

	g.Expect(provider.Calls()).To(Equal(3))
	recorded := provider.Workloads()
	g.Expect(recorded).To(HaveLen(3))
	for i, w := range workloads {
		g.Expect(recorded[i]).To(BeIdenticalTo(w))
		g.Expect(*recorded[i]).To(Equal(*w))
	}

	// The recorded slice is a copy, so mutating it cannot rewrite the fake.
	recorded[0] = nil
	g.Expect(provider.Workloads()[0]).To(BeIdenticalTo(workloads[0]))
}

func TestSessionProviderSetResult_WhileLive_ChangesLaterCalls(t *testing.T) {
	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), sessionProviderGateTimeout)
	t.Cleanup(cancel)

	var (
		expiresAt  = time.Date(1996, 3, 27, 7, 45, 23, 0, time.UTC)
		first      = newTestWorkloadSession("AKIAFIRST", expiresAt)
		second     = newTestWorkloadSession("AKIASECOND", expiresAt.Add(time.Hour))
		sessionErr = errors.New("some session error")
	)
	provider := &SessionProvider{Result: first}
	w := &workloadidentity.Workload{PodUID: "some-pod-uid", PodName: "some-pod"}

	got, err := provider.Session(ctx, w)
	g.Expect(err).To(Not(HaveOccurred()))
	expectWorkloadSessionEqual(g, got, first)

	provider.SetResult(second, nil)
	got, err = provider.Session(ctx, w)
	g.Expect(err).To(Not(HaveOccurred()))
	expectWorkloadSessionEqual(g, got, second)

	provider.SetResult(nil, sessionErr)
	got, err = provider.Session(ctx, w)
	g.Expect(err).To(MatchError(sessionErr))
	g.Expect(got).To(BeNil())

	g.Expect(provider.Calls()).To(Equal(3))
}

func TestSessionProviderInvalidate_ThreeCalls_CountsAndRecordsPodUIDsInCallOrder(t *testing.T) {
	g := NewWithT(t)

	provider := &SessionProvider{}
	podUIDs := []string{"uid-1", "uid-2", "uid-1"}

	g.Expect(provider.InvalidateCalls()).To(Equal(0))
	g.Expect(provider.Invalidated()).To(BeEmpty())

	for _, podUID := range podUIDs {
		provider.Invalidate(podUID)
	}

	g.Expect(provider.InvalidateCalls()).To(Equal(3))
	g.Expect(provider.Invalidated()).To(Equal([]string{"uid-1", "uid-2", "uid-1"}))
	// Invalidate is not a Session call, so it moves neither counter.
	g.Expect(provider.Calls()).To(Equal(0))
	g.Expect(provider.Workloads()).To(BeEmpty())

	// The returned slice is a copy, so mutating it cannot rewrite the fake.
	recorded := provider.Invalidated()
	recorded[0] = "mutated"
	g.Expect(provider.Invalidated()).To(Equal([]string{"uid-1", "uid-2", "uid-1"}))
}

func TestSessionProviderInvalidate_GateBlocked_ReturnsWithoutParking(t *testing.T) {
	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), sessionProviderGateTimeout)
	t.Cleanup(cancel)

	provider := &SessionProvider{}
	provider.Block()

	done := make(chan struct{})
	go func() {
		provider.Invalidate("some-pod-uid")
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("Invalidate parked at the gate; it takes no context and must not")
	}

	g.Expect(provider.InvalidateCalls()).To(Equal(1))
	g.Expect(provider.Invalidated()).To(Equal([]string{"some-pod-uid"}))
	g.Expect(provider.Blocked()).To(Equal(0))
}

func TestSessionProviderSession_DoneContext_ReturnsContextErrorAndCountsNothing(t *testing.T) {
	g := NewWithT(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	provider := &SessionProvider{Result: newTestWorkloadSession("AKIACANNED",
		time.Date(1996, 3, 27, 7, 45, 23, 0, time.UTC))}

	got, err := provider.Session(ctx, &workloadidentity.Workload{PodUID: "some-pod-uid"})

	g.Expect(err).To(MatchError(context.Canceled))
	g.Expect(got).To(BeNil())
	g.Expect(provider.Calls()).To(Equal(0))
	g.Expect(provider.Workloads()).To(BeEmpty())
	g.Expect(provider.Blocked()).To(Equal(0))
}

func TestSessionProviderSession_GateBlocked_ParksUntilReleased(t *testing.T) {
	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), sessionProviderGateTimeout)
	t.Cleanup(cancel)

	want := newTestWorkloadSession("AKIAPARKED",
		time.Date(1996, 3, 27, 7, 45, 23, 0, time.UTC))
	provider := &SessionProvider{Result: want}
	w := &workloadidentity.Workload{PodUID: "some-pod-uid", PodName: "some-pod"}
	provider.Block()

	done := make(chan sessionResult, 1)
	go func() {
		session, err := provider.Session(ctx, w)
		done <- sessionResult{session: session, err: err}
	}()

	g.Expect(provider.WaitForBlocked(ctx, 1)).To(Succeed())
	g.Expect(provider.Blocked()).To(Equal(1))
	g.Expect(provider.Calls()).To(Equal(0))
	g.Expect(provider.Workloads()).To(BeEmpty())

	// The call is parked at the gate, so it cannot have returned yet.
	select {
	case got := <-done:
		t.Fatalf("Session returned while the gate was closed: %+v, %v", got.session, got.err)
	default:
	}

	// Invalidate does not go through the gate, so it lands while Session waits.
	provider.Invalidate("some-pod-uid")

	provider.Release()

	var got sessionResult
	select {
	case got = <-done:
	case <-ctx.Done():
		t.Fatal("Session did not return after Release")
	}

	g.Expect(got.err).To(Not(HaveOccurred()))
	g.Expect(got.session).To(BeIdenticalTo(want))
	expectWorkloadSessionEqual(g, got.session, want)
	g.Expect(provider.Calls()).To(Equal(1))
	g.Expect(provider.Workloads()).To(Equal([]*workloadidentity.Workload{w}))
	g.Expect(provider.InvalidateCalls()).To(Equal(1))
	g.Expect(provider.Invalidated()).To(Equal([]string{"some-pod-uid"}))
	g.Expect(provider.Blocked()).To(Equal(0))
}

func TestSessionProviderSession_ParkedCallCancelled_ReturnsContextError(t *testing.T) {
	g := NewWithT(t)
	waitCtx, waitCancel := context.WithTimeout(context.Background(), sessionProviderGateTimeout)
	t.Cleanup(waitCancel)
	callCtx, callCancel := context.WithCancel(context.Background())
	t.Cleanup(callCancel)

	provider := &SessionProvider{Result: newTestWorkloadSession("AKIAPARKED",
		time.Date(1996, 3, 27, 7, 45, 23, 0, time.UTC))}
	provider.Block()

	done := make(chan sessionResult, 1)
	go func() {
		session, err := provider.Session(callCtx, &workloadidentity.Workload{PodUID: "some-pod-uid"})
		done <- sessionResult{session: session, err: err}
	}()

	g.Expect(provider.WaitForBlocked(waitCtx, 1)).To(Succeed())
	callCancel()

	var got sessionResult
	select {
	case got = <-done:
	case <-waitCtx.Done():
		t.Fatal("Session stayed parked after its context was cancelled")
	}

	g.Expect(got.err).To(MatchError(context.Canceled))
	g.Expect(got.session).To(BeNil())
	g.Expect(provider.Blocked()).To(Equal(0))
	g.Expect(provider.Calls()).To(Equal(0))
	g.Expect(provider.Workloads()).To(BeEmpty())
}

func TestSessionProviderSession_FiveParkedCallsAndConcurrentInvalidates_AllRecorded(t *testing.T) {
	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), sessionProviderGateTimeout)
	t.Cleanup(cancel)

	const callers = 5
	want := newTestWorkloadSession("AKIASHARED",
		time.Date(1996, 3, 27, 7, 45, 23, 0, time.UTC))
	provider := &SessionProvider{Result: want}
	provider.Block()

	sessions := make(chan sessionResult, callers)
	for i := 0; i < callers; i++ {
		go func() {
			session, err := provider.Session(ctx, &workloadidentity.Workload{PodUID: "some-pod-uid"})
			sessions <- sessionResult{session: session, err: err}
		}()
	}

	g.Expect(provider.WaitForBlocked(ctx, callers)).To(Succeed())
	g.Expect(provider.Calls()).To(Equal(0))

	invalidated := make(chan struct{}, callers)
	for i := 0; i < callers; i++ {
		go func() {
			provider.Invalidate("some-pod-uid")
			invalidated <- struct{}{}
		}()
	}
	for i := 0; i < callers; i++ {
		select {
		case <-invalidated:
		case <-ctx.Done():
			t.Fatalf("only %d of %d Invalidate calls returned while Session was parked", i, callers)
		}
	}

	provider.Release()

	for i := 0; i < callers; i++ {
		var got sessionResult
		select {
		case got = <-sessions:
		case <-ctx.Done():
			t.Fatalf("only %d of %d parked Session calls returned after Release", i, callers)
		}
		g.Expect(got.err).To(Not(HaveOccurred()))
		g.Expect(got.session).To(BeIdenticalTo(want))
		expectWorkloadSessionEqual(g, got.session, want)
	}

	g.Expect(provider.Calls()).To(Equal(callers))
	g.Expect(provider.Workloads()).To(HaveLen(callers))
	g.Expect(provider.InvalidateCalls()).To(Equal(callers))
	g.Expect(provider.Invalidated()).To(HaveLen(callers))
	g.Expect(provider.Blocked()).To(Equal(0))
}
