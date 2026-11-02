package bundle

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	. "github.com/onsi/gomega"

	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// recordingSigner signs with one fixed key, as the node role would, and records
// the pods each call was made for.
type recordingSigner struct {
	mu    sync.Mutex
	calls [][]string
}

func (s *recordingSigner) Credentials(_ context.Context, _ string, workloads []*workloadidentity.Workload) (aws.Credentials, error) {
	uids := []string{}
	for _, w := range workloads {
		uids = append(uids, w.PodUID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, uids)
	return aws.Credentials{AccessKeyID: "AKID-signer", SecretAccessKey: "secret"}, nil
}

func (s *recordingSigner) Calls() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]string(nil), s.calls...)
}

func TestWorkloadSessionSigner_SignsWithTheFirstSessionThatStillNamesTheProvider(t *testing.T) {
	g := NewWithT(t)
	sessions := newTestSessions()
	sessions.assign("moved", otherProviderArn)
	sessions.fail("broken", wierrors.ErrSessionUnavailable)
	sessions.assign("first", testProviderArn)
	sessions.assign("second", testProviderArn)

	creds, err := WorkloadSessionSigner(sessions).Credentials(context.Background(), testProviderArn,
		[]*workloadidentity.Workload{pod("moved"), pod("broken"), pod("first"), pod("second")})

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(creds.AccessKeyID).To(Equal("AKID-first"))
}

func TestWorkloadSessionSigner_WithNoUsableSession_IsARetryableUnavailable(t *testing.T) {
	g := NewWithT(t)
	sessions := newTestSessions()
	sessions.assign("moved", otherProviderArn)
	sessions.fail("broken", wierrors.ErrSessionUnavailable)
	signer := WorkloadSessionSigner(sessions)

	_, err := signer.Credentials(context.Background(), testProviderArn, []*workloadidentity.Workload{pod("moved"), pod("broken")})

	g.Expect(err).To(MatchError(wierrors.ErrBundleUnavailable))
	g.Expect(wierrors.IsRetryable(err)).To(BeTrue())
	g.Expect(err).To(MatchError(ContainSubstring(`pod moved: its session names provider "`+otherProviderArn+`"`)), "every workload's reason, not only the last")
	g.Expect(err).To(MatchError(ContainSubstring("pod broken: ")))
	g.Expect(errors.Is(err, wierrors.ErrSessionUnavailable)).To(BeTrue(), "a session error stays matchable")

	_, err = signer.Credentials(context.Background(), testProviderArn, nil)
	g.Expect(err).To(MatchError(wierrors.ErrBundleUnavailable))
	g.Expect(err).To(MatchError(ContainSubstring("no workload to sign as")))
}
