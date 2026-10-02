package workloadidentity_test

import (
	"context"
	"testing"

	. "github.com/onsi/gomega"

	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity/fake"
)

func TestSessionProviderArns_ReadsTheArnOffTheWorkloadsSession(t *testing.T) {
	g := NewWithT(t)
	const providerArn = "arn:aws:iam::111122223333:workload-identity-provider/example"
	sessions := &fake.SessionProvider{Result: &workloadidentity.WorkloadSession{ProviderArn: providerArn}}
	w := &workloadidentity.Workload{PodUID: "pod"}

	arn, err := workloadidentity.SessionProviderArns(sessions).ProviderArn(context.Background(), w)

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(arn).To(Equal(providerArn))
	g.Expect(sessions.Workloads()).To(Equal([]*workloadidentity.Workload{w}))
}

func TestSessionProviderArns_SessionNamingNoProvider_IsNotEnrolled(t *testing.T) {
	g := NewWithT(t)
	sessions := &fake.SessionProvider{Result: &workloadidentity.WorkloadSession{}}

	arn, err := workloadidentity.SessionProviderArns(sessions).ProviderArn(context.Background(), &workloadidentity.Workload{PodUID: "pod"})

	g.Expect(err).To(MatchError(wierrors.ErrNotEnrolled))
	g.Expect(arn).To(BeEmpty())
}

func TestSessionProviderArns_SessionError_PassesThrough(t *testing.T) {
	g := NewWithT(t)
	sessions := &fake.SessionProvider{Err: wierrors.ErrSessionUnavailable}

	_, err := workloadidentity.SessionProviderArns(sessions).ProviderArn(context.Background(), &workloadidentity.Workload{PodUID: "pod"})

	g.Expect(err).To(MatchError(wierrors.ErrSessionUnavailable))
}
