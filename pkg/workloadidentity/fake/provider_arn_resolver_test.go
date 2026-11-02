package fake

import (
	"context"
	"errors"
	"testing"

	. "github.com/onsi/gomega"

	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

func TestProviderArnResolver_AnswersByPodThenTheDefault(t *testing.T) {
	g := NewWithT(t)
	resolver := &ProviderArnResolver{Arn: "default-arn", Arns: map[string]string{"pod-a": "arn-a"}}
	podA, podB := &workloadidentity.Workload{PodUID: "pod-a"}, &workloadidentity.Workload{PodUID: "pod-b"}

	a, errA := resolver.ProviderArn(context.Background(), podA)
	b, errB := resolver.ProviderArn(context.Background(), podB)

	g.Expect(errA).ToNot(HaveOccurred())
	g.Expect(errB).ToNot(HaveOccurred())
	g.Expect(a).To(Equal("arn-a"))
	g.Expect(b).To(Equal("default-arn"))
	g.Expect(resolver.Workloads()).To(Equal([]*workloadidentity.Workload{podA, podB}))
}

func TestProviderArnResolver_FuncWinsOverErrWhichWinsOverTheArns(t *testing.T) {
	g := NewWithT(t)
	errCanned := errors.New("canned")
	w := &workloadidentity.Workload{PodUID: "pod-a"}
	resolver := &ProviderArnResolver{Arn: "default-arn", Err: errCanned}

	_, err := resolver.ProviderArn(context.Background(), w)
	g.Expect(err).To(MatchError(errCanned))

	resolver.Func = func(context.Context, *workloadidentity.Workload) (string, error) { return "from-func", nil }
	arn, err := resolver.ProviderArn(context.Background(), w)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(arn).To(Equal("from-func"))
}

func TestProviderArnResolver_APodNothingNames_IsNotEnrolled(t *testing.T) {
	g := NewWithT(t)
	resolver := &ProviderArnResolver{Arns: map[string]string{"pod-a": "arn-a"}}

	arn, err := resolver.ProviderArn(context.Background(), &workloadidentity.Workload{PodUID: "pod-b"})

	g.Expect(err).To(MatchError(wierrors.ErrNotEnrolled))
	g.Expect(arn).To(BeEmpty())
}
