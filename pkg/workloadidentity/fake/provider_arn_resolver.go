package fake

import (
	"context"
	"slices"
	"sync"

	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// ProviderArnResolver is a fake workloadidentity.ProviderArnResolver. It answers
// a pod named in Arns with its entry and any other pod with Arn, unless Func or
// Err is set, and records the workloads it was asked about. A pod neither Arns
// nor Arn names is ErrNotEnrolled, as the contract requires.
//
// Set the fields before use; they are not safe to write once a call can be in
// flight.
type ProviderArnResolver struct {
	// Arns maps a pod UID to its provider ARN.
	Arns map[string]string
	// Arn is a test convenience the real resolver has no counterpart for: the
	// provider of every pod Arns does not name, so a test that needs one provider
	// for all its pods sets only this.
	Arn string
	// Err, when non-nil and Func is nil, is returned with an empty ARN.
	Err error
	// Func, when non-nil, wins: ProviderArn returns whatever it returns.
	Func func(ctx context.Context, w *workloadidentity.Workload) (string, error)

	mu        sync.Mutex
	workloads []*workloadidentity.Workload
}

// ProviderArn records w and returns Func's answer, Err, or w's canned ARN.
func (r *ProviderArnResolver) ProviderArn(ctx context.Context, w *workloadidentity.Workload) (string, error) {
	func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.workloads = append(r.workloads, w)
	}()
	switch {
	case r.Func != nil:
		return r.Func(ctx, w)
	case r.Err != nil:
		return "", r.Err
	}
	if w != nil {
		if arn, ok := r.Arns[w.PodUID]; ok {
			return arn, nil
		}
	}
	if r.Arn == "" {
		return "", wierrors.ErrNotEnrolled.Wrapf(nil, "the fake resolver names no provider for this workload")
	}
	return r.Arn, nil
}

// Workloads returns a copy of the workloads ProviderArn was called with, in call
// order, so it is safe to read while another goroutine is calling the fake.
func (r *ProviderArnResolver) Workloads() []*workloadidentity.Workload {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.workloads)
}

var _ workloadidentity.ProviderArnResolver = &ProviderArnResolver{}
