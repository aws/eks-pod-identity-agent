package credsretriever

// This file is a placeholder for the workload identity session tier. It
// declares the public API so the tiers built on it can be written against it;
// the implementation lands separately.

import (
	"context"

	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// SessionProviderOpts configures NewSessionProvider.
type SessionProviderOpts struct{}

// SessionProvider is the workloadidentity.SessionProvider the agent uses.
type SessionProvider struct{}

var _ workloadidentity.SessionProvider = (*SessionProvider)(nil)

// NewSessionProvider builds a SessionProvider from opts.
func NewSessionProvider(opts SessionProviderOpts) (*SessionProvider, error) {
	return &SessionProvider{}, nil
}

// Session returns the workload's AWS session. Until the session tier lands it
// answers ErrSessionUnavailable.
func (p *SessionProvider) Session(ctx context.Context, w *workloadidentity.Workload) (*workloadidentity.WorkloadSession, error) {
	return nil, wierrors.ErrSessionUnavailable.Wrapf(nil, "the session tier is not implemented yet")
}

// Invalidate drops any cached session for the pod. It does nothing yet.
func (p *SessionProvider) Invalidate(podUID string) {}
