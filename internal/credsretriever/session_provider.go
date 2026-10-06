package credsretriever

// This file is a placeholder for the workload identity session tier. It
// declares the public API so the tiers built on it can be written against it;
// the implementation lands separately.

import (
	"context"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// SessionProviderOpts configures NewSessionProvider. The fields are the session
// tier's, so the wiring can pass them now; the placeholder reads none of them.
type SessionProviderOpts struct {
	// ClusterName is the EKS cluster the agent runs in.
	ClusterName string
	// Minter obtains the projected token each exchange presents.
	Minter workloadidentity.TokenMinter
	// Cache is the retriever NewCachedCredentialRetriever returned. The session
	// tier stores into it and exchanges through its delegate.
	Cache credentials.CredentialRetriever
}

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
