package workloadidentity

import (
	"context"

	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
)

// SessionProviderArns is the launch ProviderArnResolver: it reads the ARN off the
// workload's session, passing a session error through unchanged.
func SessionProviderArns(sessions SessionProvider) ProviderArnResolver {
	return sessionProviderArns{sessions: sessions}
}

type sessionProviderArns struct {
	sessions SessionProvider
}

func (r sessionProviderArns) ProviderArn(ctx context.Context, w *Workload) (string, error) {
	session, err := r.sessions.Session(ctx, w)
	if err != nil {
		return "", err
	}
	if session.ProviderArn == "" {
		return "", wierrors.ErrNotEnrolled.Wrapf(nil, "the workload's session names no workload identity provider")
	}
	return session.ProviderArn, nil
}
