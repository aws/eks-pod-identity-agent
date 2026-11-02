package bundle

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"

	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// Signer returns the credentials GetTrustBundles is signed with, so moving from
// workload sessions to the node role is a wiring change. workloads are the
// workloads it may sign as, in order of preference: for a read, the reader; for a
// refresh, the provider's leaseholders and then its latest reader. A signer that
// signs as no workload, such as the node role, ignores them.
type Signer interface {
	Credentials(ctx context.Context, providerArn string, workloads []*workloadidentity.Workload) (aws.Credentials, error)
}

// WorkloadSessionSigner is the launch Signer: it signs with the session of the
// first workload whose session still names the provider. With none it returns
// ErrBundleUnavailable joining every workload's reason.
func WorkloadSessionSigner(sessions workloadidentity.SessionProvider) Signer {
	return workloadSessionSigner{sessions: sessions}
}

type workloadSessionSigner struct {
	sessions workloadidentity.SessionProvider
}

func (s workloadSessionSigner) Credentials(ctx context.Context, providerArn string, workloads []*workloadidentity.Workload) (aws.Credentials, error) {
	var reasons []error
	for _, w := range workloads {
		session, err := s.sessions.Session(ctx, w)
		switch {
		case err != nil:
			reasons = append(reasons, fmt.Errorf("pod %s: %w", w.PodUID, err))
		case session.ProviderArn != providerArn:
			reasons = append(reasons, fmt.Errorf("pod %s: its session names provider %q", w.PodUID, session.ProviderArn))
		default:
			return session.Credentials, nil
		}
	}
	if len(workloads) == 0 {
		reasons = append(reasons, errors.New("no workload to sign as"))
	}
	return aws.Credentials{}, wierrors.ErrBundleUnavailable.Wrapf(errors.Join(reasons...), "no workload session can sign GetTrustBundles for %s", providerArn)
}
