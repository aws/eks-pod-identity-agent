// Package tokenminter mints a pod-bound ServiceAccount token (PSAT) for an
// attested workload via the Kubernetes TokenRequest API and caches it per pod.
// The token is minted with the node credential (the shared internal/kube
// client) and every field comes from the attested Workload, never the caller.
//
// minter.go holds the raw mint; cache.go the caching and renewal; csidriver.go
// the CSIDriver object the mint depends on.
package tokenminter

import (
	"context"

	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// boundObjectKind ties the token to the pod it was minted for.
//
// It is not by itself a revocation mechanism. Per the BoundObjectRef API docs,
// the reference is validated by the API server's TokenReview endpoint, and
// "other audiences may not" validate it. EKS Auth is another audience, so a
// token whose pod has been deleted may stay usable there until it expires. That
// window is expirationSeconds, which is why the mint sets it rather than leaving
// it to the server.
const boundObjectKind = "Pod"

// tokenLifetimeSeconds is the lifetime requested for every mint.
const tokenLifetimeSeconds int64 = 3600

// apiMinter is the uncached TokenMinter backed by the API server,
// authenticating as the node identity (internal/kube.NewNodeClient). CachedMinter
// wraps one.
type apiMinter struct {
	client kubernetes.Interface
}

func newAPIMinter(client kubernetes.Interface) *apiMinter {
	return &apiMinter{client: client}
}

// Mint requests a pod-bound token scoped to the EKS Auth audience for
// tokenLifetimeSeconds.
func (m *apiMinter) Mint(ctx context.Context, w *workloadidentity.Workload) (*workloadidentity.ProjectedToken, error) {
	// TokenRequestSpec takes a pointer, so the lifetime is copied per request
	// rather than shared from a package variable.
	lifetime := tokenLifetimeSeconds
	req := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         []string{configuration.EksAuthAudience},
			ExpirationSeconds: &lifetime,
			BoundObjectRef: &authenticationv1.BoundObjectReference{
				Kind:       boundObjectKind,
				APIVersion: "v1",
				Name:       w.PodName,
				UID:        types.UID(w.PodUID),
			},
		},
	}

	out, err := m.client.CoreV1().ServiceAccounts(w.Namespace).CreateToken(
		ctx, w.ServiceAccount, req, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsForbidden(err) {
			return nil, wierrors.ErrTokenMintForbidden.Wrapf(err,
				"TokenRequest for %s/%s audience %q refused",
				w.Namespace, w.ServiceAccount, configuration.EksAuthAudience)
		}
		// Throttling is called out rather than left to the fallthrough. It lands
		// on the same retryable error, so the cache keeps the pod's existing
		// token and re-mints on a later sweep, but it says so in the message:
		// client-go has already exhausted its Retry-After retries by this point,
		// and a throttled node is worth telling apart from a broken one.
		if apierrors.IsTooManyRequests(err) {
			return nil, wierrors.ErrTokenMintFailed.Wrapf(err,
				"TokenRequest for %s/%s throttled by the API server after client-go exhausted its retries",
				w.Namespace, w.ServiceAccount)
		}
		return nil, wierrors.ErrTokenMintFailed.Wrapf(err,
			"TokenRequest for %s/%s failed", w.Namespace, w.ServiceAccount)
	}

	if out.Status.Token == "" {
		return nil, wierrors.ErrTokenMintFailed.Wrapf(nil,
			"TokenRequest for %s/%s returned an empty token", w.Namespace, w.ServiceAccount)
	}

	return &workloadidentity.ProjectedToken{
		Token:     out.Status.Token,
		ExpiresAt: out.Status.ExpirationTimestamp.Time,
	}, nil
}

var _ workloadidentity.TokenMinter = (*apiMinter)(nil)
