package session

import (
	"context"

	"github.com/golang-jwt/jwt/v5"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/eksauth"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/credcache"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// RefreshWith is the cache's RefreshWith with workload identity on. An entry EKS
// Auth decorated, whichever caller stored it, refreshes through eksAuth, with
// tokens swapping a stored token close to expiry, and never through the [IMDS,
// EKS Auth] chain, whose IMDS answers aren't decorated. Every other entry gets
// (nil, nil): the cache's Delegate, presenting its stored token as it is.
//
// It is also the HOSM/WISE source selection: the provider ARN is the per-pod
// enrollment signal, so an enrolled pod's refresh never reaches IMDS, where the
// DR aggregator publishes undecorated credentials for it regardless of
// enrollment. Consuming one of those would leave the agent holding an
// undecorated session where issuance requires a decorated one, which fails
// silently rather than loudly. A sync needs no such rule: a cache miss is served
// by the authoritative delegate, EKS Auth alone, for every pod.
//
// The ARN is read off the response metadata, never off the credentials: an STS
// session token is opaque, so decoration is not observable on the node. Nothing
// here introspects a credential.
func RefreshWith(eksAuth credentials.CredentialRetriever,
	tokens credcache.TokenSource) func(*credcache.Entry) (credentials.CredentialRetriever, credcache.TokenSource) {
	return func(e *credcache.Entry) (credentials.CredentialRetriever, credcache.TokenSource) {
		if e.Metadata != nil && e.Metadata.ProviderArn() != "" {
			observeCredentialSource(workloadidentity.CredentialSourceEKSAuth)
			return eksAuth, tokens
		}
		observeCredentialSource(workloadidentity.CredentialSourceIMDSFirst)
		return nil, nil
	}
}

// minterTokens is the credcache.TokenSource MinterTokens returns.
type minterTokens struct {
	minter workloadidentity.TokenMinter
}

var _ credcache.TokenSource = minterTokens{}

// MinterTokens is the cache's TokenSource over minter. cmd passes T4's cached
// minter, the one the session tier exchanges with, so the cache's refreshes and
// the tier's exchanges share one token cache.
func MinterTokens(minter workloadidentity.TokenMinter) credcache.TokenSource {
	return minterTokens{minter: minter}
}

// Token mints a token for the pod, namespace and ServiceAccount that current's
// token names in its kubernetes.io claims. A token without them is
// ErrUnattestable, and nothing is minted.
func (t minterTokens) Token(ctx context.Context, current *credentials.EksCredentialsRequest) (string, error) {
	w, err := workloadFromToken(current.ServiceAccountToken)
	if err != nil {
		return "", err
	}
	return mint(ctx, t.minter, w)
}

// IsIrrecoverable drops the entry for a non-retryable taxonomy error, such as a
// refused mint, and for an error EKS Auth classifies as irrecoverable. The code
// is EKS Auth's.
func (minterTokens) IsIrrecoverable(err error) (string, bool) {
	errCode, irrecoverable := eksauth.IsIrrecoverableApiError(err)
	if wiErr, ok := wierrors.AsWorkloadIdentityError(err); ok && !wiErr.Retryable() {
		irrecoverable = true
	}
	return errCode, irrecoverable
}

// mint mints a token for w, mapping every failure onto the taxonomy.
func mint(ctx context.Context, minter workloadidentity.TokenMinter, w *workloadidentity.Workload) (string, error) {
	token, err := minter.Mint(ctx, w)
	if err != nil {
		if _, ok := wierrors.AsWorkloadIdentityError(err); ok {
			return "", err
		}
		return "", wierrors.ErrTokenMintFailed.Wrapf(err, "minting a ServiceAccount token for pod %s", w.PodUID)
	}
	if token == nil || token.Token == "" {
		return "", wierrors.ErrTokenMintFailed.Wrapf(nil, "the token minter returned no token for pod %s", w.PodUID)
	}
	return token.Token, nil
}

// tokenClaims is the part of a ServiceAccount token workloadFromToken reads.
type tokenClaims struct {
	jwt.RegisteredClaims
	Kubernetes struct {
		Namespace string `json:"namespace"`
		Pod       struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"pod"`
		ServiceAccount struct {
			Name string `json:"name"`
		} `json:"serviceaccount"`
	} `json:"kubernetes.io"`
}

// workloadFromToken reads the workload token names without verifying it, as
// credentials.GetPodUIDFromToken does. The cache holds only tokens EKS Auth or
// the HTTP retriever's validator accepted.
func workloadFromToken(token string) (*workloadidentity.Workload, error) {
	var claims tokenClaims
	if _, _, err := jwt.NewParser().ParseUnverified(token, &claims); err != nil {
		return nil, wierrors.ErrUnattestable.Wrapf(err, "cannot read the token a refresh would renew")
	}
	k := claims.Kubernetes
	if k.Pod.UID == "" || k.Pod.Name == "" || k.Namespace == "" || k.ServiceAccount.Name == "" {
		return nil, wierrors.ErrUnattestable.Wrapf(nil,
			"the token a refresh would renew names no pod, namespace and ServiceAccount in its kubernetes.io claims")
	}
	return &workloadidentity.Workload{
		PodUID:         k.Pod.UID,
		PodName:        k.Pod.Name,
		Namespace:      k.Namespace,
		ServiceAccount: k.ServiceAccount.Name,
	}, nil
}
