package tokenminter

// Startup wiring for PSAT minting. The clientset is injected, produced once by
// internal/kube and shared with the attestor (T3), mirroring
// attestation.NewAttestor.

import (
	"context"
	"fmt"

	"k8s.io/client-go/kubernetes"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// NewMinter checks the CSIDriver the mint depends on and returns a caching
// TokenMinter over the shared node-credentialed client. Every field of opts
// except MaxCacheSize takes a documented default when zero.
//
// The check is a pre-flight, not a gate: a missing or misdeclared CSIDriver is
// the chart's to fix and is only logged, so startup fails here only when the API
// server itself could not be reached, or the caller gave no cache bound.
func NewMinter(ctx context.Context, clientset kubernetes.Interface, opts CachedMinterOpts) (workloadidentity.TokenMinter, error) {
	// expiring.NewLru reads a zero bound as unlimited, so an unset MaxCacheSize
	// would silently grow the cache without one. The value belongs to the
	// operator, so this reports the flag rather than choosing a number.
	if opts.MaxCacheSize <= 0 {
		return nil, fmt.Errorf("token minter needs a positive cache bound, got %d: --max-cache-size sets it", opts.MaxCacheSize)
	}
	if err := VerifyCSIDriverExists(ctx, clientset); err != nil {
		return nil, fmt.Errorf("checking CSIDriver for token minting: %w", err)
	}
	logger.FromContext(ctx).Infof("token minter: ready, minting audience %q", configuration.EksAuthAudience)
	return newCachedMinter(newAPIMinter(clientset), opts), nil
}
