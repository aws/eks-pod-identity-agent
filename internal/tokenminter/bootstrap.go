package tokenminter

// Startup wiring for PSAT minting. The node-credentialed clientset and the
// node-scoped pod store are injected, built once at startup and shared with the
// attestor.

import (
	"context"
	"errors"
	"fmt"

	"k8s.io/client-go/kubernetes"

	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// NewMinter checks the CSIDriver the mint depends on and returns a caching
// TokenMinter over the shared node-credentialed client, which drops a pod's
// token once opts.PodStore reports the pod deleted. A missing or misdeclared
// CSIDriver is the chart's to fix and only logged; startup fails only on an
// unreachable API server or an unset MaxCacheSize or PodStore.
func NewMinter(ctx context.Context, clientset kubernetes.Interface, opts CachedMinterOpts) (workloadidentity.TokenMinter, error) {
	// expiring.NewLru reads a zero bound as unlimited, so an unset MaxCacheSize
	// would silently grow the cache without one. The value belongs to the
	// operator, so this reports the flag rather than choosing a number.
	if opts.MaxCacheSize <= 0 {
		return nil, fmt.Errorf("token minter needs a positive cache bound, got %d: --max-cache-size sets it", opts.MaxCacheSize)
	}
	if opts.PodStore == nil {
		return nil, errors.New("token minter needs the node-scoped pod store to drop deleted pods' tokens")
	}
	if err := VerifyCSIDriverExists(ctx, clientset); err != nil {
		return nil, fmt.Errorf("checking CSIDriver for token minting: %w", err)
	}
	m := newCachedMinter(newAPIMinter(clientset), opts)
	if err := opts.PodStore.OnPodDeleted(m.Invalidate); err != nil {
		return nil, fmt.Errorf("registering token minter pod deletion callback: %w", err)
	}
	logger.FromContext(ctx).Infof("token minter: ready, minting audience %q", configuration.EksAuthAudience)
	return m, nil
}
