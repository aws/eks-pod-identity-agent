package jwt

import (
	"context"
	"time"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
)

const minRenewalDelay = 10 * time.Second

// Jitter is centered on fraction; 0.5 with 0.1 spreads renewals across 45%-55%.
func renewalPoint(issuedAt, expiresAt time.Time, fraction, jitter float64, draw func() float64) time.Time {
	lifetime := expiresAt.Sub(issuedAt)
	if lifetime <= 0 {
		return expiresAt
	}
	at := fraction - jitter/2 + jitter*draw()
	return issuedAt.Add(time.Duration(float64(lifetime) * at))
}

func renewalDelay(now, renewAt time.Time) time.Duration {
	if delay := renewAt.Sub(now); delay > minRenewalDelay {
		return delay
	}
	return minRenewalDelay
}

func (s *Source) onRefresh(key cacheKey, cached *entry) {
	if !s.servable(cached.svid) {
		return
	}
	if err := s.beginUse(key.podUID); err != nil {
		return
	}
	defer s.finishUse(key.podUID)

	if current, ok := s.cache.Get(key); !ok || current != cached {
		return
	}
	ctx, cancel := context.WithTimeout(
		logger.ContextWithField(context.Background(), "from", "jwt-svid-renewal", "pod-uid", key.podUID),
		s.renewalTimeout,
	)
	defer cancel()

	outcome := s.group.DoChan(keyString(key), func() (any, error) {
		if current, ok := s.cache.Get(key); ok && current != cached && s.servable(current.svid) {
			return current.svid, nil
		}
		if err := s.limiter.Wait(ctx); err != nil {
			return nil, wierrors.ErrIssuanceFailed.Wrapf(err, "waiting for a JWT-SVID renewal permit")
		}
		return s.issueAndStore(ctx, cached.workload, cached.audiences, true)
	})
	select {
	case result := <-outcome:
		if result.Err != nil {
			logger.FromContext(ctx).WithError(result.Err).Infof(
				"JWT-SVID renewal failed for pod %s and audiences %q; keeping the previous token until %s",
				key.podUID, cached.audiences, cached.svid.Expiry)
		}
	case <-ctx.Done():
		logger.FromContext(ctx).WithError(ctx.Err()).Infof(
			"JWT-SVID renewal timed out for pod %s and audiences %q; keeping the previous token until %s",
			key.podUID, cached.audiences, cached.svid.Expiry)
	}
}
