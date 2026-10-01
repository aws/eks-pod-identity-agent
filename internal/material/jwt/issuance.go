package jwt

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/smithy-go"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"k8s.io/utils/set"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

func (s *Source) issueAndStore(
	ctx context.Context,
	w *workloadidentity.Workload,
	audiences []string,
	renewal bool,
) (*jwtsvid.SVID, error) {
	// Keep the deletion guard until the shared issuance ends, even if its caller leaves.
	if err := s.beginUse(w.PodUID); err != nil {
		return nil, err
	}
	defer s.finishUse(w.PodUID)

	key := makeCacheKey(w.PodUID, audiences)

	if err := s.reserveAudienceSet(key); err != nil {
		return nil, err
	}
	defer s.releaseAudienceSet(key)

	startedAt := time.Now()
	svid, issuedAt, err := s.issue(ctx, w, audiences)
	if err == nil {
		s.stateMu.Lock()
		err = s.checkPodLocked(w.PodUID)
		if err == nil {
			s.store(w, audiences, svid, issuedAt)
		}
		s.stateMu.Unlock()
	}
	s.metrics.observeIssuance(err, time.Since(startedAt).Seconds(), renewal)

	if err != nil {
		return nil, err
	}
	return svid, nil
}

func (s *Source) issue(
	ctx context.Context,
	w *workloadidentity.Workload,
	audiences []string,
) (*jwtsvid.SVID, time.Time, error) {
	session, err := s.sessionProvider.Session(ctx, w)
	if err != nil {
		return nil, time.Time{}, err
	}
	if err := s.checkPod(w.PodUID); err != nil {
		return nil, time.Time{}, err
	}
	startedAt := s.now()
	issued, err := s.issuer.GetWebIdentityToken(ctx, session.Credentials, sts.WebIdentityTokenRequest{
		Audiences: slices.Clone(audiences),
		Duration:  s.duration,
		TokenType: sts.TokenTypeJWTSVID,
	})
	if err != nil {
		if staleSession(err) {
			s.sessionProvider.Invalidate(w.PodUID)
		}
		return nil, time.Time{}, classify(err, w, audiences)
	}
	svid, tokenIssuedAt, err := parseIssuedToken(issued, audiences)
	if err != nil {
		return nil, time.Time{}, wierrors.ErrIssuanceFailed.Wrapf(err,
			"STS returned an unusable JWT-SVID for %s/%s and audiences %q", w.Namespace, w.PodName, audiences)
	}
	if tokenIssuedAt.IsZero() {
		tokenIssuedAt = startedAt
	}
	if !tokenIssuedAt.Before(svid.Expiry) || !s.now().Before(svid.Expiry) {
		return nil, time.Time{}, wierrors.ErrIssuanceFailed.Wrapf(nil,
			"STS returned an expired JWT-SVID for %s/%s and audiences %q", w.Namespace, w.PodName, audiences)
	}
	return svid, tokenIssuedAt, nil
}

var staleSessionCodes = set.New(
	"AccessDenied",
	"AccessDeniedException",
	"InvalidClientTokenId",
	"ExpiredToken",
	"ExpiredTokenException",
)

func staleSession(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && staleSessionCodes.Has(apiErr.ErrorCode())
}

func classify(err error, w *workloadidentity.Workload, audiences []string) error {
	throttle := retry.ThrottleErrorCode{Codes: retry.DefaultThrottleErrorCodes}
	if throttle.IsErrorThrottle(err).Bool() {
		return wierrors.ErrIssuanceThrottled.Wrapf(err,
			"STS throttled JWT-SVID issuance for %s/%s and audiences %q", w.Namespace, w.PodName, audiences)
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "SessionDurationEscalationException", "OutboundWebIdentityFederationDisabledException",
			"JWTPayloadSizeExceededException", "SignerNotConfiguredException", "RegionalSignerUnavailableException":
			return wierrors.ErrIssuanceRefused.Wrapf(err,
				"STS refused JWT-SVID issuance for %s/%s and audiences %q", w.Namespace, w.PodName, audiences)
		}
	}
	return wierrors.ErrIssuanceFailed.Wrapf(err,
		"JWT-SVID issuance failed for %s/%s and audiences %q", w.Namespace, w.PodName, audiences)
}
