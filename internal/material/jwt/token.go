package jwt

import (
	"fmt"
	"slices"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
)

func normalizeAudiences(audiences []string) ([]string, error) {
	if err := sts.ValidateWebIdentityTokenAudiences(audiences); err != nil {
		return nil, wierrors.ErrInvalidAudience.Wrapf(err, "invalid JWT-SVID audiences")
	}
	normalized := slices.Clone(audiences)
	slices.Sort(normalized)
	return slices.Compact(normalized), nil
}

// STS supplied this token over the authenticated issuance call. Relying parties
// still verify its signature against the provider's JWT bundle.
func parseIssuedToken(issued *sts.IssuedWebIdentityToken, audiences []string) (*jwtsvid.SVID, time.Time, error) {
	if issued == nil || issued.Token == "" {
		return nil, time.Time{}, fmt.Errorf("STS returned no web identity token")
	}
	if issued.Expiration.IsZero() {
		return nil, time.Time{}, fmt.Errorf("STS returned no web identity token expiration")
	}
	svid, err := jwtsvid.ParseInsecure(issued.Token, audiences)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parsing the JWT-SVID returned by STS: %w", err)
	}
	// ParseInsecure checks any audience match, not the complete requested set.
	expected, err := normalizeAudiences(audiences)
	if err != nil {
		return nil, time.Time{}, err
	}
	actual, err := normalizeAudiences(svid.Audience)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("invalid JWT audiences: %w", err)
	}
	if !slices.Equal(actual, expected) {
		return nil, time.Time{}, fmt.Errorf("JWT audiences %q do not match requested audiences %q", actual, expected)
	}
	if !svid.Expiry.Equal(issued.Expiration.Truncate(time.Second)) {
		return nil, time.Time{}, fmt.Errorf("STS response expiration %s does not match JWT exp %s",
			issued.Expiration, svid.Expiry)
	}
	var issuedAt time.Time
	if seconds, ok := svid.Claims["iat"].(float64); ok {
		issuedAt = time.Unix(int64(seconds), 0).UTC()
	}
	return svid, issuedAt, nil
}
