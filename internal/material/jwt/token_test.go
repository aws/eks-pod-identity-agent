package jwt

import (
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
)

func TestParseIssuedTokenRejectsNonSPIFFESubject(t *testing.T) {
	issuedAt := time.Now().UTC().Truncate(time.Second)
	expiresAt := issuedAt.Add(5 * time.Minute)
	token := signedClaims(t, jwtlib.RegisteredClaims{
		Subject:   "not-a-spiffe-id",
		Audience:  jwtlib.ClaimStrings{"payments.example"},
		IssuedAt:  jwtlib.NewNumericDate(issuedAt),
		ExpiresAt: jwtlib.NewNumericDate(expiresAt),
	})

	_, _, err := parseIssuedToken(&sts.IssuedWebIdentityToken{
		Token:      token,
		Expiration: expiresAt,
	}, []string{"payments.example"})
	require.ErrorContains(t, err, "invalid subject")
}

func TestParseIssuedTokenPreservesNativeSVIDAndMarshal(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	expiresAt := now.Add(time.Hour)
	token := signedToken(t, "payments.example", now, expiresAt, "native-svid")
	svid, issuedAt, err := parseIssuedToken(&sts.IssuedWebIdentityToken{
		Token: token, Expiration: expiresAt.Add(500 * time.Millisecond),
	}, []string{"payments.example"})
	require.NoError(t, err)
	require.Equal(t, token, svid.Marshal())
	require.Equal(t, testSpiffeID, svid.ID.String())
	require.Equal(t, []string{"payments.example"}, svid.Audience)
	require.Equal(t, expiresAt, svid.Expiry)
	require.Equal(t, now, issuedAt)
}

func TestParseIssuedTokenRejectsSymmetricSignatures(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	token, err := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.RegisteredClaims{
		Subject: testSpiffeID, Audience: jwtlib.ClaimStrings{"payments.example"},
		ExpiresAt: jwtlib.NewNumericDate(now.Add(time.Hour)),
	}).SignedString([]byte("test-only-key"))
	require.NoError(t, err)
	_, _, err = parseIssuedToken(&sts.IssuedWebIdentityToken{
		Token: token, Expiration: now.Add(time.Hour),
	}, []string{"payments.example"})
	require.Error(t, err)
}

func TestParseIssuedTokenRequiresExactlyTheRequestedAudienceSet(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	expiresAt := now.Add(time.Hour)
	requested := []string{"ledger.example", "payments.example"}
	for _, tc := range []struct {
		name      string
		audiences []string
		valid     bool
	}{
		{"complete set", requested, true},
		{"reordered set", []string{"payments.example", "ledger.example"}, true},
		{"duplicate member", []string{"payments.example", "ledger.example", "payments.example"}, true},
		{"missing member", []string{"payments.example"}, false},
		{"extra member", []string{"ledger.example", "payments.example", "other.example"}, false},
		{"unrelated set", []string{"other.example"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := signedTokenForAudiences(t, tc.audiences, now, expiresAt, tc.name)
			svid, _, err := parseIssuedToken(&sts.IssuedWebIdentityToken{
				Token: token, Expiration: expiresAt,
			}, requested)
			if tc.valid {
				require.NoError(t, err)
				require.Equal(t, token, svid.Marshal())
				require.Equal(t, tc.audiences, svid.Audience)
			} else {
				require.Error(t, err)
				require.Nil(t, svid)
			}
		})
	}
}

func TestNormalizeAudiencesPreservesExactValues(t *testing.T) {
	requested := []string{"payments.example ", "Payments.example", "payments.example", "payments.example"}
	normalized, err := normalizeAudiences(requested)
	require.NoError(t, err)
	require.Equal(t, []string{"Payments.example", "payments.example", "payments.example "}, normalized)
	require.Equal(t, []string{"payments.example ", "Payments.example", "payments.example", "payments.example"}, requested)
	requested[0] = "changed"
	require.Equal(t, []string{"Payments.example", "payments.example", "payments.example "}, normalized)
}
