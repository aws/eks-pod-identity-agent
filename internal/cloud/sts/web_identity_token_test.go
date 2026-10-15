package sts

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/smithy-go"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"
)

func tokenResponse(token, expiration string) string {
	return "<GetWebIdentityTokenResponse><GetWebIdentityTokenResult><WebIdentityToken>" +
		token + "</WebIdentityToken><Expiration>" + expiration +
		"</Expiration></GetWebIdentityTokenResult></GetWebIdentityTokenResponse>"
}

func TestGetWebIdentityTokenUsesSharedTransportAndWorkloadCredentials(t *testing.T) {
	f := newFakeSTS(t, http.StatusOK, tokenResponse("header.payload.signature", "2026-10-01T12:00:00Z"))
	svc := pinnedService(f)
	got, err := svc.GetWebIdentityToken(context.Background(), sessionCreds, WebIdentityTokenRequest{
		Audiences: []string{"payments.example", "ledger.example"}, Duration: time.Hour, TokenType: TokenTypeJWTSVID,
	})
	require.NoError(t, err)
	require.Equal(t, "header.payload.signature", got.Token)
	require.Equal(t, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC), got.Expiration)
	expectSignedQuery(NewWithT(t), f.only(t), operationGetWebIdentityToken, url.Values{
		"Audience.member.1": {"payments.example"}, "Audience.member.2": {"ledger.example"},
		"DurationSeconds": {"3600"}, "TokenType": {"JWT_SVID"}, "SigningAlgorithm": {"RS256"},
	})
}

func TestGetWebIdentityTokenOmitsUnconfiguredDuration(t *testing.T) {
	f := newFakeSTS(t, http.StatusOK, tokenResponse("token", "2026-10-01T12:00:00Z"))
	_, err := pinnedService(f).GetWebIdentityToken(context.Background(), sessionCreds, WebIdentityTokenRequest{
		Audiences: []string{"payments.example"}, TokenType: TokenTypeJWTSVID,
	})
	require.NoError(t, err)
	expectSignedQuery(NewWithT(t), f.only(t), operationGetWebIdentityToken, url.Values{
		"Audience.member.1": {"payments.example"}, "TokenType": {"JWT_SVID"}, "SigningAlgorithm": {"RS256"},
	})
}

func TestGetWebIdentityTokenRejectsInvalidRequestsBeforeCallingSTS(t *testing.T) {
	for name, req := range map[string]WebIdentityTokenRequest{
		"missing audience":   {Duration: time.Hour, TokenType: TokenTypeJWTSVID},
		"empty member":       {Audiences: []string{"aud", ""}, TokenType: TokenTypeJWTSVID},
		"blank member":       {Audiences: []string{"aud", " \t"}, TokenType: TokenTypeJWTSVID},
		"too many audiences": {Audiences: strings.Fields(strings.Repeat("aud ", MaxWebIdentityTokenAudiences+1)), TokenType: TokenTypeJWTSVID},
		"oversized audience": {Audiences: []string{strings.Repeat("a", MaxWebIdentityTokenAudienceLength+1)}, TokenType: TokenTypeJWTSVID},
		"invalid UTF-8":      {Audiences: []string{"\xff"}, TokenType: TokenTypeJWTSVID},
		"missing token type": {Audiences: []string{"aud"}},
		"wrong token type":   {Audiences: []string{"aud"}, TokenType: "AWS_IDENTITY"},
		"negative duration":  {Audiences: []string{"aud"}, TokenType: TokenTypeJWTSVID, Duration: -time.Second},
		"below minimum":      {Audiences: []string{"aud"}, TokenType: TokenTypeJWTSVID, Duration: 59 * time.Second},
		"above maximum":      {Audiences: []string{"aud"}, TokenType: TokenTypeJWTSVID, Duration: time.Hour + time.Second},
		"subsecond":          {Audiences: []string{"aud"}, TokenType: TokenTypeJWTSVID, Duration: time.Minute + time.Nanosecond},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeSTS(t, http.StatusOK, "")
			_, err := pinnedService(f).GetWebIdentityToken(context.Background(), sessionCreds, req)
			require.Error(t, err)
			require.Zero(t, f.requestCount())
		})
	}
}

func TestGetWebIdentityTokenRejectsMissingMaterial(t *testing.T) {
	for name, body := range map[string]string{
		"missing token":      tokenResponse("", "2026-10-01T12:00:00Z"),
		"missing expiration": tokenResponse("token", ""),
		"invalid expiration": tokenResponse("token", "not-a-date"),
		"wrong response":     "<GetTrustBundlesResponse/>",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeSTS(t, http.StatusOK, body)
			_, err := pinnedService(f).GetWebIdentityToken(context.Background(), sessionCreds, WebIdentityTokenRequest{
				Audiences: []string{"aud"}, TokenType: TokenTypeJWTSVID,
			})
			var operationErr *smithy.OperationError
			var decodeErr *smithy.DeserializationError
			require.ErrorAs(t, err, &operationErr)
			require.Equal(t, operationGetWebIdentityToken, operationErr.OperationName)
			require.ErrorAs(t, err, &decodeErr)
		})
	}
}

func TestGetWebIdentityTokenPreservesAPIErrorsWithoutRetrying(t *testing.T) {
	for _, tc := range []struct {
		code   string
		status int
	}{
		{"ThrottlingException", http.StatusTooManyRequests},
		{"SessionDurationEscalationException", http.StatusForbidden},
		{"OutboundWebIdentityFederationDisabledException", http.StatusForbidden},
		{"JWTPayloadSizeExceededException", http.StatusBadRequest},
		{"SignerNotConfiguredException", http.StatusNotFound},
		{"RegionalSignerUnavailableException", http.StatusNotFound},
	} {
		t.Run(tc.code, func(t *testing.T) {
			f := newFakeSTS(t, tc.status,
				"<ErrorResponse><Error><Code>"+tc.code+"</Code><Message>request refused</Message></Error></ErrorResponse>")
			_, err := pinnedService(f).GetWebIdentityToken(context.Background(), sessionCreds, WebIdentityTokenRequest{
				Audiences: []string{"aud"}, TokenType: TokenTypeJWTSVID,
			})
			var apiErr smithy.APIError
			require.True(t, errors.As(err, &apiErr))
			require.Equal(t, tc.code, apiErr.ErrorCode())
			require.Equal(t, 1, f.requestCount())
		})
	}
}

func TestGetWebIdentityTokenAcceptsAudienceLimits(t *testing.T) {
	audiences := make([]string, MaxWebIdentityTokenAudiences)
	expected := url.Values{"TokenType": {"JWT_SVID"}, "SigningAlgorithm": {"RS256"}}
	for i := range audiences {
		audiences[i] = strings.Repeat("界", MaxWebIdentityTokenAudienceLength)
		expected.Set("Audience.member."+strconv.Itoa(i+1), audiences[i])
	}
	f := newFakeSTS(t, http.StatusOK, tokenResponse("token", "2026-10-01T12:00:00Z"))
	_, err := pinnedService(f).GetWebIdentityToken(context.Background(), sessionCreds, WebIdentityTokenRequest{
		Audiences: audiences, TokenType: TokenTypeJWTSVID,
	})
	require.NoError(t, err)
	expectSignedQuery(NewWithT(t), f.only(t), operationGetWebIdentityToken, expected)
}
