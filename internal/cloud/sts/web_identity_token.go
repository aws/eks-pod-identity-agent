package sts

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/protocol/query"
	awssts "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

const (
	operationGetWebIdentityToken      = "GetWebIdentityToken"
	minWebIdentityTokenDuration       = time.Minute
	maxWebIdentityTokenDuration       = time.Hour
	MaxWebIdentityTokenAudiences      = 10
	MaxWebIdentityTokenAudienceLength = 1000
)

type WebIdentityTokenType string

const TokenTypeJWTSVID WebIdentityTokenType = "JWT_SVID"

type WebIdentityTokenRequest struct {
	Audiences []string
	Duration  time.Duration
	TokenType WebIdentityTokenType
}

type IssuedWebIdentityToken struct {
	Token      string
	Expiration time.Time
}

func (s *service) GetWebIdentityToken(ctx context.Context, creds aws.Credentials, req WebIdentityTokenRequest) (*IssuedWebIdentityToken, error) {
	if err := ValidateWebIdentityTokenAudiences(req.Audiences); err != nil {
		return nil, err
	}
	if req.TokenType != TokenTypeJWTSVID {
		return nil, fmt.Errorf("STS GetWebIdentityToken requires token type JWT_SVID")
	}
	if req.Duration < 0 || req.Duration > 0 && (req.Duration%time.Second != 0 ||
		req.Duration < minWebIdentityTokenDuration || req.Duration > maxWebIdentityTokenDuration) {
		return nil, fmt.Errorf("STS GetWebIdentityToken duration %s must be whole seconds between %s and %s",
			req.Duration, minWebIdentityTokenDuration, maxWebIdentityTokenDuration)
	}

	var decoded getWebIdentityTokenResponse
	err := s.invoke(ctx, creds, operationGetWebIdentityToken, func(input *query.Object) {
		audiences := input.Key("Audience").Array("member")
		for _, audience := range req.Audiences {
			audiences.Value().String(audience)
		}
		input.Key("TokenType").String(string(req.TokenType))
		if req.Duration > 0 {
			input.Key("DurationSeconds").Integer(int32(req.Duration.Seconds()))
		}
	}, &decoded)
	if err != nil {
		return nil, err
	}
	result := decoded.Result
	expiration, err := parseTimestamp("Expiration", result.Expiration)
	if err == nil && result.Token == "" {
		err = fmt.Errorf("the response carries no web identity token")
	}
	if err != nil {
		return nil, &smithy.OperationError{
			ServiceID: awssts.ServiceID, OperationName: operationGetWebIdentityToken,
			Err: &smithy.DeserializationError{Err: err},
		}
	}
	return &IssuedWebIdentityToken{Token: result.Token, Expiration: expiration}, nil
}

// ValidateWebIdentityTokenAudiences checks the GetWebIdentityToken audience limits.
func ValidateWebIdentityTokenAudiences(audiences []string) error {
	if len(audiences) == 0 || len(audiences) > MaxWebIdentityTokenAudiences {
		return fmt.Errorf("STS GetWebIdentityToken requires between 1 and %d audiences", MaxWebIdentityTokenAudiences)
	}
	for _, audience := range audiences {
		if !utf8.ValidString(audience) || strings.TrimSpace(audience) == "" ||
			utf8.RuneCountInString(audience) > MaxWebIdentityTokenAudienceLength {
			return fmt.Errorf("STS GetWebIdentityToken audiences must be nonblank UTF-8 strings of at most %d characters",
				MaxWebIdentityTokenAudienceLength)
		}
	}
	return nil
}

type getWebIdentityTokenResponse struct {
	XMLName xml.Name `xml:"GetWebIdentityTokenResponse"`
	Result  struct {
		Token      string `xml:"WebIdentityToken"`
		Expiration string `xml:"Expiration"`
	} `xml:"GetWebIdentityTokenResult"`
}
