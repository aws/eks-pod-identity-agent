package sts

import (
	"context"
	"encoding/xml"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/protocol/query"
)

// operationGetTrustBundles is the operation's awsQuery Action.
const operationGetTrustBundles = "GetTrustBundles"

// TrustBundle is one entry of a GetTrustBundles response.
type TrustBundle struct {
	// TrustDomain is the SPIFFE trust domain the entry is for.
	TrustDomain string
	// Bundle is the domain's SPIFFE bundle document, an RFC 7517 JWK Set. It is
	// opaque here; the bundle tier parses it.
	Bundle string
}

func (s *service) GetTrustBundles(ctx context.Context, creds aws.Credentials, providerArn string) ([]TrustBundle, error) {
	var decoded getTrustBundlesResponse
	err := s.invoke(ctx, creds, operationGetTrustBundles, func(input *query.Object) {
		input.Key("ProviderArn").String(providerArn)
	}, &decoded)
	if err != nil {
		return nil, err
	}
	entries := make([]TrustBundle, 0, len(decoded.Result.TrustBundles.Members))
	for _, member := range decoded.Result.TrustBundles.Members {
		entries = append(entries, TrustBundle(member))
	}
	return entries, nil
}

// getTrustBundlesResponse is the awsQuery response shape of GetTrustBundles. A
// list is a sequence of member elements under the list's own element, and the
// output structure sits under the operation's Result element.
type getTrustBundlesResponse struct {
	XMLName xml.Name `xml:"GetTrustBundlesResponse"`
	Result  struct {
		TrustBundles struct {
			Members []struct {
				TrustDomain string `xml:"TrustDomain"`
				Bundle      string `xml:"Bundle"`
			} `xml:"member"`
		} `xml:"TrustBundles"`
	} `xml:"GetTrustBundlesResult"`
}
