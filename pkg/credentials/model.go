package credentials

import (
	"context"
	"time"
)

//go:generate mockgen.sh mockcreds $GOFILE mockcreds

// A CredentialRetriever is meant to simply get IAM credentials
// they can be chained and internal configuration of credential
// retrieval is up to the implementing struct
type CredentialRetriever interface {
	// GetIamCredentials retrieves valid IAM credentials under
	// the given ctx deadline. If valid credentials cannot be
	// retrieved within the given timeline, this method will error
	// out
	GetIamCredentials(ctx context.Context, request *EksCredentialsRequest) (*EksCredentialsResponse, ResponseMetadata, error)
}

// ResponseMetadata contains information about the credentials
// in the response
type ResponseMetadata interface {
	AssociationId() string
}

type EksCredentialsRequest struct {
	ServiceAccountToken string
	ClusterName         string
	RequestTargetHost   string
}

type EksCredentialsResponse struct {
	AccessKeyId     string                     `json:"AccessKeyId,omitempty"`
	SecretAccessKey string                     `json:"SecretAccessKey,omitempty"`
	Token           string                     `json:"Token,omitempty"`
	AccountId       string                     `json:"AccountId,omitempty"`
	Expiration      SdkCompliantExpirationTime `json:"Expiration,omitempty"`
}

type SdkCompliantExpirationTime struct {
	time.Time
}

func (t SdkCompliantExpirationTime) MarshalText() ([]byte, error) {
	return []byte(t.Format(time.RFC3339Nano)), nil
}
