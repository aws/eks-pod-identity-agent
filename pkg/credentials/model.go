package credentials

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

// CredentialSource identifies where credentials were obtained from.
type CredentialSource string

const (
	SourceAuthService CredentialSource = "auth-service"
	SourceIMDS        CredentialSource = "imds"
)

// ResponseMetadata contains information about the credentials
// in the response
type ResponseMetadata interface {
	AssociationId() string
	Source() CredentialSource
}

// CredentialMetadata is a concrete ResponseMetadata for use by
// delegates that need to set both association ID and source.
type CredentialMetadata struct {
	Association string
	CredSource  CredentialSource
}

func (m CredentialMetadata) AssociationId() string    { return m.Association }
func (m CredentialMetadata) Source() CredentialSource { return m.CredSource }

// NamespaceInfo represents the parsed info file from an IMDS iam-eks namespace.
type NamespaceInfo struct {
	Code           string                        `json:"Code"`
	LastUpdated    string                        `json:"LastUpdated"`
	PodCredentials map[string]PodCredentialEntry `json:"PodCredentials"`
}

// PodCredentialEntry represents a single pod's status in the namespace info file.
type PodCredentialEntry struct {
	Code    string `json:"Code"`
	RoleARN string `json:"RoleARN"`
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

// GetPodUIDFromToken extracts the pod UID from a Kubernetes service account JWT.
func GetPodUIDFromToken(token string) (string, error) {
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("cannot parse service account token: %w", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("cannot parse token claims")
	}
	k8s, ok := claims["kubernetes.io"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("token missing kubernetes.io claims")
	}
	pod, ok := k8s["pod"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("token missing pod claims")
	}
	uid, ok := pod["uid"].(string)
	if !ok {
		return "", fmt.Errorf("token missing pod uid")
	}
	return uid, nil
}
