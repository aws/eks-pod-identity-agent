package credentials

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
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
	// String returns a human-readable name for this retriever (e.g. "imds", "eks-auth").
	String() string
	// IsIrrecoverable returns a human-readable error code and true if the error is 
	// irrecoverable (the credential is gone or invalid and caching it further is pointless).
	// Returns a code and false if the error is transient/recoverable.
	IsIrrecoverable(err error) (string, bool)
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
//
// The info file maps each pod UID to a status code string, e.g.:
//
//	{
//	  "LastUpdated": "2026-09-24T21:28:57Z",
//	  "PodCredentials": { "<podUID>": "0" }
//	}
//
// The per-pod value is a status code where "0" indicates success. The pod's
// role ARN and actual credentials are not present here; they live in the
// separate security-credentials/<podUID> file.
type NamespaceInfo struct {
	Code           string            `json:"Code"`
	LastUpdated    string            `json:"LastUpdated"`
	PodCredentials map[string]string `json:"PodCredentials"`
}

// PodCredentialSuccessCode is the value in a namespace info file's
// PodCredentials map that indicates a pod's credentials are ready.
const PodCredentialSuccessCode = "0"

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
// It is the single source of truth for pod UID extraction, used by the IMDS
// delegate, the request handler, and the credential cache. Failures are
// returned as RequestValidationErrors so the handler surfaces them as HTTP 400.
func GetPodUIDFromToken(token string) (string, error) {
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return "", errors.NewRequestValidationError(fmt.Sprintf("Service account token cannot be parsed: %v", err))
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.NewRequestValidationError("Service account token claims cannot be parsed")
	}
	k8s, ok := claims["kubernetes.io"].(map[string]interface{})
	if !ok {
		return "", errors.NewRequestValidationError("Service account token missing kubernetes.io claims")
	}
	pod, ok := k8s["pod"].(map[string]interface{})
	if !ok {
		return "", errors.NewRequestValidationError("Service account token missing pod claims")
	}
	uid, ok := pod["uid"].(string)
	if !ok {
		return "", errors.NewRequestValidationError("Service account token missing pod uid")
	}
	return uid, nil
}
