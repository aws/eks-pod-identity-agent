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
// The info file maps each pod UID to a status code string, where 0 is success
// and anything else is failure, e.g.:
//
//	{
//	  "Code": "0",
//	  "LastUpdated": "2026-09-24T21:28:57Z",
//	  "PodCredentials": { "<podUIDA>": "0",  <podUIDB>": "1"}
//	}
//
type NamespaceInfo struct {
	Code           string            `json:"Code"`
	LastUpdated    string            `json:"LastUpdated"`
	PodCredentials map[string]string `json:"PodCredentials"`
}

// PodCredentialSuccessCode is the value in a namespace info file's
// PodCredentials map that indicates a pod's credentials were successfully delivered
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

// PodIdentity names the pod a service account token was issued for, taken from
// its kubernetes.io claims.
type PodIdentity struct {
	Namespace string
	Name      string
	UID       string
}

// GetPodUIDFromToken extracts the pod UID from a Kubernetes service account JWT.
func GetPodUIDFromToken(token string) (string, error) {
	pod, err := parsePodClaims(token)
	if err != nil {
		return "", err
	}
	uid, ok := pod["uid"].(string)
	if !ok {
		return "", errors.NewRequestValidationError("token missing pod uid")
	}
	return uid, nil
}

// GetPodIdentityFromToken extracts the pod's namespace, name and UID from a
// Kubernetes service account JWT. ok is false when the namespace or pod name is
// missing, so a caller can proceed as if no identity were available rather than
// treat a partial token as a known pod. It doesn't verify the token.
func GetPodIdentityFromToken(token string) (PodIdentity, bool) {
	k8s, err := parseKubernetesClaims(token)
	if err != nil {
		return PodIdentity{}, false
	}
	namespace, _ := k8s["namespace"].(string)
	pod, _ := k8s["pod"].(map[string]interface{})
	name, _ := pod["name"].(string)
	uid, _ := pod["uid"].(string)
	if namespace == "" || name == "" {
		return PodIdentity{}, false
	}
	return PodIdentity{Namespace: namespace, Name: name, UID: uid}, true
}

// parseKubernetesClaims returns the kubernetes.io claim map from an unverified
// service account JWT.
func parseKubernetesClaims(token string) (map[string]interface{}, error) {
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return nil, errors.NewRequestValidationError(fmt.Sprintf("cannot parse service account token: %v", err))
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.NewRequestValidationError("cannot parse token claims")
	}
	k8s, ok := claims["kubernetes.io"].(map[string]interface{})
	if !ok {
		return nil, errors.NewRequestValidationError("token missing kubernetes.io claims")
	}
	return k8s, nil
}

// parsePodClaims returns the kubernetes.io/pod claim map from an unverified
// service account JWT.
func parsePodClaims(token string) (map[string]interface{}, error) {
	k8s, err := parseKubernetesClaims(token)
	if err != nil {
		return nil, err
	}
	pod, ok := k8s["pod"].(map[string]interface{})
	if !ok {
		return nil, errors.NewRequestValidationError("token missing pod claims")
	}
	return pod, nil
}

// GetExpiryFromToken returns the exp claim of a Kubernetes service account JWT.
// It doesn't verify the token.
func GetExpiryFromToken(token string) (time.Time, error) {
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return time.Time{}, errors.NewRequestValidationError(fmt.Sprintf("cannot parse service account token: %v", err))
	}
	exp, err := parsed.Claims.GetExpirationTime()
	if err != nil {
		return time.Time{}, errors.NewRequestValidationError(fmt.Sprintf("cannot parse token expiry: %v", err))
	}
	if exp == nil {
		return time.Time{}, errors.NewRequestValidationError("token missing exp claim")
	}
	return exp.Time, nil
}
