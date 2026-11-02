package eksauthtest

import (
	"net/http"
	"time"
)

// AccountID is the account every ARN in EnrolledSession and NotEnrolledSession
// belongs to, so a test can assert the account a client parses out of them.
const AccountID = "111122223333"

// DefaultAudience is the audience EKS Auth always returns, and what the fake
// returns for a Session whose Audience is empty.
const DefaultAudience = "pods.eks.amazonaws.com"

// Session is what the fake answers a successful exchange with. Every field is
// sent as it is, empty strings included, except Audience and ProviderArn.
type Session struct {
	// AccessKeyID, SecretAccessKey and SessionToken are the session's
	// credentials.
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	// Expiration is sent as a JSON number of epoch seconds, as EKS Auth sends
	// it, to the millisecond because that's all the SDK keeps. A test comparing
	// what a client decoded truncates its expectation the same way. A session
	// with little or no life left is just an Expiration close to or before now.
	Expiration time.Time
	// AssumedRoleArn and AssumeRoleID are the assumedRoleUser member.
	AssumedRoleArn string
	AssumeRoleID   string
	// AssociationArn and AssociationID are the podIdentityAssociation member.
	AssociationArn string
	AssociationID  string
	// Namespace and ServiceAccount are the subject member.
	Namespace      string
	ServiceAccount string
	// Audience is sent as DefaultAudience when empty.
	Audience string
	// ProviderArn is the member the released SDK doesn't model, sent as
	// workloadIdentityProviderArn. It's left out when empty, which is how EKS
	// Auth answers for a pod not enrolled in workload identity.
	ProviderArn string
}

// EnrolledSession is a realistic session for a pod enrolled in workload
// identity, expiring at expiration, and the fake's default answer. Its subject
// is always default/example-sa, where EKS Auth reports the verified token's
// subject, so a test for another workload sets Namespace and ServiceAccount.
func EnrolledSession(expiration time.Time) Session {
	return Session{
		AccessKeyID:     "ASIAEXAMPLEWORKLOAD1",
		SecretAccessKey: "eksauthtest-workload-secret-access-key",
		SessionToken:    "eksauthtest-workload-session-token",
		Expiration:      expiration,
		AssumedRoleArn: "arn:aws:sts::" + AccountID +
			":assumed-role/example-workload-role/eks-example-cl-example-po-9b3f2c1e-6a4d-4f7b-8e2a-1c5d7f9a0b3e",
		AssumeRoleID:   "AROAEXAMPLEWORKLOAD01:eks-example-cl-example-po-9b3f2c1e-6a4d-4f7b-8e2a-1c5d7f9a0b3e",
		AssociationArn: "arn:aws:eks:us-west-2:" + AccountID + ":podidentityassociation/example-cluster/a-exampleassoc00001",
		AssociationID:  "a-exampleassoc00001",
		Namespace:      "default",
		ServiceAccount: "example-sa",
		Audience:       DefaultAudience,
		ProviderArn:    "arn:aws:iam::" + AccountID + ":workload-identity-provider/example",
	}
}

// NotEnrolledSession is EnrolledSession without a provider ARN: the answer EKS
// Auth gives for a pod with an ordinary Pod Identity association and no
// workload identity enrolment.
func NotEnrolledSession(expiration time.Time) Session {
	session := EnrolledSession(expiration)
	session.ProviderArn = ""
	return session
}

// APIError is an error response in the restJson1 shape EKS Auth uses: the code
// in the X-Amzn-ErrorType header and a JSON body carrying the message. The SDK
// decodes a modelled Code into its exception type, such as
// *types.AccessDeniedException, and anything else into a smithy.GenericAPIError.
type APIError struct {
	// Status is the HTTP status. Zero is sent as 400.
	Status int
	// Code is the error code, such as "AccessDeniedException". Empty sends no
	// X-Amzn-ErrorType header, which the SDK reports as UnknownError.
	Code string
	// Message is the body's message member.
	Message string
}

// The constructors below return each error EKS Auth models for
// AssumeRoleForPodIdentity with its documented status. Each returns a new value,
// so a test may change its Message.
//
// On the enrolled path, EKS Auth reports its own STS throttling as
// InternalServer, not Throttling, and an STS AssumeRole AccessDenied, including
// a role missing sts:SetContext, as AccessDenied.

// AccessDenied is AccessDeniedException, 400.
func AccessDenied() *APIError {
	return &APIError{Status: http.StatusBadRequest, Code: "AccessDeniedException", Message: "eksauthtest: access denied"}
}

// ExpiredToken is ExpiredTokenException, 400.
func ExpiredToken() *APIError {
	return &APIError{Status: http.StatusBadRequest, Code: "ExpiredTokenException", Message: "eksauthtest: the token has expired"}
}

// InvalidParameter is InvalidParameterException, 400.
func InvalidParameter() *APIError {
	return &APIError{Status: http.StatusBadRequest, Code: "InvalidParameterException", Message: "eksauthtest: invalid parameter"}
}

// InvalidRequest is InvalidRequestException, 400.
func InvalidRequest() *APIError {
	return &APIError{Status: http.StatusBadRequest, Code: "InvalidRequestException", Message: "eksauthtest: invalid request"}
}

// InvalidToken is InvalidTokenException, 400.
func InvalidToken() *APIError {
	return &APIError{Status: http.StatusBadRequest, Code: "InvalidTokenException", Message: "eksauthtest: the token is not valid"}
}

// ResourceNotFound is ResourceNotFoundException, 404.
func ResourceNotFound() *APIError {
	return &APIError{Status: http.StatusNotFound, Code: "ResourceNotFoundException", Message: "eksauthtest: no pod identity association"}
}

// Throttling is ThrottlingException, 429.
func Throttling() *APIError {
	return &APIError{Status: http.StatusTooManyRequests, Code: "ThrottlingException", Message: "eksauthtest: rate exceeded"}
}

// InternalServer is InternalServerException, 500.
func InternalServer() *APIError {
	return &APIError{Status: http.StatusInternalServerError, Code: "InternalServerException", Message: "eksauthtest: internal error"}
}

// ServiceUnavailable is ServiceUnavailableException, 503.
func ServiceUnavailable() *APIError {
	return &APIError{Status: http.StatusServiceUnavailable, Code: "ServiceUnavailableException", Message: "eksauthtest: service unavailable"}
}
