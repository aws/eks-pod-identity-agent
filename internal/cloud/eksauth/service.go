package eksauth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/eksauth"
	"github.com/sirupsen/logrus"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
)

//go:generate mockgen.sh eksauth $GOFILE

type Iface interface {
	GetIamCredentials(ctx context.Context,
		request *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error)
}

type service struct {
	eksAuthService *eksauth.Client
}

func NewService(cfg aws.Config) Iface {
	// Configure HTTP client with custom timeouts
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout: 500 * time.Millisecond, // Socket timeout
			}).DialContext,
		},
		Timeout: 1000 * time.Millisecond, // HTTP request timeout
	}
	cfg.HTTPClient = httpClient
	eksAuthService := eksauth.NewFromConfig(cfg)
	return &service{
		eksAuthService: eksAuthService,
	}
}

type responseMetadata string

func (r responseMetadata) AssociationId() string {
	return string(r)
}

func (s *service) GetIamCredentials(ctx context.Context,
	request *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
	log := logger.FromContext(ctx)
	log.Info("Calling EKS Auth to fetch credentials")

	startRequestTime := time.Now()
	creds, err := s.eksAuthService.AssumeRoleForPodIdentity(ctx, &eksauth.AssumeRoleForPodIdentityInput{
		ClusterName: aws.String(request.ClusterName),
		Token:       aws.String(request.ServiceAccountToken),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("unable to fetch credentials from EKS Auth: %w", err)
	}

	if creds.Credentials == nil || creds.AssumedRoleUser == nil {
		return nil, nil, fmt.Errorf("invalid response from server: credentials or assumed role empty: %v", creds)
	}

	log.WithFields(logrus.Fields{
		"request_time_ms":  time.Since(startRequestTime).Milliseconds(),
		"fetched_role_arn": *creds.AssumedRoleUser.Arn,
		"fetched_role_id":  *creds.AssumedRoleUser.AssumeRoleId,
	}).Infof("Successfully fetched credentials from EKS Auth")

	// TODO: do not parse account ID from arn
	assumedUserArn := creds.AssumedRoleUser.Arn
	parsedArn, err := arn.Parse(*assumedUserArn)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse arn from assumed role: %v", err)
	}

	return &credentials.EksCredentialsResponse{
		AccessKeyId:     *creds.Credentials.AccessKeyId,
		SecretAccessKey: *creds.Credentials.SecretAccessKey,
		Token:           *creds.Credentials.SessionToken,
		AccountId:       parsedArn.AccountID,
		Expiration:      credentials.SdkCompliantExpirationTime{Time: *creds.Credentials.Expiration},
	}, responseMetadata(*creds.PodIdentityAssociation.AssociationId), nil
}
