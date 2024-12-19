package sharedcredsrotater

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

const (
	defaultRotationInterval               = time.Minute
	awsSharedCredentialsFileEnvVar        = "AWS_SHARED_CREDENTIALS_FILE"
	rotatingSharedCredentialsProviderName = "RotatingSharedCredentialsProvider"
)

// RotatingSharedCredentialsProvider is a provider that retrieves credentials via the
// shared credentials file, and adds the functionality of expiring and re-retrieving
// those credentials from the file.
type RotatingSharedCredentialsProvider struct {
	// rotationInterval is the interval at which the credentials will be rotated.
	rotationInterval time.Duration
	// sharedCredentialsFiles is the list of shared credentials files to use.
	sharedCredentialsFiles []string
}

// NewRotatingSharedCredentials returns a rotating shared credentials provider
// with default values set.
func NewRotatingSharedCredentialsProvider() *RotatingSharedCredentialsProvider {
	credsFile := config.DefaultSharedCredentialsFiles
	if cFile, ok := os.LookupEnv(awsSharedCredentialsFileEnvVar); ok {
		credsFile = []string{cFile}
	}
	return &RotatingSharedCredentialsProvider{
		rotationInterval:       defaultRotationInterval,
		sharedCredentialsFiles: credsFile,
	}
}

// Retrieve retrieves the credentials from the shared credentials file and returns it.
func (p *RotatingSharedCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	sharedConfig, err := config.LoadSharedConfigProfile(ctx, config.DefaultSharedConfigProfile, func(c *config.LoadSharedConfigOptions) {
		c.ConfigFiles = []string{}
		c.CredentialsFiles = p.sharedCredentialsFiles
	})
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("loading shared credentials: %s", err)
	}

	creds := sharedConfig.Credentials
	creds.Source = fmt.Sprintf("%s: %s", rotatingSharedCredentialsProviderName, p.sharedCredentialsFiles)
	creds.CanExpire = true
	creds.Expires = time.Now().Add(p.rotationInterval)
	return creds, nil
}
