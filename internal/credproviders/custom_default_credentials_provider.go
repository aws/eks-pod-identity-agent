package credproviders

import (
    "context"
    "fmt"
    "os"

    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/credentials"
    "github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
    "github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

// internal environment variable keys
const (
    envAWSAccessKeyID     = "AWS_ACCESS_KEY_ID"
    envAWSSecretAccessKey = "AWS_SECRET_ACCESS_KEY"
    envAWSSessionToken    = "AWS_SESSION_TOKEN"
)

// chainedProvider tries each provider in order until one succeeds
type chainedProvider struct {
    providers []aws.CredentialsProvider
}

func (c *chainedProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
    for _, p := range c.providers {
        creds, err := p.Retrieve(ctx)
        if err == nil {
            return creds, nil
        }
    }
    return aws.Credentials{}, fmt.Errorf("no valid credentials found in chained provider")
}

// CustomDefaultCredentialsProvider returns a provider that tries static env vars first, then IMDS
func CustomDefaultCredentialsProvider(cfg aws.Config) aws.CredentialsProvider {
    static := credentials.NewStaticCredentialsProvider(
        os.Getenv(envAWSAccessKeyID),
        os.Getenv(envAWSSecretAccessKey),
        os.Getenv(envAWSSessionToken),
    )

    imdsClient := imds.NewFromConfig(cfg)
    instanceProfile := ec2rolecreds.New(func(o *ec2rolecreds.Options) {
        o.Client = imdsClient
    })

    chain := &chainedProvider{
        providers: []aws.CredentialsProvider{
            static,
            instanceProfile,
        },
    }

    return aws.NewCredentialsCache(chain)
}
