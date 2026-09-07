package credproviders

import (
    "context"
    "os"
    "testing"

    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/credentials"
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/stretchr/testify/assert"
)

func TestStaticCredsAvailable(t *testing.T) {
    os.Setenv(envAWSAccessKeyID, "STATIC_KEY")
    os.Setenv(envAWSSecretAccessKey, "STATIC_SECRET")
    os.Setenv(envAWSSessionToken, "STATIC_TOKEN")
    defer os.Unsetenv(envAWSAccessKeyID)
    defer os.Unsetenv(envAWSSecretAccessKey)
    defer os.Unsetenv(envAWSSessionToken)

    cfg, err := config.LoadDefaultConfig(context.Background())
    assert.NoError(t, err)

    provider := CustomDefaultCredentialsProvider(cfg)
    creds, err := provider.Retrieve(context.Background())
    assert.NoError(t, err)

    assert.Equal(t, "STATIC_KEY", creds.AccessKeyID)
    assert.Equal(t, "STATIC_TOKEN", creds.SessionToken)
    assert.Equal(t, "StaticCredentials", creds.Source)
}

func TestFallback(t *testing.T) {
    os.Unsetenv(envAWSAccessKeyID)
    os.Unsetenv(envAWSSecretAccessKey)
    os.Unsetenv(envAWSSessionToken)

    static := credentials.NewStaticCredentialsProvider(
        os.Getenv(envAWSAccessKeyID),
        os.Getenv(envAWSSecretAccessKey),
        os.Getenv(envAWSSessionToken),
    )

    fallback := credentials.NewStaticCredentialsProvider("IMDS_KEY", "IMDS_SECRET", "IMDS_TOKEN")
    cp := &chainedProvider{
        providers: []aws.CredentialsProvider{
            static,
            fallback,
        },
    }

    creds, err := cp.Retrieve(context.Background())
    assert.NoError(t, err)

    assert.Equal(t, "IMDS_KEY", creds.AccessKeyID)
    assert.Equal(t, "IMDS_TOKEN", creds.SessionToken)
    assert.Equal(t, "StaticCredentials", creds.Source)
}
