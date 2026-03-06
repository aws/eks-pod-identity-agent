package validation

import (
	"context"
	"encoding/json"
	"fmt"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	utilversion "k8s.io/apimachinery/pkg/util/version"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	apiserverQPS    = 5
	jwksEndpoint    = "/openid/v1/jwks"
	versionEndpoint = "/version"
)

// minK8sVersion is the minimum Kubernetes version required for JWKS support.
var minK8sVersion = utilversion.MajorMinor(1, 34)

// apiserverClient manages communication with the Kubernetes API server using client-go.
type apiserverClient struct {
	clientset kubernetes.Interface
}

func newApiserverClient() (*apiserverClient, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to build in-cluster config: %w", err)
	}
	config.QPS = apiserverQPS
	config.Burst = apiserverQPS

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return &apiserverClient{clientset: clientset}, nil
}

// fetchPublicKeys fetches JWKS from the apiserver using the /openid/v1/jwks endpoint.
func (ac *apiserverClient) fetchPublicKeys(ctx context.Context) (*JWKSet, error) {
	log := logger.FromContext(ctx)

	// On Kubernetes ≤1.33, /openid/v1/jwks serves a static JWKS response built once
	// at apiserver startup from --service-account-key-file. When an external signing
	// service is used, the JWKS response does not reflect the signer's rotating keys,
	// making local signature verification unreliable. Kubernetes 1.34 introduced
	// ExternalServiceAccountTokenSigner (KEP-740), which dynamically updates the JWKS
	// response via the external signer's FetchKeys() gRPC method.
	if err := ac.checkK8sVersion(ctx); err != nil {
		return nil, err
	}

	raw, err := ac.clientset.Discovery().RESTClient().Get().
		AbsPath(jwksEndpoint).
		DoRaw(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	var jwkSet JWKSet
	if err := json.Unmarshal(raw, &jwkSet); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS response: %w", err)
	}

	log.Info("Fetched public keys from JWKS endpoint")
	return &jwkSet, nil
}

// checkK8sVersion verifies the API server is running Kubernetes >= 1.34.
func (ac *apiserverClient) checkK8sVersion(ctx context.Context) error {
	log := logger.FromContext(ctx)

	raw, err := ac.clientset.Discovery().RESTClient().Get().
		AbsPath(versionEndpoint).
		DoRaw(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch Kubernetes version: %w", err)
	}

	var info version.Info
	if err := json.Unmarshal(raw, &info); err != nil {
		return fmt.Errorf("failed to decode Kubernetes version response: %w", err)
	}
	log.Infof("Kubernetes API server version: %s.%s (full: %s)", info.Major, info.Minor, info.GitVersion)

	v, err := utilversion.ParseGeneric(fmt.Sprintf("%s.%s", info.Major, info.Minor))
	if err != nil {
		return fmt.Errorf("unable to parse Kubernetes version: %w", err)
	}
	if !v.AtLeast(minK8sVersion) {
		return fmt.Errorf("Kubernetes version does not support fetching public keys from the apiserver, apiserver is on version %d.%d", v.Major(), v.Minor())
	}

	return nil
}
