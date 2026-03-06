package validation

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
)

const (
	validKeyIDRegex = `^[0-9a-f]{40}$`
)

var (
	keyIDPattern = regexp.MustCompile(validKeyIDRegex)
)

// ValidateClaims checks that a pre-parsed JWT token has the necessary claims
// to retrieve credentials. The token must have been parsed with jwt.MapClaims.
func ValidateClaims(ctx context.Context, token *jwt.Token) error {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("failed to extract claims")
	}

	if err := validateKid(token.Header); err != nil {
		return err
	}
	if err := validateKubernetesClaims(ctx, claims); err != nil {
		return err
	}

	return nil
}

// validateKid validates that the token's key id is properly formatted
func validateKid(header map[string]interface{}) error {
	kid, _ := header["kid"].(string)

	if strings.TrimSpace(kid) == "" {
		return fmt.Errorf("missing header: kid")
	}
	if !keyIDPattern.MatchString(kid) {
		return fmt.Errorf("invalid header: kid %s", kid)
	}
	return nil
}

// validateKubernetesClaims validates the presence of kubernetes.io claims:
// namespace, serviceaccount.{name,uid}, pod.{name,uid}.
func validateKubernetesClaims(ctx context.Context, claims jwt.MapClaims) error {
	log := logger.FromContext(ctx)
	log.Debugf("validateKubernetesClaims: kubernetes.io=%v", claims["kubernetes.io"])

	val, ok := claims["kubernetes.io"]
	if !ok || val == nil {
		return fmt.Errorf("missing claim: kubernetes.io")
	}
	k8s, ok := val.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid claim: kubernetes.io")
	}

	if err := requireNestedString(k8s, "namespace", "kubernetes.io/namespace"); err != nil {
		return err
	}

	sa, ok := k8s["serviceaccount"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("missing claim: kubernetes.io/serviceaccount")
	}
	if err := requireNestedString(sa, "name", "kubernetes.io/serviceaccount/name"); err != nil {
		return fmt.Errorf("error finding claim kubernetes.io/serviceaccount/name %w", err)
	}
	if err := requireNestedString(sa, "uid", "kubernetes.io/serviceaccount/uid"); err != nil {
		return fmt.Errorf("error finding claim kubernetes.io/serviceaccount/uid %w", err)
	}

	pod, ok := k8s["pod"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("missing claim: kubernetes.io/pod")
	}
	if err := requireNestedString(pod, "name", "kubernetes.io/pod/name"); err != nil {
		return fmt.Errorf("error finding claim kubernetes.io/pod/name %w", err)
	}
	if err := requireNestedString(pod, "uid", "kubernetes.io/pod/uid"); err != nil {
		return fmt.Errorf("error finding claim kubernetes.io/pod/uid %w", err)
	}
	return nil
}

func requireNestedString(m map[string]interface{}, key, claimPath string) error {
	s, _ := m[key].(string)
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("missing or empty claim: %s", claimPath)
	}
	return nil
}
