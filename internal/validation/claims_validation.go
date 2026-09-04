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
	// expectedAudience is the audience injected by the EKS Pod Identity webhook into
	// projected service account tokens.
	// See: https://github.com/aws/amazon-eks-pod-identity-webhook/blob/272b85d83305dfa6b519685dc104fe045d86f6c0/main.go#L84
	expectedAudience = "pods.eks.amazonaws.com"
)

var (
	keyIDPattern = regexp.MustCompile(validKeyIDRegex)
)

// ValidateClaims checks that a pre-parsed JWT token has the necessary claims
// to retrieve credentials. The token must have been parsed with jwt.MapClaims.
func (tv *TokenValidator) ValidateClaims(ctx context.Context, token *jwt.Token) error {
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
	if !tv.EndpointOverridden {
		// Only enforce audience when using the default EKS Auth service. Custom
		// delegates (via --endpoint) may expect tokens with a different audience.
		if err := validateAudience(claims); err != nil {
			return err
		}
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

// validateAudience ensures the token's audience matches the EKS Pod Identity
// service. Kubernetes allows pods to project service account tokens scoped to
// different audiences (e.g., the API server or a third-party service). This
// check prevents a token intended for another consumer from being presented to
// the agent to obtain IAM credentials (a confused deputy attack).
func validateAudience(claims jwt.MapClaims) error {
	audiences := toStringSlice(claims["aud"])

	// Require exactly one audience, equal to the EKS Pod Identity audience. A
	// token that also names another audience is scoped to another consumer as
	// well, and honoring it here would let that consumer exchange a shared
	// token for these credentials — a confused deputy. Limiting to a single
	// audience prevents that.
	if len(audiences) != 1 || audiences[0] != expectedAudience {
		return fmt.Errorf("invalid audience: expected %s", expectedAudience)
	}
	return nil
}

// toStringSlice normalizes a JWT aud claim, which per RFC 7519 may be either a
// single string or an array of strings, into a []string.
// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
func toStringSlice(raw interface{}) []string {
	switch v := raw.(type) {
	case string:
		return []string{v}
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
