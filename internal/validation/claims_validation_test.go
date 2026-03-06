package validation

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

func fullK8sClaim() map[string]interface{} {
	return map[string]interface{}{
		"namespace":      "default",
		"serviceaccount": map[string]interface{}{"name": "my-sa", "uid": "sa-uid"},
		"pod":            map[string]interface{}{"name": "my-pod", "uid": "pod-uid"},
	}
}

func goodConfig() test.TokenConfig {
	now := time.Now()
	return test.TokenConfig{
		Expiry: now.Add(1 * time.Hour),
		Iat:    now,
		Nbf:    now,
		Overrides: map[string]interface{}{
			"sub":           "system:serviceaccount:default:my-sa",
			"kubernetes.io": fullK8sClaim(),
		},
	}
}

func parseToken(t *testing.T, tokenString string) *jwt.Token {
	t.Helper()
	parsed, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("failed to parse test token: %v", err)
	}
	return parsed
}

func TestValidateClaims(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{"all valid", test.CreateToken(t, goodConfig()), false},
		{"bad kid only", test.CreateToken(t, func() test.TokenConfig {
			c := goodConfig()
			c.HeaderOverrides = map[string]interface{}{"kid": "INVALID"}
			return c
		}()), true},
		{"bad k8s claims only", test.CreateToken(t, func() test.TokenConfig {
			c := goodConfig()
			c.Overrides["kubernetes.io"] = map[string]interface{}{
				"namespace": "default",
				// missing serviceaccount and pod
			}
			return c
		}()), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed := parseToken(t, tc.token)
			err := ValidateClaims(context.Background(), parsed)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			} else if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateKid(t *testing.T) {
	tests := []struct {
		name    string
		header  map[string]interface{}
		wantErr bool
	}{
		{"good kid", map[string]interface{}{"kid": test.DefaultKid}, false},
		{"bad kid", map[string]interface{}{"kid": "INVALID"}, true},
		{"missing kid", map[string]interface{}{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateKid(tc.header)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			} else if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateKubernetesClaims(t *testing.T) {
	tests := []struct {
		name    string
		claims  jwt.MapClaims
		wantErr bool
	}{
		{"all present", jwt.MapClaims{"kubernetes.io": fullK8sClaim()}, false},
		{"all missing", jwt.MapClaims{}, true},
		{"some missing", jwt.MapClaims{"kubernetes.io": map[string]interface{}{
			"namespace":      "default",
			"serviceaccount": map[string]interface{}{"name": "my-sa", "uid": "sa-uid"},
		}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateKubernetesClaims(context.Background(), tc.claims)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			} else if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
