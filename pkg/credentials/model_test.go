package credentials

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

func TestCredentialMetadata_Source(t *testing.T) {
	tests := []struct {
		name       string
		meta       CredentialMetadata
		wantSource CredentialSource
		wantAssoc  string
	}{
		{
			name:       "IMDS source",
			meta:       CredentialMetadata{Association: "assoc-1", CredSource: SourceIMDS},
			wantSource: SourceIMDS,
			wantAssoc:  "assoc-1",
		},
		{
			name:       "Auth Service source",
			meta:       CredentialMetadata{Association: "assoc-2", CredSource: SourceAuthService},
			wantSource: SourceAuthService,
			wantAssoc:  "assoc-2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(tt.meta.Source()).To(Equal(tt.wantSource))
			g.Expect(tt.meta.AssociationId()).To(Equal(tt.wantAssoc))
		})
	}
}

func TestEksCredentialsResponse_Serialization(t *testing.T) {
	var (
		expirationTime     = time.Date(1996, 3, 27, 7, 45, 23, 123_456_789, time.UTC)
		serializedTime     = "1996-03-27T07:45:23.123456789Z"
		serializedResponse = fmt.Sprintf("{"+
			"\"AccessKeyId\":\"some-access-key\","+
			"\"SecretAccessKey\":\"some-secret-key\","+
			"\"Token\":\"some-token\","+
			"\"AccountId\":\"some-account-id\","+
			"\"Expiration\":\"%s\""+
			"}", serializedTime)
	)

	testCases := []struct {
		name                  string
		eksResponse           EksCredentialsResponse
		error                 string
		expectedSerialization string
	}{
		{
			name: "serializes request properly",
			eksResponse: EksCredentialsResponse{
				AccessKeyId:     "some-access-key",
				SecretAccessKey: "some-secret-key",
				Token:           "some-token",
				AccountId:       "some-account-id",
				Expiration:      SdkCompliantExpirationTime{expirationTime},
			},
			expectedSerialization: serializedResponse,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			json, err := json.Marshal(tc.eksResponse)
			g.Expect(string(json)).To(Equal(tc.expectedSerialization))
			g.Expect(err).To(Not(HaveOccurred()))
		})
	}
}

func TestGetPodUIDFromToken(t *testing.T) {
	// Build a valid unsigned JWT with pod UID
	validToken := buildTestToken(t, map[string]interface{}{
		"kubernetes.io": map[string]interface{}{
			"pod": map[string]interface{}{
				"uid": "test-pod-uid-123",
			},
		},
	})

	tests := []struct {
		name    string
		token   string
		wantUID string
		wantErr string
	}{
		{
			name:    "valid token returns pod UID",
			token:   validToken,
			wantUID: "test-pod-uid-123",
		},
		{
			name:    "malformed JWT",
			token:   "not-a-jwt",
			wantErr: "Service account token cannot be parsed",
		},
		{
			name:    "missing kubernetes.io claims",
			token:   buildTestToken(t, map[string]interface{}{"foo": "bar"}),
			wantErr: "Service account token missing kubernetes.io claims",
		},
		{
			name: "missing pod claims",
			token: buildTestToken(t, map[string]interface{}{
				"kubernetes.io": map[string]interface{}{"serviceaccount": "sa"},
			}),
			wantErr: "Service account token missing pod claims",
		},
		{
			name: "missing pod uid",
			token: buildTestToken(t, map[string]interface{}{
				"kubernetes.io": map[string]interface{}{
					"pod": map[string]interface{}{"name": "my-pod"},
				},
			}),
			wantErr: "Service account token missing pod uid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			uid, err := GetPodUIDFromToken(tt.token)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(uid).To(Equal(tt.wantUID))
			}
		})
	}
}

// buildTestToken creates an unsigned JWT with the given claims.
func buildTestToken(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	header := base64RawURL(t, `{"alg":"none","typ":"JWT"}`)
	payload := base64RawURL(t, mustJSON(t, claims))
	return header + "." + payload + "."
}

func base64RawURL(t *testing.T, s string) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("failed to marshal JSON: %v", err)
	}
	return string(b)
}
