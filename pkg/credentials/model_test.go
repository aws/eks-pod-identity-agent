package credentials

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

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
