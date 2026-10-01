package sts

import (
	"encoding/xml"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testLeafPEM  = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"
	testInterPEM = "-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----\n"
	testRootPEM  = "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n"
)

// TestDecodeCertificateChainShapes covers the disagreement between the two
// descriptions of this response. The API model declares CertificateChain a single
// PEM string; the onboarding guide's Java sample iterates it as a list. Reading it
// as one string would be the expensive way to be wrong, because a repeated element
// decoded into a string keeps only the last and silently drops intermediate
// certificate authorities, leaving every verifier unable to build a path.
func TestDecodeCertificateChainShapes(t *testing.T) {
	tests := []struct {
		name  string
		chain string
		want  []string
	}{
		{
			name:  "one element holding one certificate, as the model declares it",
			chain: "<CertificateChain>" + testInterPEM + "</CertificateChain>",
			want:  []string{testInterPEM},
		},
		{
			name:  "one element holding several concatenated certificates",
			chain: "<CertificateChain>" + testInterPEM + testRootPEM + "</CertificateChain>",
			want:  []string{testInterPEM, testRootPEM},
		},
		{
			name: "repeated elements, as the guide's sample iterates",
			chain: "<CertificateChain>" + testInterPEM + "</CertificateChain>" +
				"<CertificateChain>" + testRootPEM + "</CertificateChain>",
			want: []string{testInterPEM, testRootPEM},
		},
		{
			name: "awsQuery list members",
			chain: "<CertificateChain><member>" + testInterPEM + "</member>" +
				"<member>" + testRootPEM + "</member></CertificateChain>",
			want: []string{testInterPEM, testRootPEM},
		},
		{
			name:  "absent, which a leaf issued directly by the root has",
			chain: "",
			want:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			issued := decodeResponse(t, testLeafPEM, tc.chain,
				"2026-09-29T12:00:00Z", "2026-09-29T18:00:00Z", "spiffe://example.aws/w")

			assert.Equal(t, testLeafPEM, issued.CertificatePEM)
			for _, want := range tc.want {
				assert.Contains(t, issued.CertificateChainPEM, want)
			}
			if tc.want == nil {
				assert.Empty(t, issued.CertificateChainPEM)
			}
		})
	}
}

func TestDecodeResponseParsesTheIssuedWindow(t *testing.T) {
	issued := decodeResponse(t, testLeafPEM, "", "2026-09-29T11:55:00Z", "2026-09-29T15:55:00Z", "spiffe://example.aws/w")

	assert.Equal(t, time.Date(2026, 9, 29, 11, 55, 0, 0, time.UTC), issued.NotBefore)
	assert.Equal(t, time.Date(2026, 9, 29, 15, 55, 0, 0, time.UTC), issued.NotAfter)
	assert.Equal(t, "spiffe://example.aws/w", issued.Subject)
	assert.Equal(t, 4*time.Hour, issued.NotAfter.Sub(issued.NotBefore),
		"the issued window is four hours even though six may have been requested")
}

func TestDecodeResponseAcceptsFractionalSeconds(t *testing.T) {
	issued := decodeResponse(t, testLeafPEM, "", "2026-09-29T11:55:00.123Z", "2026-09-29T15:55:00Z", "")
	assert.Equal(t, 123*time.Millisecond, time.Duration(issued.NotBefore.Nanosecond()))
}

// TestDecodeResponseRejectsWhatCannotBeScheduledFrom pins why these are errors
// rather than zero values: the renewal schedule is derived from the timestamps, and
// a zero NotAfter reads as long expired, which would drive a re-issuance loop
// against the customer's certificate authority.
func TestDecodeResponseRejectsWhatCannotBeScheduledFrom(t *testing.T) {
	tests := []struct {
		name                      string
		leaf, notBefore, notAfter string
		wantError                 string
	}{
		{
			name: "no certificate", leaf: "", notBefore: "2026-09-29T12:00:00Z", notAfter: "2026-09-29T18:00:00Z",
			wantError: "no certificate",
		},
		{
			name: "no NotBefore", leaf: testLeafPEM, notBefore: "", notAfter: "2026-09-29T18:00:00Z",
			wantError: "no NotBefore",
		},
		{
			name: "no NotAfter", leaf: testLeafPEM, notBefore: "2026-09-29T12:00:00Z", notAfter: "",
			wantError: "no NotAfter",
		},
		{
			name: "unparseable timestamp", leaf: testLeafPEM, notBefore: "not a timestamp", notAfter: "2026-09-29T18:00:00Z",
			wantError: "parsing NotBefore",
		},
		{
			name: "a window that ends before it starts", leaf: testLeafPEM, notBefore: "2026-09-29T18:00:00Z", notAfter: "2026-09-29T12:00:00Z",
			wantError: "ends at or before it starts",
		},
		{
			name: "a window with no duration", leaf: testLeafPEM, notBefore: "2026-09-29T12:00:00Z", notAfter: "2026-09-29T12:00:00Z",
			wantError: "ends at or before it starts",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var decoded getWorkloadIdentityCertificateResponse
			body := "<GetWorkloadIdentityCertificateResponse><GetWorkloadIdentityCertificateResult>" +
				"<Certificate>" + tc.leaf + "</Certificate>" +
				"<NotBefore>" + tc.notBefore + "</NotBefore>" +
				"<NotAfter>" + tc.notAfter + "</NotAfter>" +
				"</GetWorkloadIdentityCertificateResult></GetWorkloadIdentityCertificateResponse>"
			require.NoError(t, xml.Unmarshal([]byte(body), &decoded))

			_, err := decoded.Result.toIssuedCertificate()
			require.Error(t, err)
			assert.ErrorContains(t, err, tc.wantError)
		})
	}
}

// decodeResponse unmarshals one awsQuery response body and converts it.
func decodeResponse(t *testing.T, leaf, chainXML, notBefore, notAfter, subject string) *IssuedCertificate {
	t.Helper()
	body := "<GetWorkloadIdentityCertificateResponse><GetWorkloadIdentityCertificateResult>" +
		"<Certificate>" + leaf + "</Certificate>" +
		chainXML +
		"<NotBefore>" + notBefore + "</NotBefore>" +
		"<NotAfter>" + notAfter + "</NotAfter>" +
		"<Subject>" + subject + "</Subject>" +
		"</GetWorkloadIdentityCertificateResult></GetWorkloadIdentityCertificateResponse>"

	var decoded getWorkloadIdentityCertificateResponse
	require.NoError(t, xml.Unmarshal([]byte(body), &decoded))
	issued, err := decoded.Result.toIssuedCertificate()
	require.NoError(t, err)
	return issued
}
