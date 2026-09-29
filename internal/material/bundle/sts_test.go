package bundle

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	. "github.com/onsi/gomega"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity/fake"
)

// TestRegistry_OverTheSTSClient_FetchesSignedWithTheNodeRole runs the tier over
// the real STS client against a fake STS endpoint: the caller's ARN goes out as
// the request input, the request is signed with the agent's own credentials, and
// the parsed authorities come back keyed by trust domain.
func TestRegistry_OverTheSTSClient_FetchesSignedWithTheNodeRole(t *testing.T) {
	g := NewWithT(t)
	ca := newAuthority(t, "ca")
	jwtKey := newECKey(t)
	document := bundleDoc(t, 300, x509Key(t, ca), jwtECKey(t, "k1", jwtKey))

	var escaped bytes.Buffer
	g.Expect(xml.EscapeText(&escaped, []byte(document))).To(Succeed())
	response := `<GetTrustBundlesResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetTrustBundlesResult><TrustBundles>` +
		`<member><TrustDomain>` + testDomain + `</TrustDomain><Bundle>` + escaped.String() + `</Bundle></member>` +
		`</TrustBundles></GetTrustBundlesResult></GetTrustBundlesResponse>`

	var mu sync.Mutex
	var forms []url.Values
	var authorizations []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(raw))
		mu.Lock()
		forms = append(forms, form)
		authorizations = append(authorizations, r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = io.WriteString(w, response)
	}))
	defer server.Close()

	nodeConfig := aws.Config{
		Region:       "us-west-2",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIDNODEROLE", "node-secret", ""),
		BaseEndpoint: aws.String(server.URL),
	}
	registry, err := New(Opts{Fetcher: sts.NewService(nodeConfig), Notifier: &fake.Subscriber{}})
	g.Expect(err).ToNot(HaveOccurred())

	x509Bundles, err := registry.X509Bundles(context.Background(), testProviderArn)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(x509Bundles).To(Equal(map[string][][]byte{testDomain: {ca.der}}))
	authority, err := registry.JWTAuthority(testProviderArn, testDomain, "k1")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(jwtKey.PublicKey.Equal(authority)).To(BeTrue())
	g.Expect(registry.OwnTrustDomain(testProviderArn)).To(Equal(testDomain))

	mu.Lock()
	defer mu.Unlock()
	g.Expect(forms).To(HaveLen(1))
	g.Expect(forms[0].Get("Action")).To(Equal("GetTrustBundles"))
	g.Expect(forms[0].Get("ProviderArn")).To(Equal(testProviderArn))
	g.Expect(authorizations[0]).To(ContainSubstring("Credential=AKIDNODEROLE/"))
}

// TestSource_OverTheSTSClient_UnknownProvider_IsARefusal carries the one error
// the API model declares for GetTrustBundles through the real client, so the
// classification is pinned against the wire error and not only a hand-built one.
func TestRegistry_OverTheSTSClient_UnknownProvider_IsARefusal(t *testing.T) {
	g := NewWithT(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">`+
			`<Error><Type>Sender</Type><Code>ResourceNotFoundException</Code><Message>no such provider</Message></Error>`+
			`<RequestId>req-1</RequestId></ErrorResponse>`)
	}))
	defer server.Close()
	registry, err := New(Opts{
		Fetcher: sts.NewService(aws.Config{
			Region:       "us-west-2",
			Credentials:  credentials.NewStaticCredentialsProvider("AKIDNODEROLE", "node-secret", ""),
			BaseEndpoint: aws.String(server.URL),
		}),
		Notifier: &fake.Subscriber{},
	})
	g.Expect(err).ToNot(HaveOccurred())

	_, err = registry.X509Bundles(context.Background(), testProviderArn)

	g.Expect(err).To(MatchError(wierrors.ErrBundleRefused))
	g.Expect(wierrors.IsRetryable(err)).To(BeFalse())
	g.Expect(err).To(MatchError(ContainSubstring("no such provider")))
}
