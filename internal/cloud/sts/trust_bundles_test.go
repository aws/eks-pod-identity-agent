package sts

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/aws/smithy-go"
	. "github.com/onsi/gomega"
)

const testProviderArn = "arn:aws:iam::111122223333:workload-identity-provider/example"

const twoBundlesResponse = `<GetTrustBundlesResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetTrustBundlesResult>
    <TrustBundles>
      <member>
        <TrustDomain>example.org</TrustDomain>
        <Bundle>{"keys":[{"use":"jwt-svid","kid":"k1"}],"spiffe_refresh_hint":300}</Bundle>
      </member>
      <member>
        <TrustDomain>peer.example.org</TrustDomain>
        <Bundle>{"keys":[]}</Bundle>
      </member>
    </TrustBundles>
  </GetTrustBundlesResult>
  <ResponseMetadata>
    <RequestId>c6104cbe-af31-11e0-8154-cbc7ccf896c7</RequestId>
  </ResponseMetadata>
</GetTrustBundlesResponse>`

func TestGetTrustBundles_SendsTheProviderArnSignedWithTheGivenCredentials(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusOK, twoBundlesResponse)

	_, err := pinnedService(fake).GetTrustBundles(context.Background(), sessionCreds, testProviderArn)

	g.Expect(err).ToNot(HaveOccurred())
	expectSignedQuery(g, fake.only(t), "GetTrustBundles", url.Values{"ProviderArn": {testProviderArn}})
}

func TestGetTrustBundles_DecodesEveryEntryInResponseOrder(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusOK, twoBundlesResponse)

	entries, err := pinnedService(fake).GetTrustBundles(context.Background(), sessionCreds, testProviderArn)

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(entries).To(Equal([]TrustBundle{
		{TrustDomain: "example.org", Bundle: `{"keys":[{"use":"jwt-svid","kid":"k1"}],"spiffe_refresh_hint":300}`},
		{TrustDomain: "peer.example.org", Bundle: `{"keys":[]}`},
	}))
}

func TestGetTrustBundles_EmptyList_DecodesToNoEntries(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusOK, `<GetTrustBundlesResponse><GetTrustBundlesResult><TrustBundles/></GetTrustBundlesResult></GetTrustBundlesResponse>`)

	entries, err := pinnedService(fake).GetTrustBundles(context.Background(), sessionCreds, testProviderArn)

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(entries).To(BeEmpty())
}

func TestGetTrustBundles_AnotherOperationsResponse_IsADeserializationError(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusOK, testOperationOK)

	entries, err := pinnedService(fake).GetTrustBundles(context.Background(), sessionCreds, testProviderArn)

	g.Expect(entries).To(BeNil())
	var deserializationErr *smithy.DeserializationError
	g.Expect(errors.As(err, &deserializationErr)).To(BeTrue())
}

func TestGetTrustBundles_Error_NamesTheOperationAndCarriesTheCode(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeSTS(t, http.StatusNotFound, `<ErrorResponse><Error><Type>Sender</Type><Code>ResourceNotFoundException</Code><Message>provider not found</Message></Error><RequestId>req-404</RequestId></ErrorResponse>`)

	entries, err := pinnedService(fake).GetTrustBundles(context.Background(), sessionCreds, testProviderArn)

	g.Expect(entries).To(BeNil())
	var operationErr *smithy.OperationError
	g.Expect(errors.As(err, &operationErr)).To(BeTrue())
	g.Expect(operationErr.Operation()).To(Equal("GetTrustBundles"))
	var apiErr smithy.APIError
	g.Expect(errors.As(err, &apiErr)).To(BeTrue())
	g.Expect(apiErr.ErrorCode()).To(Equal("ResourceNotFoundException"))
}
