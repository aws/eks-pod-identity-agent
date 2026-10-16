package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/golang-jwt/jwt/v5"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/credcache"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

const (
	wiSpiffeID    = "spiffe://example.org/ns/default/sa/sa-1"
	wiAudience    = "spiffe://example.org/audience"
	wiProviderArn = "arn:aws:iam::111122223333:workload-identity-provider/example"
)

// TestWorkloadIdentityTiers_APodDeletion_DropsThePodFromEveryTier warms a pod in
// every per-pod tier, deletes it through the API server, and proves each tier
// lets it go: the credential cache drops its session and refuses to store one
// again, and the PSAT, session, X.509-SVID and JWT-SVID tiers refuse the pod
// with ErrUnattestable, with no TokenRequest, EKS Auth exchange or STS call.
func TestWorkloadIdentityTiers_APodDeletion_DropsThePodFromEveryTier(t *testing.T) {
	g := NewWithT(t)
	w := &workloadidentity.Workload{
		PodUID: "pod-uid-1", PodName: "pod-1", Namespace: "default", ServiceAccount: "sa-1", NodeName: wiTestNode,
	}
	client := newWINodeClientset("system:node:"+wiTestNode, w)
	eksAuth := &wiEnrolledExchange{}
	issuer := newWIIssuingSTS(t)
	opts := wiOpts
	// Its own cache, since the deletion leaves the pod's UID forgotten in it.
	opts.CredentialCache = credcache.New(credcache.Opts{
		Delegate: wiNoExchange{}, RenewalTtl: time.Hour, MaxSize: 100, CleanupInterval: time.Hour,
	})
	opts.EKSAuth = eksAuth
	tiers, clients := wiBuildTiersWith(t, opts, client, issuer)
	upstream := func() wiUpstreamCalls {
		return wiUpstreamCalls{
			TokenRequests: len(client.tokenRequests()),
			Exchanges:     int(eksAuth.exchanges.Load()),
			Certificates:  int(issuer.certificates.Load()),
			JWTSVIDs:      int(issuer.jwtSVIDs.Load()),
		}
	}
	once := wiUpstreamCalls{TokenRequests: 1, Exchanges: 1, Certificates: 1, JWTSVIDs: 1}

	// Twice, so the second round is served from every tier's cache.
	for range 2 {
		for tier, err := range wiCallEveryTier(t.Context(), tiers, clients, w) {
			g.Expect(err).ToNot(HaveOccurred(), tier)
		}
	}
	g.Expect(upstream()).To(Equal(once))
	entry, ok := opts.CredentialCache.Get(w.PodUID)
	g.Expect(ok).To(BeTrue(), "the session tier caches the pod's session")

	g.Eventually(client.podWatch, 10*time.Second).Should(BeClosed())
	g.Expect(client.CoreV1().Pods(w.Namespace).Delete(t.Context(), w.PodName, metav1.DeleteOptions{})).To(Succeed())

	// The pod leaves the store before any deletion callback runs, so once the
	// session tier's has run, every tier finds the pod gone.
	g.Eventually(func() bool {
		_, ok := opts.CredentialCache.Get(w.PodUID)
		return ok
	}, 10*time.Second, 5*time.Millisecond).Should(BeFalse(), "the session tier drops the pod's credentials")
	g.Expect(opts.CredentialCache.Store(t.Context(), w.PodUID, entry)).To(MatchError(credcache.ErrForgotten),
		"a write still in flight can't put them back")
	for tier, err := range wiCallEveryTier(t.Context(), tiers, clients, w) {
		g.Expect(err).To(MatchError(wierrors.ErrUnattestable), tier)
	}
	g.Expect(upstream()).To(Equal(once), "nothing is minted, exchanged or issued for the deleted pod")
	_, ok = opts.CredentialCache.Get(w.PodUID)
	g.Expect(ok).To(BeFalse())
}

// wiUpstreamCalls counts what the tiers asked of the API server, EKS Auth and STS.
type wiUpstreamCalls struct {
	TokenRequests, Exchanges, Certificates, JWTSVIDs int
}

// wiCallEveryTier asks each per-pod tier for w directly, in the order a first
// round fills them: the PSAT minter, then the session tier, then the X.509-SVID
// and JWT-SVID tiers, which exchange through it. Errors are keyed by tier.
func wiCallEveryTier(ctx context.Context, tiers *workloadIdentityTiers, clients *workloadIdentityClients,
	w *workloadidentity.Workload) map[string]error {
	_, psat := clients.minter.Mint(ctx, w)
	_, session := tiers.sessions.Session(ctx, w)
	_, x509SVID := tiers.certs.X509SVIDs(ctx, w)
	_, jwtSVID := tiers.tokens.JWTSVIDs(ctx, w, []string{wiAudience})
	return map[string]error{"PSAT": psat, "session": session, "X.509-SVID": x509SVID, "JWT-SVID": jwtSVID}
}

// wiEnrolledExchange stands in for EKS Auth for an enrolled pod: it answers every
// exchange with an hour-long session decorated with wiProviderArn, counting them.
type wiEnrolledExchange struct {
	exchanges atomic.Int32
}

func (e *wiEnrolledExchange) GetIamCredentials(context.Context, *credentials.EksCredentialsRequest) (
	*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
	e.exchanges.Add(1)
	return &credentials.EksCredentialsResponse{
			AccessKeyId:     "ASIAWORKLOAD",
			SecretAccessKey: "secret",
			Token:           "session",
			Expiration:      credentials.SdkCompliantExpirationTime{Time: time.Now().Add(time.Hour)},
		}, credentials.CredentialMetadata{
			Association: "a-1", CredSource: credentials.SourceAuthService, Provider: wiProviderArn,
		}, nil
}

func (*wiEnrolledExchange) String() string                       { return "wi-enrolled-exchange" }
func (*wiEnrolledExchange) IsIrrecoverable(error) (string, bool) { return "Unknown", false }

// wiIssuingSTS is an STS client that issues for wiSpiffeID, counting each call:
// it signs every certificate request with its own CA, and answers every JWT-SVID
// request with an hour-long ES256 token for the audiences asked for. It serves no
// trust bundles.
type wiIssuingSTS struct {
	key *ecdsa.PrivateKey
	ca  *x509.Certificate

	certificates atomic.Int32
	jwtSVIDs     atomic.Int32
}

func newWIIssuingSTS(t *testing.T) *wiIssuingSTS {
	t.Helper()
	g := NewWithT(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	g.Expect(err).ToNot(HaveOccurred())
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "workload identity test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	g.Expect(err).ToNot(HaveOccurred())
	ca, err := x509.ParseCertificate(der)
	g.Expect(err).ToNot(HaveOccurred())
	return &wiIssuingSTS{key: key, ca: ca}
}

func (*wiIssuingSTS) GetTrustBundles(context.Context, aws.Credentials, string) ([]sts.TrustBundle, error) {
	return nil, errors.New("wiIssuingSTS serves no trust bundles")
}

func (s *wiIssuingSTS) GetWorkloadIdentityCertificate(_ context.Context, _ aws.Credentials,
	req sts.CertificateRequest) (*sts.IssuedCertificate, error) {
	s.certificates.Add(1)
	block, _ := pem.Decode([]byte(req.CertificateSigningRequestPEM))
	if block == nil {
		return nil, errors.New("the certificate signing request is not PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	id, err := url.Parse(wiSpiffeID)
	if err != nil {
		return nil, err
	}
	notBefore, notAfter := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		URIs:         []*url.URL{id},
	}, s.ca, csr.PublicKey, s.key)
	if err != nil {
		return nil, err
	}
	return &sts.IssuedCertificate{
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		Subject:        wiSpiffeID,
	}, nil
}

func (s *wiIssuingSTS) GetWebIdentityToken(_ context.Context, _ aws.Credentials,
	req sts.WebIdentityTokenRequest) (*sts.IssuedWebIdentityToken, error) {
	s.jwtSVIDs.Add(1)
	now := time.Now()
	// The tier checks the response's expiration against the token's exp, in seconds.
	expires := now.Add(time.Hour).Truncate(time.Second)
	token, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": wiSpiffeID, "aud": req.Audiences, "iat": now.Unix(), "exp": expires.Unix(),
	}).SignedString(s.key)
	if err != nil {
		return nil, err
	}
	return &sts.IssuedWebIdentityToken{Token: token, Expiration: expires}, nil
}
