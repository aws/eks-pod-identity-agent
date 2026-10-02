package bundle

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/go-jose/go-jose/v4"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
)

const (
	testProviderArn = "arn:aws:iam::111122223333:workload-identity-provider/example"
	testDomain      = "example.org"
	peerDomain      = "peer.example.org"
)

// authority is an x509-svid CA: its DER and its public key.
type authority struct {
	der []byte
	key *ecdsa.PrivateKey
}

// newAuthority mints a self-signed CA certificate to stand in for an x509-svid
// authority.
func newAuthority(t *testing.T, name string) authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a CA certificate: %v", err)
	}
	return authority{der: der, key: key}
}

// newECKey generates a P-256 key to stand in for a jwt-svid authority.
func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating an EC key: %v", err)
	}
	return key
}

// newRSAKey generates an RSA key to stand in for a jwt-svid authority.
func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating an RSA key: %v", err)
	}
	return key
}

// sortedDER is the order the tier serves X.509 authorities in.
func sortedDER(authorities ...[]byte) [][]byte {
	out := slices.Clone(authorities)
	slices.SortFunc(out, bytes.Compare)
	return out
}

// The SPIFFE bundle key uses the test documents route on.
const (
	useX509SVID = "x509-svid"
	useJWTSVID  = "jwt-svid"
)

// jwkMembers marshals key with go-jose and returns its members, so a test can add,
// change or drop one before the key goes into a document.
func jwkMembers(key jose.JSONWebKey) map[string]any {
	raw, err := json.Marshal(key)
	if err != nil {
		panic(fmt.Sprintf("encoding a JWK: %v", err))
	}
	var members map[string]any
	if err := json.Unmarshal(raw, &members); err != nil {
		panic(fmt.Sprintf("re-reading a JWK: %v", err))
	}
	return members
}

// x509Key is an x509-svid JWK for a, carrying its certificate in x5c and its
// public key parameters, as SPIFFE bundles do.
func x509Key(t *testing.T, a authority) map[string]any {
	t.Helper()
	cert, err := x509.ParseCertificate(a.der)
	if err != nil {
		t.Fatalf("parsing a CA certificate: %v", err)
	}
	return jwkMembers(jose.JSONWebKey{Key: &a.key.PublicKey, Certificates: []*x509.Certificate{cert}, Use: useX509SVID})
}

// jwtECKey is a jwt-svid JWK for an EC key.
func jwtECKey(t *testing.T, kid string, key *ecdsa.PrivateKey) map[string]any {
	t.Helper()
	return jwkMembers(jose.JSONWebKey{Key: &key.PublicKey, KeyID: kid, Use: useJWTSVID})
}

// jwtRSAKey is a jwt-svid JWK for an RSA key.
func jwtRSAKey(kid string, key *rsa.PrivateKey) map[string]any {
	return jwkMembers(jose.JSONWebKey{Key: &key.PublicKey, KeyID: kid, Use: useJWTSVID})
}

// bundleDoc serialises a SPIFFE bundle document. A zero hint omits the member.
func bundleDoc(t *testing.T, hintSeconds int, keys ...map[string]any) string {
	t.Helper()
	doc := map[string]any{"keys": keys}
	if hintSeconds != 0 {
		doc["spiffe_refresh_hint"] = hintSeconds
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encoding a bundle document: %v", err)
	}
	return string(out)
}

// indentedBundleDoc serialises the same document with different whitespace.
func indentedBundleDoc(t *testing.T, hintSeconds int, keys ...map[string]any) string {
	t.Helper()
	var doc any
	if err := json.Unmarshal([]byte(bundleDoc(t, hintSeconds, keys...)), &doc); err != nil {
		t.Fatalf("re-reading a bundle document: %v", err)
	}
	out, err := json.MarshalIndent(doc, "", "\t  ")
	if err != nil {
		t.Fatalf("indenting a bundle document: %v", err)
	}
	return "\n  " + string(out) + "\n"
}

// fakeFetcher is a counting fake GetTrustBundles. respond decides each call's
// result by its 1-based call number. When gate is non-nil every call reports
// itself on entered and then waits on gate, so a test can hold a fetch in
// flight.
type fakeFetcher struct {
	respond func(call int) ([]sts.TrustBundle, error)
	gate    chan struct{}
	entered chan struct{}

	mu        sync.Mutex
	calls     int
	arns      []string
	deadlines []time.Time
	creds     []aws.Credentials
}

func (f *fakeFetcher) GetTrustBundles(ctx context.Context, creds aws.Credentials, providerArn string) ([]sts.TrustBundle, error) {
	call := func() int {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		f.arns = append(f.arns, providerArn)
		f.creds = append(f.creds, creds)
		deadline, _ := ctx.Deadline()
		f.deadlines = append(f.deadlines, deadline)
		return f.calls
	}()

	if f.gate != nil {
		f.entered <- struct{}{}
		select {
		case <-f.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.respond(call)
}

func (f *fakeFetcher) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// fixed answers every call with the same entries.
func fixed(entries ...sts.TrustBundle) func(int) ([]sts.TrustBundle, error) {
	return func(int) ([]sts.TrustBundle, error) { return entries, nil }
}

// sequence answers call n with responses[n-1], and the last response after that.
func sequence(responses ...func() ([]sts.TrustBundle, error)) func(int) ([]sts.TrustBundle, error) {
	return func(call int) ([]sts.TrustBundle, error) {
		if call > len(responses) {
			call = len(responses)
		}
		return responses[call-1]()
	}
}

func ok(entries ...sts.TrustBundle) func() ([]sts.TrustBundle, error) {
	return func() ([]sts.TrustBundle, error) { return entries, nil }
}

func fail(err error) func() ([]sts.TrustBundle, error) {
	return func() ([]sts.TrustBundle, error) { return nil, err }
}

// testCreds stand in for the workload session's credentials a source fetches with.
var testCreds = aws.Credentials{AccessKeyID: "AKIDSESSION", SecretAccessKey: "session-secret", SessionToken: "session-token"}

// signTest signs a read's fetch with testCreds.
func signTest(context.Context) (aws.Credentials, error) { return testCreds, nil }

// refreshOnce runs one refresh with testCreds, whenever it is due.
func refreshOnce(s *providerSource, ctx context.Context) error {
	return s.refresh(ctx, testCreds, s.dueAt())
}
