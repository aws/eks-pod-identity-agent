package fake

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

// bundleSourceTestTimeout bounds every wait in this file, so a fake that never
// releases a parked call fails the test instead of hanging the suite.
const bundleSourceTestTimeout = 2 * time.Second

// bundleSourceProvider and bundleSourceOtherProvider are the workload identity
// provider ARNs the calls in this file name. The canned values answer both alike;
// only the funcs and ProviderRequests can tell them apart.
const (
	bundleSourceProvider      = "arn:aws:iam::111122223333:workload-identity-provider/example"
	bundleSourceOtherProvider = "arn:aws:iam::111122223333:workload-identity-provider/other"
)

// bundleSourceCtxKey tags the ctx a test passes in, so a func can report whether
// the fake handed it the caller's ctx.
type bundleSourceCtxKey struct{}

// bundleSourceOwnKey and bundleSourceFederatedKey are deterministic verification
// keys for the JWTAuthority lookup table.
var (
	bundleSourceOwnKey       = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public()
	bundleSourceFederatedKey = ed25519.NewKeyFromSeed(bundleSourceSeed(0x02)).Public()
)

// bundleSourceSeed builds a distinct ed25519 seed so two test keys differ.
func bundleSourceSeed(b byte) []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = b
	}
	return seed
}

// bundleSourceX509Result is what an X509Bundles call running in another goroutine
// hands back to the test.
type bundleSourceX509Result struct {
	bundles map[string][][]byte
	err     error
}

// bundleSourceJWTResult is what a JWTBundles call running in another goroutine
// hands back to the test.
type bundleSourceJWTResult struct {
	bundles map[string][]byte
	err     error
}

// bundleSourceFuncCall is what one of the fake's canned funcs saw when the fake
// called it.
type bundleSourceFuncCall struct {
	// ctxValue is what the func's ctx carries under bundleSourceCtxKey, and nil
	// for AuthorityFunc, which takes no ctx.
	ctxValue    any
	providerArn string
	trustDomain string
	keyID       string
	// providerRequests is ProviderRequests as read from inside the func.
	providerRequests []string
}

func TestBundleSourceOwnTrustDomain_Called_ReturnsTrustDomainForAnyProviderAndRecordsIt(t *testing.T) {
	testCases := []struct {
		name     string
		source   *BundleSource
		expected string
	}{
		{
			name:     "zero value returns the empty trust domain",
			source:   &BundleSource{},
			expected: "",
		},
		{
			name:     "canned trust domain is returned",
			source:   &BundleSource{TrustDomain: "example.org"},
			expected: "example.org",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			g.Expect(tc.source.OwnTrustDomainCalls()).To(Equal(0))
			g.Expect(tc.source.ProviderRequests()).To(BeEmpty())
			g.Expect(tc.source.OwnTrustDomain(bundleSourceProvider)).To(Equal(tc.expected))
			g.Expect(tc.source.OwnTrustDomain(bundleSourceOtherProvider)).To(Equal(tc.expected))
			g.Expect(tc.source.OwnTrustDomainCalls()).To(Equal(2))
			g.Expect(tc.source.ProviderRequests()).To(Equal([]string{bundleSourceProvider, bundleSourceOtherProvider}))
			g.Expect(tc.source.X509BundlesCalls()).To(Equal(0))
			g.Expect(tc.source.JWTBundlesCalls()).To(Equal(0))
			g.Expect(tc.source.JWTAuthorityCalls()).To(Equal(0))
			g.Expect(tc.source.LeaseCalls()).To(Equal(0))
		})
	}
}

func TestBundleSourceX509Bundles_CannedBehaviour_ReturnsThatBehaviour(t *testing.T) {
	cannedErr := errors.New("bundle unavailable")
	canned := map[string][][]byte{
		"example.org": {[]byte("own-authority-der")},
		"other.org":   {[]byte("federated-authority-der"), []byte("federated-authority-der-2")},
	}

	testCases := []struct {
		name        string
		source      *BundleSource
		expected    map[string][][]byte
		expectedErr error
	}{
		{
			name:     "zero value returns a nil map and no error",
			source:   &BundleSource{},
			expected: nil,
		},
		{
			name:     "canned bundles are returned",
			source:   &BundleSource{X509: canned},
			expected: canned,
		},
		{
			name:     "empty canned bundles stay distinguishable from nil",
			source:   &BundleSource{X509: map[string][][]byte{}},
			expected: map[string][][]byte{},
		},
		{
			name:        "canned error wins over canned bundles",
			source:      &BundleSource{X509: canned, X509Err: cannedErr},
			expectedErr: cannedErr,
		},
		{
			name: "func wins over canned bundles and canned error",
			source: &BundleSource{
				X509:    canned,
				X509Err: cannedErr,
				X509Func: func(_ context.Context, _ string) (map[string][][]byte, error) {
					return map[string][][]byte{"func.org": {[]byte("func-der")}}, nil
				},
			},
			expected: map[string][][]byte{"func.org": {[]byte("func-der")}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := tc.source.X509Bundles(context.Background(), bundleSourceProvider)

			if tc.expectedErr != nil {
				g.Expect(err).To(MatchError(tc.expectedErr))
				g.Expect(got).To(BeNil())
			} else {
				g.Expect(err).To(Not(HaveOccurred()))
				if tc.expected == nil {
					g.Expect(got).To(BeNil())
				} else {
					g.Expect(got).To(Equal(tc.expected))
				}
			}
			g.Expect(tc.source.X509BundlesCalls()).To(Equal(1))
			g.Expect(tc.source.ProviderRequests()).To(Equal([]string{bundleSourceProvider}))
			g.Expect(tc.source.JWTBundlesCalls()).To(Equal(0))
			g.Expect(tc.source.OwnTrustDomainCalls()).To(Equal(0))
			g.Expect(tc.source.JWTAuthorityCalls()).To(Equal(0))
			g.Expect(tc.source.LeaseCalls()).To(Equal(0))
			g.Expect(tc.source.Blocked()).To(Equal(0))
		})
	}
}

func TestBundleSourceJWTBundles_CannedBehaviour_ReturnsThatBehaviour(t *testing.T) {
	cannedErr := errors.New("bundle unavailable")
	canned := map[string][]byte{
		"example.org": []byte(`{"keys":[{"kid":"own"}]}`),
		"other.org":   []byte(`{"keys":[{"kid":"federated"}]}`),
	}

	testCases := []struct {
		name        string
		source      *BundleSource
		expected    map[string][]byte
		expectedErr error
	}{
		{
			name:     "zero value returns a nil map and no error",
			source:   &BundleSource{},
			expected: nil,
		},
		{
			name:     "canned jwk sets are returned",
			source:   &BundleSource{JWT: canned},
			expected: canned,
		},
		{
			name:     "empty canned jwk sets stay distinguishable from nil",
			source:   &BundleSource{JWT: map[string][]byte{}},
			expected: map[string][]byte{},
		},
		{
			name:        "canned error wins over canned jwk sets",
			source:      &BundleSource{JWT: canned, JWTErr: cannedErr},
			expectedErr: cannedErr,
		},
		{
			name: "func wins over canned jwk sets and canned error",
			source: &BundleSource{
				JWT:    canned,
				JWTErr: cannedErr,
				JWTFunc: func(_ context.Context, _ string) (map[string][]byte, error) {
					return map[string][]byte{"func.org": []byte(`{"keys":[]}`)}, nil
				},
			},
			expected: map[string][]byte{"func.org": []byte(`{"keys":[]}`)},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := tc.source.JWTBundles(context.Background(), bundleSourceProvider)

			if tc.expectedErr != nil {
				g.Expect(err).To(MatchError(tc.expectedErr))
				g.Expect(got).To(BeNil())
			} else {
				g.Expect(err).To(Not(HaveOccurred()))
				if tc.expected == nil {
					g.Expect(got).To(BeNil())
				} else {
					g.Expect(got).To(Equal(tc.expected))
				}
			}
			g.Expect(tc.source.JWTBundlesCalls()).To(Equal(1))
			g.Expect(tc.source.ProviderRequests()).To(Equal([]string{bundleSourceProvider}))
			g.Expect(tc.source.X509BundlesCalls()).To(Equal(0))
			g.Expect(tc.source.OwnTrustDomainCalls()).To(Equal(0))
			g.Expect(tc.source.JWTAuthorityCalls()).To(Equal(0))
			g.Expect(tc.source.LeaseCalls()).To(Equal(0))
			g.Expect(tc.source.Blocked()).To(Equal(0))
		})
	}
}

func TestBundleSourceJWTAuthority_CannedBehaviour_ReturnsThatBehaviour(t *testing.T) {
	cannedErr := errors.New("authority unavailable")
	funcKey := ed25519.NewKeyFromSeed(bundleSourceSeed(0x03)).Public()
	authorities := map[AuthorityKey]crypto.PublicKey{
		{TrustDomain: "example.org", KeyID: "own-kid"}:     bundleSourceOwnKey,
		{TrustDomain: "other.org", KeyID: "federated-kid"}: bundleSourceFederatedKey,
	}

	testCases := []struct {
		name        string
		source      *BundleSource
		trustDomain string
		keyID       string
		expected    crypto.PublicKey
		expectedErr error
	}{
		{
			name:        "zero value reports the key as not found",
			source:      &BundleSource{},
			trustDomain: "example.org",
			keyID:       "own-kid",
			expectedErr: ErrAuthorityNotFound,
		},
		{
			name:        "known key resolves to its authority",
			source:      &BundleSource{Authorities: authorities},
			trustDomain: "example.org",
			keyID:       "own-kid",
			expected:    bundleSourceOwnKey,
		},
		{
			name:        "known key in a federated domain resolves to its authority",
			source:      &BundleSource{Authorities: authorities},
			trustDomain: "other.org",
			keyID:       "federated-kid",
			expected:    bundleSourceFederatedKey,
		},
		{
			name:        "key id missing from a known trust domain is not found",
			source:      &BundleSource{Authorities: authorities},
			trustDomain: "example.org",
			keyID:       "unknown-kid",
			expectedErr: ErrAuthorityNotFound,
		},
		{
			name:        "trust domain missing altogether is not found",
			source:      &BundleSource{Authorities: authorities},
			trustDomain: "unknown.org",
			keyID:       "own-kid",
			expectedErr: ErrAuthorityNotFound,
		},
		{
			name:        "canned error wins over the lookup table",
			source:      &BundleSource{Authorities: authorities, AuthorityErr: cannedErr},
			trustDomain: "example.org",
			keyID:       "own-kid",
			expectedErr: cannedErr,
		},
		{
			name: "func wins over the lookup table and the canned error",
			source: &BundleSource{
				Authorities:  authorities,
				AuthorityErr: cannedErr,
				AuthorityFunc: func(_, _, _ string) (crypto.PublicKey, error) {
					return funcKey, nil
				},
			},
			trustDomain: "example.org",
			keyID:       "own-kid",
			expected:    funcKey,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := tc.source.JWTAuthority(bundleSourceProvider, tc.trustDomain, tc.keyID)

			if tc.expectedErr != nil {
				g.Expect(err).To(MatchError(tc.expectedErr))
				g.Expect(got).To(BeNil())
			} else {
				g.Expect(err).To(Not(HaveOccurred()))
				g.Expect(got).To(Equal(tc.expected))
			}
			// The request is recorded and counted on every path, misses included.
			g.Expect(tc.source.JWTAuthorityCalls()).To(Equal(1))
			g.Expect(tc.source.AuthorityRequests()).To(Equal([]AuthorityKey{{
				TrustDomain: tc.trustDomain,
				KeyID:       tc.keyID,
			}}))
			g.Expect(tc.source.ProviderRequests()).To(Equal([]string{bundleSourceProvider}))
			g.Expect(tc.source.OwnTrustDomainCalls()).To(Equal(0))
			g.Expect(tc.source.X509BundlesCalls()).To(Equal(0))
			g.Expect(tc.source.JWTBundlesCalls()).To(Equal(0))
			g.Expect(tc.source.LeaseCalls()).To(Equal(0))
		})
	}
}

func TestBundleSourceJWTAuthority_CalledRepeatedly_CountsCallsAndRecordsKeysAndProvidersInOrder(t *testing.T) {
	g := NewWithT(t)

	source := &BundleSource{Authorities: map[AuthorityKey]crypto.PublicKey{
		{TrustDomain: "example.org", KeyID: "own-kid"}: bundleSourceOwnKey,
	}}

	g.Expect(source.JWTAuthorityCalls()).To(Equal(0))
	g.Expect(source.AuthorityRequests()).To(BeEmpty())

	got, err := source.JWTAuthority(bundleSourceProvider, "example.org", "own-kid")
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(Equal(bundleSourceOwnKey))

	got, err = source.JWTAuthority(bundleSourceOtherProvider, "other.org", "missing-kid")
	g.Expect(err).To(MatchError(ErrAuthorityNotFound))
	g.Expect(got).To(BeNil())

	// The table is keyed without the provider, so a different provider resolves
	// the same key.
	got, err = source.JWTAuthority(bundleSourceOtherProvider, "example.org", "own-kid")
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(Equal(bundleSourceOwnKey))

	g.Expect(source.JWTAuthorityCalls()).To(Equal(3))
	g.Expect(source.AuthorityRequests()).To(Equal([]AuthorityKey{
		{TrustDomain: "example.org", KeyID: "own-kid"},
		{TrustDomain: "other.org", KeyID: "missing-kid"},
		{TrustDomain: "example.org", KeyID: "own-kid"},
	}))
	g.Expect(source.ProviderRequests()).To(Equal([]string{
		bundleSourceProvider,
		bundleSourceOtherProvider,
		bundleSourceOtherProvider,
	}))

	// AuthorityRequests hands back a copy, so a test mutating it cannot rewrite
	// the record.
	recorded := source.AuthorityRequests()
	recorded[0] = AuthorityKey{}
	g.Expect(source.AuthorityRequests()[0]).To(Equal(AuthorityKey{TrustDomain: "example.org", KeyID: "own-kid"}))
}

func TestBundleSourceX509Bundles_ReturnedMapMutated_NextCallIsUnaffected(t *testing.T) {
	g := NewWithT(t)

	der := []byte("own-authority-der")
	source := &BundleSource{X509: map[string][][]byte{"example.org": {der}}}
	expected := map[string][][]byte{"example.org": {[]byte("own-authority-der")}}

	got, err := source.X509Bundles(context.Background(), bundleSourceProvider)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(Equal(expected))

	// Mutate every level the caller can reach: the map, the per-domain slice, and
	// the authority bytes.
	got["injected.org"] = [][]byte{[]byte("injected-der")}
	got["example.org"] = append(got["example.org"], []byte("appended-der"))
	got["example.org"][0][0] = 'X'

	again, err := source.X509Bundles(context.Background(), bundleSourceProvider)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(again).To(Equal(expected))
	g.Expect(source.X509).To(Equal(expected))
	g.Expect(der).To(Equal([]byte("own-authority-der")))
	g.Expect(source.X509BundlesCalls()).To(Equal(2))
}

func TestBundleSourceX509Bundles_DomainWithNilAuthorities_KeepsNilApartFromEmpty(t *testing.T) {
	g := NewWithT(t)

	// A trust domain the agent knows about but holds no authority for is a
	// different state from one holding an empty set, and the copy has to keep the
	// two apart or a test cannot assert on either.
	source := &BundleSource{X509: map[string][][]byte{
		"nil.example.org":   nil,
		"empty.example.org": {},
	}}

	got, err := source.X509Bundles(context.Background(), bundleSourceProvider)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(HaveLen(2))
	g.Expect(got).To(HaveKey("nil.example.org"))
	g.Expect(got["nil.example.org"]).To(BeNil())
	g.Expect(got["empty.example.org"]).ToNot(BeNil())
	g.Expect(got["empty.example.org"]).To(BeEmpty())
	g.Expect(source.X509BundlesCalls()).To(Equal(1))
}

func TestBundleSourceJWTBundles_ReturnedMapMutated_NextCallIsUnaffected(t *testing.T) {
	g := NewWithT(t)

	jwks := []byte(`{"keys":[{"kid":"own"}]}`)
	source := &BundleSource{JWT: map[string][]byte{"example.org": jwks}}
	expected := map[string][]byte{"example.org": []byte(`{"keys":[{"kid":"own"}]}`)}

	got, err := source.JWTBundles(context.Background(), bundleSourceProvider)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(Equal(expected))

	got["injected.org"] = []byte(`{"keys":[]}`)
	got["example.org"][0] = 'X'

	again, err := source.JWTBundles(context.Background(), bundleSourceProvider)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(again).To(Equal(expected))
	g.Expect(source.JWT).To(Equal(expected))
	g.Expect(jwks).To(Equal([]byte(`{"keys":[{"kid":"own"}]}`)))
	g.Expect(source.JWTBundlesCalls()).To(Equal(2))
}

func TestBundleSourceSetters_CalledWhileLive_ReplaceCannedBehaviour(t *testing.T) {
	g := NewWithT(t)

	x509Err := errors.New("x509 bundle unavailable")
	jwtErr := errors.New("jwt bundle unavailable")
	source := &BundleSource{}

	x509Bundles, err := source.X509Bundles(context.Background(), bundleSourceProvider)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(x509Bundles).To(BeNil())

	source.SetX509Bundles(map[string][][]byte{"example.org": {[]byte("own-authority-der")}}, nil)
	x509Bundles, err = source.X509Bundles(context.Background(), bundleSourceProvider)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(x509Bundles).To(Equal(map[string][][]byte{"example.org": {[]byte("own-authority-der")}}))

	source.SetX509Bundles(nil, x509Err)
	x509Bundles, err = source.X509Bundles(context.Background(), bundleSourceProvider)
	g.Expect(err).To(MatchError(x509Err))
	g.Expect(x509Bundles).To(BeNil())

	jwtBundles, err := source.JWTBundles(context.Background(), bundleSourceProvider)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(jwtBundles).To(BeNil())

	source.SetJWTBundles(map[string][]byte{"example.org": []byte(`{"keys":[]}`)}, nil)
	jwtBundles, err = source.JWTBundles(context.Background(), bundleSourceProvider)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(jwtBundles).To(Equal(map[string][]byte{"example.org": []byte(`{"keys":[]}`)}))

	source.SetJWTBundles(nil, jwtErr)
	jwtBundles, err = source.JWTBundles(context.Background(), bundleSourceProvider)
	g.Expect(err).To(MatchError(jwtErr))
	g.Expect(jwtBundles).To(BeNil())

	g.Expect(source.X509BundlesCalls()).To(Equal(3))
	g.Expect(source.JWTBundlesCalls()).To(Equal(3))
}

func TestBundleSourceSetTrustDomain_CalledWhileLive_ChangesTheNextOwnTrustDomain(t *testing.T) {
	g := NewWithT(t)

	source := &BundleSource{TrustDomain: "example.org"}
	g.Expect(source.OwnTrustDomain(bundleSourceProvider)).To(Equal("example.org"))

	source.SetTrustDomain("rotated.org")
	g.Expect(source.OwnTrustDomain(bundleSourceProvider)).To(Equal("rotated.org"))

	// An empty domain is what a real implementation answers for a provider it
	// has not read yet.
	source.SetTrustDomain("")
	g.Expect(source.OwnTrustDomain(bundleSourceProvider)).To(BeEmpty())

	g.Expect(source.OwnTrustDomainCalls()).To(Equal(3))
}

func TestBundleSourceSetAuthorities_CalledWhileLive_ReplacesLookupTableAndError(t *testing.T) {
	g := NewWithT(t)

	cannedErr := errors.New("authority unavailable")
	own := AuthorityKey{TrustDomain: "example.org", KeyID: "own-kid"}
	// rotated stands in for a key id that only appears after a bundle refresh.
	rotated := AuthorityKey{TrustDomain: "example.org", KeyID: "rotated-kid"}
	source := &BundleSource{Authorities: map[AuthorityKey]crypto.PublicKey{own: bundleSourceOwnKey}}

	got, err := source.JWTAuthority(bundleSourceProvider, rotated.TrustDomain, rotated.KeyID)
	g.Expect(err).To(MatchError(ErrAuthorityNotFound))
	g.Expect(got).To(BeNil())

	source.SetAuthorities(map[AuthorityKey]crypto.PublicKey{rotated: bundleSourceFederatedKey}, nil)

	got, err = source.JWTAuthority(bundleSourceProvider, rotated.TrustDomain, rotated.KeyID)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(Equal(bundleSourceFederatedKey))

	// The table is replaced rather than merged, so the key the old one held is
	// gone with it.
	got, err = source.JWTAuthority(bundleSourceProvider, own.TrustDomain, own.KeyID)
	g.Expect(err).To(MatchError(ErrAuthorityNotFound))
	g.Expect(got).To(BeNil())

	// A canned error set alongside a table wins over that table.
	source.SetAuthorities(map[AuthorityKey]crypto.PublicKey{rotated: bundleSourceFederatedKey}, cannedErr)
	got, err = source.JWTAuthority(bundleSourceProvider, rotated.TrustDomain, rotated.KeyID)
	g.Expect(err).To(MatchError(cannedErr))
	g.Expect(got).To(BeNil())

	// Clearing the canned error puts the table back in charge.
	source.SetAuthorities(map[AuthorityKey]crypto.PublicKey{rotated: bundleSourceFederatedKey}, nil)
	got, err = source.JWTAuthority(bundleSourceProvider, rotated.TrustDomain, rotated.KeyID)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(Equal(bundleSourceFederatedKey))

	g.Expect(source.JWTAuthorityCalls()).To(Equal(5))
	g.Expect(source.AuthorityRequests()).To(Equal([]AuthorityKey{rotated, rotated, own, rotated, rotated}))
}

func TestBundleSourceSetters_CalledConcurrentlyWithTheirReader_CountEveryRead(t *testing.T) {
	const (
		writers    = 8
		readers    = 8
		iterations = 50
	)

	leaseErr := errors.New("lease refused")

	// read reports what it observed rather than asserting, because a gomega
	// failure in a reader goroutine would leave the writers running.
	testCases := []struct {
		name  string
		set   func(s *BundleSource, i int)
		read  func(s *BundleSource) error
		calls func(s *BundleSource) int
	}{
		{
			name: "SetTrustDomain against OwnTrustDomain",
			set: func(s *BundleSource, i int) {
				s.SetTrustDomain(fmt.Sprintf("domain-%d.org", i))
			},
			read: func(s *BundleSource) error {
				// Every value the writers set, and the value the fake started
				// with, is one a reader may legitimately see.
				switch domain := s.OwnTrustDomain(bundleSourceProvider); {
				case domain == "example.org", strings.HasPrefix(domain, "domain-"):
					return nil
				default:
					return fmt.Errorf("OwnTrustDomain returned %q, which no writer set", domain)
				}
			},
			calls: func(s *BundleSource) int { return s.OwnTrustDomainCalls() },
		},
		{
			name: "SetAuthorities against JWTAuthority",
			set: func(s *BundleSource, i int) {
				// Every table the writers set keeps own-kid, so the reader below
				// must resolve it whichever table it lands on.
				s.SetAuthorities(map[AuthorityKey]crypto.PublicKey{
					{TrustDomain: "example.org", KeyID: fmt.Sprintf("kid-%d", i)}: bundleSourceFederatedKey,
					{TrustDomain: "example.org", KeyID: "own-kid"}:                bundleSourceOwnKey,
				}, nil)
			},
			read: func(s *BundleSource) error {
				authority, err := s.JWTAuthority(bundleSourceProvider, "example.org", "own-kid")
				if err != nil {
					return err
				}
				if got, ok := authority.(ed25519.PublicKey); !ok || !got.Equal(bundleSourceOwnKey) {
					return fmt.Errorf("JWTAuthority returned %v, want the own key", authority)
				}
				return nil
			},
			calls: func(s *BundleSource) int { return s.JWTAuthorityCalls() },
		},
		{
			name: "SetLease against Lease",
			set: func(s *BundleSource, i int) {
				if i%2 == 0 {
					s.SetLease(nil)
				} else {
					s.SetLease(leaseErr)
				}
			},
			read: func(s *BundleSource) error {
				// A reader sees either a lease or the canned error, never a mix.
				release, err := s.Lease(context.Background(), bundleSourceProvider)
				switch {
				case err == nil && release != nil:
					release()
					return nil
				case errors.Is(err, leaseErr) && release == nil:
					return nil
				default:
					return fmt.Errorf("Lease returned a release func %t and error %v, which no writer set", release != nil, err)
				}
			},
			calls: func(s *BundleSource) int { return s.LeaseCalls() },
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			source := &BundleSource{
				TrustDomain: "example.org",
				Authorities: map[AuthorityKey]crypto.PublicKey{
					{TrustDomain: "example.org", KeyID: "own-kid"}: bundleSourceOwnKey,
				},
			}

			// Each reader owns one slot, so collecting results needs no lock of
			// its own and cannot mask a race inside the fake.
			readErrs := make([]error, readers)
			var wg sync.WaitGroup
			for w := 0; w < writers; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					for i := 0; i < iterations; i++ {
						tc.set(source, w*iterations+i)
					}
				}(w)
			}
			for r := 0; r < readers; r++ {
				wg.Add(1)
				go func(r int) {
					defer wg.Done()
					for i := 0; i < iterations; i++ {
						if err := tc.read(source); err != nil && readErrs[r] == nil {
							readErrs[r] = err
						}
					}
				}(r)
			}
			wg.Wait()

			for _, err := range readErrs {
				g.Expect(err).To(Not(HaveOccurred()))
			}
			g.Expect(tc.calls(source)).To(Equal(readers * iterations))
			g.Expect(source.ProviderRequests()).To(HaveLen(readers * iterations))
			g.Expect(source.LiveLeases()).To(Equal(0))
		})
	}
}

func TestBundleSourceX509Bundles_GateBlocked_ReturnsCannedBundlesAfterRelease(t *testing.T) {
	g := NewWithT(t)

	expected := map[string][][]byte{"example.org": {[]byte("own-authority-der")}}
	source := &BundleSource{X509: map[string][][]byte{"example.org": {[]byte("own-authority-der")}}}
	source.Block()

	ctx, cancel := context.WithTimeout(context.Background(), bundleSourceTestTimeout)
	t.Cleanup(cancel)

	done := make(chan bundleSourceX509Result, 1)
	go func() {
		bundles, err := source.X509Bundles(ctx, bundleSourceProvider)
		done <- bundleSourceX509Result{bundles: bundles, err: err}
	}()

	g.Expect(source.WaitForBlocked(ctx, 1)).To(Succeed())
	g.Expect(source.Blocked()).To(Equal(1))
	g.Expect(done).To(Not(Receive()))
	g.Expect(source.X509BundlesCalls()).To(Equal(0))
	g.Expect(source.ProviderRequests()).To(BeEmpty())

	source.Release()

	var got bundleSourceX509Result
	select {
	case got = <-done:
	case <-ctx.Done():
		t.Fatalf("X509Bundles did not return after Release: %v", ctx.Err())
	}

	g.Expect(got.err).To(Not(HaveOccurred()))
	g.Expect(got.bundles).To(Equal(expected))
	g.Expect(source.X509BundlesCalls()).To(Equal(1))
	g.Expect(source.ProviderRequests()).To(Equal([]string{bundleSourceProvider}))
	g.Expect(source.Blocked()).To(Equal(0))
}

func TestBundleSourceJWTBundles_GateBlocked_ReturnsCannedBundlesAfterRelease(t *testing.T) {
	g := NewWithT(t)

	expected := map[string][]byte{"example.org": []byte(`{"keys":[{"kid":"own"}]}`)}
	source := &BundleSource{JWT: map[string][]byte{"example.org": []byte(`{"keys":[{"kid":"own"}]}`)}}
	source.Block()

	ctx, cancel := context.WithTimeout(context.Background(), bundleSourceTestTimeout)
	t.Cleanup(cancel)

	done := make(chan bundleSourceJWTResult, 1)
	go func() {
		bundles, err := source.JWTBundles(ctx, bundleSourceProvider)
		done <- bundleSourceJWTResult{bundles: bundles, err: err}
	}()

	g.Expect(source.WaitForBlocked(ctx, 1)).To(Succeed())
	g.Expect(source.Blocked()).To(Equal(1))
	g.Expect(done).To(Not(Receive()))
	g.Expect(source.JWTBundlesCalls()).To(Equal(0))
	g.Expect(source.ProviderRequests()).To(BeEmpty())

	source.Release()

	var got bundleSourceJWTResult
	select {
	case got = <-done:
	case <-ctx.Done():
		t.Fatalf("JWTBundles did not return after Release: %v", ctx.Err())
	}

	g.Expect(got.err).To(Not(HaveOccurred()))
	g.Expect(got.bundles).To(Equal(expected))
	g.Expect(source.JWTBundlesCalls()).To(Equal(1))
	g.Expect(source.ProviderRequests()).To(Equal([]string{bundleSourceProvider}))
	g.Expect(source.Blocked()).To(Equal(0))
}

func TestBundleSourceBundles_ParkedCallContextCancelled_ReturnsContextError(t *testing.T) {
	testCases := []struct {
		name  string
		call  func(ctx context.Context, s *BundleSource) (bool, error)
		calls func(s *BundleSource) int
	}{
		{
			name: "x509 bundles",
			call: func(ctx context.Context, s *BundleSource) (bool, error) {
				bundles, err := s.X509Bundles(ctx, bundleSourceProvider)
				return bundles == nil, err
			},
			calls: func(s *BundleSource) int { return s.X509BundlesCalls() },
		},
		{
			name: "jwt bundles",
			call: func(ctx context.Context, s *BundleSource) (bool, error) {
				bundles, err := s.JWTBundles(ctx, bundleSourceProvider)
				return bundles == nil, err
			},
			calls: func(s *BundleSource) int { return s.JWTBundlesCalls() },
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			source := &BundleSource{
				X509: map[string][][]byte{"example.org": {[]byte("own-authority-der")}},
				JWT:  map[string][]byte{"example.org": []byte(`{"keys":[]}`)},
			}
			source.Block()

			waitCtx, cancelWait := context.WithTimeout(context.Background(), bundleSourceTestTimeout)
			t.Cleanup(cancelWait)
			callCtx, cancelCall := context.WithCancel(context.Background())
			t.Cleanup(cancelCall)

			type result struct {
				nilBundles bool
				err        error
			}
			done := make(chan result, 1)
			go func() {
				nilBundles, err := tc.call(callCtx, source)
				done <- result{nilBundles: nilBundles, err: err}
			}()

			g.Expect(source.WaitForBlocked(waitCtx, 1)).To(Succeed())
			cancelCall()

			var got result
			select {
			case got = <-done:
			case <-waitCtx.Done():
				t.Fatalf("the call did not return after its context was cancelled: %v", waitCtx.Err())
			}

			g.Expect(got.err).To(MatchError(context.Canceled))
			g.Expect(got.nilBundles).To(BeTrue())
			g.Expect(tc.calls(source)).To(Equal(0))
			g.Expect(source.ProviderRequests()).To(BeEmpty())
			g.Expect(source.Blocked()).To(Equal(0))
		})
	}
}

func TestBundleSourceGateBlocked_MethodsWithoutContext_DoNotPark(t *testing.T) {
	g := NewWithT(t)

	source := &BundleSource{
		TrustDomain: "example.org",
		Authorities: map[AuthorityKey]crypto.PublicKey{
			{TrustDomain: "example.org", KeyID: "own-kid"}: bundleSourceOwnKey,
		},
	}
	source.Block()
	t.Cleanup(source.Release)

	type result struct {
		trustDomain string
		authority   crypto.PublicKey
		err         error
	}
	done := make(chan result, 1)
	go func() {
		trustDomain := source.OwnTrustDomain(bundleSourceProvider)
		authority, err := source.JWTAuthority(bundleSourceOtherProvider, "example.org", "own-kid")
		done <- result{trustDomain: trustDomain, authority: authority, err: err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), bundleSourceTestTimeout)
	t.Cleanup(cancel)

	var got result
	select {
	case got = <-done:
	case <-ctx.Done():
		t.Fatalf("OwnTrustDomain or JWTAuthority parked at a closed gate: %v", ctx.Err())
	}

	g.Expect(got.err).To(Not(HaveOccurred()))
	g.Expect(got.trustDomain).To(Equal("example.org"))
	g.Expect(got.authority).To(Equal(bundleSourceOwnKey))
	g.Expect(source.Blocked()).To(Equal(0))
	g.Expect(source.OwnTrustDomainCalls()).To(Equal(1))
	g.Expect(source.JWTAuthorityCalls()).To(Equal(1))
	g.Expect(source.AuthorityRequests()).To(Equal([]AuthorityKey{{TrustDomain: "example.org", KeyID: "own-kid"}}))
	g.Expect(source.ProviderRequests()).To(Equal([]string{bundleSourceProvider, bundleSourceOtherProvider}))
}

func TestBundleSourceBundles_ContextAlreadyDone_ReturnContextErrorWithoutParking(t *testing.T) {
	g := NewWithT(t)

	source := &BundleSource{
		X509: map[string][][]byte{"example.org": {[]byte("own-authority-der")}},
		JWT:  map[string][]byte{"example.org": []byte(`{"keys":[]}`)},
	}
	source.Block()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	x509Bundles, err := source.X509Bundles(ctx, bundleSourceProvider)
	g.Expect(err).To(MatchError(context.Canceled))
	g.Expect(x509Bundles).To(BeNil())

	jwtBundles, err := source.JWTBundles(ctx, bundleSourceProvider)
	g.Expect(err).To(MatchError(context.Canceled))
	g.Expect(jwtBundles).To(BeNil())

	g.Expect(source.X509BundlesCalls()).To(Equal(0))
	g.Expect(source.JWTBundlesCalls()).To(Equal(0))
	g.Expect(source.ProviderRequests()).To(BeEmpty())
	g.Expect(source.Blocked()).To(Equal(0))
}

func TestBundleSourceCannedValues_DifferentProviders_AllGetTheSameAnswer(t *testing.T) {
	g := NewWithT(t)

	source := &BundleSource{
		TrustDomain: "example.org",
		X509:        map[string][][]byte{"example.org": {[]byte("own-authority-der")}},
		JWT:         map[string][]byte{"example.org": []byte(`{"keys":[{"kid":"own"}]}`)},
		Authorities: map[AuthorityKey]crypto.PublicKey{
			{TrustDomain: "example.org", KeyID: "own-kid"}: bundleSourceOwnKey,
		},
	}

	// The empty ARN is answered like any other. The fake does not model the
	// ErrNotEnrolled a real implementation returns for it; a test that needs that
	// error sets LeaseErr or a func.
	providers := []string{bundleSourceProvider, bundleSourceOtherProvider, ""}
	var expectedRequests []string
	for _, providerArn := range providers {
		g.Expect(source.OwnTrustDomain(providerArn)).To(Equal("example.org"), "provider %q", providerArn)

		x509Bundles, err := source.X509Bundles(context.Background(), providerArn)
		g.Expect(err).To(Not(HaveOccurred()), "provider %q", providerArn)
		g.Expect(x509Bundles).To(Equal(source.X509), "provider %q", providerArn)

		jwtBundles, err := source.JWTBundles(context.Background(), providerArn)
		g.Expect(err).To(Not(HaveOccurred()), "provider %q", providerArn)
		g.Expect(jwtBundles).To(Equal(source.JWT), "provider %q", providerArn)

		authority, err := source.JWTAuthority(providerArn, "example.org", "own-kid")
		g.Expect(err).To(Not(HaveOccurred()), "provider %q", providerArn)
		g.Expect(authority).To(Equal(bundleSourceOwnKey), "provider %q", providerArn)

		release, err := source.Lease(context.Background(), providerArn)
		g.Expect(err).To(Not(HaveOccurred()), "provider %q", providerArn)
		g.Expect(release).To(Not(BeNil()), "provider %q", providerArn)
		release()

		expectedRequests = append(expectedRequests, providerArn, providerArn, providerArn, providerArn, providerArn)
	}

	g.Expect(source.ProviderRequests()).To(Equal(expectedRequests))
	g.Expect(source.LeaseCalls()).To(Equal(len(providers)))
	g.Expect(source.Released()).To(Equal(len(providers)))
	g.Expect(source.LiveLeases()).To(Equal(0))
}

func TestBundleSourceFuncs_Set_ReceiveTheProviderEachCallNames(t *testing.T) {
	// keysByProvider gives AuthorityFunc an answer only the named provider gets.
	keysByProvider := map[string]crypto.PublicKey{
		bundleSourceProvider:      bundleSourceOwnKey,
		bundleSourceOtherProvider: bundleSourceFederatedKey,
	}

	testCases := []struct {
		name string
		// install sets the func under test on s. The func reports what it saw
		// through record, reading ProviderRequests from inside itself, and
		// answers with something only the provider it was handed gets.
		install func(s *BundleSource, record func(bundleSourceFuncCall))
		// call makes one call naming providerArn.
		call func(ctx context.Context, s *BundleSource, providerArn string) (any, error)
		// expected is the answer install's func gives providerArn.
		expected func(providerArn string) any
		// ctxValue, trustDomain and keyID are what the func must have seen
		// besides the provider.
		ctxValue    any
		trustDomain string
		keyID       string
	}{
		{
			name: "X509Func",
			install: func(s *BundleSource, record func(bundleSourceFuncCall)) {
				s.X509Func = func(ctx context.Context, providerArn string) (map[string][][]byte, error) {
					record(bundleSourceFuncCall{
						ctxValue:         ctx.Value(bundleSourceCtxKey{}),
						providerArn:      providerArn,
						providerRequests: s.ProviderRequests(),
					})
					return map[string][][]byte{"example.org": {[]byte(providerArn)}}, nil
				}
			},
			call: func(ctx context.Context, s *BundleSource, providerArn string) (any, error) {
				return s.X509Bundles(ctx, providerArn)
			},
			expected: func(providerArn string) any {
				return map[string][][]byte{"example.org": {[]byte(providerArn)}}
			},
			ctxValue: "the caller's ctx",
		},
		{
			name: "JWTFunc",
			install: func(s *BundleSource, record func(bundleSourceFuncCall)) {
				s.JWTFunc = func(ctx context.Context, providerArn string) (map[string][]byte, error) {
					record(bundleSourceFuncCall{
						ctxValue:         ctx.Value(bundleSourceCtxKey{}),
						providerArn:      providerArn,
						providerRequests: s.ProviderRequests(),
					})
					return map[string][]byte{"example.org": []byte(providerArn)}, nil
				}
			},
			call: func(ctx context.Context, s *BundleSource, providerArn string) (any, error) {
				return s.JWTBundles(ctx, providerArn)
			},
			expected: func(providerArn string) any {
				return map[string][]byte{"example.org": []byte(providerArn)}
			},
			ctxValue: "the caller's ctx",
		},
		{
			name: "AuthorityFunc",
			install: func(s *BundleSource, record func(bundleSourceFuncCall)) {
				s.AuthorityFunc = func(providerArn, trustDomain, keyID string) (crypto.PublicKey, error) {
					record(bundleSourceFuncCall{
						providerArn:      providerArn,
						trustDomain:      trustDomain,
						keyID:            keyID,
						providerRequests: s.ProviderRequests(),
					})
					return keysByProvider[providerArn], nil
				}
			},
			call: func(_ context.Context, s *BundleSource, providerArn string) (any, error) {
				return s.JWTAuthority(providerArn, "example.org", "own-kid")
			},
			expected:    func(providerArn string) any { return keysByProvider[providerArn] },
			trustDomain: "example.org",
			keyID:       "own-kid",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			ctx := context.WithValue(context.Background(), bundleSourceCtxKey{}, "the caller's ctx")
			source := &BundleSource{}
			var seen []bundleSourceFuncCall
			tc.install(source, func(c bundleSourceFuncCall) { seen = append(seen, c) })

			first, err := tc.call(ctx, source, bundleSourceProvider)
			g.Expect(err).To(Not(HaveOccurred()))
			g.Expect(first).To(Equal(tc.expected(bundleSourceProvider)))

			second, err := tc.call(ctx, source, bundleSourceOtherProvider)
			g.Expect(err).To(Not(HaveOccurred()))
			g.Expect(second).To(Equal(tc.expected(bundleSourceOtherProvider)))

			// Each call's provider is recorded before its func runs, and reading
			// the record from inside the func does not deadlock because the fake
			// does not hold its lock across the callback.
			g.Expect(seen).To(Equal([]bundleSourceFuncCall{
				{
					ctxValue:         tc.ctxValue,
					providerArn:      bundleSourceProvider,
					trustDomain:      tc.trustDomain,
					keyID:            tc.keyID,
					providerRequests: []string{bundleSourceProvider},
				},
				{
					ctxValue:         tc.ctxValue,
					providerArn:      bundleSourceOtherProvider,
					trustDomain:      tc.trustDomain,
					keyID:            tc.keyID,
					providerRequests: []string{bundleSourceProvider, bundleSourceOtherProvider},
				},
			}))
			g.Expect(source.ProviderRequests()).To(Equal([]string{bundleSourceProvider, bundleSourceOtherProvider}))
		})
	}
}

func TestBundleSourceProviderRequests_CallsAcrossMethods_RecordsEveryCountedCallInOrder(t *testing.T) {
	g := NewWithT(t)

	// provider names each call distinctly, so the record shows which call landed
	// where.
	provider := func(name string) string {
		return "arn:aws:iam::111122223333:workload-identity-provider/" + name
	}
	x509Err := errors.New("x509 bundle unavailable")
	leaseErr := errors.New("lease refused")
	source := &BundleSource{
		TrustDomain: "example.org",
		X509Err:     x509Err,
		JWT:         map[string][]byte{"example.org": []byte(`{"keys":[]}`)},
		Authorities: map[AuthorityKey]crypto.PublicKey{
			{TrustDomain: "example.org", KeyID: "own-kid"}: bundleSourceOwnKey,
		},
	}
	doneCtx, cancel := context.WithCancel(context.Background())
	cancel()

	g.Expect(source.OwnTrustDomain(provider("a"))).To(Equal("example.org"))

	// A canned error is still a counted call, so its provider is recorded.
	_, err := source.X509Bundles(context.Background(), provider("b"))
	g.Expect(err).To(MatchError(x509Err))

	// So is a lookup miss.
	_, err = source.JWTAuthority(provider("c"), "unknown.org", "missing-kid")
	g.Expect(err).To(MatchError(ErrAuthorityNotFound))

	_, err = source.JWTBundles(context.Background(), provider("d"))
	g.Expect(err).To(Not(HaveOccurred()))

	// A lease is recorded when it is taken; releasing it records nothing.
	release, err := source.Lease(context.Background(), provider("e"))
	g.Expect(err).To(Not(HaveOccurred()))

	// The empty ARN is recorded as it was passed, so a handler test can catch a
	// session whose provider was never filled in.
	g.Expect(source.OwnTrustDomain("")).To(Equal("example.org"))

	// Calls turned away by their ctx are not counted, so they are not recorded.
	_, err = source.X509Bundles(doneCtx, provider("turned-away-x509"))
	g.Expect(err).To(MatchError(context.Canceled))
	_, err = source.JWTBundles(doneCtx, provider("turned-away-jwt"))
	g.Expect(err).To(MatchError(context.Canceled))

	// Lease does not go through the Gate, so a done ctx does not turn it away.
	_, err = source.Lease(doneCtx, provider("f"))
	g.Expect(err).To(Not(HaveOccurred()))

	// A canned lease error is still a counted call.
	source.SetLease(leaseErr)
	_, err = source.Lease(context.Background(), provider("g"))
	g.Expect(err).To(MatchError(leaseErr))
	release()

	// A provider named again is recorded again.
	_, err = source.JWTAuthority(provider("a"), "example.org", "own-kid")
	g.Expect(err).To(Not(HaveOccurred()))

	g.Expect(source.ProviderRequests()).To(Equal([]string{
		provider("a"),
		provider("b"),
		provider("c"),
		provider("d"),
		provider("e"),
		"",
		provider("f"),
		provider("g"),
		provider("a"),
	}))
	g.Expect(source.OwnTrustDomainCalls()).To(Equal(2))
	g.Expect(source.X509BundlesCalls()).To(Equal(1))
	g.Expect(source.JWTBundlesCalls()).To(Equal(1))
	g.Expect(source.JWTAuthorityCalls()).To(Equal(2))
	g.Expect(source.LeaseCalls()).To(Equal(3))
}

func TestBundleSourceProviderRequests_ReturnedSliceMutated_RecordIsUnaffected(t *testing.T) {
	g := NewWithT(t)

	source := &BundleSource{}
	source.OwnTrustDomain(bundleSourceProvider)
	source.OwnTrustDomain(bundleSourceOtherProvider)

	recorded := source.ProviderRequests()
	recorded[0] = "rewritten"
	g.Expect(source.ProviderRequests()).To(Equal([]string{bundleSourceProvider, bundleSourceOtherProvider}))

	// A copy taken before a later call does not grow with the record.
	snapshot := source.ProviderRequests()
	source.OwnTrustDomain(bundleSourceProvider)
	g.Expect(snapshot).To(Equal([]string{bundleSourceProvider, bundleSourceOtherProvider}))
	g.Expect(source.ProviderRequests()).To(Equal([]string{
		bundleSourceProvider,
		bundleSourceOtherProvider,
		bundleSourceProvider,
	}))
}

func TestBundleSourceProviderRequests_ConcurrentCallersAndReaders_RecordEveryCallInEachCallersOrder(t *testing.T) {
	g := NewWithT(t)

	const (
		callers    = 8
		iterations = 25
		readers    = 4
		reads      = 50
	)

	source := &BundleSource{
		TrustDomain: "example.org",
		X509:        map[string][][]byte{"example.org": {[]byte("own-authority-der")}},
		JWT:         map[string][]byte{"example.org": []byte(`{"keys":[]}`)},
		Authorities: map[AuthorityKey]crypto.PublicKey{
			{TrustDomain: "example.org", KeyID: "own-kid"}: bundleSourceOwnKey,
		},
	}

	// Every call names a provider no other call names, so the final record
	// shows both that each call landed exactly once and where.
	provider := func(caller, iteration int, method string) string {
		return fmt.Sprintf("arn:aws:iam::111122223333:workload-identity-provider/caller-%d-%d-%s", caller, iteration, method)
	}
	methods := []string{"own", "x509", "jwt", "authority", "lease"}
	expectedPerCaller := make([][]string, callers)
	callerOf := make(map[string]int, callers*iterations*len(methods))
	for c := 0; c < callers; c++ {
		for i := 0; i < iterations; i++ {
			for _, method := range methods {
				expectedPerCaller[c] = append(expectedPerCaller[c], provider(c, i, method))
				callerOf[provider(c, i, method)] = c
			}
		}
	}

	// Each goroutine owns one slot, so collecting results needs no lock of its
	// own and cannot mask a race inside the fake.
	callErrs := make([]error, callers)
	snapshots := make([][][]string, readers)
	var wg sync.WaitGroup
	for c := 0; c < callers; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				source.OwnTrustDomain(provider(c, i, "own"))
				if _, err := source.X509Bundles(context.Background(), provider(c, i, "x509")); err != nil {
					callErrs[c] = err
					return
				}
				if _, err := source.JWTBundles(context.Background(), provider(c, i, "jwt")); err != nil {
					callErrs[c] = err
					return
				}
				if _, err := source.JWTAuthority(provider(c, i, "authority"), "example.org", "own-kid"); err != nil {
					callErrs[c] = err
					return
				}
				release, err := source.Lease(context.Background(), provider(c, i, "lease"))
				if err != nil {
					callErrs[c] = err
					return
				}
				release()
			}
		}(c)
	}
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func(r int) {
			defer wg.Done()
			for i := 0; i < reads; i++ {
				snapshots[r] = append(snapshots[r], source.ProviderRequests())
			}
		}(r)
	}
	wg.Wait()

	for _, err := range callErrs {
		g.Expect(err).To(Not(HaveOccurred()))
	}

	recorded := source.ProviderRequests()
	g.Expect(recorded).To(HaveLen(callers * iterations * len(methods)))

	// The record only grows at its end, so every copy a reader took mid-run is a
	// prefix of the final record.
	for r, taken := range snapshots {
		for i, snapshot := range taken {
			if !g.Expect(len(snapshot)).To(BeNumerically("<=", len(recorded)), "reader %d snapshot %d", r, i) {
				continue
			}
			g.Expect(slices.Equal(recorded[:len(snapshot)], snapshot)).To(BeTrue(),
				"reader %d snapshot %d is not a prefix of the final record", r, i)
		}
	}

	// Whatever the interleaving across callers, each caller's own calls appear
	// in the order it made them.
	gotPerCaller := make([][]string, callers)
	for _, providerArn := range recorded {
		c, ok := callerOf[providerArn]
		if !g.Expect(ok).To(BeTrue(), "recorded provider %q was never passed", providerArn) {
			continue
		}
		gotPerCaller[c] = append(gotPerCaller[c], providerArn)
	}
	g.Expect(gotPerCaller).To(Equal(expectedPerCaller))

	g.Expect(source.OwnTrustDomainCalls()).To(Equal(callers * iterations))
	g.Expect(source.X509BundlesCalls()).To(Equal(callers * iterations))
	g.Expect(source.JWTBundlesCalls()).To(Equal(callers * iterations))
	g.Expect(source.JWTAuthorityCalls()).To(Equal(callers * iterations))
	g.Expect(source.LeaseCalls()).To(Equal(callers * iterations))
	g.Expect(source.LiveLeases()).To(Equal(0))
}

// bundleSourceBookedLeases reads how many canned leases the fake still holds. A
// lease leaves when its release func runs or its AfterFunc does, so this reaching
// zero after a cancel shows the AfterFunc ran.
func bundleSourceBookedLeases(s *BundleSource) func() int {
	return func() int {
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.leases)
	}
}

func TestBundleSourceLease_CannedBehaviour_ReturnsThatBehaviour(t *testing.T) {
	cannedErr := errors.New("lease refused")

	testCases := []struct {
		name        string
		source      *BundleSource
		expectedErr error
		// expectedLive is how many leases the fake tracks after the call.
		expectedLive int
	}{
		{
			name:         "zero value hands out a canned lease",
			source:       &BundleSource{},
			expectedLive: 1,
		},
		{
			name:        "canned error is returned with a nil release func",
			source:      &BundleSource{LeaseErr: cannedErr},
			expectedErr: cannedErr,
		},
		{
			name:   "func alone is returned as is and its lease goes untracked",
			source: &BundleSource{LeaseFunc: func(_ context.Context, _ string) (func(), error) { return func() {}, nil }},
		},
		{
			name: "func wins over the canned error and its lease goes untracked",
			source: &BundleSource{
				LeaseErr:  cannedErr,
				LeaseFunc: func(_ context.Context, _ string) (func(), error) { return func() {}, nil },
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			release, err := tc.source.Lease(context.Background(), bundleSourceProvider)

			if tc.expectedErr != nil {
				g.Expect(err).To(MatchError(tc.expectedErr))
				g.Expect(release).To(BeNil())
			} else {
				g.Expect(err).To(Not(HaveOccurred()))
				g.Expect(release).To(Not(BeNil()))
			}
			g.Expect(tc.source.LeaseCalls()).To(Equal(1))
			g.Expect(tc.source.LiveLeases()).To(Equal(tc.expectedLive))
			g.Expect(tc.source.Released()).To(Equal(0))
			g.Expect(tc.source.ReleaseCalls()).To(Equal(0))
			g.Expect(tc.source.ProviderRequests()).To(Equal([]string{bundleSourceProvider}))
			g.Expect(tc.source.OwnTrustDomainCalls()).To(Equal(0))
			g.Expect(tc.source.X509BundlesCalls()).To(Equal(0))
			g.Expect(tc.source.JWTBundlesCalls()).To(Equal(0))
			g.Expect(tc.source.JWTAuthorityCalls()).To(Equal(0))
			g.Expect(tc.source.Blocked()).To(Equal(0))
		})
	}
}

func TestBundleSourceLease_FuncSet_SeesItsCallCountedAndIsReturnedAsIs(t *testing.T) {
	g := NewWithT(t)

	// notEnrolled stands in for the ErrNotEnrolled a real implementation returns
	// for the empty ARN, which is how a test that needs it sets it up.
	notEnrolled := errors.New("not enrolled")
	type funcCall struct {
		ctxValue         any
		providerArn      string
		leaseCalls       int
		providerRequests []string
	}
	var seen []funcCall
	funcReleases := 0

	source := &BundleSource{LeaseErr: errors.New("canned lease error")}
	source.LeaseFunc = func(ctx context.Context, providerArn string) (func(), error) {
		// Reading the fake from inside the func does not deadlock, because the
		// fake does not hold its lock across the callback.
		seen = append(seen, funcCall{
			ctxValue:         ctx.Value(bundleSourceCtxKey{}),
			providerArn:      providerArn,
			leaseCalls:       source.LeaseCalls(),
			providerRequests: source.ProviderRequests(),
		})
		if providerArn == "" {
			return nil, notEnrolled
		}
		return func() { funcReleases++ }, nil
	}
	ctx := context.WithValue(context.Background(), bundleSourceCtxKey{}, "the caller's ctx")

	release, err := source.Lease(ctx, bundleSourceProvider)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(release).To(Not(BeNil()))

	// The func's release is handed back unwrapped, so the fake does not make it
	// idempotent and does not count it.
	release()
	release()
	g.Expect(funcReleases).To(Equal(2))

	release, err = source.Lease(ctx, "")
	g.Expect(err).To(MatchError(notEnrolled))
	g.Expect(release).To(BeNil())

	g.Expect(seen).To(Equal([]funcCall{
		{
			ctxValue:         "the caller's ctx",
			providerArn:      bundleSourceProvider,
			leaseCalls:       1,
			providerRequests: []string{bundleSourceProvider},
		},
		{
			ctxValue:         "the caller's ctx",
			providerArn:      "",
			leaseCalls:       2,
			providerRequests: []string{bundleSourceProvider, ""},
		},
	}))
	g.Expect(source.LeaseCalls()).To(Equal(2))
	g.Expect(source.LiveLeases()).To(Equal(0))
	g.Expect(source.Released()).To(Equal(0))
	g.Expect(source.ReleaseCalls()).To(Equal(0))
}

func TestBundleSourceLease_ReleasedByFuncOrCtx_ReleasesOnceByWhicheverComesFirst(t *testing.T) {
	testCases := []struct {
		name string
		// newCtx builds the ctx the lease under test is taken with.
		newCtx func() (context.Context, context.CancelFunc)
		// end drives the lease's two ways of being released, in some order.
		end func(ctx context.Context, release func(), cancel context.CancelFunc)
		// expectedReleaseCalls is 1 when the release func got there first.
		expectedReleaseCalls int
	}{
		{
			name: "release func called",
			end: func(_ context.Context, release func(), _ context.CancelFunc) {
				release()
			},
			expectedReleaseCalls: 1,
		},
		{
			name: "release func called twice",
			end: func(_ context.Context, release func(), _ context.CancelFunc) {
				release()
				release()
			},
			expectedReleaseCalls: 1,
		},
		{
			name: "ctx cancelled",
			end: func(_ context.Context, _ func(), cancel context.CancelFunc) {
				cancel()
			},
		},
		{
			name: "ctx deadline passes",
			newCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 10*time.Millisecond)
			},
			end: func(ctx context.Context, _ func(), _ context.CancelFunc) {
				<-ctx.Done()
			},
		},
		{
			name: "release func called, then ctx cancelled",
			end: func(_ context.Context, release func(), cancel context.CancelFunc) {
				release()
				cancel()
			},
			expectedReleaseCalls: 1,
		},
		{
			name: "ctx cancelled, then release func called twice",
			end: func(_ context.Context, release func(), cancel context.CancelFunc) {
				cancel()
				release()
				release()
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			newCtx := tc.newCtx
			if newCtx == nil {
				newCtx = func() (context.Context, context.CancelFunc) {
					return context.WithCancel(context.Background())
				}
			}
			ctx, cancel := newCtx()
			t.Cleanup(cancel)

			source := &BundleSource{}
			// bystander is a second lease that nothing below ends, so ending one
			// lease is shown not to end the other.
			bystander, err := source.Lease(context.Background(), bundleSourceOtherProvider)
			g.Expect(err).To(Not(HaveOccurred()))
			release, err := source.Lease(ctx, bundleSourceProvider)
			g.Expect(err).To(Not(HaveOccurred()))
			g.Expect(source.LiveLeases()).To(Equal(2))
			g.Expect(source.Released()).To(Equal(0))

			tc.end(ctx, release, cancel)

			// Exact as soon as end returns, without waiting for the AfterFunc.
			g.Expect(source.LiveLeases()).To(Equal(1))
			g.Expect(source.Released()).To(Equal(1))
			g.Expect(source.ReleaseCalls()).To(Equal(tc.expectedReleaseCalls))

			// Once the AfterFunc has had its turn, and after both routes are
			// taken again, nothing moves.
			g.Eventually(bundleSourceBookedLeases(source), bundleSourceTestTimeout).Should(Equal(1))
			release()
			cancel()
			g.Expect(source.LiveLeases()).To(Equal(1))
			g.Expect(source.Released()).To(Equal(1))
			g.Expect(source.ReleaseCalls()).To(Equal(tc.expectedReleaseCalls))

			bystander()
			g.Expect(source.LiveLeases()).To(Equal(0))
			g.Expect(source.Released()).To(Equal(2))
			g.Expect(source.ReleaseCalls()).To(Equal(tc.expectedReleaseCalls + 1))
			g.Expect(source.LeaseCalls()).To(Equal(2))
		})
	}
}

func TestBundleSourceLease_CtxAlreadyDone_HandsOutALeaseThatIsNeverLive(t *testing.T) {
	g := NewWithT(t)

	source := &BundleSource{}
	// A closed gate would turn a Gate-taking call away with the ctx's error;
	// Lease does not go through it.
	source.Block()
	t.Cleanup(source.Release)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	release, err := source.Lease(ctx, bundleSourceProvider)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(release).To(Not(BeNil()))
	g.Expect(source.LeaseCalls()).To(Equal(1))
	g.Expect(source.ProviderRequests()).To(Equal([]string{bundleSourceProvider}))
	g.Expect(source.LiveLeases()).To(Equal(0))
	g.Expect(source.Released()).To(Equal(1))

	// The ctx released it first, so the func is not credited.
	release()
	g.Expect(source.Released()).To(Equal(1))
	g.Expect(source.ReleaseCalls()).To(Equal(0))
	g.Expect(source.Blocked()).To(Equal(0))
	g.Eventually(bundleSourceBookedLeases(source), bundleSourceTestTimeout).Should(BeZero())
}

func TestBundleSourceLease_GateBlocked_DoesNotPark(t *testing.T) {
	g := NewWithT(t)

	source := &BundleSource{}
	source.Block()
	t.Cleanup(source.Release)

	ctx, cancel := context.WithTimeout(context.Background(), bundleSourceTestTimeout)
	t.Cleanup(cancel)

	type result struct {
		release func()
		err     error
	}
	done := make(chan result, 1)
	go func() {
		release, err := source.Lease(ctx, bundleSourceProvider)
		done <- result{release: release, err: err}
	}()

	var got result
	select {
	case got = <-done:
	case <-ctx.Done():
		t.Fatalf("Lease parked at a closed gate: %v", ctx.Err())
	}

	g.Expect(got.err).To(Not(HaveOccurred()))
	g.Expect(got.release).To(Not(BeNil()))
	g.Expect(source.Blocked()).To(Equal(0))
	g.Expect(source.LeaseCalls()).To(Equal(1))
	g.Expect(source.LiveLeases()).To(Equal(1))

	got.release()
	g.Expect(source.LiveLeases()).To(Equal(0))
}

func TestBundleSourceSetLease_CalledWhileLive_ChangesLaterLeasesOnly(t *testing.T) {
	g := NewWithT(t)

	cannedErr := errors.New("lease refused")
	source := &BundleSource{}

	first, err := source.Lease(context.Background(), bundleSourceProvider)
	g.Expect(err).To(Not(HaveOccurred()))

	source.SetLease(cannedErr)
	refused, err := source.Lease(context.Background(), bundleSourceProvider)
	g.Expect(err).To(MatchError(cannedErr))
	g.Expect(refused).To(BeNil())

	// The lease taken before the error was set is still live and still releases.
	g.Expect(source.LiveLeases()).To(Equal(1))
	first()
	g.Expect(source.LiveLeases()).To(Equal(0))

	// Clearing the error puts canned leases back.
	source.SetLease(nil)
	third, err := source.Lease(context.Background(), bundleSourceProvider)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(source.LiveLeases()).To(Equal(1))
	third()

	g.Expect(source.LeaseCalls()).To(Equal(3))
	g.Expect(source.Released()).To(Equal(2))
	g.Expect(source.ReleaseCalls()).To(Equal(2))
	g.Expect(source.LiveLeases()).To(Equal(0))
}

func TestBundleSourceLease_ConcurrentLeasesAndReleases_CountEveryLeaseOnce(t *testing.T) {
	g := NewWithT(t)

	const (
		holders   = 8
		perHolder = 24
		readers   = 4
		total     = holders * perHolder
		// A third of the leases end by func, a third by ctx, and a third by
		// both at once from separate goroutines.
		byFunc = total / 3
		byBoth = total / 3
	)

	type held struct {
		release func()
		cancel  context.CancelFunc
	}
	source := &BundleSource{}

	// Each holder owns one slot, so collecting results needs no lock of its own
	// and cannot mask a race inside the fake.
	heldBy := make([][]held, holders)
	leaseErrs := make([]error, holders)
	var wg sync.WaitGroup
	for h := 0; h < holders; h++ {
		wg.Add(1)
		go func(h int) {
			defer wg.Done()
			for i := 0; i < perHolder; i++ {
				ctx, cancel := context.WithCancel(context.Background())
				release, err := source.Lease(ctx, bundleSourceProvider)
				if err != nil {
					cancel()
					leaseErrs[h] = err
					return
				}
				heldBy[h] = append(heldBy[h], held{release: release, cancel: cancel})
			}
		}(h)
	}
	wg.Wait()

	for _, err := range leaseErrs {
		g.Expect(err).To(Not(HaveOccurred()))
	}
	g.Expect(source.LeaseCalls()).To(Equal(total))
	g.Expect(source.LiveLeases()).To(Equal(total))
	g.Expect(source.Released()).To(Equal(0))

	// While the leases end, readers check that LiveLeases only falls and
	// Released only rises, since nothing takes a new lease.
	stop := make(chan struct{})
	readErrs := make([]error, readers)
	var readWG sync.WaitGroup
	for r := 0; r < readers; r++ {
		readWG.Add(1)
		go func(r int) {
			defer readWG.Done()
			lastLive, lastReleased := total, 0
			for {
				select {
				case <-stop:
					return
				default:
				}
				live, released := source.LiveLeases(), source.Released()
				if live > lastLive || released < lastReleased {
					readErrs[r] = fmt.Errorf("live went %d to %d and released %d to %d", lastLive, live, lastReleased, released)
					return
				}
				lastLive, lastReleased = live, released
			}
		}(r)
	}

	for h := range heldBy {
		for i, lease := range heldBy[h] {
			switch i % 3 {
			case 0:
				wg.Add(2)
				go func() { defer wg.Done(); lease.release() }()
				go func() { defer wg.Done(); lease.release() }()
			case 1:
				wg.Add(1)
				go func() { defer wg.Done(); lease.cancel() }()
			default:
				wg.Add(3)
				go func() { defer wg.Done(); lease.release() }()
				go func() { defer wg.Done(); lease.cancel() }()
				go func() { defer wg.Done(); lease.release() }()
			}
		}
	}
	wg.Wait()
	close(stop)
	readWG.Wait()

	for _, err := range readErrs {
		g.Expect(err).To(Not(HaveOccurred()))
	}
	g.Expect(source.LiveLeases()).To(Equal(0))
	g.Expect(source.Released()).To(Equal(total))
	// Which route wins a race is up to the scheduler, so only the bounds are
	// fixed.
	g.Expect(source.ReleaseCalls()).To(BeNumerically(">=", byFunc))
	g.Expect(source.ReleaseCalls()).To(BeNumerically("<=", byFunc+byBoth))
	g.Eventually(bundleSourceBookedLeases(source), bundleSourceTestTimeout).Should(BeZero())
	g.Expect(source.ProviderRequests()).To(HaveLen(total))

	for h := range heldBy {
		for _, lease := range heldBy[h] {
			lease.cancel()
		}
	}
}

func TestBundleSourceLease_FuncLease_EndingNeverCountsAsARelease(t *testing.T) {
	g := NewWithT(t)
	source := &BundleSource{LeaseFunc: func(_ context.Context, _ string) (func(), error) { return func() {}, nil }}
	ctx, cancel := context.WithCancel(context.Background())

	release, err := source.Lease(ctx, bundleSourceProvider)
	g.Expect(err).To(Not(HaveOccurred()))
	cancel()
	release()

	g.Consistently(source.Released, 50*time.Millisecond).Should(Equal(0))
	g.Expect(source.ReleaseCalls()).To(Equal(0))
	g.Expect(source.LiveLeases()).To(Equal(0))
}
