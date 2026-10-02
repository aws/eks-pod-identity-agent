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
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// bundleSourceTestTimeout bounds every wait in this file, so a fake that never
// releases a parked call fails the test instead of hanging the suite.
const bundleSourceTestTimeout = 2 * time.Second

// bundleSourceWorkload and bundleSourceOtherWorkload are the attested workloads
// the calls in this file pass. The canned values answer both alike; only the
// funcs and WorkloadRequests can tell them apart. Nothing may mutate them.
var (
	bundleSourceWorkload      = bundleSourceNamedWorkload("example")
	bundleSourceOtherWorkload = bundleSourceNamedWorkload("other")
)

// bundleSourceNamedWorkload builds a fresh workload whose fields all carry name,
// so two built from different names never compare equal.
func bundleSourceNamedWorkload(name string) *workloadidentity.Workload {
	return &workloadidentity.Workload{
		PodUID:         "uid-" + name,
		PodName:        "pod-" + name,
		Namespace:      "ns-" + name,
		ServiceAccount: "sa-" + name,
		NodeName:       "node-1",
	}
}

// bundleSourceCtxKey tags the ctx a test passes in, so a func can report whether
// the fake handed it the caller's ctx.
type bundleSourceCtxKey struct{}

// bundleSourceOwnDomain and bundleSourceFederatedDomain are the trust domains
// the canned JWT sources in this file cover.
var (
	bundleSourceOwnDomain       = spiffeid.RequireTrustDomainFromString("example.org")
	bundleSourceFederatedDomain = spiffeid.RequireTrustDomainFromString("other.org")
)

// bundleSourceOwnKey, bundleSourceFederatedKey and bundleSourceRotatedKey are
// deterministic JWT authorities. The fake never verifies with them, so the
// algorithm does not matter.
var (
	bundleSourceOwnKey       = ed25519.NewKeyFromSeed(bundleSourceSeed(0x01)).Public()
	bundleSourceFederatedKey = ed25519.NewKeyFromSeed(bundleSourceSeed(0x02)).Public()
	bundleSourceRotatedKey   = ed25519.NewKeyFromSeed(bundleSourceSeed(0x03)).Public()
)

// bundleSourceSeed builds a distinct ed25519 seed so two test keys differ.
func bundleSourceSeed(b byte) []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = b
	}
	return seed
}

// bundleSourceOwnBundle builds a fresh own-domain bundle holding own-kid.
func bundleSourceOwnBundle() *jwtbundle.Bundle {
	return jwtbundle.FromJWTAuthorities(bundleSourceOwnDomain, map[string]crypto.PublicKey{"own-kid": bundleSourceOwnKey})
}

// bundleSourceSet builds a fresh set of the own bundle and a federated bundle
// holding federated-kid.
func bundleSourceSet() *jwtbundle.Set {
	return jwtbundle.NewSet(
		bundleSourceOwnBundle(),
		jwtbundle.FromJWTAuthorities(bundleSourceFederatedDomain, map[string]crypto.PublicKey{"federated-kid": bundleSourceFederatedKey}),
	)
}

// bundleSourceAuthorities reads td's authorities out of source the way
// jwtsvid.ParseAndValidate does, returning nil when source has no bundle for td.
func bundleSourceAuthorities(source jwtbundle.Source, td spiffeid.TrustDomain) map[string]crypto.PublicKey {
	bundle, err := source.GetJWTBundleForTrustDomain(td)
	if err != nil {
		return nil
	}
	return bundle.JWTAuthorities()
}

// bundleSourceOpaqueSource is a jwtbundle.Source the fake has no way to copy.
type bundleSourceOpaqueSource struct{}

func (*bundleSourceOpaqueSource) GetJWTBundleForTrustDomain(td spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	return jwtbundle.New(td), nil
}

// bundleSourceFuncCall is what one of the fake's canned funcs saw when the fake
// called it.
type bundleSourceFuncCall struct {
	// ctxValue is what the func's ctx carries under bundleSourceCtxKey.
	ctxValue any
	workload *workloadidentity.Workload
	// workloadRequests is WorkloadRequests as read from inside the func.
	workloadRequests []*workloadidentity.Workload
}

// bundleSourceGatedMethod is one of the four methods that pass the Gate, called
// in a way that hands back whatever it returned as an any.
type bundleSourceGatedMethod struct {
	name  string
	call  func(ctx context.Context, s *BundleSource, w *workloadidentity.Workload) (any, error)
	calls func(s *BundleSource) int
}

// bundleSourceGatedMethods lists the four methods that pass the Gate.
var bundleSourceGatedMethods = []bundleSourceGatedMethod{
	{
		name: "OwnTrustDomain",
		call: func(ctx context.Context, s *BundleSource, w *workloadidentity.Workload) (any, error) {
			return s.OwnTrustDomain(ctx, w)
		},
		calls: func(s *BundleSource) int { return s.OwnTrustDomainCalls() },
	},
	{
		name: "X509Bundles",
		call: func(ctx context.Context, s *BundleSource, w *workloadidentity.Workload) (any, error) {
			return s.X509Bundles(ctx, w)
		},
		calls: func(s *BundleSource) int { return s.X509BundlesCalls() },
	},
	{
		name: "JWTBundles",
		call: func(ctx context.Context, s *BundleSource, w *workloadidentity.Workload) (any, error) {
			return s.JWTBundles(ctx, w)
		},
		calls: func(s *BundleSource) int { return s.JWTBundlesCalls() },
	},
	{
		name: "JWTSource",
		call: func(ctx context.Context, s *BundleSource, w *workloadidentity.Workload) (any, error) {
			return s.JWTSource(ctx, w)
		},
		calls: func(s *BundleSource) int { return s.JWTSourceCalls() },
	},
}

// bundleSourceExpectOnlyCalls asserts that the named method was counted calls
// times and that no other method was counted at all.
func bundleSourceExpectOnlyCalls(g *WithT, s *BundleSource, method string, calls int) {
	counters := map[string]int{
		"OwnTrustDomain": s.OwnTrustDomainCalls(),
		"X509Bundles":    s.X509BundlesCalls(),
		"JWTBundles":     s.JWTBundlesCalls(),
		"JWTSource":      s.JWTSourceCalls(),
		"Lease":          s.LeaseCalls(),
	}
	for name, got := range counters {
		expected := 0
		if name == method {
			expected = calls
		}
		g.Expect(got).To(Equal(expected), "%s calls", name)
	}
}

func TestBundleSourceOwnTrustDomain_CannedBehaviour_ReturnsThatBehaviourForAnyWorkload(t *testing.T) {
	cannedErr := errors.New("bundle unavailable")

	testCases := []struct {
		name        string
		source      *BundleSource
		expected    string
		expectedErr error
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
		{
			name:        "canned error wins over the canned trust domain",
			source:      &BundleSource{TrustDomain: "example.org", OwnTrustDomainErr: cannedErr},
			expectedErr: cannedErr,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			g.Expect(tc.source.WorkloadRequests()).To(BeEmpty())
			for _, w := range []*workloadidentity.Workload{bundleSourceWorkload, bundleSourceOtherWorkload} {
				got, err := tc.source.OwnTrustDomain(context.Background(), w)
				if tc.expectedErr != nil {
					g.Expect(err).To(MatchError(tc.expectedErr))
				} else {
					g.Expect(err).To(Not(HaveOccurred()))
				}
				g.Expect(got).To(Equal(tc.expected))
			}
			bundleSourceExpectOnlyCalls(g, tc.source, "OwnTrustDomain", 2)
			g.Expect(tc.source.WorkloadRequests()).To(Equal([]*workloadidentity.Workload{bundleSourceWorkload, bundleSourceOtherWorkload}))
			g.Expect(tc.source.Blocked()).To(Equal(0))
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
				X509Func: func(_ context.Context, _ *workloadidentity.Workload) (map[string][][]byte, error) {
					return map[string][][]byte{"func.org": {[]byte("func-der")}}, nil
				},
			},
			expected: map[string][][]byte{"func.org": {[]byte("func-der")}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := tc.source.X509Bundles(context.Background(), bundleSourceWorkload)

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
			bundleSourceExpectOnlyCalls(g, tc.source, "X509Bundles", 1)
			g.Expect(tc.source.WorkloadRequests()).To(Equal([]*workloadidentity.Workload{bundleSourceWorkload}))
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
				JWTFunc: func(_ context.Context, _ *workloadidentity.Workload) (map[string][]byte, error) {
					return map[string][]byte{"func.org": []byte(`{"keys":[]}`)}, nil
				},
			},
			expected: map[string][]byte{"func.org": []byte(`{"keys":[]}`)},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := tc.source.JWTBundles(context.Background(), bundleSourceWorkload)

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
			bundleSourceExpectOnlyCalls(g, tc.source, "JWTBundles", 1)
			g.Expect(tc.source.WorkloadRequests()).To(Equal([]*workloadidentity.Workload{bundleSourceWorkload}))
			g.Expect(tc.source.Blocked()).To(Equal(0))
		})
	}
}

func TestBundleSourceJWTSource_CannedBehaviour_ReturnsThatBehaviour(t *testing.T) {
	cannedErr := errors.New("bundle unavailable")
	opaque := &bundleSourceOpaqueSource{}
	funcSource := jwtbundle.FromJWTAuthorities(bundleSourceOwnDomain, map[string]crypto.PublicKey{"func-kid": bundleSourceRotatedKey})
	var nilSet *jwtbundle.Set

	testCases := []struct {
		name        string
		source      *BundleSource
		expectedErr error
		// check asserts on the source that came back without error.
		check func(g *WithT, got jwtbundle.Source)
	}{
		{
			name:   "zero value returns a nil source and no error",
			source: &BundleSource{},
			check:  func(g *WithT, got jwtbundle.Source) { g.Expect(got).To(BeNil()) },
		},
		{
			name:   "canned set comes back as an equal set",
			source: &BundleSource{JWTSourceResult: bundleSourceSet()},
			check: func(g *WithT, got jwtbundle.Source) {
				g.Expect(got).To(BeAssignableToTypeOf(&jwtbundle.Set{}))
				g.Expect(bundleSourceAuthorities(got, bundleSourceOwnDomain)).To(Equal(map[string]crypto.PublicKey{"own-kid": bundleSourceOwnKey}))
				g.Expect(bundleSourceAuthorities(got, bundleSourceFederatedDomain)).To(Equal(map[string]crypto.PublicKey{"federated-kid": bundleSourceFederatedKey}))
				g.Expect(bundleSourceAuthorities(got, spiffeid.RequireTrustDomainFromString("unknown.org"))).To(BeNil())
			},
		},
		{
			name:   "canned bundle comes back as an equal bundle",
			source: &BundleSource{JWTSourceResult: bundleSourceOwnBundle()},
			check: func(g *WithT, got jwtbundle.Source) {
				g.Expect(got).To(BeAssignableToTypeOf(&jwtbundle.Bundle{}))
				g.Expect(got.(*jwtbundle.Bundle).Equal(bundleSourceOwnBundle())).To(BeTrue())
			},
		},
		{
			name:   "a source the fake cannot copy comes back as is",
			source: &BundleSource{JWTSourceResult: opaque},
			check:  func(g *WithT, got jwtbundle.Source) { g.Expect(got).To(BeIdenticalTo(opaque)) },
		},
		{
			name:   "a typed nil set comes back as is",
			source: &BundleSource{JWTSourceResult: nilSet},
			check: func(g *WithT, got jwtbundle.Source) {
				g.Expect(got).To(BeAssignableToTypeOf(&jwtbundle.Set{}))
				g.Expect(got.(*jwtbundle.Set)).To(BeNil())
			},
		},
		{
			name:        "canned error wins over the canned source",
			source:      &BundleSource{JWTSourceResult: bundleSourceSet(), JWTSourceErr: cannedErr},
			expectedErr: cannedErr,
		},
		{
			name: "func wins over the canned source and canned error, uncopied",
			source: &BundleSource{
				JWTSourceResult: bundleSourceSet(),
				JWTSourceErr:    cannedErr,
				JWTSourceFunc: func(_ context.Context, _ *workloadidentity.Workload) (jwtbundle.Source, error) {
					return funcSource, nil
				},
			},
			check: func(g *WithT, got jwtbundle.Source) { g.Expect(got).To(BeIdenticalTo(funcSource)) },
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := tc.source.JWTSource(context.Background(), bundleSourceWorkload)

			if tc.expectedErr != nil {
				g.Expect(err).To(MatchError(tc.expectedErr))
				g.Expect(got).To(BeNil())
			} else {
				g.Expect(err).To(Not(HaveOccurred()))
				tc.check(g, got)
			}
			bundleSourceExpectOnlyCalls(g, tc.source, "JWTSource", 1)
			g.Expect(tc.source.WorkloadRequests()).To(Equal([]*workloadidentity.Workload{bundleSourceWorkload}))
			g.Expect(tc.source.Blocked()).To(Equal(0))
		})
	}
}

func TestBundleSourceJWTSource_CannedSourceChangedEitherSide_ReturnedSourceStaysPointInTime(t *testing.T) {
	testCases := []struct {
		name string
		// canned is a fresh canned source; ownBundle finds the own-domain bundle
		// inside a source of the same type, so the test can rotate it in place.
		canned    func() jwtbundle.Source
		ownBundle func(jwtbundle.Source) *jwtbundle.Bundle
	}{
		{
			name:   "set",
			canned: func() jwtbundle.Source { return bundleSourceSet() },
			ownBundle: func(s jwtbundle.Source) *jwtbundle.Bundle {
				own, _ := s.(*jwtbundle.Set).Get(bundleSourceOwnDomain)
				return own
			},
		},
		{
			name:      "bundle",
			canned:    func() jwtbundle.Source { return bundleSourceOwnBundle() },
			ownBundle: func(s jwtbundle.Source) *jwtbundle.Bundle { return s.(*jwtbundle.Bundle) },
		},
	}

	own := map[string]crypto.PublicKey{"own-kid": bundleSourceOwnKey}
	rotated := map[string]crypto.PublicKey{"own-kid": bundleSourceOwnKey, "rotated-kid": bundleSourceRotatedKey}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			canned := tc.canned()
			source := &BundleSource{JWTSourceResult: canned}
			rotate := func(s jwtbundle.Source) {
				g.Expect(tc.ownBundle(s).AddJWTAuthority("rotated-kid", bundleSourceRotatedKey)).To(Succeed())
			}

			// Rotating the returned copy leaves the canned source alone.
			first, err := source.JWTSource(context.Background(), bundleSourceWorkload)
			g.Expect(err).To(Not(HaveOccurred()))
			rotate(first)
			g.Expect(bundleSourceAuthorities(first, bundleSourceOwnDomain)).To(Equal(rotated))
			g.Expect(bundleSourceAuthorities(canned, bundleSourceOwnDomain)).To(Equal(own))

			// Rotating the canned source reaches the next call but not a copy
			// already handed out.
			second, err := source.JWTSource(context.Background(), bundleSourceWorkload)
			g.Expect(err).To(Not(HaveOccurred()))
			rotate(canned)
			g.Expect(bundleSourceAuthorities(second, bundleSourceOwnDomain)).To(Equal(own))

			third, err := source.JWTSource(context.Background(), bundleSourceWorkload)
			g.Expect(err).To(Not(HaveOccurred()))
			g.Expect(bundleSourceAuthorities(third, bundleSourceOwnDomain)).To(Equal(rotated))
			g.Expect(source.JWTSourceCalls()).To(Equal(3))
		})
	}
}

func TestBundleSourceX509Bundles_ReturnedMapMutated_NextCallIsUnaffected(t *testing.T) {
	g := NewWithT(t)

	der := []byte("own-authority-der")
	source := &BundleSource{X509: map[string][][]byte{"example.org": {der}}}
	expected := map[string][][]byte{"example.org": {[]byte("own-authority-der")}}

	got, err := source.X509Bundles(context.Background(), bundleSourceWorkload)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(Equal(expected))

	// Mutate every level the caller can reach: the map, the per-domain slice, and
	// the authority bytes.
	got["injected.org"] = [][]byte{[]byte("injected-der")}
	got["example.org"] = append(got["example.org"], []byte("appended-der"))
	got["example.org"][0][0] = 'X'

	again, err := source.X509Bundles(context.Background(), bundleSourceWorkload)
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

	got, err := source.X509Bundles(context.Background(), bundleSourceWorkload)
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

	got, err := source.JWTBundles(context.Background(), bundleSourceWorkload)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(Equal(expected))

	got["injected.org"] = []byte(`{"keys":[]}`)
	got["example.org"][0] = 'X'

	again, err := source.JWTBundles(context.Background(), bundleSourceWorkload)
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

	x509Bundles, err := source.X509Bundles(context.Background(), bundleSourceWorkload)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(x509Bundles).To(BeNil())

	source.SetX509Bundles(map[string][][]byte{"example.org": {[]byte("own-authority-der")}}, nil)
	x509Bundles, err = source.X509Bundles(context.Background(), bundleSourceWorkload)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(x509Bundles).To(Equal(map[string][][]byte{"example.org": {[]byte("own-authority-der")}}))

	source.SetX509Bundles(nil, x509Err)
	x509Bundles, err = source.X509Bundles(context.Background(), bundleSourceWorkload)
	g.Expect(err).To(MatchError(x509Err))
	g.Expect(x509Bundles).To(BeNil())

	jwtBundles, err := source.JWTBundles(context.Background(), bundleSourceWorkload)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(jwtBundles).To(BeNil())

	source.SetJWTBundles(map[string][]byte{"example.org": []byte(`{"keys":[]}`)}, nil)
	jwtBundles, err = source.JWTBundles(context.Background(), bundleSourceWorkload)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(jwtBundles).To(Equal(map[string][]byte{"example.org": []byte(`{"keys":[]}`)}))

	source.SetJWTBundles(nil, jwtErr)
	jwtBundles, err = source.JWTBundles(context.Background(), bundleSourceWorkload)
	g.Expect(err).To(MatchError(jwtErr))
	g.Expect(jwtBundles).To(BeNil())

	g.Expect(source.X509BundlesCalls()).To(Equal(3))
	g.Expect(source.JWTBundlesCalls()).To(Equal(3))
}

func TestBundleSourceSetTrustDomain_CalledWhileLive_ChangesTheNextOwnTrustDomain(t *testing.T) {
	g := NewWithT(t)

	cannedErr := errors.New("bundle unavailable")
	source := &BundleSource{TrustDomain: "example.org"}
	ownTrustDomain := func() (string, error) {
		return source.OwnTrustDomain(context.Background(), bundleSourceWorkload)
	}

	g.Expect(ownTrustDomain()).To(Equal("example.org"))

	source.SetTrustDomain("rotated.org", nil)
	g.Expect(ownTrustDomain()).To(Equal("rotated.org"))

	// A canned error set alongside a domain wins over that domain.
	source.SetTrustDomain("rotated.org", cannedErr)
	domain, err := ownTrustDomain()
	g.Expect(err).To(MatchError(cannedErr))
	g.Expect(domain).To(BeEmpty())

	// Clearing the error puts the domain back in charge.
	source.SetTrustDomain("rotated.org", nil)
	g.Expect(ownTrustDomain()).To(Equal("rotated.org"))

	g.Expect(source.OwnTrustDomainCalls()).To(Equal(4))
}

func TestBundleSourceSetJWTSource_CalledWhileLive_ReplacesSourceAndError(t *testing.T) {
	g := NewWithT(t)

	cannedErr := errors.New("bundle unavailable")
	// rotated stands in for the bundle a refresh brings in once own-kid retires.
	rotated := jwtbundle.FromJWTAuthorities(bundleSourceOwnDomain, map[string]crypto.PublicKey{"rotated-kid": bundleSourceRotatedKey})
	source := &BundleSource{JWTSourceResult: bundleSourceOwnBundle()}

	before, err := source.JWTSource(context.Background(), bundleSourceWorkload)
	g.Expect(err).To(Not(HaveOccurred()))

	source.SetJWTSource(rotated, nil)
	after, err := source.JWTSource(context.Background(), bundleSourceWorkload)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(bundleSourceAuthorities(after, bundleSourceOwnDomain)).To(Equal(map[string]crypto.PublicKey{"rotated-kid": bundleSourceRotatedKey}))

	// The source handed out before the swap still holds what it held.
	g.Expect(bundleSourceAuthorities(before, bundleSourceOwnDomain)).To(Equal(map[string]crypto.PublicKey{"own-kid": bundleSourceOwnKey}))

	source.SetJWTSource(rotated, cannedErr)
	got, err := source.JWTSource(context.Background(), bundleSourceWorkload)
	g.Expect(err).To(MatchError(cannedErr))
	g.Expect(got).To(BeNil())

	source.SetJWTSource(nil, nil)
	got, err = source.JWTSource(context.Background(), bundleSourceWorkload)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(BeNil())

	g.Expect(source.JWTSourceCalls()).To(Equal(4))
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
				s.SetTrustDomain(fmt.Sprintf("domain-%d.org", i), nil)
			},
			read: func(s *BundleSource) error {
				// Every value the writers set, and the value the fake started
				// with, is one a reader may legitimately see.
				domain, err := s.OwnTrustDomain(context.Background(), bundleSourceWorkload)
				switch {
				case err != nil:
					return err
				case domain == "example.org", strings.HasPrefix(domain, "domain-"):
					return nil
				default:
					return fmt.Errorf("OwnTrustDomain returned %q, which no writer set", domain)
				}
			},
			calls: func(s *BundleSource) int { return s.OwnTrustDomainCalls() },
		},
		{
			name: "SetJWTSource against JWTSource",
			set: func(s *BundleSource, i int) {
				// Every set the writers install keeps own-kid, so the reader below
				// must resolve it whichever set it lands on.
				s.SetJWTSource(jwtbundle.NewSet(jwtbundle.FromJWTAuthorities(bundleSourceOwnDomain, map[string]crypto.PublicKey{
					fmt.Sprintf("kid-%d", i): bundleSourceFederatedKey,
					"own-kid":                bundleSourceOwnKey,
				})), nil)
			},
			read: func(s *BundleSource) error {
				source, err := s.JWTSource(context.Background(), bundleSourceWorkload)
				if err != nil {
					return err
				}
				authority := bundleSourceAuthorities(source, bundleSourceOwnDomain)["own-kid"]
				if got, ok := authority.(ed25519.PublicKey); !ok || !got.Equal(bundleSourceOwnKey) {
					return fmt.Errorf("JWTSource resolved own-kid to %v, want the own key", authority)
				}
				return nil
			},
			calls: func(s *BundleSource) int { return s.JWTSourceCalls() },
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
				release, err := s.Lease(context.Background(), bundleSourceWorkload)
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
				TrustDomain:     "example.org",
				JWTSourceResult: bundleSourceSet(),
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
			g.Expect(source.WorkloadRequests()).To(HaveLen(readers * iterations))
			g.Expect(source.LiveLeases()).To(Equal(0))
		})
	}
}

func TestBundleSourceGatedMethods_GateBlocked_ParkUntilReleasedThenAnswer(t *testing.T) {
	expected := map[string]any{
		"OwnTrustDomain": "example.org",
		"X509Bundles":    map[string][][]byte{"example.org": {[]byte("own-authority-der")}},
		"JWTBundles":     map[string][]byte{"example.org": []byte(`{"keys":[{"kid":"own"}]}`)},
	}

	for _, method := range bundleSourceGatedMethods {
		t.Run(method.name, func(t *testing.T) {
			g := NewWithT(t)

			source := &BundleSource{
				TrustDomain:     "example.org",
				X509:            map[string][][]byte{"example.org": {[]byte("own-authority-der")}},
				JWT:             map[string][]byte{"example.org": []byte(`{"keys":[{"kid":"own"}]}`)},
				JWTSourceResult: bundleSourceOwnBundle(),
			}
			source.Block()

			ctx, cancel := context.WithTimeout(context.Background(), bundleSourceTestTimeout)
			t.Cleanup(cancel)

			type result struct {
				value any
				err   error
			}
			done := make(chan result, 1)
			go func() {
				value, err := method.call(ctx, source, bundleSourceWorkload)
				done <- result{value: value, err: err}
			}()

			g.Expect(source.WaitForBlocked(ctx, 1)).To(Succeed())
			g.Expect(source.Blocked()).To(Equal(1))
			g.Expect(done).To(Not(Receive()))
			g.Expect(method.calls(source)).To(Equal(0))
			g.Expect(source.WorkloadRequests()).To(BeEmpty())

			source.Release()

			var got result
			select {
			case got = <-done:
			case <-ctx.Done():
				t.Fatalf("%s did not return after Release: %v", method.name, ctx.Err())
			}

			g.Expect(got.err).To(Not(HaveOccurred()))
			if want, ok := expected[method.name]; ok {
				g.Expect(got.value).To(Equal(want))
			} else {
				g.Expect(bundleSourceAuthorities(got.value.(jwtbundle.Source), bundleSourceOwnDomain)).
					To(Equal(map[string]crypto.PublicKey{"own-kid": bundleSourceOwnKey}))
			}
			bundleSourceExpectOnlyCalls(g, source, method.name, 1)
			g.Expect(source.WorkloadRequests()).To(Equal([]*workloadidentity.Workload{bundleSourceWorkload}))
			g.Expect(source.Blocked()).To(Equal(0))
		})
	}
}

func TestBundleSourceGatedMethods_ParkedCallContextCancelled_ReturnContextError(t *testing.T) {
	for _, method := range bundleSourceGatedMethods {
		t.Run(method.name, func(t *testing.T) {
			g := NewWithT(t)

			source := &BundleSource{
				TrustDomain:     "example.org",
				X509:            map[string][][]byte{"example.org": {[]byte("own-authority-der")}},
				JWT:             map[string][]byte{"example.org": []byte(`{"keys":[]}`)},
				JWTSourceResult: bundleSourceOwnBundle(),
			}
			source.Block()

			waitCtx, cancelWait := context.WithTimeout(context.Background(), bundleSourceTestTimeout)
			t.Cleanup(cancelWait)
			callCtx, cancelCall := context.WithCancel(context.Background())
			t.Cleanup(cancelCall)

			type result struct {
				value any
				err   error
			}
			done := make(chan result, 1)
			go func() {
				value, err := method.call(callCtx, source, bundleSourceWorkload)
				done <- result{value: value, err: err}
			}()

			g.Expect(source.WaitForBlocked(waitCtx, 1)).To(Succeed())
			cancelCall()

			var got result
			select {
			case got = <-done:
			case <-waitCtx.Done():
				t.Fatalf("%s did not return after its context was cancelled: %v", method.name, waitCtx.Err())
			}

			g.Expect(got.err).To(MatchError(context.Canceled))
			g.Expect(got.value).To(BeZero())
			g.Expect(method.calls(source)).To(Equal(0))
			g.Expect(source.WorkloadRequests()).To(BeEmpty())
			g.Expect(source.Blocked()).To(Equal(0))
		})
	}
}

func TestBundleSourceGatedMethods_ContextAlreadyDone_ReturnContextErrorWithoutParking(t *testing.T) {
	g := NewWithT(t)

	source := &BundleSource{
		TrustDomain:     "example.org",
		X509:            map[string][][]byte{"example.org": {[]byte("own-authority-der")}},
		JWT:             map[string][]byte{"example.org": []byte(`{"keys":[]}`)},
		JWTSourceResult: bundleSourceOwnBundle(),
	}
	source.Block()
	t.Cleanup(source.Release)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, method := range bundleSourceGatedMethods {
		value, err := method.call(ctx, source, bundleSourceWorkload)
		g.Expect(err).To(MatchError(context.Canceled), method.name)
		g.Expect(value).To(BeZero(), method.name)
		g.Expect(method.calls(source)).To(Equal(0), method.name)
	}
	g.Expect(source.WorkloadRequests()).To(BeEmpty())
	g.Expect(source.Blocked()).To(Equal(0))
}

func TestBundleSourceCannedValues_DifferentWorkloads_AllGetTheSameAnswer(t *testing.T) {
	g := NewWithT(t)

	source := &BundleSource{
		TrustDomain:     "example.org",
		X509:            map[string][][]byte{"example.org": {[]byte("own-authority-der")}},
		JWT:             map[string][]byte{"example.org": []byte(`{"keys":[{"kid":"own"}]}`)},
		JWTSourceResult: bundleSourceSet(),
	}

	// A nil workload is answered like any other. The fake does not model the
	// ErrUnattestable or ErrNotEnrolled a real implementation returns; a test
	// that needs either sets a canned error or a func.
	workloads := []*workloadidentity.Workload{bundleSourceWorkload, bundleSourceOtherWorkload, nil}
	var expectedRequests []*workloadidentity.Workload
	for _, w := range workloads {
		domain, err := source.OwnTrustDomain(context.Background(), w)
		g.Expect(err).To(Not(HaveOccurred()), "workload %v", w)
		g.Expect(domain).To(Equal("example.org"), "workload %v", w)

		x509Bundles, err := source.X509Bundles(context.Background(), w)
		g.Expect(err).To(Not(HaveOccurred()), "workload %v", w)
		g.Expect(x509Bundles).To(Equal(source.X509), "workload %v", w)

		jwtBundles, err := source.JWTBundles(context.Background(), w)
		g.Expect(err).To(Not(HaveOccurred()), "workload %v", w)
		g.Expect(jwtBundles).To(Equal(source.JWT), "workload %v", w)

		jwtSource, err := source.JWTSource(context.Background(), w)
		g.Expect(err).To(Not(HaveOccurred()), "workload %v", w)
		g.Expect(bundleSourceAuthorities(jwtSource, bundleSourceOwnDomain)).
			To(Equal(map[string]crypto.PublicKey{"own-kid": bundleSourceOwnKey}), "workload %v", w)

		release, err := source.Lease(context.Background(), w)
		g.Expect(err).To(Not(HaveOccurred()), "workload %v", w)
		g.Expect(release).To(Not(BeNil()), "workload %v", w)
		release()

		expectedRequests = append(expectedRequests, w, w, w, w, w)
	}

	g.Expect(source.WorkloadRequests()).To(Equal(expectedRequests))
	g.Expect(source.LeaseCalls()).To(Equal(len(workloads)))
	g.Expect(source.Released()).To(Equal(len(workloads)))
	g.Expect(source.LiveLeases()).To(Equal(0))
}

func TestBundleSourceFuncs_Set_ReceiveTheCallersCtxAndWorkload(t *testing.T) {
	// sourceFor gives JWTSourceFunc an answer only the named workload gets.
	sourceFor := func(w *workloadidentity.Workload) jwtbundle.Source {
		return jwtbundle.FromJWTAuthorities(bundleSourceOwnDomain, map[string]crypto.PublicKey{w.PodUID: bundleSourceOwnKey})
	}

	testCases := []struct {
		name string
		// install sets the func under test on s. The func reports what it saw
		// through record, reading WorkloadRequests from inside itself, and
		// answers with something only the workload it was handed gets.
		install func(s *BundleSource, record func(bundleSourceFuncCall))
		// call makes one call passing w.
		call func(ctx context.Context, s *BundleSource, w *workloadidentity.Workload) (any, error)
		// expected is the answer install's func gives w.
		expected func(w *workloadidentity.Workload) any
	}{
		{
			name: "X509Func",
			install: func(s *BundleSource, record func(bundleSourceFuncCall)) {
				s.X509Func = func(ctx context.Context, w *workloadidentity.Workload) (map[string][][]byte, error) {
					record(bundleSourceFuncCall{
						ctxValue:         ctx.Value(bundleSourceCtxKey{}),
						workload:         w,
						workloadRequests: s.WorkloadRequests(),
					})
					return map[string][][]byte{"example.org": {[]byte(w.PodUID)}}, nil
				}
			},
			call: func(ctx context.Context, s *BundleSource, w *workloadidentity.Workload) (any, error) {
				return s.X509Bundles(ctx, w)
			},
			expected: func(w *workloadidentity.Workload) any {
				return map[string][][]byte{"example.org": {[]byte(w.PodUID)}}
			},
		},
		{
			name: "JWTFunc",
			install: func(s *BundleSource, record func(bundleSourceFuncCall)) {
				s.JWTFunc = func(ctx context.Context, w *workloadidentity.Workload) (map[string][]byte, error) {
					record(bundleSourceFuncCall{
						ctxValue:         ctx.Value(bundleSourceCtxKey{}),
						workload:         w,
						workloadRequests: s.WorkloadRequests(),
					})
					return map[string][]byte{"example.org": []byte(w.PodUID)}, nil
				}
			},
			call: func(ctx context.Context, s *BundleSource, w *workloadidentity.Workload) (any, error) {
				return s.JWTBundles(ctx, w)
			},
			expected: func(w *workloadidentity.Workload) any {
				return map[string][]byte{"example.org": []byte(w.PodUID)}
			},
		},
		{
			name: "JWTSourceFunc",
			install: func(s *BundleSource, record func(bundleSourceFuncCall)) {
				s.JWTSourceFunc = func(ctx context.Context, w *workloadidentity.Workload) (jwtbundle.Source, error) {
					record(bundleSourceFuncCall{
						ctxValue:         ctx.Value(bundleSourceCtxKey{}),
						workload:         w,
						workloadRequests: s.WorkloadRequests(),
					})
					return sourceFor(w), nil
				}
			},
			call: func(ctx context.Context, s *BundleSource, w *workloadidentity.Workload) (any, error) {
				source, err := s.JWTSource(ctx, w)
				if err != nil {
					return nil, err
				}
				return bundleSourceAuthorities(source, bundleSourceOwnDomain), nil
			},
			expected: func(w *workloadidentity.Workload) any {
				return bundleSourceAuthorities(sourceFor(w), bundleSourceOwnDomain)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			ctx := context.WithValue(context.Background(), bundleSourceCtxKey{}, "the caller's ctx")
			source := &BundleSource{}
			var seen []bundleSourceFuncCall
			tc.install(source, func(c bundleSourceFuncCall) { seen = append(seen, c) })

			first, err := tc.call(ctx, source, bundleSourceWorkload)
			g.Expect(err).To(Not(HaveOccurred()))
			g.Expect(first).To(Equal(tc.expected(bundleSourceWorkload)))

			second, err := tc.call(ctx, source, bundleSourceOtherWorkload)
			g.Expect(err).To(Not(HaveOccurred()))
			g.Expect(second).To(Equal(tc.expected(bundleSourceOtherWorkload)))

			// Each call's workload is recorded before its func runs, and reading
			// the record from inside the func does not deadlock because the fake
			// does not hold its lock across the callback.
			g.Expect(seen).To(Equal([]bundleSourceFuncCall{
				{
					ctxValue:         "the caller's ctx",
					workload:         bundleSourceWorkload,
					workloadRequests: []*workloadidentity.Workload{bundleSourceWorkload},
				},
				{
					ctxValue:         "the caller's ctx",
					workload:         bundleSourceOtherWorkload,
					workloadRequests: []*workloadidentity.Workload{bundleSourceWorkload, bundleSourceOtherWorkload},
				},
			}))
			g.Expect(seen[0].workload).To(BeIdenticalTo(bundleSourceWorkload))
			g.Expect(seen[1].workload).To(BeIdenticalTo(bundleSourceOtherWorkload))
		})
	}
}

func TestBundleSourceWorkloadRequests_CallsAcrossMethods_RecordsEveryCountedCallInOrder(t *testing.T) {
	g := NewWithT(t)

	// Each call passes a workload of its own, so the record shows which call
	// landed where.
	a, b, c, d, e, f, h := bundleSourceNamedWorkload("a"), bundleSourceNamedWorkload("b"),
		bundleSourceNamedWorkload("c"), bundleSourceNamedWorkload("d"), bundleSourceNamedWorkload("e"),
		bundleSourceNamedWorkload("f"), bundleSourceNamedWorkload("h")
	turnedAway := bundleSourceNamedWorkload("turned-away")
	x509Err := errors.New("x509 bundle unavailable")
	jwtSourceErr := errors.New("jwt source unavailable")
	leaseErr := errors.New("lease refused")
	source := &BundleSource{
		TrustDomain:  "example.org",
		X509Err:      x509Err,
		JWT:          map[string][]byte{"example.org": []byte(`{"keys":[]}`)},
		JWTSourceErr: jwtSourceErr,
	}
	doneCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := source.OwnTrustDomain(context.Background(), a)
	g.Expect(err).To(Not(HaveOccurred()))

	// A canned error is still a counted call, so its workload is recorded.
	_, err = source.X509Bundles(context.Background(), b)
	g.Expect(err).To(MatchError(x509Err))
	_, err = source.JWTSource(context.Background(), c)
	g.Expect(err).To(MatchError(jwtSourceErr))

	_, err = source.JWTBundles(context.Background(), d)
	g.Expect(err).To(Not(HaveOccurred()))

	// A lease is recorded when it is taken; releasing it records nothing.
	release, err := source.Lease(context.Background(), e)
	g.Expect(err).To(Not(HaveOccurred()))

	// A nil workload is recorded as passed, so a handler test can catch a call
	// made before attestation finished.
	_, err = source.OwnTrustDomain(context.Background(), nil)
	g.Expect(err).To(Not(HaveOccurred()))

	// Calls turned away by their ctx are not counted, so they are not recorded.
	for _, method := range bundleSourceGatedMethods {
		_, err = method.call(doneCtx, source, turnedAway)
		g.Expect(err).To(MatchError(context.Canceled), method.name)
	}

	// Lease does not go through the Gate, so a done ctx does not turn it away.
	_, err = source.Lease(doneCtx, f)
	g.Expect(err).To(Not(HaveOccurred()))

	// A canned lease error is still a counted call.
	source.SetLease(leaseErr)
	_, err = source.Lease(context.Background(), h)
	g.Expect(err).To(MatchError(leaseErr))
	release()

	// A workload passed again is recorded again.
	_, err = source.JWTBundles(context.Background(), a)
	g.Expect(err).To(Not(HaveOccurred()))

	expected := []*workloadidentity.Workload{a, b, c, d, e, nil, f, h, a}
	recorded := source.WorkloadRequests()
	g.Expect(recorded).To(Equal(expected))
	// The record holds the pointers as passed, not copies of them.
	for i := range expected {
		g.Expect(recorded[i]).To(BeIdenticalTo(expected[i]), "request %d", i)
	}
	g.Expect(source.OwnTrustDomainCalls()).To(Equal(2))
	g.Expect(source.X509BundlesCalls()).To(Equal(1))
	g.Expect(source.JWTBundlesCalls()).To(Equal(2))
	g.Expect(source.JWTSourceCalls()).To(Equal(1))
	g.Expect(source.LeaseCalls()).To(Equal(3))
}

func TestBundleSourceWorkloadRequests_ReturnedSliceMutated_RecordIsUnaffected(t *testing.T) {
	g := NewWithT(t)

	source := &BundleSource{}
	_, _ = source.OwnTrustDomain(context.Background(), bundleSourceWorkload)
	_, _ = source.OwnTrustDomain(context.Background(), bundleSourceOtherWorkload)

	recorded := source.WorkloadRequests()
	recorded[0] = nil
	g.Expect(source.WorkloadRequests()).To(Equal([]*workloadidentity.Workload{bundleSourceWorkload, bundleSourceOtherWorkload}))

	// A copy taken before a later call does not grow with the record.
	snapshot := source.WorkloadRequests()
	_, _ = source.OwnTrustDomain(context.Background(), bundleSourceWorkload)
	g.Expect(snapshot).To(Equal([]*workloadidentity.Workload{bundleSourceWorkload, bundleSourceOtherWorkload}))
	g.Expect(source.WorkloadRequests()).To(Equal([]*workloadidentity.Workload{
		bundleSourceWorkload,
		bundleSourceOtherWorkload,
		bundleSourceWorkload,
	}))
}

func TestBundleSourceWorkloadRequests_ConcurrentCallersAndReaders_RecordEveryCallInEachCallersOrder(t *testing.T) {
	g := NewWithT(t)

	const (
		callers    = 8
		iterations = 25
		readers    = 4
		reads      = 50
	)

	source := &BundleSource{
		TrustDomain:     "example.org",
		X509:            map[string][][]byte{"example.org": {[]byte("own-authority-der")}},
		JWT:             map[string][]byte{"example.org": []byte(`{"keys":[]}`)},
		JWTSourceResult: bundleSourceSet(),
	}

	// Every call passes a workload no other call passes, so the final record
	// shows both that each call landed exactly once and where.
	methods := []string{"own", "x509", "jwt", "source", "lease"}
	workloads := make([][][]*workloadidentity.Workload, callers)
	expectedPerCaller := make([][]*workloadidentity.Workload, callers)
	callerOf := make(map[*workloadidentity.Workload]int, callers*iterations*len(methods))
	for c := 0; c < callers; c++ {
		workloads[c] = make([][]*workloadidentity.Workload, iterations)
		for i := 0; i < iterations; i++ {
			for _, method := range methods {
				w := bundleSourceNamedWorkload(fmt.Sprintf("caller-%d-%d-%s", c, i, method))
				workloads[c][i] = append(workloads[c][i], w)
				expectedPerCaller[c] = append(expectedPerCaller[c], w)
				callerOf[w] = c
			}
		}
	}

	// Each goroutine owns one slot, so collecting results needs no lock of its
	// own and cannot mask a race inside the fake.
	callErrs := make([]error, callers)
	snapshots := make([][][]*workloadidentity.Workload, readers)
	var wg sync.WaitGroup
	for c := 0; c < callers; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			ctx := context.Background()
			for i := 0; i < iterations; i++ {
				ws := workloads[c][i]
				if _, err := source.OwnTrustDomain(ctx, ws[0]); err != nil {
					callErrs[c] = err
					return
				}
				if _, err := source.X509Bundles(ctx, ws[1]); err != nil {
					callErrs[c] = err
					return
				}
				if _, err := source.JWTBundles(ctx, ws[2]); err != nil {
					callErrs[c] = err
					return
				}
				if _, err := source.JWTSource(ctx, ws[3]); err != nil {
					callErrs[c] = err
					return
				}
				release, err := source.Lease(ctx, ws[4])
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
				snapshots[r] = append(snapshots[r], source.WorkloadRequests())
			}
		}(r)
	}
	wg.Wait()

	for _, err := range callErrs {
		g.Expect(err).To(Not(HaveOccurred()))
	}

	recorded := source.WorkloadRequests()
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
	// in the order it made them. callerOf is keyed by pointer, so this also
	// shows the record holds the pointers as passed.
	gotPerCaller := make([][]*workloadidentity.Workload, callers)
	for _, w := range recorded {
		c, ok := callerOf[w]
		if !g.Expect(ok).To(BeTrue(), "recorded workload %v was never passed", w) {
			continue
		}
		gotPerCaller[c] = append(gotPerCaller[c], w)
	}
	for c := range gotPerCaller {
		g.Expect(slices.Equal(gotPerCaller[c], expectedPerCaller[c])).To(BeTrue(), "caller %d's calls are out of order", c)
	}

	g.Expect(source.OwnTrustDomainCalls()).To(Equal(callers * iterations))
	g.Expect(source.X509BundlesCalls()).To(Equal(callers * iterations))
	g.Expect(source.JWTBundlesCalls()).To(Equal(callers * iterations))
	g.Expect(source.JWTSourceCalls()).To(Equal(callers * iterations))
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
	funcLease := func(_ context.Context, _ *workloadidentity.Workload) (func(), error) { return func() {}, nil }

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
			source: &BundleSource{LeaseFunc: funcLease},
		},
		{
			name:   "func wins over the canned error and its lease goes untracked",
			source: &BundleSource{LeaseErr: cannedErr, LeaseFunc: funcLease},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			release, err := tc.source.Lease(context.Background(), bundleSourceWorkload)

			if tc.expectedErr != nil {
				g.Expect(err).To(MatchError(tc.expectedErr))
				g.Expect(release).To(BeNil())
			} else {
				g.Expect(err).To(Not(HaveOccurred()))
				g.Expect(release).To(Not(BeNil()))
			}
			bundleSourceExpectOnlyCalls(g, tc.source, "Lease", 1)
			g.Expect(tc.source.LiveLeases()).To(Equal(tc.expectedLive))
			g.Expect(tc.source.Released()).To(Equal(0))
			g.Expect(tc.source.ReleaseCalls()).To(Equal(0))
			g.Expect(tc.source.WorkloadRequests()).To(Equal([]*workloadidentity.Workload{bundleSourceWorkload}))
			g.Expect(tc.source.Blocked()).To(Equal(0))
		})
	}
}

func TestBundleSourceLease_FuncSet_SeesItsCallCountedAndIsReturnedAsIs(t *testing.T) {
	g := NewWithT(t)

	// unattestable stands in for the ErrUnattestable a real implementation
	// returns for a nil workload, which is how a test that needs it sets it up.
	unattestable := errors.New("unattestable")
	type funcCall struct {
		ctxValue         any
		workload         *workloadidentity.Workload
		leaseCalls       int
		workloadRequests []*workloadidentity.Workload
	}
	var seen []funcCall
	funcReleases := 0

	source := &BundleSource{LeaseErr: errors.New("canned lease error")}
	source.LeaseFunc = func(ctx context.Context, w *workloadidentity.Workload) (func(), error) {
		// Reading the fake from inside the func does not deadlock, because the
		// fake does not hold its lock across the callback.
		seen = append(seen, funcCall{
			ctxValue:         ctx.Value(bundleSourceCtxKey{}),
			workload:         w,
			leaseCalls:       source.LeaseCalls(),
			workloadRequests: source.WorkloadRequests(),
		})
		if w == nil {
			return nil, unattestable
		}
		return func() { funcReleases++ }, nil
	}
	ctx := context.WithValue(context.Background(), bundleSourceCtxKey{}, "the caller's ctx")

	release, err := source.Lease(ctx, bundleSourceWorkload)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(release).To(Not(BeNil()))

	// The func's release is handed back unwrapped, so the fake does not make it
	// idempotent and does not count it.
	release()
	release()
	g.Expect(funcReleases).To(Equal(2))

	release, err = source.Lease(ctx, nil)
	g.Expect(err).To(MatchError(unattestable))
	g.Expect(release).To(BeNil())

	g.Expect(seen).To(Equal([]funcCall{
		{
			ctxValue:         "the caller's ctx",
			workload:         bundleSourceWorkload,
			leaseCalls:       1,
			workloadRequests: []*workloadidentity.Workload{bundleSourceWorkload},
		},
		{
			ctxValue:         "the caller's ctx",
			workload:         nil,
			leaseCalls:       2,
			workloadRequests: []*workloadidentity.Workload{bundleSourceWorkload, nil},
		},
	}))
	g.Expect(seen[0].workload).To(BeIdenticalTo(bundleSourceWorkload))
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
			bystander, err := source.Lease(context.Background(), bundleSourceOtherWorkload)
			g.Expect(err).To(Not(HaveOccurred()))
			release, err := source.Lease(ctx, bundleSourceWorkload)
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

	release, err := source.Lease(ctx, bundleSourceWorkload)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(release).To(Not(BeNil()))
	g.Expect(source.LeaseCalls()).To(Equal(1))
	g.Expect(source.WorkloadRequests()).To(Equal([]*workloadidentity.Workload{bundleSourceWorkload}))
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
		release, err := source.Lease(ctx, bundleSourceWorkload)
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

	first, err := source.Lease(context.Background(), bundleSourceWorkload)
	g.Expect(err).To(Not(HaveOccurred()))

	source.SetLease(cannedErr)
	refused, err := source.Lease(context.Background(), bundleSourceWorkload)
	g.Expect(err).To(MatchError(cannedErr))
	g.Expect(refused).To(BeNil())

	// The lease taken before the error was set is still live and still releases.
	g.Expect(source.LiveLeases()).To(Equal(1))
	first()
	g.Expect(source.LiveLeases()).To(Equal(0))

	// Clearing the error puts canned leases back.
	source.SetLease(nil)
	third, err := source.Lease(context.Background(), bundleSourceWorkload)
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
				release, err := source.Lease(ctx, bundleSourceWorkload)
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
	g.Expect(source.WorkloadRequests()).To(HaveLen(total))

	for h := range heldBy {
		for _, lease := range heldBy[h] {
			lease.cancel()
		}
	}
}

func TestBundleSourceLease_FuncLease_EndingNeverCountsAsARelease(t *testing.T) {
	g := NewWithT(t)
	source := &BundleSource{LeaseFunc: func(_ context.Context, _ *workloadidentity.Workload) (func(), error) {
		return func() {}, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())

	release, err := source.Lease(ctx, bundleSourceWorkload)
	g.Expect(err).To(Not(HaveOccurred()))
	cancel()
	release()

	g.Consistently(source.Released, 50*time.Millisecond).Should(Equal(0))
	g.Expect(source.ReleaseCalls()).To(Equal(0))
	g.Expect(source.LiveLeases()).To(Equal(0))
}
