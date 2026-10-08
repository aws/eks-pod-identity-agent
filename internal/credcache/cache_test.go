package credcache

import (
	"cmp"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cache/expiring"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
)

var (
	authMetadata = credentials.CredentialMetadata{Association: "assoc-1", CredSource: credentials.SourceAuthService}
	imdsMetadata = credentials.CredentialMetadata{CredSource: credentials.SourceIMDS}
)

// fakeSource is a credential source whose answer a test scripts. It records the
// requests it's given and the errors it's asked to classify.
type fakeSource struct {
	get func(ctx context.Context, req *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error)
	// code and irrecoverable are what IsIrrecoverable reports for every error.
	code          string
	irrecoverable bool

	mu         sync.Mutex
	reqs       []*credentials.EksCredentialsRequest
	classified []error
}

func (s *fakeSource) GetIamCredentials(ctx context.Context, req *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.reqs = append(s.reqs, req)
	}()
	if s.get == nil {
		return nil, nil, errors.New("fakeSource has no answer")
	}
	return s.get(ctx, req)
}

func (s *fakeSource) String() string { return "fake" }

func (s *fakeSource) IsIrrecoverable(err error) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.classified = append(s.classified, err)
	return s.code, s.irrecoverable
}

func (s *fakeSource) requests() []*credentials.EksCredentialsRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*credentials.EksCredentialsRequest(nil), s.reqs...)
}

// serving is a fakeSource answering with a new copy of creds, and metadata, on
// every call, as a real source allocates new credentials per fetch.
func serving(creds *credentials.EksCredentialsResponse, metadata credentials.ResponseMetadata) *fakeSource {
	return &fakeSource{get: func(context.Context, *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
		fresh := *creds
		return &fresh, metadata, nil
	}}
}

// failing is a fakeSource failing with err, classified as irrecoverable says.
func failing(err error, code string, irrecoverable bool) *fakeSource {
	return &fakeSource{
		get: func(context.Context, *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
			return nil, nil, err
		},
		code:          code,
		irrecoverable: irrecoverable,
	}
}

// fakeTokens is a TokenSource answering with token or err. It records the
// requests it's asked to renew and the errors it's asked to classify.
type fakeTokens struct {
	token         string
	err           error
	code          string
	irrecoverable bool

	asked      []*credentials.EksCredentialsRequest
	classified []error
}

func (f *fakeTokens) Token(_ context.Context, current *credentials.EksCredentialsRequest) (string, error) {
	f.asked = append(f.asked, current)
	return f.token, f.err
}

func (f *fakeTokens) IsIrrecoverable(err error) (string, bool) {
	f.classified = append(f.classified, err)
	return f.code, f.irrecoverable
}

// newTestCache builds a Cache whose sweep is an hour away, so a test drives
// onRefresh itself.
func newTestCache(delegate credentials.CredentialRetriever) *Cache {
	return newTestCacheWith(Opts{Delegate: delegate})
}

// newTestCacheWith is newTestCache with opts, filling in the sizes and putting
// the sweep an hour away.
func newTestCacheWith(opts Opts) *Cache {
	opts.RenewalTtl = cmp.Or(opts.RenewalTtl, 3*time.Hour)
	opts.MaxSize = cmp.Or(opts.MaxSize, 100)
	opts.RefreshQPS = cmp.Or(opts.RefreshQPS, 3)
	opts.CleanupInterval = time.Hour
	if opts.Delegate == nil {
		opts.Delegate = &fakeSource{}
	}
	return New(opts)
}

// creds are credentials that expire after d.
func creds(d time.Duration) *credentials.EksCredentialsResponse {
	return &credentials.EksCredentialsResponse{
		AccessKeyId: "AKIA-" + d.String(),
		Expiration:  credentials.SdkCompliantExpirationTime{Time: time.Now().Add(d)},
	}
}

// entryExpiringIn is an entry whose credentials expire after d, with a request
// to refresh it by.
func entryExpiringIn(d time.Duration, metadata credentials.ResponseMetadata) *Entry {
	return &Entry{
		Credentials: creds(d),
		Metadata:    metadata,
		Request:     &credentials.EksCredentialsRequest{ServiceAccountToken: "stored-token", ClusterName: "cluster"},
	}
}

// tokenExpiringAt is a service account JWT whose exp is exp.
func tokenExpiringAt(t *testing.T, exp time.Time) string {
	return test.CreateToken(t, test.TokenConfig{Expiry: exp, Iat: exp.Add(-time.Hour), Nbf: exp.Add(-time.Hour), PodUID: "pod"})
}

// TestEntry_Source_DefaultsToAuthService verifies that an entry with no metadata
// reports SourceAuthService. This is the safety default that keeps
// pre-existing / IMDS-disabled behavior unchanged: with no source information,
// the cache applies the Auth Service policy (evict on expiry), never the IMDS one.
func TestEntry_Source_DefaultsToAuthService(t *testing.T) {
	g := NewWithT(t)

	g.Expect((&Entry{}).source()).To(Equal(credentials.SourceAuthService))
	g.Expect((&Entry{Metadata: imdsMetadata}).source()).To(Equal(credentials.SourceIMDS))
	g.Expect((&Entry{Metadata: authMetadata}).source()).To(Equal(credentials.SourceAuthService))
}

// TestCache_Ttls verifies that ttls returns the correct refresh and eviction
// durations for each source.
func TestCache_Ttls(t *testing.T) {
	c := newTestCache(nil)

	tests := []struct {
		name         string
		source       credentials.CredentialSource
		credsDur     time.Duration
		wantRefresh  time.Duration
		wantEviction time.Duration
	}{
		{"IMDS always 30min/NoExpiration", credentials.SourceIMDS, 6 * time.Hour, imdsRefreshInterval, expiring.NoExpiration},
		{"Auth Service short creds", credentials.SourceAuthService, 2 * time.Hour, 2 * time.Hour, 2 * time.Hour},
		{"Auth Service long creds capped by renewalTtl", credentials.SourceAuthService, 6 * time.Hour, 3 * time.Hour, 6 * time.Hour},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			refresh, eviction := c.ttls(tc.source, tc.credsDur)
			g.Expect(refresh).To(Equal(tc.wantRefresh))
			g.Expect(eviction).To(Equal(tc.wantEviction))
		})
	}
}

// TestCache_Store_SchedulesRefreshAndEviction verifies an Auth Service entry
// refreshes at the earlier of its expiry and the renewal TTL, and is evicted at
// its expiry.
func TestCache_Store_SchedulesRefreshAndEviction(t *testing.T) {
	tests := []struct {
		name        string
		credsDur    time.Duration
		wantRefresh time.Duration
	}{
		{"credentials shorter than the renewal TTL refresh at expiry", time.Hour, time.Hour},
		{"credentials longer than the renewal TTL refresh at the renewal TTL", 6 * time.Hour, 3 * time.Hour},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			c := newTestCache(nil)
			e := entryExpiringIn(tc.credsDur, authMetadata)

			g.Expect(c.Store(context.Background(), "pod", e)).To(Succeed())

			got, refresh, expiration, found := c.items.GetWithRenewExpiry("pod")
			g.Expect(found).To(BeTrue())
			g.Expect(got).To(BeIdenticalTo(e))
			g.Expect(time.Until(refresh)).To(BeNumerically("~", tc.wantRefresh, time.Second))
			g.Expect(expiration).To(BeTemporally("~", e.Credentials.Expiration.Time, time.Second))
		})
	}
}

// TestCache_Store_RefusesWhatItCannotServe covers the entries Store refuses,
// leaving the cache as it was.
func TestCache_Store_RefusesWhatItCannotServe(t *testing.T) {
	tests := []struct {
		name    string
		entry   *Entry
		wantErr string
	}{
		{"no credentials", &Entry{}, "no credentials to cache"},
		{"within the minimum TTL", entryExpiringIn(DefaultMinCredentialTtl-time.Second, authMetadata),
			"fetched credentials are expired or will expire within the next"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			c := newTestCache(nil)

			err := c.Store(context.Background(), "pod", tc.entry)

			g.Expect(err).To(MatchError(ContainSubstring(tc.wantErr)))
			_, found := c.Get("pod")
			g.Expect(found).To(BeFalse())
		})
	}
}

// TestCache_Refresh_SourceAware verifies the sweep's refresh is source-aware:
//   - Recoverable failure: valid entries are re-inserted, IMDS with NoExpiration
//     (static stability), Auth Service with a finite expiry-based eviction TTL.
//   - Successful refresh: an expired IMDS entry is replaced with the fresh credential.
//   - Irrecoverable failure: the entry is evicted regardless of source.
func TestCache_Refresh_SourceAware(t *testing.T) {
	t.Run("failed recoverable renewal re-inserts valid entries with source-specific TTLs", func(t *testing.T) {
		tests := []struct {
			name             string
			metadata         credentials.ResponseMetadata
			credsAge         time.Duration // relative to now; negative = expired
			wantNoExpiration bool          // IMDS re-inserted with NoExpiration; Auth with a finite TTL
		}{
			{"IMDS expired: re-inserted with NoExpiration", imdsMetadata, -30 * time.Minute, true},
			{"Auth Service valid: re-inserted with finite eviction TTL", authMetadata, 2 * time.Hour, false},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				g := NewWithT(t)
				c := newTestCacheWith(Opts{
					Delegate:      failing(errors.New("recoverable error"), "Unknown", false),
					RetryInterval: 5 * time.Minute, MaxRetryJitter: 1,
				})
				e := entryExpiringIn(tc.credsAge, tc.metadata)
				c.items.Set("pod", e)

				c.onRefresh("pod", e)

				got, refresh, expirationTime, found := c.items.GetWithRenewExpiry("pod")
				g.Expect(found).To(BeTrue())
				g.Expect(got).To(BeIdenticalTo(e))
				g.Expect(time.Until(refresh)).To(BeNumerically("<=", 5*time.Minute))
				if tc.wantNoExpiration {
					g.Expect(expirationTime.IsZero()).To(BeTrue(), "IMDS entry should be re-inserted with NoExpiration")
				} else {
					g.Expect(expirationTime.IsZero()).To(BeFalse(), "Auth Service entry should keep a finite eviction TTL")
				}
			})
		}
	})

	t.Run("successful renewal updates expired IMDS entry with fresh creds", func(t *testing.T) {
		g := NewWithT(t)
		fresh := creds(6 * time.Hour)
		c := newTestCache(serving(fresh, imdsMetadata))
		e := entryExpiringIn(-30*time.Minute, imdsMetadata)
		c.items.Set("pod", e)

		c.onRefresh("pod", e)

		got, found := c.Get("pod")
		g.Expect(found).To(BeTrue())
		g.Expect(got.Credentials).To(Equal(fresh))
	})

	t.Run("irrecoverable renewal error evicts the entry regardless of source", func(t *testing.T) {
		// When the source classifies the refresh error as irrecoverable, the
		// credential is gone/invalid, so the entry is evicted even for IMDS.
		for _, meta := range []credentials.ResponseMetadata{imdsMetadata, authMetadata} {
			g := NewWithT(t)
			c := newTestCache(failing(errors.New("gone"), "Gone", true))
			e := entryExpiringIn(6*time.Hour, meta)
			c.items.Set("pod", e)
			evictedBefore := testutil.ToFloat64(promCacheState.WithLabelValues("evicted"))

			c.onRefresh("pod", e)

			_, found := c.Get("pod")
			g.Expect(found).To(BeFalse(), "irrecoverable error should evict the entry for source %s", meta.Source())
			g.Expect(testutil.ToFloat64(promCacheState.WithLabelValues("evicted"))).To(Equal(evictedBefore + 1))
		}
	})
}

// TestCache_Refresh_DefaultSourceIsDelegate proves a refresh without RefreshWith
// presents the entry's request to Delegate and stores a new entry carrying the
// new credentials, metadata and association, logging from the renewal thread.
func TestCache_Refresh_DefaultSourceIsDelegate(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	fresh := creds(5 * time.Hour)
	newMetadata := credentials.CredentialMetadata{Association: "assoc-2", CredSource: credentials.SourceAuthService}
	delegate := serving(fresh, newMetadata)
	c := newTestCache(delegate)
	old := entryExpiringIn(2*time.Hour, authMetadata)
	old.LogCtx = logger.ContextWithField(ctx, "podUID", "pod", "association-id", "assoc-1")
	g.Expect(c.Store(ctx, "pod", old)).To(Succeed())
	hitsBefore := testutil.ToFloat64(promCacheState.WithLabelValues("hit"))

	c.onRefresh("pod", old)

	g.Expect(delegate.requests()).To(HaveExactElements(Equal(old.Request)))
	got, found := c.Get("pod")
	g.Expect(found).To(BeTrue())
	g.Expect(got).ToNot(BeIdenticalTo(old))
	g.Expect(got.Credentials).To(Equal(fresh))
	g.Expect(got.Metadata).To(Equal(newMetadata))
	g.Expect(got.Request).To(Equal(old.Request))
	g.Expect(logger.FromContext(got.LogCtx).Data).To(SatisfyAll(
		HaveKeyWithValue("association-id", "assoc-2"), HaveKeyWithValue("podUID", "pod"),
		HaveKeyWithValue("from", "renewal-thread")))
	g.Expect(testutil.ToFloat64(promCacheState.WithLabelValues("hit"))).To(Equal(hitsBefore + 1))
}

// TestCache_Refresh_WithoutMetadata_KeepsTheAssociation proves a renewal whose
// source returns no metadata is stored as an Auth Service entry and keeps the
// association it logged with before.
func TestCache_Refresh_WithoutMetadata_KeepsTheAssociation(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	c := newTestCache(serving(creds(5*time.Hour), nil))
	old := entryExpiringIn(2*time.Hour, authMetadata)
	old.LogCtx = logger.ContextWithField(ctx, "association-id", "assoc-1")
	g.Expect(c.Store(ctx, "pod", old)).To(Succeed())

	c.onRefresh("pod", old)

	got, found := c.Get("pod")
	g.Expect(found).To(BeTrue())
	g.Expect(got).ToNot(BeIdenticalTo(old))
	g.Expect(got.Metadata).To(BeNil())
	g.Expect(got.source()).To(Equal(credentials.SourceAuthService))
	g.Expect(logger.FromContext(got.LogCtx).Data).To(HaveKeyWithValue("association-id", "assoc-1"))
}

// TestCache_Refresh_UsesRefreshWithsSource proves a refresh goes to the source
// RefreshWith gives the entry, and to Delegate when it gives none.
func TestCache_Refresh_UsesRefreshWithsSource(t *testing.T) {
	decorated := credentials.CredentialMetadata{Association: "decorated", CredSource: credentials.SourceAuthService}
	for name, tc := range map[string]struct {
		metadata     credentials.ResponseMetadata
		wantGiven    bool
		wantDelegate bool
	}{
		"an entry given a source refreshes through it": {decorated, true, false},
		"a nil source falls back to Delegate":          {authMetadata, false, true},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			delegate := serving(creds(5*time.Hour), authMetadata)
			given := serving(creds(5*time.Hour), decorated)
			c := newTestCacheWith(Opts{
				Delegate: delegate,
				RefreshWith: func(e *Entry) (credentials.CredentialRetriever, TokenSource) {
					if e.Metadata.AssociationId() == "decorated" {
						return given, nil
					}
					return nil, nil
				},
			})
			old := entryExpiringIn(2*time.Hour, tc.metadata)
			g.Expect(c.Store(context.Background(), "pod", old)).To(Succeed())

			c.onRefresh("pod", old)

			g.Expect(given.requests()).To(HaveLen(boolToInt(tc.wantGiven)))
			g.Expect(delegate.requests()).To(HaveLen(boolToInt(tc.wantDelegate)))
			got, _ := c.Get("pod")
			g.Expect(got).ToNot(BeIdenticalTo(old))
		})
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// TestCache_Refresh_RenewsAnExpiringToken proves a refresh presents the stored
// token while it has more than 5 minutes left by the cache's clock, and otherwise
// a current one from RefreshWith's TokenSource, which the renewed entry then
// carries. Without RefreshWith it presents the stored token whatever its expiry.
func TestCache_Refresh_RenewsAnExpiringToken(t *testing.T) {
	// Far from the wall clock, so a floor measured against it fails every case.
	now := time.Unix(1_600_000_000, 0)
	tests := []struct {
		name        string
		storedToken string
		noHook      bool
		wantRenewed bool
	}{
		{"a fresh token is replayed", tokenExpiringAt(t, now.Add(time.Hour)), false, false},
		{"a token a second past the floor is replayed", tokenExpiringAt(t, now.Add(5*time.Minute+time.Second)), false, false},
		{"a token at the floor is renewed", tokenExpiringAt(t, now.Add(5*time.Minute)), false, true},
		{"a token a second inside the floor is renewed", tokenExpiringAt(t, now.Add(5*time.Minute-time.Second)), false, true},
		{"a token inside the floor is renewed", tokenExpiringAt(t, now.Add(time.Minute)), false, true},
		{"an expired token is renewed", tokenExpiringAt(t, now.Add(-time.Minute)), false, true},
		{"an unparsable token is renewed", "not-a-jwt", false, true},
		{"without RefreshWith an expiring token is replayed", tokenExpiringAt(t, now.Add(time.Minute)), true, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			delegate := serving(creds(5*time.Hour), authMetadata)
			tokens := &fakeTokens{token: "current-token"}
			opts := Opts{Delegate: delegate, Now: func() time.Time { return now }}
			if !tc.noHook {
				opts.RefreshWith = func(*Entry) (credentials.CredentialRetriever, TokenSource) { return nil, tokens }
			}
			c := newTestCacheWith(opts)
			old := entryExpiringIn(2*time.Hour, authMetadata)
			old.Request.ServiceAccountToken = tc.storedToken
			stored := *old.Request
			g.Expect(c.Store(context.Background(), "pod", old)).To(Succeed())

			c.onRefresh("pod", old)

			wantPresented := stored
			if tc.wantRenewed {
				wantPresented.ServiceAccountToken = "current-token"
				g.Expect(tokens.asked).To(HaveExactElements(BeIdenticalTo(old.Request)))
			} else {
				g.Expect(tokens.asked).To(BeEmpty())
			}
			g.Expect(delegate.requests()).To(HaveExactElements(Equal(&wantPresented)))
			got, found := c.Get("pod")
			g.Expect(found).To(BeTrue())
			g.Expect(got).ToNot(BeIdenticalTo(old))
			g.Expect(got.Request).To(Equal(&wantPresented))
			g.Expect(*old.Request).To(Equal(stored), "the stored entry is never edited")
		})
	}
}

// TestCache_Refresh_SwapsTokensOnlyForEntriesGivenATokenSource proves an entry
// RefreshWith gives no TokenSource presents its expiring token as it is and
// never reaches another entry's TokenSource.
func TestCache_Refresh_SwapsTokensOnlyForEntriesGivenATokenSource(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	now := time.Unix(1_600_000_000, 0)
	withTokens := credentials.CredentialMetadata{Association: "with-tokens", CredSource: credentials.SourceAuthService}
	delegate := serving(creds(5*time.Hour), authMetadata)
	tokens := &fakeTokens{token: "current-token"}
	c := newTestCacheWith(Opts{
		Delegate: delegate,
		Now:      func() time.Time { return now },
		RefreshWith: func(e *Entry) (credentials.CredentialRetriever, TokenSource) {
			if e.Metadata.AssociationId() == "with-tokens" {
				return nil, tokens
			}
			return nil, nil
		},
	})
	expiring := tokenExpiringAt(t, now.Add(time.Minute))
	given := entryExpiringIn(2*time.Hour, withTokens)
	given.Request.ServiceAccountToken = expiring
	notGiven := entryExpiringIn(2*time.Hour, authMetadata)
	notGiven.Request.ServiceAccountToken = expiring
	g.Expect(c.Store(ctx, "pod-given", given)).To(Succeed())
	g.Expect(c.Store(ctx, "pod-not-given", notGiven)).To(Succeed())

	c.onRefresh("pod-not-given", notGiven)
	c.onRefresh("pod-given", given)

	g.Expect(tokens.asked).To(HaveExactElements(BeIdenticalTo(given.Request)))
	g.Expect(delegate.requests()).To(HaveExactElements(
		HaveField("ServiceAccountToken", expiring), HaveField("ServiceAccountToken", "current-token")))
}

// TestCache_Refresh_ClassifiesFailures proves RefreshWith's TokenSource
// classifies a token error and the source used classifies a source error,
// whatever the other says, and that each is asked about the error once.
func TestCache_Refresh_ClassifiesFailures(t *testing.T) {
	tests := []struct {
		name string
		// tokens is nil to replay the stored token, and given nil for Delegate.
		tokens    *fakeTokens
		delegate  *fakeSource
		given     *fakeSource
		wantKept  bool
		wantState string
		wantCode  string
		wantErr   string
	}{
		{
			name:      "an irrecoverable token error drops the entry",
			tokens:    &fakeTokens{err: errors.New("pod gone"), code: "TokenGone", irrecoverable: true},
			delegate:  failing(errors.New("unused"), "SourceDown", false),
			wantState: "NonRecoverable", wantCode: "TokenGone",
			wantErr: "error getting a current token to refresh with: pod gone",
		},
		{
			name:      "a recoverable token error keeps the entry",
			tokens:    &fakeTokens{err: errors.New("kubelet down"), code: "TokenDown"},
			delegate:  failing(errors.New("unused"), "SourceGone", true),
			wantKept:  true,
			wantState: "Recoverable", wantCode: "TokenDown",
			wantErr: "error getting a current token to refresh with: kubelet down",
		},
		{
			name:      "an irrecoverable source error drops the entry",
			tokens:    &fakeTokens{token: "current-token", code: "TokenDown"},
			delegate:  failing(errors.New("access denied"), "SourceGone", true),
			wantState: "NonRecoverable", wantCode: "SourceGone",
			wantErr: "error getting credentials to cache: access denied",
		},
		{
			name:      "a recoverable source error keeps the entry",
			tokens:    &fakeTokens{token: "current-token", code: "TokenGone", irrecoverable: true},
			delegate:  failing(errors.New("throttled"), "SourceDown", false),
			wantKept:  true,
			wantState: "Recoverable", wantCode: "SourceDown",
			wantErr: "error getting credentials to cache: throttled",
		},
		{
			name:      "the given source classifies its own error",
			delegate:  failing(errors.New("unused"), "SourceDown", false),
			given:     failing(errors.New("access denied"), "GivenGone", true),
			wantState: "NonRecoverable", wantCode: "GivenGone",
			wantErr: "error getting credentials to cache: access denied",
		},
		{
			name: "nil credentials are classified by the source",
			delegate: &fakeSource{get: func(context.Context, *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
				return nil, authMetadata, nil
			}, code: "NilCreds", irrecoverable: true},
			wantState: "NonRecoverable", wantCode: "NilCreds",
			wantErr: "delegate returned nil credentials",
		},
		{
			name: "credentials within the minimum TTL are classified by the source",
			delegate: &fakeSource{get: func(context.Context, *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
				return creds(DefaultMinCredentialTtl - time.Second), authMetadata, nil
			}, code: "TooShort"},
			wantKept:  true,
			wantState: "Recoverable", wantCode: "TooShort",
			wantErr: "fetched credentials are expired or will expire within the next",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			// Typed nils would read as a given source or TokenSource.
			var source credentials.CredentialRetriever
			if tc.given != nil {
				source = tc.given
			}
			var tokens TokenSource
			if tc.tokens != nil {
				tokens = tc.tokens
			}
			c := newTestCacheWith(Opts{
				Delegate:    tc.delegate,
				RefreshWith: func(*Entry) (credentials.CredentialRetriever, TokenSource) { return source, tokens },
			})
			old := entryExpiringIn(2*time.Hour, authMetadata)
			g.Expect(c.Store(context.Background(), "pod", old)).To(Succeed())
			before := testutil.ToFloat64(promCacheError.WithLabelValues(tc.wantState, tc.wantCode))

			c.onRefresh("pod", old)

			g.Expect(c.contains("pod", old)).To(Equal(tc.wantKept))
			g.Expect(testutil.ToFloat64(promCacheError.WithLabelValues(tc.wantState, tc.wantCode))).To(Equal(before + 1))
			var classified []error
			for _, source := range []*fakeSource{tc.delegate, tc.given} {
				if source != nil {
					classified = append(classified, source.classified...)
				}
			}
			if tc.tokens != nil {
				classified = append(classified, tc.tokens.classified...)
			}
			g.Expect(classified).To(HaveExactElements(MatchError(ContainSubstring(tc.wantErr))))
		})
	}
}

// TestCache_Refresh_WithoutRequest_KeepsTheEntry proves an entry with no request
// to present fails its refresh recoverably without reaching a source, and is
// kept until it expires.
func TestCache_Refresh_WithoutRequest_KeepsTheEntry(t *testing.T) {
	g := NewWithT(t)
	delegate := failing(errors.New("must not be called"), "Gone", true)
	c := newTestCache(delegate)
	old := entryExpiringIn(2*time.Hour, authMetadata)
	old.Request = nil
	g.Expect(c.Store(context.Background(), "pod", old)).To(Succeed())
	before := testutil.ToFloat64(promCacheError.WithLabelValues("Recoverable", noRequestErrCode))

	c.onRefresh("pod", old)

	g.Expect(delegate.requests()).To(BeEmpty())
	g.Expect(c.contains("pod", old)).To(BeTrue())
	g.Expect(testutil.ToFloat64(promCacheError.WithLabelValues("Recoverable", noRequestErrCode))).To(Equal(before + 1))
	_, refresh, expiration, _ := c.items.GetWithRenewExpiry("pod")
	g.Expect(refresh.Before(expiration)).To(BeTrue())
	g.Expect(expiration).To(BeTemporally("~", old.Credentials.Expiration.Time, time.Second))
}

// TestCache_Refresh_FailureAfterAChange proves what a failed refresh does when
// its entry was replaced or removed while it renewed. Keeping never puts the old
// entry back or reschedules the replacement; dropping goes by pod UID.
func TestCache_Refresh_FailureAfterAChange(t *testing.T) {
	for name, tc := range map[string]struct {
		removed, irrecoverable, wantReplacement bool
	}{
		"a recoverable failure leaves the replacement as stored":  {false, false, true},
		"an irrecoverable failure removes the replacement":        {false, true, false},
		"a recoverable failure doesn't revive a removed entry":    {true, false, false},
		"an irrecoverable failure leaves a removed entry removed": {true, true, false},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			ctx := context.Background()
			old := entryExpiringIn(2*time.Hour, authMetadata)
			replacement := entryExpiringIn(4*time.Hour, authMetadata)
			var c *Cache
			c = newTestCache(&fakeSource{
				get: func(context.Context, *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
					// Another caller changes the entry while this renewal is out.
					if tc.removed {
						c.Delete("pod")
					} else {
						g.Expect(c.Store(ctx, "pod", replacement)).To(Succeed())
					}
					return nil, nil, errors.New("refresh failed")
				},
				code:          "Code",
				irrecoverable: tc.irrecoverable,
			})
			g.Expect(c.Store(ctx, "pod", old)).To(Succeed())

			c.onRefresh("pod", old)

			got, _, found := c.items.GetStale("pod")
			if !tc.wantReplacement {
				g.Expect(found).To(BeFalse(), "found %v", got)
				return
			}
			g.Expect(found).To(BeTrue())
			g.Expect(got).To(BeIdenticalTo(replacement))
			_, _, expiration, _ := c.items.GetWithRenewExpiry("pod")
			g.Expect(expiration).To(BeTemporally("~", replacement.Credentials.Expiration.Time, time.Second))
		})
	}
}

// TestCache_Refresh_StoresItsRenewalWhateverTheCacheHolds proves a successful
// refresh stores its renewal even when its entry was replaced or removed while
// it renewed, as upstream did.
func TestCache_Refresh_StoresItsRenewalWhateverTheCacheHolds(t *testing.T) {
	for name, removed := range map[string]bool{
		"over a replacement": false,
		"after a removal":    true,
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			ctx := context.Background()
			old := entryExpiringIn(2*time.Hour, authMetadata)
			fresh := creds(5 * time.Hour)
			var c *Cache
			c = newTestCache(&fakeSource{
				get: func(context.Context, *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
					if removed {
						c.Delete("pod")
					} else {
						g.Expect(c.Store(ctx, "pod", entryExpiringIn(4*time.Hour, authMetadata))).To(Succeed())
					}
					renewed := *fresh
					return &renewed, authMetadata, nil
				},
			})
			g.Expect(c.Store(ctx, "pod", old)).To(Succeed())
			hitsBefore := testutil.ToFloat64(promCacheState.WithLabelValues("hit"))

			c.onRefresh("pod", old)

			got, found := c.Get("pod")
			g.Expect(found).To(BeTrue())
			g.Expect(got.Credentials).To(Equal(fresh))
			g.Expect(got.Request).To(Equal(old.Request))
			g.Expect(testutil.ToFloat64(promCacheState.WithLabelValues("hit"))).To(Equal(hitsBefore + 1))
		})
	}
}

// TestCache_Refresh_TreatsAModifiedEntryAsTheSame proves a Modify while a
// refresh is out leaves the entry the same one: a recoverable failure keeps and
// reschedules the modified entry, and an irrecoverable one removes it.
func TestCache_Refresh_TreatsAModifiedEntryAsTheSame(t *testing.T) {
	for name, irrecoverable := range map[string]bool{
		"a kept entry keeps what Modify set": false,
		"a dropped entry is removed":         true,
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			ctx := context.Background()
			request := &credentials.EksCredentialsRequest{ServiceAccountToken: "admitted"}
			old := entryExpiringIn(2*time.Hour, authMetadata)
			var c *Cache
			c = newTestCacheWith(Opts{
				Delegate: &fakeSource{
					get: func(context.Context, *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
						g.Expect(c.Modify("pod", func(e *Entry) { e.Request = request })).To(BeTrue())
						return nil, authMetadata, errors.New("refresh failed")
					},
					code:          "Code",
					irrecoverable: irrecoverable,
				},
				RetryInterval: 5 * time.Minute, MaxRetryJitter: 1,
			})
			g.Expect(c.Store(ctx, "pod", old)).To(Succeed())

			c.onRefresh("pod", old)

			got, refresh, _, found := c.items.GetWithRenewExpiry("pod")
			g.Expect(found).To(Equal(!irrecoverable))
			if irrecoverable {
				return
			}
			g.Expect(got.Credentials).To(BeIdenticalTo(old.Credentials))
			g.Expect(got.Request).To(BeIdenticalTo(request))
			g.Expect(time.Until(refresh)).To(BeNumerically("<=", 5*time.Minute), "rescheduled for a retry")
		})
	}
}

// TestCache_Refresh_SkipsAnEntryRemovedSinceTheSweepPickedIt proves the sweep
// doesn't renew an entry that a caller removed or replaced after it was picked.
func TestCache_Refresh_SkipsAnEntryRemovedSinceTheSweepPickedIt(t *testing.T) {
	for name, change := range map[string]func(c *Cache, old *Entry){
		"removed": func(c *Cache, _ *Entry) { c.Delete("pod") },
		"replaced": func(c *Cache, _ *Entry) {
			_ = c.Store(context.Background(), "pod", entryExpiringIn(4*time.Hour, authMetadata))
		},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			delegate := failing(errors.New("must not be called"), "Unknown", false)
			c := newTestCache(delegate)
			old := entryExpiringIn(2*time.Hour, authMetadata)
			g.Expect(c.Store(context.Background(), "pod", old)).To(Succeed())
			change(c, old)

			c.onRefresh("pod", old)

			g.Expect(delegate.requests()).To(BeEmpty())
		})
	}
}

// TestCache_Writes_GoByPodUID proves Modify and Delete act on whatever the pod
// holds, as upstream's writes did.
func TestCache_Writes_GoByPodUID(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	c := newTestCache(nil)
	stale := entryExpiringIn(time.Hour, authMetadata)
	current := entryExpiringIn(2*time.Hour, authMetadata)
	current.Request = nil
	g.Expect(c.Store(ctx, "pod", stale)).To(Succeed())
	g.Expect(c.Store(ctx, "pod", current)).To(Succeed())
	request := &credentials.EksCredentialsRequest{ServiceAccountToken: "token"}

	g.Expect(c.Modify("pod", func(e *Entry) { e.Request = request })).To(BeTrue())
	got, found := c.Get("pod")
	g.Expect(found).To(BeTrue())
	g.Expect(got.Credentials).To(BeIdenticalTo(current.Credentials))
	g.Expect(got.Request).To(BeIdenticalTo(request))
	g.Expect(c.contains("pod", stale)).To(BeFalse())

	c.Delete("pod")
	_, found = c.Get("pod")
	g.Expect(found).To(BeFalse())
	g.Expect(c.Modify("pod", func(e *Entry) { e.Request = request })).To(BeFalse())
}

// captureLogs records what the shared logger logs for the rest of the test.
func captureLogs(t *testing.T) *logtest.Hook {
	log := logger.FromContext(context.Background()).Logger
	hooks := log.ReplaceHooks(make(logrus.LevelHooks))
	t.Cleanup(func() { log.ReplaceHooks(hooks) })
	return logtest.NewLocal(log)
}

// storeLogs returns the "Storing creds in cache" lines hook recorded for podUID.
func storeLogs(hook *logtest.Hook, podUID string) []*logrus.Entry {
	var stored []*logrus.Entry
	for _, e := range hook.AllEntries() {
		if e.Message == "Storing creds in cache" && e.Data["podUID"] == podUID {
			stored = append(stored, e)
		}
	}
	return stored
}

// TestCache_StoreLog_FiresOncePerStore proves "Storing creds in cache" is logged
// for each Store and refresh that stores, and not for a refused Store.
func TestCache_StoreLog_FiresOncePerStore(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	hook := captureLogs(t)
	const podUID = "store-log-pod"
	c := newTestCache(serving(creds(5*time.Hour), authMetadata))
	old := entryExpiringIn(time.Hour, authMetadata)

	g.Expect(c.Store(ctx, podUID, old)).To(Succeed())
	g.Expect(storeLogs(hook, podUID)).To(HaveLen(1))
	g.Expect(c.Store(ctx, podUID, entryExpiringIn(time.Second, authMetadata))).ToNot(Succeed())
	g.Expect(storeLogs(hook, podUID)).To(HaveLen(1), "a refused Store stores nothing")

	c.onRefresh(podUID, old)
	g.Expect(storeLogs(hook, podUID)).To(HaveLen(2))
}

// TestCache_Refresh_StoreLogNamesTheNewAssociation proves a renewal's store log
// carries the renewed entry's association, from the renewal thread.
func TestCache_Refresh_StoreLogNamesTheNewAssociation(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	hook := captureLogs(t)
	const podUID = "association-log-pod"
	newMetadata := credentials.CredentialMetadata{Association: "assoc-2", CredSource: credentials.SourceAuthService}
	c := newTestCache(serving(creds(5*time.Hour), newMetadata))
	old := entryExpiringIn(2*time.Hour, authMetadata)
	old.LogCtx = logger.ContextWithField(ctx, "association-id", "assoc-1")
	g.Expect(c.Store(old.LogCtx, podUID, old)).To(Succeed())

	c.onRefresh(podUID, old)

	g.Expect(storeLogs(hook, podUID)).To(HaveExactElements(
		HaveField("Data", HaveKeyWithValue("association-id", "assoc-1")),
		HaveField("Data", SatisfyAll(
			HaveKeyWithValue("association-id", "assoc-2"), HaveKeyWithValue("from", "renewal-thread")))))
}

// TestCache_Modify_KeepsTheSchedule proves Modify swaps in a changed copy and
// leaves the refresh and eviction times where Store put them.
func TestCache_Modify_KeepsTheSchedule(t *testing.T) {
	g := NewWithT(t)
	c := newTestCache(nil)
	e := entryExpiringIn(2*time.Hour, authMetadata)
	e.Request = nil
	g.Expect(c.Store(context.Background(), "pod", e)).To(Succeed())
	_, refreshBefore, expirationBefore, _ := c.items.GetWithRenewExpiry("pod")
	request := &credentials.EksCredentialsRequest{ServiceAccountToken: "token"}

	g.Expect(c.Modify("pod", func(next *Entry) { next.Request = request })).To(BeTrue())

	got, refresh, expiration, found := c.items.GetWithRenewExpiry("pod")
	g.Expect(found).To(BeTrue())
	g.Expect(got).ToNot(BeIdenticalTo(e))
	g.Expect(got.Request).To(BeIdenticalTo(request))
	g.Expect(got.Credentials).To(BeIdenticalTo(e.Credentials))
	g.Expect(e.Request).To(BeNil(), "the stored entry is never edited")
	g.Expect(refresh).To(Equal(refreshBefore))
	g.Expect(expiration).To(Equal(expirationBefore))
}

// TestCache_Evictions_AreCounted proves a deletion and a capacity eviction each
// count once.
func TestCache_Evictions_AreCounted(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	c := newTestCacheWith(Opts{MaxSize: 1})
	first := entryExpiringIn(time.Hour, authMetadata)
	second := entryExpiringIn(time.Hour, authMetadata)
	before := testutil.ToFloat64(promCacheState.WithLabelValues("evicted"))

	g.Expect(c.Store(ctx, "pod-1", first)).To(Succeed())
	g.Expect(c.Store(ctx, "pod-2", second)).To(Succeed())
	c.Delete("pod-2")

	g.Expect(testutil.ToFloat64(promCacheState.WithLabelValues("evicted"))).To(Equal(before + 2))
}

// TestNew_WithoutDelegate_Panics proves a cache needs a source to refresh from.
func TestNew_WithoutDelegate_Panics(t *testing.T) {
	g := NewWithT(t)

	g.Expect(func() {
		New(Opts{RenewalTtl: time.Hour, MaxSize: 100})
	}).To(PanicWith(ContainSubstring("Delegate must be non-nil")))
}

// TestNew_RefreshQPSTooLowForTheCache_Panics keeps the startup check that the
// refresh rate can cycle a full cache within the renewal TTL.
func TestNew_RefreshQPSTooLowForTheCache_Panics(t *testing.T) {
	g := NewWithT(t)

	g.Expect(func() {
		New(Opts{Delegate: &fakeSource{}, RenewalTtl: time.Second, MaxSize: 100, RefreshQPS: 1})
	}).To(PanicWith(ContainSubstring("Refresh QPS is too small")))
}
