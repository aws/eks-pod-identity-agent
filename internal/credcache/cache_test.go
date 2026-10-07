package credcache

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cache/expiring"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
)

var (
	authMetadata = credentials.CredentialMetadata{Association: "assoc-1", CredSource: credentials.SourceAuthService}
	imdsMetadata = credentials.CredentialMetadata{CredSource: credentials.SourceIMDS}
)

// eviction is one Owner.Evicted call.
type eviction struct {
	podUID  string
	entry   *Entry
	removed bool
}

// fakeOwner is an Owner whose renewal a test scripts. It records evictions.
type fakeOwner struct {
	renew         func(ctx context.Context, podUID string, e *Entry) (*Entry, error)
	irrecoverable bool

	mu        sync.Mutex
	evictions []eviction
}

func (o *fakeOwner) Renew(ctx context.Context, podUID string, e *Entry) (*Entry, error) {
	return o.renew(ctx, podUID, e)
}

func (o *fakeOwner) IsIrrecoverable(error) (string, bool) {
	if o.irrecoverable {
		return "Irrecoverable", true
	}
	return "Unknown", false
}

func (o *fakeOwner) Evicted(podUID string, e *Entry, removed bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.evictions = append(o.evictions, eviction{podUID: podUID, entry: e, removed: removed})
}

func (o *fakeOwner) evicted() []eviction {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]eviction(nil), o.evictions...)
}

// newTestCache builds a Cache with its sweep off, so a test drives onRefresh.
func newTestCache() *Cache {
	return New(Opts{RenewalTtl: 3 * time.Hour, MaxSize: 100, RefreshQPS: 3, CleanupInterval: -1})
}

// entryExpiringIn is an entry owned by owner whose credentials expire after d.
func entryExpiringIn(d time.Duration, metadata credentials.ResponseMetadata, owner Owner) *Entry {
	return &Entry{
		Credentials: &credentials.EksCredentialsResponse{
			AccessKeyId: "AKIA-" + d.String(),
			Expiration:  credentials.SdkCompliantExpirationTime{Time: time.Now().Add(d)},
		},
		Metadata: metadata,
		Owner:    owner,
	}
}

// failingRenewal is a renewal that fails with err.
func failingRenewal(err error) func(context.Context, string, *Entry) (*Entry, error) {
	return func(context.Context, string, *Entry) (*Entry, error) { return nil, err }
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
	c := newTestCache()

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
			c := newTestCache()
			e := entryExpiringIn(tc.credsDur, authMetadata, &fakeOwner{})

			g.Expect(c.Store(context.Background(), "pod", e)).To(Succeed())

			got, refresh, expiration, found := c.items.GetWithRenewExpiry("pod")
			g.Expect(found).To(BeTrue())
			g.Expect(got).To(BeIdenticalTo(e))
			g.Expect(time.Until(refresh)).To(BeNumerically("~", tc.wantRefresh, time.Second))
			g.Expect(expiration).To(BeTemporally("~", e.Credentials.Expiration.Time, time.Second))
		})
	}
}

// TestCache_Store_RefusesWhatItCannotRenewOrServe covers the entries Store
// refuses, leaving the cache as it was.
func TestCache_Store_RefusesWhatItCannotRenewOrServe(t *testing.T) {
	tests := []struct {
		name    string
		entry   *Entry
		wantErr string
	}{
		{"no credentials", &Entry{Owner: &fakeOwner{}}, "no credentials to cache"},
		{"no owner", entryExpiringIn(time.Hour, authMetadata, nil), "no owner"},
		{"within the minimum TTL", entryExpiringIn(DefaultMinCredentialTtl-time.Second, authMetadata, &fakeOwner{}),
			"fetched credentials are expired or will expire within the next"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			c := newTestCache()

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
				c := New(Opts{RenewalTtl: 3 * time.Hour, MaxSize: 100, RefreshQPS: 3, CleanupInterval: -1,
					RetryInterval: 5 * time.Minute, MaxRetryJitter: 1})
				owner := &fakeOwner{renew: failingRenewal(errors.New("recoverable error"))}
				e := entryExpiringIn(tc.credsAge, tc.metadata, owner)
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
		c := newTestCache()
		owner := &fakeOwner{}
		fresh := entryExpiringIn(6*time.Hour, imdsMetadata, owner)
		owner.renew = func(context.Context, string, *Entry) (*Entry, error) { return fresh, nil }
		e := entryExpiringIn(-30*time.Minute, imdsMetadata, owner)
		c.items.Set("pod", e)

		c.onRefresh("pod", e)

		got, found := c.Get("pod")
		g.Expect(found).To(BeTrue())
		g.Expect(got).To(BeIdenticalTo(fresh))
	})

	t.Run("irrecoverable renewal error evicts the entry regardless of source", func(t *testing.T) {
		// When the owner classifies the refresh error as irrecoverable, the
		// credential is gone/invalid, so the entry is evicted even for IMDS.
		for _, meta := range []credentials.ResponseMetadata{imdsMetadata, authMetadata} {
			g := NewWithT(t)
			c := newTestCache()
			owner := &fakeOwner{renew: failingRenewal(errors.New("gone")), irrecoverable: true}
			e := entryExpiringIn(6*time.Hour, meta, owner)
			c.items.Set("pod", e)

			c.onRefresh("pod", e)

			_, found := c.Get("pod")
			g.Expect(found).To(BeFalse(), "irrecoverable error should evict the entry for source %s", meta.Source())
			g.Expect(owner.evicted()).To(Equal([]eviction{{podUID: "pod", entry: e, removed: true}}))
		}
	})
}

// TestCache_Refresh_ActsOnlyOnTheEntryItRenewed proves a refresh whose entry was
// replaced while it renewed leaves the replacement alone, however it ends.
func TestCache_Refresh_ActsOnlyOnTheEntryItRenewed(t *testing.T) {
	tests := []struct {
		name          string
		renewed       func(owner *fakeOwner) (*Entry, error)
		irrecoverable bool
	}{
		{"a successful renewal isn't stored", func(owner *fakeOwner) (*Entry, error) {
			return entryExpiringIn(5*time.Hour, authMetadata, owner), nil
		}, false},
		{"a recoverable failure doesn't put the old entry back", func(*fakeOwner) (*Entry, error) {
			return nil, errors.New("recoverable error")
		}, false},
		{"an irrecoverable failure doesn't remove the replacement", func(*fakeOwner) (*Entry, error) {
			return nil, errors.New("gone")
		}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			ctx := context.Background()
			c := newTestCache()
			owner := &fakeOwner{irrecoverable: tc.irrecoverable}
			old := entryExpiringIn(2*time.Hour, authMetadata, owner)
			replacement := entryExpiringIn(4*time.Hour, authMetadata, owner)
			g.Expect(c.Store(ctx, "pod", old)).To(Succeed())
			owner.renew = func(context.Context, string, *Entry) (*Entry, error) {
				// Another caller stores a newer entry while this renewal is out.
				g.Expect(c.Store(ctx, "pod", replacement)).To(Succeed())
				return tc.renewed(owner)
			}

			c.onRefresh("pod", old)

			got, found := c.Get("pod")
			g.Expect(found).To(BeTrue())
			g.Expect(got).To(BeIdenticalTo(replacement))
		})
	}
}

// TestCache_Refresh_SurvivesAModify proves a Modify while a refresh is out
// leaves the entry the same one: the renewal is stored, and a kept entry keeps
// what Modify set.
func TestCache_Refresh_SurvivesAModify(t *testing.T) {
	request := &credentials.EksCredentialsRequest{ServiceAccountToken: "admitted"}

	t.Run("a successful renewal is stored", func(t *testing.T) {
		g := NewWithT(t)
		ctx := context.Background()
		c := newTestCache()
		owner := &fakeOwner{}
		old := entryExpiringIn(2*time.Hour, authMetadata, owner)
		renewed := entryExpiringIn(5*time.Hour, authMetadata, owner)
		g.Expect(c.Store(ctx, "pod", old)).To(Succeed())
		owner.renew = func(context.Context, string, *Entry) (*Entry, error) {
			g.Expect(c.Modify("pod", old, func(e *Entry) { e.Request = request })).To(BeTrue())
			return renewed, nil
		}

		c.onRefresh("pod", old)

		got, found := c.Get("pod")
		g.Expect(found).To(BeTrue())
		g.Expect(got).To(BeIdenticalTo(renewed))
	})

	t.Run("a kept entry keeps what Modify set", func(t *testing.T) {
		g := NewWithT(t)
		ctx := context.Background()
		c := newTestCache()
		owner := &fakeOwner{}
		old := entryExpiringIn(2*time.Hour, authMetadata, owner)
		g.Expect(c.Store(ctx, "pod", old)).To(Succeed())
		owner.renew = func(context.Context, string, *Entry) (*Entry, error) {
			g.Expect(c.Modify("pod", old, func(e *Entry) { e.Request = request })).To(BeTrue())
			return nil, errors.New("recoverable error")
		}

		c.onRefresh("pod", old)

		got, found := c.Get("pod")
		g.Expect(found).To(BeTrue())
		g.Expect(got.Credentials).To(BeIdenticalTo(old.Credentials))
		g.Expect(got.Request).To(BeIdenticalTo(request))
	})
}

// TestCache_Refresh_AcceptsARenewalItsOwnerStored proves a renewal the owner
// stored itself, as one shared with its own callers would be, counts as stored.
func TestCache_Refresh_AcceptsARenewalItsOwnerStored(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	c := newTestCache()
	owner := &fakeOwner{}
	old := entryExpiringIn(2*time.Hour, authMetadata, owner)
	renewed := entryExpiringIn(5*time.Hour, authMetadata, owner)
	g.Expect(c.Store(ctx, "pod", old)).To(Succeed())
	owner.renew = func(context.Context, string, *Entry) (*Entry, error) {
		replaced, err := c.Replace(ctx, "pod", old, renewed)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(replaced).To(BeTrue())
		return renewed, nil
	}
	hitsBefore := testutil.ToFloat64(promCacheState.WithLabelValues("hit"))

	c.onRefresh("pod", old)

	g.Expect(c.Contains("pod", renewed)).To(BeTrue())
	g.Expect(testutil.ToFloat64(promCacheState.WithLabelValues("hit"))).To(Equal(hitsBefore + 1))
}

// TestCache_Refresh_SkipsAnEntryRemovedSinceTheSweepPickedIt proves the sweep
// doesn't renew an entry that a caller removed or replaced after it was picked.
func TestCache_Refresh_SkipsAnEntryRemovedSinceTheSweepPickedIt(t *testing.T) {
	for name, change := range map[string]func(c *Cache, old *Entry, owner *fakeOwner){
		"removed": func(c *Cache, old *Entry, _ *fakeOwner) { c.Delete("pod", old) },
		"replaced": func(c *Cache, _ *Entry, owner *fakeOwner) {
			_ = c.Store(context.Background(), "pod", entryExpiringIn(4*time.Hour, authMetadata, owner))
		},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			c := newTestCache()
			renewals := 0
			owner := &fakeOwner{renew: func(context.Context, string, *Entry) (*Entry, error) {
				renewals++
				return nil, errors.New("must not be called")
			}}
			old := entryExpiringIn(2*time.Hour, authMetadata, owner)
			g.Expect(c.Store(context.Background(), "pod", old)).To(Succeed())
			change(c, old, owner)

			c.onRefresh("pod", old)

			g.Expect(renewals).To(BeZero())
		})
	}
}

// TestCache_Writes_ActOnlyOnTheEntryTheyWereGiven covers Replace, Modify and
// Delete against an entry the cache no longer holds.
func TestCache_Writes_ActOnlyOnTheEntryTheyWereGiven(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	c := newTestCache()
	owner := &fakeOwner{}
	stale := entryExpiringIn(time.Hour, authMetadata, owner)
	current := entryExpiringIn(2*time.Hour, authMetadata, owner)
	g.Expect(c.Store(ctx, "pod", stale)).To(Succeed())
	g.Expect(c.Store(ctx, "pod", current)).To(Succeed())

	replaced, err := c.Replace(ctx, "pod", stale, entryExpiringIn(3*time.Hour, authMetadata, owner))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(replaced).To(BeFalse())
	g.Expect(c.Modify("pod", stale, func(e *Entry) { e.Request = &credentials.EksCredentialsRequest{} })).To(BeFalse())
	g.Expect(c.Delete("pod", stale)).To(BeFalse())
	g.Expect(c.Contains("pod", stale)).To(BeFalse())

	got, found := c.Get("pod")
	g.Expect(found).To(BeTrue())
	g.Expect(got).To(BeIdenticalTo(current))
	g.Expect(got.Request).To(BeNil())
}

// TestCache_Modify_KeepsTheSchedule proves Modify swaps in a changed copy and
// leaves the refresh and eviction times where Store put them.
func TestCache_Modify_KeepsTheSchedule(t *testing.T) {
	g := NewWithT(t)
	c := newTestCache()
	e := entryExpiringIn(2*time.Hour, authMetadata, &fakeOwner{})
	g.Expect(c.Store(context.Background(), "pod", e)).To(Succeed())
	_, refreshBefore, expirationBefore, _ := c.items.GetWithRenewExpiry("pod")
	request := &credentials.EksCredentialsRequest{ServiceAccountToken: "token"}

	g.Expect(c.Modify("pod", e, func(next *Entry) { next.Request = request })).To(BeTrue())

	got, refresh, expiration, found := c.items.GetWithRenewExpiry("pod")
	g.Expect(found).To(BeTrue())
	g.Expect(got).ToNot(BeIdenticalTo(e))
	g.Expect(got.Request).To(BeIdenticalTo(request))
	g.Expect(got.Credentials).To(BeIdenticalTo(e.Credentials))
	g.Expect(e.Request).To(BeNil(), "the stored entry is never edited")
	g.Expect(refresh).To(Equal(refreshBefore))
	g.Expect(expiration).To(Equal(expirationBefore))
}

// TestCache_Evicted_TellsARemovalFromAnEviction proves Owner.Evicted reports
// removed for Delete, and not for an entry pushed out for capacity.
func TestCache_Evicted_TellsARemovalFromAnEviction(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	c := New(Opts{RenewalTtl: 3 * time.Hour, MaxSize: 1, RefreshQPS: 3, CleanupInterval: -1})
	owner := &fakeOwner{}
	first := entryExpiringIn(time.Hour, authMetadata, owner)
	second := entryExpiringIn(time.Hour, authMetadata, owner)

	g.Expect(c.Store(ctx, "pod-1", first)).To(Succeed())
	g.Expect(c.Store(ctx, "pod-2", second)).To(Succeed())
	g.Expect(c.Delete("pod-2", second)).To(BeTrue())

	g.Expect(owner.evicted()).To(Equal([]eviction{
		{podUID: "pod-1", entry: first, removed: false},
		{podUID: "pod-2", entry: second, removed: true},
	}))
}

// TestNew_RefreshQPSTooLowForTheCache_Panics keeps the startup check that the
// refresh rate can cycle a full cache within the renewal TTL.
func TestNew_RefreshQPSTooLowForTheCache_Panics(t *testing.T) {
	g := NewWithT(t)

	g.Expect(func() {
		New(Opts{RenewalTtl: time.Second, MaxSize: 100, RefreshQPS: 1, CleanupInterval: -1})
	}).To(PanicWith(ContainSubstring("Refresh QPS is too small")))
}
