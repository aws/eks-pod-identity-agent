package noderole

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	. "github.com/onsi/gomega"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

var epoch = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

// fakeSource stands in for IMDS. Each fetch's key ID is keyFor(fetch number),
// and it fails with err when set.
type fakeSource struct {
	clock    *fakeClock
	lifetime time.Duration // zero means credentials that cannot expire

	mu            sync.Mutex
	err           error
	fetches       int
	invalidations int
	// gate, when set, holds every fetch until it is closed.
	gate chan struct{}
}

func (s *fakeSource) Retrieve(context.Context) (aws.Credentials, error) {
	s.mu.Lock()
	gate := s.gate
	s.mu.Unlock()
	if gate != nil {
		<-gate
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fetches++
	if s.err != nil {
		return aws.Credentials{}, s.err
	}
	creds := aws.Credentials{AccessKeyID: keyFor(s.fetches), SecretAccessKey: "secret", SessionToken: "token"}
	if s.lifetime != 0 {
		creds.CanExpire = true
		creds.Expires = s.clock.Now().Add(s.lifetime)
	}
	return creds, nil
}

func (s *fakeSource) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invalidations++
}

func (s *fakeSource) setErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *fakeSource) counts() (fetches, invalidations int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetches, s.invalidations
}

func keyFor(fetch int) string {
	return "AKID-" + string(rune('0'+fetch))
}

// fakeClock moves only when a test advances it.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeTimer stands in for time.After. It reports each wait and fires on demand.
type fakeTimer struct {
	waits chan time.Duration
	fire  chan time.Time
}

func newFakeTimer() *fakeTimer {
	return &fakeTimer{waits: make(chan time.Duration, 16), fire: make(chan time.Time)}
}

func (t *fakeTimer) After(d time.Duration) <-chan time.Time {
	t.waits <- d
	return t.fire
}

// newTestCache builds a cache whose credentials last lifetime; zero never expires.
func newTestCache(t *testing.T, lifetime time.Duration) (*Cache, *fakeSource, *fakeClock) {
	t.Helper()
	clock := &fakeClock{now: epoch}
	source := &fakeSource{clock: clock, lifetime: lifetime}
	cache, err := New(source)
	NewWithT(t).Expect(err).ToNot(HaveOccurred())
	cache.now = clock.Now
	return cache, source, clock
}

// runCache runs the cache until the test ends.
func runCache(t *testing.T, cache *Cache, timer *fakeTimer) {
	t.Helper()
	cache.after = timer.After
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		cache.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func TestNew_WithoutASource_Fails(t *testing.T) {
	_, err := New(nil)
	NewWithT(t).Expect(err).To(MatchError(ContainSubstring("source")))
}

func TestNew_FetchesNothing(t *testing.T) {
	_, source, _ := newTestCache(t, time.Hour)

	fetches, invalidations := source.counts()

	NewWithT(t).Expect([]int{fetches, invalidations}).To(Equal([]int{0, 0}))
}

func TestRetrieve_AHungSource_IsBoundedByTheFetchTimeoutEvenForAReaderThatNeverGivesUp(t *testing.T) {
	g := NewWithT(t)
	cache, err := New(aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		<-ctx.Done()
		return aws.Credentials{}, ctx.Err()
	}))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(cache.timeout).To(Equal(fetchTimeout))
	cache.timeout = 50 * time.Millisecond

	start := time.Now()
	_, err = cache.Retrieve(context.Background())

	g.Expect(err).To(MatchError(context.DeadlineExceeded))
	g.Expect(time.Since(start)).To(BeNumerically("<", 5*time.Second))
}

func TestRetrieve_ServesTheCachedCredentialsUntilTheyExpire(t *testing.T) {
	g := NewWithT(t)
	cache, source, clock := newTestCache(t, time.Hour)

	first, err := cache.Retrieve(t.Context())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(first.AccessKeyID).To(Equal(keyFor(1)))

	clock.Advance(59 * time.Minute)
	again, err := cache.Retrieve(t.Context())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(again.AccessKeyID).To(Equal(keyFor(1)), "valid credentials are served from the cache")

	clock.Advance(time.Minute)
	renewed, err := cache.Retrieve(t.Context())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(renewed.AccessKeyID).To(Equal(keyFor(2)), "expired credentials are fetched again")

	fetches, invalidations := source.counts()
	g.Expect(fetches).To(Equal(2))
	g.Expect(invalidations).To(Equal(2), "the source is invalidated before every fetch")
}

func TestRetrieve_ConcurrentReadersShareOneFetch(t *testing.T) {
	g := NewWithT(t)
	cache, source, _ := newTestCache(t, time.Hour)
	source.gate = make(chan struct{})

	const readers = 8
	var wg sync.WaitGroup
	var failures atomic.Int32
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if creds, err := cache.Retrieve(context.Background()); err != nil || creds.AccessKeyID != keyFor(1) {
				failures.Add(1)
			}
		}()
	}
	close(source.gate)
	wg.Wait()

	fetches, _ := source.counts()
	g.Expect(fetches).To(Equal(1))
	g.Expect(failures.Load()).To(BeZero())
}

func TestRetrieve_AFailedFetchWithNothingCached_ReturnsTheError(t *testing.T) {
	g := NewWithT(t)
	cache, source, _ := newTestCache(t, time.Hour)
	source.setErr(errors.New("IMDS unreachable"))

	_, err := cache.Retrieve(t.Context())

	g.Expect(err).To(MatchError(ContainSubstring("IMDS unreachable")))
}

func TestRetrieve_CredentialsWithNoKeys_AreRefused(t *testing.T) {
	g := NewWithT(t)
	cache, err := New(aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{}, nil
	}))
	g.Expect(err).ToNot(HaveOccurred())

	_, err = cache.Retrieve(t.Context())

	g.Expect(err).To(MatchError(ContainSubstring("no keys")))
}

func TestRetrieve_AGoneReader_GivesUpWaitingForAFetch(t *testing.T) {
	g := NewWithT(t)
	cache, source, _ := newTestCache(t, time.Hour)
	source.gate = make(chan struct{})
	defer close(source.gate)
	go func() { _, _ = cache.Retrieve(context.Background()) }()
	g.Eventually(func() int { return len(cache.fetching) }).Should(Equal(1))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := cache.Retrieve(ctx)

	g.Expect(err).To(MatchError(context.DeadlineExceeded))
}

func TestRun_FetchesAtOnceThenRenewsAtHalfTheRemainingLifetime(t *testing.T) {
	g := NewWithT(t)
	cache, source, clock := newTestCache(t, time.Hour)
	timer := newFakeTimer()

	runCache(t, cache, timer)

	g.Eventually(timer.waits).Should(Receive(Equal(maxSleep)), "Run fetched at once and sleeps no longer than maxSleep")
	fetches, _ := source.counts()
	g.Expect(fetches).To(Equal(1))

	// Before the renewal point, a wake fetches nothing.
	clock.Advance(29 * time.Minute)
	timer.fire <- clock.Now()
	g.Eventually(timer.waits).Should(Receive(Equal(time.Minute)))
	fetches, _ = source.counts()
	g.Expect(fetches).To(Equal(1))

	clock.Advance(time.Minute)
	timer.fire <- clock.Now()
	g.Eventually(timer.waits).Should(Receive())
	fetches, _ = source.counts()
	g.Expect(fetches).To(Equal(2), "Run renews at half of the hour the credentials had left")

	creds, err := cache.Retrieve(t.Context())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(creds.AccessKeyID).To(Equal(keyFor(2)), "readers get the renewed credentials without fetching")
	fetches, _ = source.counts()
	g.Expect(fetches).To(Equal(2))
}

func TestRun_AFailedRenewal_ServesTheLastGoodCredentialsAndBacksOff(t *testing.T) {
	g := NewWithT(t)
	cache, source, clock := newTestCache(t, time.Hour)
	_, err := cache.Retrieve(t.Context())
	g.Expect(err).ToNot(HaveOccurred())
	source.setErr(errors.New("IMDS unreachable"))
	clock.Advance(30 * time.Minute)
	timer := newFakeTimer()

	runCache(t, cache, timer)

	g.Eventually(timer.waits).Should(Receive(Equal(retryBaseDelay)), "the first retry waits retryBaseDelay")
	creds, err := cache.Retrieve(t.Context())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(creds.AccessKeyID).To(Equal(keyFor(1)), "the last good credentials are served while renewal fails")

	clock.Advance(retryBaseDelay)
	timer.fire <- clock.Now()
	g.Eventually(timer.waits).Should(Receive(Equal(2*retryBaseDelay)), "each failure doubles the backoff")

	source.setErr(nil)
	clock.Advance(2 * retryBaseDelay)
	timer.fire <- clock.Now()
	g.Eventually(timer.waits).Should(Receive())
	creds, err = cache.Retrieve(t.Context())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(creds.AccessKeyID).To(Equal(keyFor(4)))
}

func TestRun_CredentialsThatCannotExpire_AreNeverRenewed(t *testing.T) {
	g := NewWithT(t)
	cache, source, clock := newTestCache(t, 0)
	timer := newFakeTimer()

	runCache(t, cache, timer)

	g.Eventually(timer.waits).Should(Receive(Equal(maxSleep)))
	clock.Advance(24 * time.Hour)
	timer.fire <- clock.Now()
	g.Eventually(timer.waits).Should(Receive(Equal(maxSleep)))
	fetches, _ := source.counts()
	g.Expect(fetches).To(Equal(1))
}

func TestRetrieve_AlreadyExpiredCredentials_AreRefusedAndBackOff(t *testing.T) {
	g := NewWithT(t)
	cache, _, _ := newTestCache(t, -time.Minute)
	timer := newFakeTimer()

	_, err := cache.Retrieve(t.Context())
	g.Expect(err).To(MatchError(ContainSubstring("expired")))

	runCache(t, cache, timer)
	g.Eventually(timer.waits).Should(Receive(Equal(retryBaseDelay)), "Run waits out the backoff instead of refetching at once")
}

func TestRun_StopsWhenItsContextEnds(t *testing.T) {
	g := NewWithT(t)
	cache, _, _ := newTestCache(t, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		cache.Run(ctx)
	}()

	cancel()

	g.Eventually(done, 5*time.Second).Should(BeClosed())
}

func TestRetryDelay_DoublesUpToTheCap(t *testing.T) {
	g := NewWithT(t)
	g.Expect(retryDelay(1)).To(Equal(retryBaseDelay))
	g.Expect(retryDelay(2)).To(Equal(2 * retryBaseDelay))
	g.Expect(retryDelay(4)).To(Equal(8 * retryBaseDelay))
	g.Expect(retryDelay(5)).To(Equal(retryMaxDelay))
	g.Expect(retryDelay(100)).To(Equal(retryMaxDelay))
}
