// Package noderole caches the node role's AWS credentials and renews them in
// the background. The node client's IAM token and GetTrustBundles sign with them.
//
// The cache invalidates its source before each fetch, so each Cache needs a
// source of its own.
package noderole

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
)

const (
	// renewFraction is when to renew, as a share of the remaining lifetime.
	renewFraction = 0.5
	// retryBaseDelay doubles after each failed renewal, up to retryMaxDelay.
	retryBaseDelay = 5 * time.Second
	retryMaxDelay  = time.Minute
	// maxSleep is the longest Run sleeps before checking the schedule again.
	maxSleep = time.Minute
	// fetchTimeout caps one fetch, in line with the agent's IMDS poller. The IAM
	// token generator signs with context.Background(), so this is its only limit.
	fetchTimeout = 3 * time.Second
)

// invalidator is a source that caches, such as aws.CredentialsCache.
type invalidator interface {
	Invalidate()
}

// Cache holds the node's credentials and Run renews them. Retrieve fetches only
// when nothing valid is cached.
type Cache struct {
	source aws.CredentialsProvider

	// fetching is a one-slot semaphore, so concurrent fetches share one call.
	fetching chan struct{}

	mu sync.Mutex
	// creds are the last good credentials. A failed fetch keeps them.
	creds *aws.Credentials
	// renewAt is the next renewal. Zero means the credentials never expire.
	renewAt  time.Time
	failures int
	retryAt  time.Time

	// Replaced in tests.
	now     func() time.Time
	after   func(time.Duration) <-chan time.Time
	timeout time.Duration
}

// New builds a cache that owns source. It fetches nothing, so it never blocks
// startup.
func New(source aws.CredentialsProvider) (*Cache, error) {
	// This error would fail agent startup, but it can't happen:
	// newNodeCredentialsSource never returns nil.
	if source == nil {
		return nil, errors.New("a source of the node's AWS credentials is required")
	}
	return &Cache{
		source:   source,
		fetching: make(chan struct{}, 1),
		now:      time.Now,
		after:    time.After,
		timeout:  fetchTimeout,
	}, nil
}

// Retrieve returns the cached credentials, or fetches when none are valid.
func (c *Cache) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if creds, ok := c.valid(); ok {
		return creds, nil
	}
	if err := c.acquire(ctx); err != nil {
		return aws.Credentials{}, err
	}
	defer c.release()
	// Another caller may have fetched while this one waited.
	if creds, ok := c.valid(); ok {
		return creds, nil
	}
	return c.fetch(ctx)
}

// Run renews the credentials when due, until ctx is done.
func (c *Cache) Run(ctx context.Context) {
	for {
		c.renewIfDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-c.after(c.sleep()):
		}
	}
}

// sleep is how long Run waits before checking again.
func (c *Cache) sleep() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	due, ok := c.dueAtLocked()
	if !ok {
		return maxSleep
	}
	return min(max(due.Sub(c.now()), 0), maxSleep)
}

// renewIfDue fetches if a renewal is due. On failure it logs, and readers keep
// the last good credentials.
func (c *Cache) renewIfDue(ctx context.Context) {
	if c.acquire(ctx) != nil {
		return
	}
	defer c.release()
	if !c.due() {
		return
	}
	if _, err := c.fetch(ctx); err != nil && ctx.Err() == nil {
		c.mu.Lock()
		creds, failures, retryAt := c.creds, c.failures, c.retryAt
		c.mu.Unlock()
		log := logger.FromContext(ctx).WithError(err).WithField("failures", failures).
			WithField("retry_at", retryAt.Format(time.RFC3339))
		if creds != nil && creds.CanExpire {
			log = log.WithField("expires", creds.Expires.Format(time.RFC3339))
		}
		log.Warn("Renewing the node's AWS credentials failed, serving the last good ones until they expire")
	}
}

// due reports whether a renewal should run now.
func (c *Cache) due() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	due, ok := c.dueAtLocked()
	return ok && !c.now().Before(due)
}

// dueAtLocked is the next renewal time, or false if none is scheduled.
func (c *Cache) dueAtLocked() (time.Time, bool) {
	switch {
	case c.failures > 0:
		return c.retryAt, true
	case c.creds == nil:
		return time.Time{}, true
	case c.renewAt.IsZero():
		return time.Time{}, false
	default:
		return c.renewAt, true
	}
}

// valid returns the cached credentials if they haven't expired.
func (c *Cache) valid() (aws.Credentials, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.creds == nil || (c.creds.CanExpire && !c.now().Before(c.creds.Expires)) {
		return aws.Credentials{}, false
	}
	return *c.creds, true
}

// fetch gets new credentials and schedules the next renewal. The caller holds
// the semaphore.
func (c *Cache) fetch(ctx context.Context) (aws.Credentials, error) {
	// Otherwise a caching source returns the same credentials again.
	if source, ok := c.source.(invalidator); ok {
		source.Invalidate()
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	creds, err := c.source.Retrieve(ctx)
	switch {
	case err != nil:
	case !creds.HasKeys():
		err = errors.New("the source returned credentials with no keys")
	case creds.CanExpire && !c.now().Before(creds.Expires):
		// Refused, so they back off instead of being fetched again at once.
		err = fmt.Errorf("the source returned credentials that expired at %s", creds.Expires.Format(time.RFC3339))
	}
	if err != nil {
		err = fmt.Errorf("fetching the node's AWS credentials: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if err != nil {
		c.failures++
		c.retryAt = now.Add(retryDelay(c.failures))
		return aws.Credentials{}, err
	}
	if c.failures > 0 {
		logger.FromContext(ctx).WithField("failures", c.failures).
			Info("Renewed the node's AWS credentials after earlier attempts failed")
	}
	c.creds = &creds
	c.failures, c.retryAt = 0, time.Time{}
	c.renewAt = time.Time{}
	if creds.CanExpire {
		c.renewAt = now.Add(time.Duration(float64(creds.Expires.Sub(now)) * renewFraction))
	}
	return creds, nil
}

// retryDelay is the backoff after the given number of failures.
func retryDelay(failures int) time.Duration {
	// Avoids overflowing the shift.
	if failures > 8 {
		return retryMaxDelay
	}
	return min(retryBaseDelay<<(failures-1), retryMaxDelay)
}

// acquire takes the semaphore, or gives up when ctx ends.
func (c *Cache) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("gave up waiting for the node's AWS credentials: %w", err)
	}
	select {
	case c.fetching <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("gave up waiting for the node's AWS credentials: %w", ctx.Err())
	}
}

func (c *Cache) release() {
	<-c.fetching
}

var _ aws.CredentialsProvider = &Cache{}
