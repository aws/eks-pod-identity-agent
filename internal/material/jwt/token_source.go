package jwt

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cache/expiring"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

const (
	// Refuse new audience sets at the cap instead of evicting live tokens and
	// turning caller-controlled cache churn into an issuance loop.
	defaultMaxAudienceSetsPerPod = 10
	defaultCleanupInterval       = time.Minute
	defaultIssueTimeout          = 10 * time.Second
	defaultRenewalTimeout        = 10 * time.Second
	defaultRefreshQPS            = 20
	defaultRenewalFraction       = 0.5
)

// Issuer is the STS operation used to mint JWT-SVIDs.
type Issuer interface {
	GetWebIdentityToken(context.Context, aws.Credentials, sts.WebIdentityTokenRequest) (*sts.IssuedWebIdentityToken, error)
}

// PodStore supplies presence and deletion events from the same node-scoped cache.
type PodStore interface {
	HasPod(podUID string) bool
	OnPodDeleted(func(podUID string)) error
}

type Opts struct {
	Issuer                Issuer
	SessionProvider       workloadidentity.SessionProvider
	PodStore              PodStore
	MaxCacheSize          int
	MaxAudienceSetsPerPod int
	Duration              time.Duration
	RenewalFraction       float64
	RenewalJitter         float64
	CleanupInterval       time.Duration
	IssueTimeout          time.Duration
	RenewalTimeout        time.Duration
	RefreshQPS            int
	now                   func() time.Time
	draw                  func() float64
	metrics               *svidMetrics
}

type Source struct {
	issuer          Issuer
	sessionProvider workloadidentity.SessionProvider
	pods            PodStore
	cache           *expiring.Cache[cacheKey, *entry]
	group           singleflight.Group
	limiter         *rate.Limiter

	maxAudienceSetsPerPod int
	duration              time.Duration
	renewalFraction       float64
	renewalJitter         float64
	issueTimeout          time.Duration
	renewalTimeout        time.Duration
	now                   func() time.Time
	draw                  func() float64
	metrics               svidMetrics

	quotaMu sync.Mutex
	pending map[cacheKey]struct{}

	stateMu sync.Mutex
	states  map[string]*podIssueState
}

func New(opts Opts) (*Source, error) {
	switch {
	case opts.Issuer == nil:
		return nil, errors.New("a JWT-SVID source needs an issuer")
	case opts.SessionProvider == nil:
		return nil, errors.New("a JWT-SVID source needs a session provider")
	case opts.PodStore == nil:
		return nil, errors.New("a JWT-SVID source needs the node-scoped pod store")
	case opts.MaxCacheSize <= 0:
		return nil, fmt.Errorf("a JWT-SVID source needs a positive cache bound, got %d", opts.MaxCacheSize)
	case opts.Duration <= 0:
		return nil, fmt.Errorf("a JWT-SVID source needs a positive requested duration, got %s", opts.Duration)
	}
	if opts.MaxAudienceSetsPerPod <= 0 {
		opts.MaxAudienceSetsPerPod = defaultMaxAudienceSetsPerPod
	}
	if opts.RenewalFraction == 0 {
		opts.RenewalFraction = defaultRenewalFraction
	}
	if !(opts.RenewalFraction > 0 && opts.RenewalFraction < 1) {
		return nil, fmt.Errorf("JWT-SVID renewal fraction must be in (0, 1), got %v", opts.RenewalFraction)
	}
	if !(opts.RenewalJitter >= 0 && opts.RenewalJitter <= 0.5) {
		return nil, fmt.Errorf("JWT-SVID renewal jitter must be in [0, 0.5], got %v", opts.RenewalJitter)
	}
	if earliest, latest := opts.RenewalFraction-opts.RenewalJitter/2, opts.RenewalFraction+opts.RenewalJitter/2; earliest <= 0 || latest >= 1 {
		return nil, fmt.Errorf("JWT-SVID renewal band [%v, %v] must remain inside (0, 1)", earliest, latest)
	}
	if opts.CleanupInterval == 0 {
		opts.CleanupInterval = defaultCleanupInterval
	}
	if opts.IssueTimeout <= 0 {
		opts.IssueTimeout = defaultIssueTimeout
	}
	if opts.RenewalTimeout <= 0 {
		opts.RenewalTimeout = defaultRenewalTimeout
	}
	if opts.RefreshQPS <= 0 {
		opts.RefreshQPS = defaultRefreshQPS
	}
	if opts.now == nil {
		opts.now = time.Now
	}
	if opts.draw == nil {
		opts.draw = rand.Float64
	}
	if opts.metrics == nil {
		metrics := defaultSVIDMetrics()
		opts.metrics = &metrics
	}

	s := &Source{
		issuer:                opts.Issuer,
		sessionProvider:       opts.SessionProvider,
		pods:                  opts.PodStore,
		cache:                 expiring.NewLru[cacheKey, *entry](opts.MaxCacheSize, expiring.NoExpiration, opts.CleanupInterval),
		limiter:               rate.NewLimiter(rate.Limit(opts.RefreshQPS), 1),
		maxAudienceSetsPerPod: opts.MaxAudienceSetsPerPod,
		duration:              opts.Duration,
		renewalFraction:       opts.RenewalFraction,
		renewalJitter:         opts.RenewalJitter,
		issueTimeout:          opts.IssueTimeout,
		renewalTimeout:        opts.RenewalTimeout,
		now:                   opts.now,
		draw:                  opts.draw,
		metrics:               *opts.metrics,
		pending:               make(map[cacheKey]struct{}),
		states:                make(map[string]*podIssueState),
	}
	s.cache.OnRefresh(s.onRefresh)
	if err := opts.PodStore.OnPodDeleted(s.Invalidate); err != nil {
		return nil, fmt.Errorf("registering JWT-SVID pod deletion callback: %w", err)
	}
	return s, nil
}

func (s *Source) JWTSVIDs(ctx context.Context, w *workloadidentity.Workload, audiences []string) ([]*jwtsvid.SVID, error) {
	if w == nil || w.PodUID == "" {
		return nil, wierrors.ErrIssuanceFailed.Wrapf(nil, "cannot issue a JWT-SVID for an empty workload")
	}
	audiences, err := normalizeAudiences(audiences)
	if err != nil {
		return nil, err
	}

	if err := s.beginUse(w.PodUID); err != nil {
		return nil, err
	}
	defer s.finishUse(w.PodUID)

	svid, err := s.forAudiences(ctx, w, audiences)
	if err != nil {
		return nil, err
	}
	return []*jwtsvid.SVID{svid}, nil
}

func (s *Source) forAudiences(ctx context.Context, w *workloadidentity.Workload, audiences []string) (*jwtsvid.SVID, error) {
	if err := s.checkPod(w.PodUID); err != nil {
		return nil, err
	}
	key := makeCacheKey(w.PodUID, audiences)
	cached, cachedOK := s.cache.Get(key)
	if cachedOK && s.now().Before(cached.renewAt) && s.servable(cached.svid) {
		return cached.svid, nil
	}

	outcome := s.group.DoChan(keyString(key), func() (any, error) {
		issueCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.issueTimeout)
		defer cancel()
		if err := s.checkPod(w.PodUID); err != nil {
			return nil, err
		}
		// Another flight may have filled the cache and finished after our first lookup.
		if current, ok := s.cache.Get(key); ok && s.now().Before(current.renewAt) && s.servable(current.svid) {
			return current.svid, nil
		}
		return s.issueAndStore(issueCtx, w, audiences, cachedOK && s.servable(cached.svid))
	})

	select {
	case result := <-outcome:
		if err := s.checkPod(w.PodUID); err != nil {
			return nil, err
		}
		if result.Err == nil {
			return result.Val.(*jwtsvid.SVID), nil
		}
		// Renewal after the halfway point is opportunistic. Preserve
		// availability by serving the last-known-good token until expiration.
		if current, ok := s.cache.Get(key); ok && s.servable(current.svid) {
			return current.svid, nil
		}
		return nil, result.Err
	case <-ctx.Done():
		return nil, wierrors.ErrIssuanceFailed.Wrapf(ctx.Err(),
			"gave up waiting for a JWT-SVID for %s/%s and audiences %q", w.Namespace, w.PodName, audiences)
	}
}

var _ workloadidentity.TokenSource = (*Source)(nil)
