package x509

// Getting a certificate for a pod, keeping it, and replacing it before it runs out.
//
// The sequence for one pod is: ask the session tier for AWS credentials that carry
// the pod's identity, make a key pair, ask STS to sign a certificate for it, keep
// both in memory, and arrange to do it again partway through the certificate's life.
//
// The cache comes from internal/cache/expiring, which the AWS credentials cache and
// the token cache also use. We reuse its storage and its background timer, but not
// its idea of when to refresh, because all three of us want something different.
// Ours is driven by command line flags. See renewal.go.
//
// A deleted pod's certificate goes when the pod store reports the deletion. An issuance
// still running then checks the pod is there before storing, so it cannot put one back.

import (
	"context"
	cryptox509 "crypto/x509"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
	"k8s.io/utils/set"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cache/expiring"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/podstore"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// The timing defaults. Each certificate is a signing operation at the customer's
// certificate authority, so these favour asking less often over replacing promptly. The
// janitor interval, the renewal timeout and the rate limit interact; change them together.
// The lifetime we request and the point we replace at are not here. They come from
// --x509-svid-duration, --svid-renewal-fraction and --svid-renewal-jitter.
const (
	// defaultMinRemaining is how much life a certificate needs left before we hand it to
	// a workload. A minute outlasts a TLS handshake and the requests that follow it, so a
	// workload does not find its certificate expiring mid-connection.
	defaultMinRemaining = 1 * time.Minute

	// defaultCleanupInterval is how often the cache looks for certificates due for
	// replacement, and so also how long a failed replacement waits before retrying. A
	// minute against lifetimes in hours gives a transient failure dozens of attempts. It
	// matches the credentials cache.
	defaultCleanupInterval = 1 * time.Minute

	// defaultRenewalTimeout caps one background replacement, below
	// defaultCleanupInterval so a slow attempt cannot still be running when the next
	// sweep arrives.
	defaultRenewalTimeout = 30 * time.Second

	// defaultIssueTimeout caps one request made while a workload waits. Separate from the
	// renewal timeout because here a pod has no certificate at all, whereas a renewal runs
	// behind one that still works. The values happen to match today.
	defaultIssueTimeout = 30 * time.Second

	// defaultRefreshQPS is the rate and burst of background replacements, per second, not
	// per sweep: a sweep accrues tokens while it runs. Work the limit turns away is
	// skipped, and the next sweep picks it up a minute later. Jitter on the renewal point
	// is what stops a node's certificates coming due together. Two may be low for a node
	// running many pods, and should be revisited alongside the other per-pod tiers.
	defaultRefreshQPS = 2
)

// Issuer is the one call this package makes to STS. internal/cloud/sts implements
// it. It is declared here, narrowly, so tests can supply a stand-in without building
// a real STS client.
type Issuer interface {
	GetWorkloadIdentityCertificate(ctx context.Context, creds aws.Credentials, req sts.CertificateRequest) (*sts.IssuedCertificate, error)
}

// Opts configures the tier. Issuer, SessionProvider, Notifier, PodStore and MaxCacheSize
// have to be supplied; everything else falls back to the defaults above.
type Opts struct {
	// Issuer makes the call to STS. Required.
	Issuer Issuer

	// SessionProvider supplies the AWS credentials each request is signed with. STS
	// takes the identity for the certificate from who signed the call, so these
	// credentials decide whose certificate comes back. Required.
	SessionProvider workloadidentity.SessionProvider

	// Notifier is told when a pod's certificate has changed, so the streams serving that
	// pod wake and send the new one. Required: without it a replacement reaches a workload
	// only when its stream is re-established.
	Notifier workloadidentity.WorkloadNotifier

	// PodStore is the attestor's node-scoped pod store. Its deletion events drop a
	// pod's certificate and key, and every store checks the pod is still in it. Required:
	// without it a deleted pod's key stays in memory until the certificate expires.
	PodStore podstore.Interface

	// MaxCacheSize is the most certificates we hold, one per pod, from --max-cache-size.
	// Zero or negative is rejected rather than defaulted: the cache underneath reads zero
	// as "no limit", and an unbounded store of private keys should not happen by accident.
	MaxCacheSize int

	// Duration is the certificate lifetime we ask for, from --x509-svid-duration. Zero
	// means we do not ask, which STS answers with twelve hours, the same as the flag's
	// default.
	Duration time.Duration

	// RenewFraction and RenewJitter decide when we replace a certificate, and come
	// from --svid-renewal-fraction and --svid-renewal-jitter. They are checked at
	// startup, so by the time we get here the values make sense. See renewal.go.
	RenewFraction float64
	RenewJitter   float64

	// KeyType is the kind of key pair to generate, from --svid-key-type. Empty takes
	// the default. An unknown value is rejected when the tier is built, rather than at
	// the first issuance, so a mistyped flag stops the agent instead of failing pods.
	KeyType workloadidentity.KeyType

	// MinRemaining overrides defaultMinRemaining.
	MinRemaining time.Duration

	// CleanupInterval overrides defaultCleanupInterval. A negative value turns the
	// background timer off entirely, which is what unit tests want so they can trigger
	// replacement themselves instead of waiting.
	CleanupInterval time.Duration

	// RenewalTimeout, IssueTimeout and RefreshQPS override their defaults.
	RenewalTimeout time.Duration
	IssueTimeout   time.Duration
	RefreshQPS     int

	// now reads the clock and draw produces the randomness used to spread out
	// renewals. Tests replace both so they can check timing without waiting around.
	now  func() time.Time
	draw func() float64
}

// entry is what we keep for one pod: the certificate, and the pod details needed to
// get another one later without a workload having to ask.
//
// No request context. A replacement may happen hours after the first request, and
// carrying that request's details along would only put stale information in the logs.
type entry struct {
	workload *workloadidentity.Workload
	svid     *x509svid.SVID
}

// Source hands out X.509 certificates to workloads.
type Source struct {
	issuer          Issuer
	sessionProvider workloadidentity.SessionProvider
	notifier        workloadidentity.WorkloadNotifier
	pods            podstore.Interface
	cache           *expiring.Cache[string, entry]

	// storeMu makes store's presence check and cache write one step, and Invalidate
	// holds it too, so an issuance finishing as its pod is deleted cannot repopulate the
	// cache. onEvicted can run under it, from a delete or an LRU eviction; it only
	// notifies the hub, which never calls back into the Source.
	storeMu sync.Mutex

	// group collapses several requests for one pod into a single call to STS. This is the
	// normal case: a workload using the SPIFFE library opens one stream per material, Envoy
	// subscribes separately for its certificate and its trust store, and every container in
	// the pod shares the socket. Each call signs a new certificate.
	group   singleflight.Group
	limiter *rate.Limiter

	duration       time.Duration
	renewFraction  float64
	renewJitter    float64
	keyType        workloadidentity.KeyType
	minRemaining   time.Duration
	renewalTimeout time.Duration
	issueTimeout   time.Duration

	now  func() time.Time
	draw func() float64
}

// New builds the tier.
func New(opts Opts) (*Source, error) {
	if opts.Issuer == nil {
		return nil, errors.New("an X.509-SVID source needs an issuer")
	}
	if opts.SessionProvider == nil {
		return nil, errors.New("an X.509-SVID source needs a session provider")
	}
	if opts.Notifier == nil {
		return nil, errors.New("an X.509-SVID source needs a change notifier")
	}
	if opts.PodStore == nil {
		return nil, errors.New("an X.509-SVID source needs the node-scoped pod store")
	}
	if opts.MaxCacheSize <= 0 {
		return nil, fmt.Errorf("an X.509-SVID source needs a positive cache bound, got %d", opts.MaxCacheSize)
	}
	if opts.KeyType == "" {
		opts.KeyType = workloadidentity.DefaultKeyType
	}
	if err := opts.KeyType.Validate(); err != nil {
		return nil, fmt.Errorf("an X.509-SVID source cannot generate that key type: %w", err)
	}
	if opts.MinRemaining <= 0 {
		opts.MinRemaining = defaultMinRemaining
	}
	if opts.CleanupInterval == 0 {
		opts.CleanupInterval = defaultCleanupInterval
	}
	if opts.RenewalTimeout <= 0 {
		opts.RenewalTimeout = defaultRenewalTimeout
	}
	if opts.IssueTimeout <= 0 {
		opts.IssueTimeout = defaultIssueTimeout
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

	s := &Source{
		issuer:          opts.Issuer,
		sessionProvider: opts.SessionProvider,
		notifier:        opts.Notifier,
		pods:            opts.PodStore,
		// Each entry gets its own expiry when we store it, taken from the certificate,
		// so the cache-wide default here is never actually used.
		cache:          expiring.NewLru[string, entry](opts.MaxCacheSize, expiring.NoExpiration, opts.CleanupInterval),
		limiter:        rate.NewLimiter(rate.Limit(opts.RefreshQPS), opts.RefreshQPS),
		duration:       opts.Duration,
		renewFraction:  opts.RenewFraction,
		renewJitter:    opts.RenewJitter,
		keyType:        opts.KeyType,
		minRemaining:   opts.MinRemaining,
		renewalTimeout: opts.RenewalTimeout,
		issueTimeout:   opts.IssueTimeout,
		now:            opts.now,
		draw:           opts.draw,
	}
	s.cache.OnRefresh(s.onRefresh)
	s.cache.OnEvicted(s.onEvicted)
	if err := opts.PodStore.OnPodDeleted(s.Invalidate); err != nil {
		return nil, fmt.Errorf("registering the X.509-SVID pod deletion callback: %w", err)
	}
	return s, nil
}

// X509SVIDs returns the pod's certificate, fetching one if the cache holds nothing usable.
//
// The result always holds exactly one certificate, because STS gives a workload one
// identity. It is a list only because the SPIFFE API this feeds returns a list.
func (s *Source) X509SVIDs(ctx context.Context, w *workloadidentity.Workload) ([]*x509svid.SVID, error) {
	if w == nil || w.PodUID == "" {
		return nil, wierrors.ErrIssuanceFailed.Wrapf(nil, "cannot issue a certificate for an empty workload")
	}
	// A stream attests once and calls this on every wake, including the one Invalidate's
	// eviction sends, so w can be a pod deleted since. Refuse it before the cache or STS.
	if !s.pods.HasPod(w.PodUID) {
		return nil, podGone(w)
	}

	if cached, ok := s.cache.Get(w.PodUID); ok && s.servable(cached.svid) {
		return []*x509svid.SVID{cached.svid}, nil
	}
	// We can also get here holding a certificate too close to expiry to pass on, which
	// happens when replacements have been failing. It stays in the cache, since
	// workloads already holding it can keep using it, and this caller gets a fresh one.

	// Detached from this caller's context, because other callers wait on the same answer
	// and abandoning it would mean asking for a second certificate. issueTimeout stops it
	// running forever. DoChan rather than Do lets this caller stop waiting when its own
	// context ends, while the request carries on for the others.
	issueCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.issueTimeout)
	result := s.group.DoChan(w.PodUID, func() (any, error) {
		defer cancel()
		return s.issueAndStore(issueCtx, w, false)
	})

	select {
	case outcome := <-result:
		if outcome.Err != nil {
			return nil, outcome.Err
		}
		return []*x509svid.SVID{outcome.Val.(*x509svid.SVID)}, nil
	case <-ctx.Done():
		// Wrapped in one of our own error types rather than passed back raw, so the gRPC
		// handlers above have something they recognise to turn into a status code.
		return nil, wierrors.ErrIssuanceFailed.Wrapf(ctx.Err(),
			"gave up waiting for a certificate for %s/%s", w.Namespace, w.PodName)
	}
}

// Invalidate forgets the pod's certificate, and with it the private key. New registers it
// as the pod store's deletion callback. storeMu isn't for the cache, which locks itself:
// store checks HasPod and then writes, and without storeMu this delete could land between
// the two and leave the deleted pod's certificate cached.
func (s *Source) Invalidate(podUID string) {
	s.storeMu.Lock()
	defer s.storeMu.Unlock()
	s.cache.Delete(podUID)
}

// podGone is the answer for a pod the pod store no longer has.
func podGone(w *workloadidentity.Workload) error {
	return wierrors.ErrUnattestable.Wrapf(nil, "pod %s/%s is no longer in the node-scoped pod store", w.Namespace, w.PodName)
}

// servable says whether a certificate has enough life left to hand out.
func (s *Source) servable(svid *x509svid.SVID) bool {
	return s.now().Before(leaf(svid).NotAfter.Add(-s.minRemaining))
}

// leaf is the workload's own certificate. parseChain puts it first and never returns an
// empty chain, so this is in range for every SVID this package builds.
func leaf(svid *x509svid.SVID) *cryptox509.Certificate {
	return svid.Certificates[0]
}

// issueAndStore gets one certificate and puts it in the cache. The renewal flag only
// affects which metrics the attempt is counted on. If the pod was deleted meanwhile, store
// keeps nothing and the attempt counts as a failure.
func (s *Source) issueAndStore(ctx context.Context, w *workloadidentity.Workload, renewal bool) (_ *x509svid.SVID, err error) {
	start := s.now()
	defer func() { observeIssuance(err, s.now().Sub(start).Seconds(), renewal) }()
	svid, err := s.issue(ctx, w)
	if err != nil {
		return nil, err
	}
	if err = s.store(w, svid); err != nil {
		return nil, err
	}
	return svid, nil
}

// issue does the actual work of getting one certificate: credentials, key pair,
// request, then checking what came back.
func (s *Source) issue(ctx context.Context, w *workloadidentity.Workload) (*x509svid.SVID, error) {
	session, err := s.sessionProvider.Session(ctx, w)
	if err != nil {
		// Passed straight through. The session tier already said what went wrong, and in
		// more useful terms than we could: a pod that was never set up for this is not a
		// certificate problem.
		return nil, err
	}

	key, err := generateKey(s.keyType)
	if err != nil {
		return nil, wierrors.ErrIssuanceFailed.Wrapf(err, "generating a key for %s/%s", w.Namespace, w.PodName)
	}
	csr, err := buildCSR(key)
	if err != nil {
		return nil, wierrors.ErrIssuanceFailed.Wrapf(err, "building a certificate signing request for %s/%s", w.Namespace, w.PodName)
	}

	// The full lifetime, even when the credentials are nearly expired: they prove who we
	// are now, and the certificate has its own life. Capping to the credentials would put
	// every certificate under an hour and multiply signing operations by about six. Do not
	// add a cap here.
	issued, err := s.issuer.GetWorkloadIdentityCertificate(ctx, session.Credentials, sts.CertificateRequest{
		CertificateSigningRequestPEM: csr,
		MaxDuration:                  s.duration,
	})
	if err != nil {
		// If STS turned us away because it did not like our credentials, throw them
		// out so the next attempt fetches new ones. Otherwise we would keep presenting
		// the same rejected credentials until they expired on their own.
		if staleSession(err) {
			s.sessionProvider.Invalidate(w.PodUID)
		}
		return nil, classify(err, w)
	}

	chain, err := parseChain(issued.CertificatePEM, issued.CertificateChainPEM)
	if err != nil {
		return nil, wierrors.ErrIssuanceFailed.Wrapf(err, "the certificate issued for %s/%s cannot be used", w.Namespace, w.PodName)
	}
	if err := checkIdentity(chain.spiffeID, issued.Subject); err != nil {
		return nil, wierrors.ErrIssuanceFailed.Wrapf(err, "the certificate issued for %s/%s was not issued for the identity it should have been", w.Namespace, w.PodName)
	}

	return &x509svid.SVID{
		ID:           chain.spiffeID,
		Certificates: chain.certs,
		PrivateKey:   key,
	}, nil
}

// store caches the certificate under the pod's UID with two deadlines: when to replace
// it, and when to discard it. They are separate so a failed replacement loses nothing.
// Passing the replacement deadline leaves the entry in place, so a workload keeps using
// what it holds while we retry. Only the real expiry removes it. A pod the pod store no
// longer has gets nothing stored and ErrUnattestable back.
func (s *Source) store(w *workloadidentity.Workload, svid *x509svid.SVID) error {
	stored := func() bool {
		s.storeMu.Lock()
		defer s.storeMu.Unlock()
		if !s.pods.HasPod(w.PodUID) {
			return false
		}
		now := s.now()
		leafCert := leaf(svid)
		renewAt := renewalPoint(leafCert.NotBefore, leafCert.NotAfter, s.renewFraction, s.renewJitter, s.draw)
		s.cache.SetWithRefreshExpire(
			w.PodUID,
			entry{workload: w, svid: svid},
			renewalDelay(now, renewAt),
			leafCert.NotAfter.Sub(now),
		)
		return true
	}()
	if !stored {
		return podGone(w)
	}

	// After the cache holds the new certificate, never before: a stream woken first would
	// re-read the old one and nothing would wake it again. In store rather than
	// issueAndStore so it runs only on success, since a failed replacement changes nothing
	// a stream could send.
	s.notifier.NotifyWorkloadChange(w.PodUID)
	return nil
}

// onRefresh replaces a due certificate when the cache's timer calls it, paced by the rate
// limit. A failure keeps the certificate the workload holds, because taking a working one
// away turns a replacement problem into an outage; the entry stays due, so the next sweep
// retries. See workloadGone for the exception. A deleted pod's entry is dropped up front,
// at no cost against the rate limit.
func (s *Source) onRefresh(uid string, cached entry) {
	if !s.pods.HasPod(uid) {
		s.Invalidate(uid)
		return
	}
	if !s.limiter.Allow() {
		return
	}

	ctx, cancel := context.WithTimeout(
		logger.ContextWithField(context.Background(),
			"from", "x509-svid-renewal",
			"pod", cached.workload.Namespace+"/"+cached.workload.PodName),
		s.renewalTimeout)
	defer cancel()

	// A replacement makes a brand new key pair rather than reusing the old one, so any
	// single key is only ever in use for one certificate's lifetime.
	_, err := s.issueAndStore(ctx, cached.workload, true)
	if err == nil {
		return
	}

	log := logger.FromContext(ctx).WithError(err)
	if workloadGone(err) {
		log.Infof("pod %s is gone, dropping its certificate and key", uid)
		s.cache.Delete(uid)
		return
	}
	log.Infof("X.509-SVID renewal for pod %s failed, keeping the certificate it holds until it expires at %s",
		uid, leaf(cached.svid).NotAfter)
}

// workloadGone reports whether err means there is no workload left to serve. The deletion
// callback normally drops a deleted pod's key first; these cover a pod the token or session
// tier already treats as gone, and ErrUnattestable a pod deleted mid-renewal. A named set
// rather than "not retryable": ErrIssuanceRefused is also not retryable and says nothing
// about whether the pod exists.
func workloadGone(err error) bool {
	return errors.Is(err, wierrors.ErrNotEnrolled) ||
		errors.Is(err, wierrors.ErrTokenMintForbidden) ||
		errors.Is(err, wierrors.ErrSessionRefused) ||
		errors.Is(err, wierrors.ErrUnattestable)
}

// onEvicted wakes the pod's streams, so one still holding the evicted certificate,
// expired or dropped, re-reads and waits for a new one instead of being left on the
// old one with nothing to wake it. The entry, and the key inside it, is then garbage.
// It records nothing; metrics.go explains why.
func (s *Source) onEvicted(uid string, _ entry) {
	s.notifier.NotifyWorkloadChange(uid)
}

// checkIdentity confirms STS reported an identity and that it matches the certificate. An
// empty subject fails, because STS always reports one, so its absence means the call
// resolved to no workload identity.
//
// Weaker than intended: the check worth having compares the certificate against the
// identity the credentials carried, but EKS Auth returns no identity alongside them.
func checkIdentity(leafID spiffeid.ID, reportedSubject string) error {
	if reportedSubject == "" {
		return fmt.Errorf("STS reported no subject, so it issued for no workload identity")
	}
	if reportedSubject != leafID.String() {
		return fmt.Errorf("the leaf names %q but STS reported issuing for %q", leafID.String(), reportedSubject)
	}
	return nil
}

// refusalCodes are the failures a retry would get the same answer to, so they are marked
// refused rather than retryable. The first three are the only failures the operation
// models: a request we built wrong, a Provider with no signer, and a signer absent from
// this Region.
var refusalCodes = set.New(
	"MalformedCertificateSigningRequestException",
	"SignerNotConfiguredException",
	"RegionalSignerUnavailableException",
	"ValidationError",
	"ValidationException",
	"AccessDenied",
	"AccessDeniedException",
	"InvalidAction",
)

// staleSessionCodes are the failures where our credentials are plausibly the problem,
// so we throw them away. A badly built request or a missing signer has nothing to do
// with the credentials, and discarding them would mean fetching new ones for nothing.
var staleSessionCodes = set.New(
	"AccessDenied",
	"AccessDeniedException",
	"InvalidClientTokenId",
	"ExpiredToken",
	"ExpiredTokenException",
)

// throttleCodes mean STS turned us away because we asked too often.
var throttleCodes = set.New(
	"Throttling",
	"ThrottlingException",
	"RequestLimitExceeded",
	"TooManyRequestsException",
)

// staleSession says whether this failure suggests our credentials are the problem.
func staleSession(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && staleSessionCodes.Has(apiErr.ErrorCode())
}

// classify turns an STS failure into one of our own error types, so that callers and
// metrics do not have to go picking apart error strings.
func classify(err error, w *workloadidentity.Workload) error {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch code := apiErr.ErrorCode(); {
		case throttleCodes.Has(code):
			return wierrors.ErrIssuanceThrottled.Wrapf(err, "STS throttled the certificate issuance for %s/%s", w.Namespace, w.PodName)
		case refusalCodes.Has(code):
			return wierrors.ErrIssuanceRefused.Wrapf(err, "STS refused the certificate issuance for %s/%s", w.Namespace, w.PodName)
		}
	}
	return wierrors.ErrIssuanceFailed.Wrapf(err, "the certificate issuance for %s/%s failed", w.Namespace, w.PodName)
}

var _ workloadidentity.CertSource = (*Source)(nil)
