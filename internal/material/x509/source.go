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

import (
	"context"
	cryptox509 "crypto/x509"
	"errors"
	"fmt"
	"math/rand/v2"
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
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// The timing defaults, and why each has the value it does.
//
// One fact sets most of them: a certificate we ask for is a signing operation at the
// customer's own certificate authority, which is rate limited and not free. So the
// defaults lean towards asking less often and tolerating a late replacement, which a
// certificate valid for hours can absorb.
//
// Three of them are related and should be changed together. The janitor interval is
// also the retry interval for a failed replacement, because a due entry stays due. The
// renewal timeout sits below the janitor interval so a slow attempt cannot still be
// running when the next sweep arrives. And the rate limit is per second, so what a
// single sweep gets through depends on how long the sweep itself takes.
//
// Two values are not here. The lifetime we request and the point we replace at come
// from --x509-svid-duration, --svid-renewal-fraction and --svid-renewal-jitter, which
// T1 validates at startup. See renewal.go.
const (
	// defaultMinRemaining is how much life a certificate needs left before we hand it to
	// a workload.
	//
	// A minute is longer than a TLS handshake and the requests likely to follow it, so a
	// workload will not find its certificate expiring mid-connection. Generous rather
	// than tuned: too big fetches a new certificate slightly early, too small hands out
	// one that dies while in use. The first is cheap.
	defaultMinRemaining = 1 * time.Minute

	// defaultCleanupInterval is how often the cache's background timer looks for
	// certificates due for replacement, and so also how long a failed replacement waits
	// before the next attempt.
	//
	// A minute against lifetimes measured in hours means a replacement happens within a
	// minute of becoming due, and a transient failure gets dozens of attempts before the
	// certificate expires. It matches the existing credentials cache, which sweeps on
	// the same interval.
	defaultCleanupInterval = 1 * time.Minute

	// defaultRenewalTimeout caps one background replacement, below
	// defaultCleanupInterval so a slow attempt cannot still be running when the next
	// sweep arrives.
	defaultRenewalTimeout = 30 * time.Second

	// defaultIssueTimeout caps one request made while a workload waits. Separate from
	// the renewal timeout because the situations differ: here a pod is blocked with no
	// certificate at all, where a renewal runs behind one that still works. The values
	// happen to match today.
	defaultIssueTimeout = 30 * time.Second

	// defaultRefreshQPS is the rate and burst of background replacements, in calls per
	// second.
	//
	// Two is low, for the reason above. A sweep accrues tokens while it runs, so
	// this is not a cap of two per sweep; the throughput is roughly two per second of
	// sweep. Work the limit turns away is skipped rather than queued, and the next sweep
	// picks it up a minute later.
	//
	// The risk this creates is a backlog on a node where many certificates come due
	// together, which jitter on the replacement point is what avoids. The same concern
	// was raised against the session tier on PR #7, where it matters more because a
	// session lives an hour against a certificate's twelve. Whatever that settles on
	// should apply here too.
	defaultRefreshQPS = 2
)

// Issuer is the one call this package makes to STS. internal/cloud/sts implements
// it. It is declared here, narrowly, so tests can supply a stand-in without building
// a real STS client.
type Issuer interface {
	GetWorkloadIdentityCertificate(ctx context.Context, creds aws.Credentials, req sts.CertificateRequest) (*sts.IssuedCertificate, error)
}

// Opts configures the tier. Issuer, SessionProvider, Notifier and MaxCacheSize have
// to be supplied; everything else falls back to the defaults above.
type Opts struct {
	// Issuer makes the call to STS. Required.
	Issuer Issuer

	// SessionProvider supplies the AWS credentials each request is signed with. STS
	// takes the identity for the certificate from who signed the call, so these
	// credentials decide whose certificate comes back. Required.
	SessionProvider workloadidentity.SessionProvider

	// Notifier is told when a pod's certificate has changed, so the streams serving
	// that pod wake up and send the new one. Required.
	//
	// Without it a replacement never reaches a workload: the agent would hold a fresh
	// certificate while the pod carried on with the old one until its stream was
	// re-established. One hub serves the node, and this tier only publishes to it.
	Notifier workloadidentity.WorkloadNotifier

	// MaxCacheSize is the most certificates we will hold, one per pod. It comes from
	// --max-cache-size, the same per-node budget the other per-pod caches use.
	//
	// There is no default and a zero or negative value is rejected, because the cache
	// underneath treats zero as "no limit", and an unlimited store of private keys is
	// not something to end up with by accident.
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
	cache           *expiring.Cache[string, entry]

	// group makes sure that several requests arriving for the same pod at once result
	// in one call to STS, with the rest waiting for its answer.
	//
	// This is the normal case, not a rare one. A workload using the SPIFFE library
	// opens one stream for its certificate and another for the trust bundle; Envoy
	// subscribes separately for its certificate and for what it should trust; and
	// every container in the pod shares the same socket. So one pod starting up can
	// easily produce several requests at the same moment, and each certificate we ask for
	// is a signing operation at the customer's certificate authority.
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
	return s, nil
}

// X509SVIDs returns the pod's certificate, fetching one if we do not have a usable
// one already.
//
// The result always has exactly one certificate in it. STS gives a workload one
// identity, so there is never a choice to make. It is a list only because the SPIFFE
// API this feeds is defined to return a list.
func (s *Source) X509SVIDs(ctx context.Context, w *workloadidentity.Workload) ([]*x509svid.SVID, error) {
	if w == nil || w.PodUID == "" {
		return nil, wierrors.ErrIssuanceFailed.Wrapf(nil, "cannot issue a certificate for an empty workload")
	}

	if cached, ok := s.cache.Get(w.PodUID); ok && s.servable(cached.svid) {
		return []*x509svid.SVID{cached.svid}, nil
	}
	// We can also get here holding a certificate too close to expiry to pass on, which
	// happens when replacements have been failing. It stays in the cache, since
	// workloads already holding it can keep using it, and this caller gets a fresh one.

	// The request to STS is cut loose from this caller's context. If the workload that
	// triggered it hangs up, we still want the answer, because other callers are
	// waiting on the same one and abandoning it would mean paying for a second
	// certificate. issueTimeout stops it running forever.
	//
	// DoChan rather than Do lets this caller stop waiting when its own context ends,
	// while the request carries on for everyone else.
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

// Invalidate forgets the pod's certificate, and with it the private key.
//
// The pod watcher calls this when a pod goes away. Kubernetes never reuses a pod's
// UID, so nothing will ever ask for this entry again, and there is no reason to keep
// a key belonging to something that no longer exists.
func (s *Source) Invalidate(podUID string) {
	s.cache.Delete(podUID)
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
// affects which metrics the attempt is counted on.
func (s *Source) issueAndStore(ctx context.Context, w *workloadidentity.Workload, renewal bool) (*x509svid.SVID, error) {
	start := s.now()
	svid, err := s.issue(ctx, w)
	observeIssuance(err, s.now().Sub(start).Seconds(), renewal)
	if err != nil {
		return nil, err
	}
	s.store(w, svid)
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

	// We ask for the full lifetime even when the credentials are about to expire. They
	// only prove who we are now; the certificate has its own life. Credentials are capped
	// at an hour, so matching them would put every certificate under an hour and multiply
	// signing operations at the customer's certificate authority by about six.
	//
	// The comment on workloadIdentityCertificateMaxDurationSecondsType in
	// IAMTokenServiceModel says the certificate is cut down to the credentials' remaining
	// life. STS confirmed on 2026-10-02 that nothing clamps it, so the lifetime we ask
	// for is the one we get, within the model's range. Do not add a cap on the strength
	// of that comment.
	//
	// They did add that the session lifetime is recorded in the certificate and limits
	// its use "in some places". Where, and what reads it, is an open question.
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

// store puts the certificate in the cache under the pod's UID, with two separate
// times attached: when to replace it, and when to throw it away.
//
// The two times are kept apart so a failed replacement loses nothing. Passing the
// replacement time does not remove the entry, so a workload carries on using the
// certificate it has while we keep trying. Only the real expiry removes it.
func (s *Source) store(w *workloadidentity.Workload, svid *x509svid.SVID) {
	now := s.now()
	leafCert := leaf(svid)
	renewAt := renewalPoint(leafCert.NotBefore, leafCert.NotAfter, s.renewFraction, s.renewJitter, s.draw)
	s.cache.SetWithRefreshExpire(
		w.PodUID,
		entry{workload: w, svid: svid},
		renewalDelay(now, renewAt),
		leafCert.NotAfter.Sub(now),
	)

	// Told after the cache holds the new certificate, never before. A stream woken
	// first would re-read and find the old one, and nothing would wake it again until
	// the next change.
	//
	// Only on success, which is why this sits in store rather than in issueAndStore:
	// a failed replacement changes nothing a stream could send, and an eviction is not
	// a change either.
	s.notifier.NotifyWorkloadChange(w.PodUID)
}

// onRefresh replaces a certificate that is due, and is called by the cache's
// background timer. The rate limit stops a node full of pods all coming due together
// from overwhelming the customer's certificate authority.
//
// A failure usually keeps the certificate the workload already has. The workload is
// holding something that still works, and taking it away would turn a replacement
// problem into an outage for that pod. The entry stays due, so the next sweep retries.
//
// The exception is a failure saying the workload is gone, where we drop the entry. See
// workloadGone.
func (s *Source) onRefresh(uid string, cached entry) {
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

// workloadGone reports whether err means there is no workload left to serve, as opposed
// to something transient we should retry through.
//
// Dropping the entry on these is what evicts a deleted pod's certificate and private
// key. Without it, nothing does: deletion reaches this tier only as a renewal failure,
// and the agent would hold a dead pod's key until the certificate expired, up to twelve
// hours. Upstream issue 171 reports the same shape of bug on the AWS credentials path,
// where ghost renewals for terminated pods consume EKS Auth capacity; here each one is a
// signing operation against the customer's own certificate authority.
//
// A named set rather than "not retryable". ErrIssuanceRefused is also not retryable,
// and means a malformed request or a Provider with no signer, neither of which says
// anything about whether the pod is still there.
func workloadGone(err error) bool {
	return errors.Is(err, wierrors.ErrNotEnrolled) ||
		errors.Is(err, wierrors.ErrTokenMintForbidden) ||
		errors.Is(err, wierrors.ErrSessionRefused)
}

// onEvicted is where the entry, and the pod's private key inside it, becomes garbage
// and is collected. It records nothing; metrics.go explains why.
func (s *Source) onEvicted(_ string, _ entry) {}

// checkIdentity makes sure the certificate we got back names who we expected.
//
// Weaker than intended. The check to have is the certificate's identity against the
// identity the credentials carried, which would catch the agent muddling up two pods.
// EKS Auth does not return an identity with the credentials, so there is nothing to
// compare against. If that changes, the comparison goes here.
//
// What is checked instead: STS reported an identity, and it is the one in the
// certificate. That the leaf's identity is a well formed SPIFFE name is already known,
// because go-spiffe parsed it in parseChain.
//
// A missing subject is a failure. STS said on 2026-10-02 that the field is always set,
// and that an empty one means there is no workload identity behind the call.
//
// The comparison is exact because the two are the same kind of string. The model
// documents workloadIdentitySubjectType as the workload identity stamped into the
// certificate, so it is a SPIFFE ID rather than a distinguished name.
func checkIdentity(leafID spiffeid.ID, reportedSubject string) error {
	if reportedSubject == "" {
		return fmt.Errorf("STS reported no subject, so it issued for no workload identity")
	}
	if reportedSubject != leafID.String() {
		return fmt.Errorf("the leaf names %q but STS reported issuing for %q", leafID.String(), reportedSubject)
	}
	return nil
}

// refusalCodes are the failures where trying again would get the same answer, so we
// mark them as refused rather than as something to retry. Retrying spends another
// signing operation at the customer's certificate authority for nothing.
//
// The first three are the only failures the STS operation itself defines: a request
// it would not accept, which means we built it wrong; a provider with no certificate
// signer set up, which the customer has to fix; and a signer whose key material is
// not present in this region.
//
// STS confirmed on 2026-10-02 that RegionalSignerUnavailableException is not
// retryable, so all three belong here.
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
