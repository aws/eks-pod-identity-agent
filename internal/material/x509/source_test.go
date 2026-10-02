package x509

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/smithy-go"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/sts"
	agentlogger "go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	// Initializes the agent's logger, which the tier logs a failed renewal
	// through. Without it FromContext returns an entry over a nil logger.
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity/fake"
)

func TestNewRejectsAnIncompleteConfiguration(t *testing.T) {
	ca := newTestCA(t)
	issuer := &fakeIssuer{respond: func(int, sts.CertificateRequest) (*sts.IssuedCertificate, error) {
		return nil, errors.New("unused")
	}}
	_ = ca

	t.Run("no issuer", func(t *testing.T) {
		_, err := New(Opts{SessionProvider: testSessions(time.Now()), MaxCacheSize: 1})
		assert.ErrorContains(t, err, "issuer")
	})
	t.Run("no session provider", func(t *testing.T) {
		_, err := New(Opts{Issuer: issuer, MaxCacheSize: 1})
		assert.ErrorContains(t, err, "session provider")
	})
	t.Run("no change notifier", func(t *testing.T) {
		// Without one a replacement never reaches a workload, so this is refused rather
		// than defaulted to a no-op.
		_, err := New(Opts{Issuer: issuer, SessionProvider: testSessions(time.Now()), MaxCacheSize: 1})
		assert.ErrorContains(t, err, "change notifier")
	})
	t.Run("an unbounded cache is refused", func(t *testing.T) {
		// expiring.NewLru reads zero as unlimited, and an unbounded cache of private
		// keys is not something to arrive at by accident.
		_, err := New(Opts{Issuer: issuer, SessionProvider: testSessions(time.Now()), Notifier: &fake.Subscriber{}, MaxCacheSize: 0})
		assert.ErrorContains(t, err, "positive cache bound")
	})
}

// TestX509SVIDsIssuesAndParses is the happy path: a certificate is obtained for an
// attested workload, and the parsed leaf, chain and timestamps come back.
func TestX509SVIDsIssuesAndParses(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()
	// The window STS issued, which is not the window that was requested.
	notBefore := now.Add(-5 * time.Minute)
	notAfter := notBefore.Add(4 * time.Hour)

	issuer := &fakeIssuer{respond: func(_ int, req sts.CertificateRequest) (*sts.IssuedCertificate, error) {
		return ca.issue(t, req.CertificateSigningRequestPEM, testSpiffeID, notBefore, notAfter), nil
	}}
	source := newTestSource(t, issuer, testSessions(now.Add(time.Hour)), clockAt(&now), func() float64 { return 0.5 })

	svids, err := source.X509SVIDs(context.Background(), testWorkload(testPodUID))
	require.NoError(t, err)
	require.Len(t, svids, 1, "STS issues one identity per workload, so there is never a set to select from")
	svid := svids[0]

	assert.Equal(t, testSpiffeID, svid.SpiffeID)
	assert.Empty(t, svid.Hint, "nothing populates Hint")
	require.NotNil(t, svid.PrivateKey)

	// Timestamps come off the parsed leaf, to the second: a certificate's own
	// window is what the renewal schedule is derived from.
	assert.WithinDuration(t, notBefore, svid.NotBefore, time.Second)
	assert.WithinDuration(t, notAfter, svid.NotAfter, time.Second)

	// Leaf first, then the issuing chain, and the root is absent because a verifier
	// takes it from the trust bundle.
	require.Len(t, svid.Certificates, 2)
	leaf, err := x509.ParseCertificate(svid.Certificates[0])
	require.NoError(t, err)
	assert.Equal(t, testSpiffeID, leaf.URIs[0].String())
	assert.Equal(t, svid.PrivateKey.Public(), leaf.PublicKey, "the leaf certifies the key the agent generated")

	intermediate, err := x509.ParseCertificate(svid.Certificates[1])
	require.NoError(t, err)
	assert.Equal(t, "test intermediate", intermediate.Subject.CommonName)
	for _, der := range svid.Certificates {
		assert.NotEqual(t, ca.rootDER, der, "the chain excludes the root")
	}
}

// TestX509SVIDsDoesNotClampToTheSession asserts the requested duration survives a
// session with minutes left. The session authenticates the mint; the certificate
// is a separate credential, and clamping would cut every certificate to under an
// hour and multiply the issuance rate against the customer's certificate authority.
//
// Confirmed by STS on 2026-09-30: a certificate can be issued for up to 12 hours
// from a session with a minute left. The API model comment still says the opposite
// and is out of date, so this test is also what stops someone reinstating a clamp
// after reading it.
func TestX509SVIDsDoesNotClampToTheSession(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()
	issuer := &fakeIssuer{respond: func(_ int, req sts.CertificateRequest) (*sts.IssuedCertificate, error) {
		return ca.issue(t, req.CertificateSigningRequestPEM, testSpiffeID, now, now.Add(6*time.Hour)), nil
	}}

	// Two minutes of session left, against a six hour request.
	source := newTestSource(t, issuer, testSessions(now.Add(2*time.Minute)), clockAt(&now), func() float64 { return 0.5 })

	_, err := source.X509SVIDs(context.Background(), testWorkload(testPodUID))
	require.NoError(t, err)

	assert.Equal(t, 6*time.Hour, issuer.lastRequest(t).MaxDuration,
		"the requested lifetime is not reduced to the session's remaining life")
}

// TestX509SVIDsCoalescesConcurrentRequests covers the cost property: a burst of
// streams opening for one pod is one issuance, because each issuance is a real
// signing operation at the customer's certificate authority.
func TestX509SVIDsCoalescesConcurrentRequests(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()
	release := make(chan struct{})
	issuer := &fakeIssuer{
		block: release,
		respond: func(_ int, req sts.CertificateRequest) (*sts.IssuedCertificate, error) {
			return ca.issue(t, req.CertificateSigningRequestPEM, testSpiffeID, now, now.Add(6*time.Hour)), nil
		},
	}
	source := newTestSource(t, issuer, testSessions(now.Add(time.Hour)), clockAt(&now), func() float64 { return 0.5 })
	w := testWorkload(testPodUID)

	const callers = 8
	var wg sync.WaitGroup
	results := make([]*workloadidentity.X509SVID, callers)
	errs := make([]error, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			svids, err := source.X509SVIDs(context.Background(), w)
			errs[i] = err
			if err == nil {
				results[i] = svids[0]
			}
		}()
	}

	// Let every caller attach to the one in-flight issuance before it answers.
	require.Eventually(t, func() bool { return issuer.calls() == 1 }, time.Second, time.Millisecond)
	close(release)
	wg.Wait()

	assert.Equal(t, 1, issuer.calls(), "eight concurrent requests for one pod are one issuance")
	for i := range callers {
		require.NoError(t, errs[i])
		assert.Same(t, results[0], results[i], "every caller gets the same certificate")
	}
}

// TestX509SVIDsSeparatePodsIssueSeparately guards the coalescing key: two pods
// share nothing, even though at launch they may well share a SPIFFE ID.
func TestX509SVIDsSeparatePodsIssueSeparately(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()
	issuer := &fakeIssuer{respond: func(_ int, req sts.CertificateRequest) (*sts.IssuedCertificate, error) {
		return ca.issue(t, req.CertificateSigningRequestPEM, testSpiffeID, now, now.Add(6*time.Hour)), nil
	}}
	source := newTestSource(t, issuer, testSessions(now.Add(time.Hour)), clockAt(&now), func() float64 { return 0.5 })

	first, err := source.X509SVIDs(context.Background(), testWorkload("pod-a"))
	require.NoError(t, err)
	second, err := source.X509SVIDs(context.Background(), testWorkload("pod-b"))
	require.NoError(t, err)

	assert.Equal(t, 2, issuer.calls())
	assert.Equal(t, first[0].SpiffeID, second[0].SpiffeID,
		"replicas of one Deployment share a SPIFFE ID, since the name renders from cluster, namespace and service account")
	assert.NotEqual(t, first[0].PrivateKey.Public(), second[0].PrivateKey.Public(),
		"but each pod holds its own key")
}

func TestX509SVIDsServesFromCache(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()
	issuer := &fakeIssuer{respond: func(_ int, req sts.CertificateRequest) (*sts.IssuedCertificate, error) {
		return ca.issue(t, req.CertificateSigningRequestPEM, testSpiffeID, now, now.Add(6*time.Hour)), nil
	}}
	source := newTestSource(t, issuer, testSessions(now.Add(time.Hour)), clockAt(&now), func() float64 { return 0.5 })
	w := testWorkload(testPodUID)

	first, err := source.X509SVIDs(context.Background(), w)
	require.NoError(t, err)
	second, err := source.X509SVIDs(context.Background(), w)
	require.NoError(t, err)

	assert.Equal(t, 1, issuer.calls())
	assert.Same(t, first[0], second[0])
}

// TestStoreSchedulesRenewalAtTheJitteredFraction asserts the schedule that was
// actually written into the cache, with a controlled clock and draw.
func TestStoreSchedulesRenewalAtTheJitteredFraction(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()
	notBefore := now
	notAfter := now.Add(6 * time.Hour)

	issuer := &fakeIssuer{respond: func(_ int, req sts.CertificateRequest) (*sts.IssuedCertificate, error) {
		return ca.issue(t, req.CertificateSigningRequestPEM, testSpiffeID, notBefore, notAfter), nil
	}}
	// Draw at the middle of the band, so the point is exactly half life.
	source := newTestSource(t, issuer, testSessions(now.Add(time.Hour)), clockAt(&now), func() float64 { return 0.5 })

	_, err := source.X509SVIDs(context.Background(), testWorkload(testPodUID))
	require.NoError(t, err)

	_, renewAt, expireAt, ok := source.cache.GetWithRenewExpiry(testPodUID)
	require.True(t, ok)

	assert.WithinDuration(t, notBefore.Add(3*time.Hour), renewAt, 5*time.Second,
		"renewal is scheduled at the configured fraction of the issued lifetime")
	assert.WithinDuration(t, notAfter, expireAt, 5*time.Second,
		"eviction is at real expiry, which is what lets a failed renewal keep serving")
	assert.True(t, renewAt.Before(expireAt))
}

// TestFailedRenewalKeepsServingTheExistingCertificate is the availability
// property: a renewal problem must not become an outage for a pod holding a
// working credential.
func TestFailedRenewalKeepsServingTheExistingCertificate(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()
	issuer := &fakeIssuer{respond: func(attempt int, req sts.CertificateRequest) (*sts.IssuedCertificate, error) {
		if attempt > 1 {
			return nil, errors.New("STS is unavailable")
		}
		return ca.issue(t, req.CertificateSigningRequestPEM, testSpiffeID, now, now.Add(6*time.Hour)), nil
	}}
	source := newTestSource(t, issuer, testSessions(now.Add(time.Hour)), clockAt(&now), func() float64 { return 0.5 })
	w := testWorkload(testPodUID)

	original, err := source.X509SVIDs(context.Background(), w)
	require.NoError(t, err)

	// Drive the renewal the janitor would have run. It fails.
	cached, ok := source.cache.Get(testPodUID)
	require.True(t, ok)
	source.onRefresh(testPodUID, cached)
	require.Equal(t, 2, issuer.calls(), "the renewal was attempted")

	// Still served, and still the same certificate.
	after, err := source.X509SVIDs(context.Background(), w)
	require.NoError(t, err)
	assert.Same(t, original[0], after[0],
		"a failed renewal leaves the previous certificate served until it truly expires")
	assert.Equal(t, 2, issuer.calls(), "and serving it costs no further issuance")
}

// TestRenewalForAGonePodDropsTheCertificate is what evicts a deleted pod's key.
// Deletion reaches this tier only as a renewal failure, so without this the agent holds
// the key until the certificate expires, up to twelve hours. Upstream issue 171 reports
// the same bug on the AWS credentials path.
func TestRenewalForAGonePodDropsTheCertificate(t *testing.T) {
	tests := []struct {
		name     string
		renewErr error
		wantKept bool
	}{
		{
			name:     "pod has no association any more",
			renewErr: wierrors.ErrNotEnrolled.Wrapf(nil, "pod is gone"),
			wantKept: false,
		},
		{
			name:     "the API server refuses to mint for the pod",
			renewErr: wierrors.ErrTokenMintForbidden.Wrapf(nil, "pod is gone"),
			wantKept: false,
		},
		{
			name:     "EKS Auth refuses the session exchange",
			renewErr: wierrors.ErrSessionRefused.Wrapf(nil, "pod is gone"),
			wantKept: false,
		},
		{
			name:     "STS is unavailable, so the pod may well still be running",
			renewErr: wierrors.ErrIssuanceFailed.Wrapf(nil, "STS is down"),
			wantKept: true,
		},
		{
			name:     "a refusal that says nothing about the pod keeps the certificate",
			renewErr: wierrors.ErrIssuanceRefused.Wrapf(nil, "the Provider has no signer"),
			wantKept: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ca := newTestCA(t)
			now := time.Now()
			issuer := &fakeIssuer{respond: func(attempt int, req sts.CertificateRequest) (*sts.IssuedCertificate, error) {
				if attempt > 1 {
					return nil, tc.renewErr
				}
				return ca.issue(t, req.CertificateSigningRequestPEM, testSpiffeID, now, now.Add(6*time.Hour)), nil
			}}
			sessions := testSessions(now.Add(time.Hour))
			source := newTestSource(t, issuer, sessions, clockAt(&now), func() float64 { return 0.5 })
			w := testWorkload(testPodUID)

			_, err := source.X509SVIDs(context.Background(), w)
			require.NoError(t, err)

			cached, ok := source.cache.Get(testPodUID)
			require.True(t, ok)
			source.onRefresh(testPodUID, cached)
			require.Equal(t, 2, issuer.calls(), "the renewal was attempted")

			_, stillCached := source.cache.Get(testPodUID)
			assert.Equal(t, tc.wantKept, stillCached)
		})
	}
}

// TestStoreNotifiesTheOpenStreams covers what makes a replacement reach a workload.
// Without it the agent holds a fresh certificate while the pod carries on with the old
// one, which is T10's definition of done: a renewal produces a fresh response on an
// already-open stream.
func TestStoreNotifiesTheOpenStreams(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()
	issuer := &fakeIssuer{respond: func(attempt int, req sts.CertificateRequest) (*sts.IssuedCertificate, error) {
		if attempt > 2 {
			return nil, errors.New("STS is unavailable")
		}
		return ca.issue(t, req.CertificateSigningRequestPEM, testSpiffeID, now, now.Add(6*time.Hour)), nil
	}}
	notifier := &fake.Subscriber{}
	source, err := New(Opts{
		Issuer:          issuer,
		SessionProvider: testSessions(now.Add(time.Hour)),
		Notifier:        notifier,
		MaxCacheSize:    10,
		Duration:        6 * time.Hour,
		RenewFraction:   0.5,
		RenewJitter:     0.1,
		CleanupInterval: -1,
		now:             clockAt(&now),
		draw:            func() float64 { return 0.5 },
	})
	require.NoError(t, err)
	w := testWorkload(testPodUID)

	_, err = source.X509SVIDs(context.Background(), w)
	require.NoError(t, err)
	assert.Equal(t, []string{testPodUID}, notifier.WorkloadChanges(),
		"the first issuance is a change too: a stream primed before it has nothing to send")

	// A successful replacement notifies again.
	cached, ok := source.cache.Get(testPodUID)
	require.True(t, ok)
	source.onRefresh(testPodUID, cached)
	require.Equal(t, 2, issuer.calls())
	assert.Equal(t, []string{testPodUID, testPodUID}, notifier.WorkloadChanges())

	// A failed replacement notifies nothing: the stream would re-read what it already
	// has, and the certificate it holds is unchanged.
	cached, ok = source.cache.Get(testPodUID)
	require.True(t, ok)
	source.onRefresh(testPodUID, cached)
	require.Equal(t, 3, issuer.calls(), "the third attempt ran and failed")
	assert.Len(t, notifier.WorkloadChanges(), 2, "a failed replacement is not a change")
}

// TestExpiredCertificateStopsBeingServed is the other half of that: holding a
// certificate past its renewal point is fine, holding it past its usable life is
// not.
func TestExpiredCertificateStopsBeingServed(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()
	notAfter := now.Add(6 * time.Hour)
	issuer := &fakeIssuer{respond: func(attempt int, req sts.CertificateRequest) (*sts.IssuedCertificate, error) {
		if attempt > 1 {
			return nil, errors.New("STS is still unavailable")
		}
		return ca.issue(t, req.CertificateSigningRequestPEM, testSpiffeID, now, notAfter), nil
	}}
	source := newTestSource(t, issuer, testSessions(now.Add(100*time.Hour)), clockAt(&now), func() float64 { return 0.5 })
	w := testWorkload(testPodUID)

	_, err := source.X509SVIDs(context.Background(), w)
	require.NoError(t, err)

	// Move past the point where the certificate has enough life left to hand out.
	now = notAfter.Add(-time.Second)

	svids, err := source.X509SVIDs(context.Background(), w)
	assert.Nil(t, svids, "an expired certificate is not served")
	require.Error(t, err)
	assert.True(t, errors.Is(err, wierrors.ErrIssuanceFailed),
		"the failure is a taxonomy member so the handler's status mapping stays total, got %v", err)
	assert.Equal(t, wierrors.MetricLabel(err), "issuance_failed")
}

// TestLeafIdentityMismatchIsRejected covers the self-check: a certificate that is
// individually valid but names the wrong identity is not served and not cached.
func TestLeafIdentityMismatchIsRejected(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()
	issuer := &fakeIssuer{respond: func(_ int, req sts.CertificateRequest) (*sts.IssuedCertificate, error) {
		issued := ca.issue(t, req.CertificateSigningRequestPEM, "spiffe://example.aws/eks/cluster/default/somebody-else", now, now.Add(6*time.Hour))
		// STS reports issuing for one identity while the signer stamped another.
		issued.Subject = testSpiffeID
		return issued, nil
	}}
	source := newTestSource(t, issuer, testSessions(now.Add(time.Hour)), clockAt(&now), func() float64 { return 0.5 })

	svids, err := source.X509SVIDs(context.Background(), testWorkload(testPodUID))
	assert.Nil(t, svids)
	require.Error(t, err)
	assert.ErrorContains(t, err, "somebody-else")

	_, ok := source.cache.Get(testPodUID)
	assert.False(t, ok, "a certificate that fails the check is never cached")
}

func TestNonSpiffeLeafIsRejected(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()
	issuer := &fakeIssuer{respond: func(_ int, req sts.CertificateRequest) (*sts.IssuedCertificate, error) {
		issued := ca.issue(t, req.CertificateSigningRequestPEM, "https://example.aws/not-a-spiffe-id", now, now.Add(6*time.Hour))
		issued.Subject = ""
		return issued, nil
	}}
	source := newTestSource(t, issuer, testSessions(now.Add(time.Hour)), clockAt(&now), func() float64 { return 0.5 })

	_, err := source.X509SVIDs(context.Background(), testWorkload(testPodUID))
	require.Error(t, err)
	assert.ErrorContains(t, err, "not a SPIFFE ID")
}

func TestIssuanceFailuresAreClassified(t *testing.T) {
	tests := []struct {
		name      string
		code      string
		want      *wierrors.WorkloadIdentityError
		retryable bool
	}{
		{"throttling", "ThrottlingException", wierrors.ErrIssuanceThrottled, true},
		{"malformed request is our own defect", "MalformedCertificateSigningRequestException", wierrors.ErrIssuanceRefused, false},
		{"no signer on the provider", "SignerNotConfiguredException", wierrors.ErrIssuanceRefused, false},
		{"access denied", "AccessDeniedException", wierrors.ErrIssuanceRefused, false},
		{"anything else is a transient failure", "InternalFailure", wierrors.ErrIssuanceFailed, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			issuer := &fakeIssuer{respond: func(int, sts.CertificateRequest) (*sts.IssuedCertificate, error) {
				return nil, &smithy.GenericAPIError{Code: tc.code, Message: "from the test"}
			}}
			source := newTestSource(t, issuer, testSessions(now.Add(time.Hour)), clockAt(&now), func() float64 { return 0.5 })

			_, err := source.X509SVIDs(context.Background(), testWorkload(testPodUID))
			require.Error(t, err)
			assert.True(t, errors.Is(err, tc.want), "want %v, got %v", tc.want, err)
			assert.Equal(t, tc.retryable, wierrors.IsRetryable(err))
		})
	}
}

// TestStaleSessionIsInvalidated covers the one failure the cached session could be
// the cause of. Without this the tier retries against the same stale session until
// its TTL runs out.
func TestStaleSessionIsInvalidated(t *testing.T) {
	tests := []struct {
		name            string
		code            string
		wantInvalidated bool
	}{
		{"access denied drops the session", "AccessDeniedException", true},
		{"an expired session token drops it", "ExpiredToken", true},
		{"a malformed request is not the session's fault", "MalformedCertificateSigningRequestException", false},
		{"a missing signer is not the session's fault", "SignerNotConfiguredException", false},
		{"throttling is not the session's fault", "ThrottlingException", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			issuer := &fakeIssuer{respond: func(int, sts.CertificateRequest) (*sts.IssuedCertificate, error) {
				return nil, &smithy.GenericAPIError{Code: tc.code, Message: "from the test"}
			}}
			sessions := testSessions(now.Add(time.Hour))
			source := newTestSource(t, issuer, sessions, clockAt(&now), func() float64 { return 0.5 })

			_, err := source.X509SVIDs(context.Background(), testWorkload(testPodUID))
			require.Error(t, err)

			if tc.wantInvalidated {
				assert.Equal(t, []string{testPodUID}, sessions.Invalidated(),
					"the session should have been dropped so the next attempt re-exchanges")
			} else {
				assert.Empty(t, sessions.Invalidated(),
					"dropping the session here would only cost a needless re-exchange")
			}
		})
	}
}

// TestSessionFailurePropagatesUnchanged keeps the session tier's own classification
// intact: a pod that is not enrolled is not an issuance failure.
func TestSessionFailurePropagatesUnchanged(t *testing.T) {
	now := time.Now()
	issuer := &fakeIssuer{respond: func(int, sts.CertificateRequest) (*sts.IssuedCertificate, error) {
		return nil, errors.New("never reached")
	}}
	sessions := testSessions(now)
	sessions.SetResult(nil, wierrors.ErrNotEnrolled.Wrapf(nil, "pod has no association"))
	source := newTestSource(t, issuer, sessions, clockAt(&now), func() float64 { return 0.5 })

	_, err := source.X509SVIDs(context.Background(), testWorkload(testPodUID))
	require.Error(t, err)
	assert.True(t, errors.Is(err, wierrors.ErrNotEnrolled))
	assert.Equal(t, 0, issuer.calls(), "no certificate is requested without a session")
}

func TestInvalidateDropsTheEntryAndItsKey(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()
	issuer := &fakeIssuer{respond: func(_ int, req sts.CertificateRequest) (*sts.IssuedCertificate, error) {
		return ca.issue(t, req.CertificateSigningRequestPEM, testSpiffeID, now, now.Add(6*time.Hour)), nil
	}}
	source := newTestSource(t, issuer, testSessions(now.Add(time.Hour)), clockAt(&now), func() float64 { return 0.5 })
	w := testWorkload(testPodUID)

	first, err := source.X509SVIDs(context.Background(), w)
	require.NoError(t, err)

	source.Invalidate(testPodUID)
	_, ok := source.cache.Get(testPodUID)
	require.False(t, ok, "pod deletion evicts the entry")

	// A pod UID is never reused, so in production nothing asks again. If something
	// does, it gets a fresh keypair rather than the deleted one.
	second, err := source.X509SVIDs(context.Background(), w)
	require.NoError(t, err)
	assert.Equal(t, 2, issuer.calls())
	assert.NotEqual(t, first[0].PrivateKey.Public(), second[0].PrivateKey.Public())
}

func TestEmptyWorkloadIsRejected(t *testing.T) {
	now := time.Now()
	issuer := &fakeIssuer{respond: func(int, sts.CertificateRequest) (*sts.IssuedCertificate, error) {
		return nil, errors.New("never reached")
	}}
	source := newTestSource(t, issuer, testSessions(now), clockAt(&now), func() float64 { return 0.5 })

	for _, w := range []*workloadidentity.Workload{nil, {}} {
		_, err := source.X509SVIDs(context.Background(), w)
		require.Error(t, err)
		assert.True(t, errors.Is(err, wierrors.ErrIssuanceFailed))
	}
	assert.Equal(t, 0, issuer.calls())
}

// TestPrivateKeyNeverReachesALogLine captures everything the tier logs across a
// successful issuance and a failed renewal, and asserts the key is not in it.
func TestPrivateKeyNeverReachesALogLine(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()
	issuer := &fakeIssuer{respond: func(attempt int, req sts.CertificateRequest) (*sts.IssuedCertificate, error) {
		if attempt > 1 {
			return nil, errors.New("STS is unavailable")
		}
		return ca.issue(t, req.CertificateSigningRequestPEM, testSpiffeID, now, now.Add(6*time.Hour)), nil
	}}
	source := newTestSource(t, issuer, testSessions(now.Add(time.Hour)), clockAt(&now), func() float64 { return 0.5 })

	// The agent's logger is its own logrus instance rather than the standard one,
	// reached here through an entry so its output can be redirected.
	agentLog := agentlogger.FromContext(context.Background()).Logger
	var captured strings.Builder
	previousOut, previousLevel := agentLog.Out, agentLog.GetLevel()
	agentLog.SetOutput(&captured)
	agentLog.SetLevel(logrus.TraceLevel)
	t.Cleanup(func() {
		agentLog.SetOutput(previousOut)
		agentLog.SetLevel(previousLevel)
	})

	svids, err := source.X509SVIDs(context.Background(), testWorkload(testPodUID))
	require.NoError(t, err)

	cached, ok := source.cache.Get(testPodUID)
	require.True(t, ok)
	source.onRefresh(testPodUID, cached)
	require.Equal(t, 2, issuer.calls(), "the renewal ran and failed, so its log line was emitted")

	logged := captured.String()
	require.NotEmpty(t, logged, "the failed renewal should have logged something to check")

	// The key in every encoding it could plausibly leak in.
	pkcs8, err := x509.MarshalPKCS8PrivateKey(svids[0].PrivateKey)
	require.NoError(t, err)
	for name, secret := range map[string]string{
		"PKCS#8 hex":    hex.EncodeToString(pkcs8),
		"Go formatting": fmt.Sprintf("%v", svids[0].PrivateKey),
	} {
		assert.NotContains(t, logged, secret, "the private key leaked into a log line as %s", name)
	}
	assert.NotContains(t, logged, "PRIVATE KEY")
}
