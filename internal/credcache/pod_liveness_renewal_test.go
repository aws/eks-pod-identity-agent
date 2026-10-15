package credcache

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// fakeLiveness is a PodLiveness whose answer a test scripts. It records every
// pod it was asked about so a test can assert the entry's identity was used.
type fakeLiveness struct {
	alive bool
	asked [][3]string
}

func (f *fakeLiveness) IsAlive(namespace, name, uid string) bool {
	f.asked = append(f.asked, [3]string{namespace, name, uid})
	return f.alive
}

// tokenForPod is a service account JWT carrying the kubernetes.io claims the
// liveness guard reads: namespace, pod name and pod uid.
func tokenForPod(t *testing.T, namespace, name, uid string) string {
	return test.CreateToken(t, test.TokenConfig{
		Expiry: time.Now().Add(time.Hour),
		Iat:    time.Now().Add(-time.Hour),
		Nbf:    time.Now().Add(-time.Hour),
		Overrides: map[string]interface{}{
			"kubernetes.io": map[string]interface{}{
				"namespace": namespace,
				"pod": map[string]interface{}{
					"name": name,
					"uid":  uid,
				},
			},
		},
	})
}

// TestOnRefresh_SkipsAndEvicts_WhenPodTerminated is the regression test for
// issue #171: when the pod a cached entry belongs to has left this node, a
// background refresh must not present the entry's request to its source, and the
// entry must be evicted. This is what keeps terminated-pod churn from spending
// AssumeRoleForPodIdentity calls and EKS Auth rate-limiter capacity.
func TestOnRefresh_SkipsAndEvicts_WhenPodTerminated(t *testing.T) {
	g := NewWithT(t)
	delegate := serving(creds(5*time.Hour), authMetadata)
	liveness := &fakeLiveness{alive: false}
	c := newTestCacheWith(Opts{Delegate: delegate, PodLiveness: liveness})
	e := entryExpiringIn(2*time.Hour, authMetadata)
	e.Request.ServiceAccountToken = tokenForPod(t, "team-a", "worker-7", "uid-123")
	g.Expect(c.Store(context.Background(), "uid-123", e)).To(Succeed())
	skippedBefore := testutil.ToFloat64(promCacheState.WithLabelValues("skipped-terminated"))

	c.onRefresh("uid-123", e)

	g.Expect(delegate.requests()).To(BeEmpty(), "a terminated pod's credentials must not be renewed through the source")
	_, found := c.Get("uid-123")
	g.Expect(found).To(BeFalse(), "a terminated pod's entry must be evicted")
	g.Expect(liveness.asked).To(HaveExactElements(Equal([3]string{"team-a", "worker-7", "uid-123"})))
	g.Expect(testutil.ToFloat64(promCacheState.WithLabelValues("skipped-terminated"))).To(Equal(skippedBefore + 1))
}

// TestOnRefresh_Renews_WhenPodAlive proves the guard only skips terminated pods:
// a pod still present on the node is renewed as before, its request reaching the
// source and its entry staying in the cache.
func TestOnRefresh_Renews_WhenPodAlive(t *testing.T) {
	g := NewWithT(t)
	fresh := creds(5 * time.Hour)
	delegate := serving(fresh, authMetadata)
	liveness := &fakeLiveness{alive: true}
	c := newTestCacheWith(Opts{Delegate: delegate, PodLiveness: liveness})
	e := entryExpiringIn(2*time.Hour, authMetadata)
	e.Request.ServiceAccountToken = tokenForPod(t, "team-a", "worker-7", "uid-123")
	g.Expect(c.Store(context.Background(), "uid-123", e)).To(Succeed())

	c.onRefresh("uid-123", e)

	g.Expect(delegate.requests()).To(HaveLen(1), "a live pod's credentials must still be renewed")
	got, found := c.Get("uid-123")
	g.Expect(found).To(BeTrue(), "a live pod's entry must stay cached")
	g.Expect(got.Credentials).To(Equal(fresh))
	g.Expect(liveness.asked).To(HaveExactElements(Equal([3]string{"team-a", "worker-7", "uid-123"})))
}

// TestOnRefresh_Renews_WhenTokenHasNoPodIdentity proves the guard fails open: an
// entry whose token carries no usable pod identity is renewed as before, so a
// malformed or minimal token never causes a skip. The liveness checker reports
// terminated, yet the refresh still proceeds because the identity is unknown.
func TestOnRefresh_Renews_WhenTokenHasNoPodIdentity(t *testing.T) {
	g := NewWithT(t)
	delegate := serving(creds(5*time.Hour), authMetadata)
	liveness := &fakeLiveness{alive: false}
	c := newTestCacheWith(Opts{Delegate: delegate, PodLiveness: liveness})
	e := entryExpiringIn(2*time.Hour, authMetadata)
	e.Request.ServiceAccountToken = "not-a-jwt"
	g.Expect(c.Store(context.Background(), "uid-123", e)).To(Succeed())

	c.onRefresh("uid-123", e)

	g.Expect(liveness.asked).To(BeEmpty(), "liveness must not be consulted without a resolvable pod identity")
	g.Expect(delegate.requests()).To(HaveLen(1), "an unresolvable identity must fail open and renew")
	_, found := c.Get("uid-123")
	g.Expect(found).To(BeTrue())
}

// TestOnRefresh_DefaultLiveness_RenewsEveryPod proves the behavior is unchanged
// when no PodLiveness is configured: the cache treats every pod as alive, so no
// renewal is skipped.
func TestOnRefresh_DefaultLiveness_RenewsEveryPod(t *testing.T) {
	g := NewWithT(t)
	delegate := serving(creds(5*time.Hour), authMetadata)
	c := newTestCacheWith(Opts{Delegate: delegate}) // no PodLiveness
	e := entryExpiringIn(2*time.Hour, authMetadata)
	e.Request.ServiceAccountToken = tokenForPod(t, "team-a", "worker-7", "uid-123")
	g.Expect(c.Store(context.Background(), "uid-123", e)).To(Succeed())

	c.onRefresh("uid-123", e)

	g.Expect(delegate.requests()).To(HaveLen(1))
	_, found := c.Get("uid-123")
	g.Expect(found).To(BeTrue())
}
