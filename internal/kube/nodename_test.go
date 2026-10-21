package kube

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

const testNode = "ip-10-0-1-23.us-west-2.compute.internal"

// clientReturningUsername builds a fake clientset whose SelfSubjectReview create
// reports the given authenticated username, which is how the API server tells
// the agent which identity it presented.
func clientReturningUsername(username string) *fake.Clientset {
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "selfsubjectreviews",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, &authenticationv1.SelfSubjectReview{
				Status: authenticationv1.SelfSubjectReviewStatus{
					UserInfo: authenticationv1.UserInfo{Username: username},
				},
			}, nil
		})
	return client
}

// TestResolveNodeName_StripsNodePrefix proves the node name is the username with
// the system:node: prefix removed, which is the identity the API server will
// authorize the pod watch against.
func TestResolveNodeName_StripsNodePrefix(t *testing.T) {
	g := NewWithT(t)

	client := clientReturningUsername("system:node:" + testNode)

	name, err := ResolveNodeName(context.Background(), client)

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(name).To(Equal(testNode))
}

// TestResolveNodeName_RejectsNonNodeIdentity proves a username that is not a node
// identity is a hard error, not a silently stripped value: it means the agent is
// not authenticating as the node and the node-scoped design does not hold.
func TestResolveNodeName_RejectsNonNodeIdentity(t *testing.T) {
	testCases := []struct {
		name     string
		username string
	}{
		{name: "service account", username: "system:serviceaccount:kube-system:pod-identity-agent"},
		{name: "empty node name", username: "system:node:"},
		{name: "anonymous", username: "system:anonymous"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			client := clientReturningUsername(tc.username)

			_, err := ResolveNodeName(context.Background(), client)

			g.Expect(err).To(HaveOccurred())
		})
	}
}

// countingClient answers SelfSubjectReview with username, failing the first
// failures calls with a transient error, and counts every call.
func countingClient(username string, failures int32) (*fake.Clientset, *atomic.Int32) {
	var calls atomic.Int32
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "selfsubjectreviews",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			if calls.Add(1) <= failures {
				return true, nil, errors.New("connection refused")
			}
			return true, &authenticationv1.SelfSubjectReview{
				Status: authenticationv1.SelfSubjectReviewStatus{
					UserInfo: authenticationv1.UserInfo{Username: username},
				},
			}, nil
		})
	return client, &calls
}

// fastNodeNameBackoff shortens the startup retry for the test and restores it.
func fastNodeNameBackoff(t *testing.T) {
	saved := nodeNameBackoff
	nodeNameBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 2, Steps: 8, Cap: 10 * time.Millisecond}
	t.Cleanup(func() { nodeNameBackoff = saved })
}

// TestResolveNodeNameWithRetry_ANonNodeIdentity_FailsWithoutRetrying proves every
// identity that is not a node stops the retry at once, the empty node name
// included, since no retry can turn it into one. The real backoff is kept, so a
// retry would show as a second call.
func TestResolveNodeNameWithRetry_ANonNodeIdentity_FailsWithoutRetrying(t *testing.T) {
	for _, username := range []string{
		"system:serviceaccount:kube-system:pod-identity-agent",
		"system:node:",
		"system:anonymous",
	} {
		t.Run(username, func(t *testing.T) {
			g := NewWithT(t)
			client, calls := countingClient(username, 0)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			_, err := ResolveNodeNameWithRetry(ctx, client)

			g.Expect(err).To(MatchError(errNotANode))
			g.Expect(ctx.Err()).ToNot(HaveOccurred(), "the retry waited for the deadline instead of failing")
			g.Expect(calls.Load()).To(BeEquivalentTo(1))
		})
	}
}

// TestResolveNodeNameWithRetry_ATransientFailure_IsRetried proves an API server
// that cannot be reached yet is waited out rather than failing the boot.
func TestResolveNodeNameWithRetry_ATransientFailure_IsRetried(t *testing.T) {
	g := NewWithT(t)
	fastNodeNameBackoff(t)
	client, calls := countingClient("system:node:"+testNode, 2)

	name, err := ResolveNodeNameWithRetry(context.Background(), client)

	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(name).To(Equal(testNode))
	g.Expect(calls.Load()).To(BeEquivalentTo(3))
}

// TestResolveNodeNameWithRetry_ARefusedCredential_GivesUpNamingTheCause proves a
// boot that gives up reports the last failure and what a 401 usually means,
// rather than only that the retry timed out.
func TestResolveNodeNameWithRetry_ARefusedCredential_GivesUpNamingTheCause(t *testing.T) {
	g := NewWithT(t)
	fastNodeNameBackoff(t)
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "selfsubjectreviews",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewUnauthorized("Unauthorized")
		})

	_, err := ResolveNodeNameWithRetry(context.Background(), client)

	g.Expect(err).To(MatchError(ContainSubstring("gave up retrying")))
	g.Expect(apierrors.IsUnauthorized(err)).To(BeTrue(), "the cause has to stay inspectable")
	g.Expect(err).To(MatchError(ContainSubstring("access entry")))
}
