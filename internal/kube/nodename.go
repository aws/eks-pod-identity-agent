package kube

// This file resolves the agent's own Kubernetes node name. The attestor's pod
// store field selector and node recheck depend on it. A wrong value is
// expensive and silent: spec.nodeName=<wrong> is a valid selector that matches
// nothing, so the store stays empty and every attestation fails as "pod not in
// store" rather than as a misconfiguration.
//
// The name is asked of the API server rather than derived from IMDS, the
// instance profile, or a hostname. SelfSubjectReview returns the username the
// request authenticated as, and because the client presents the node credential
// (see NewNodeClient), that username is system:node:<nodeName>. This is the one
// source that cannot disagree with what the API server authorizes against, and
// it is a single code path for both the DaemonSet and the Auto Mode systemd
// shapes.
//
// This only works because the client is the node. If that credential decision
// changes, the username stops being a node identity and this returns a hard
// error rather than a wrong name; a ServiceAccount client would need the
// downward-API fallback instead.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
)

// nodeUsernamePrefix is the prefix the API server puts on a node identity's
// username. A username without it is not a node identity, which means the client
// is not authenticating as the node and the whole node-scoped design does not
// hold; that is a startup failure, not a value to strip blindly.
const nodeUsernamePrefix = "system:node:"

// credentialHint names what a refused or non-node credential most often means, on
// both credential paths the node client has.
const credentialHint = "the agent must present the node credential. With the IAM token, its AWS credentials " +
	"must be the node's role, mapped to the node by an access entry, and its ServiceAccount must carry no IAM " +
	"role; with a --node-kubeconfig user other than exec, that user must be the node"

// errNotANode marks an authenticated identity that is not a node, which no retry
// can change: a ServiceAccount, anonymous, or system:node: with an empty name.
var errNotANode = errors.New("not a node identity")

// ResolveNodeName asks the API server for the node name the client
// authenticates as. It requires no RBAC: create on selfsubjectreviews is in the
// system:basic-user ClusterRole, bound to system:authenticated, so any
// authenticated caller may ask. The API is GA from 1.28.
func ResolveNodeName(ctx context.Context, clientset kubernetes.Interface) (string, error) {
	res, err := clientset.AuthenticationV1().SelfSubjectReviews().Create(
		ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if apierrors.IsUnauthorized(err) {
		return "", fmt.Errorf("creating SelfSubjectReview: %w: %s", err, credentialHint)
	}
	if err != nil {
		return "", fmt.Errorf("creating SelfSubjectReview: %w", err)
	}

	username := res.Status.UserInfo.Username
	if !strings.HasPrefix(username, nodeUsernamePrefix) {
		return "", fmt.Errorf("authenticated as %q, which is %w (%s...): %s",
			username, errNotANode, nodeUsernamePrefix, credentialHint)
	}

	nodeName := strings.TrimPrefix(username, nodeUsernamePrefix)
	if nodeName == "" {
		return "", fmt.Errorf("authenticated as %q, which carries an empty node name, so it is %w", username, errNotANode)
	}
	return nodeName, nil
}

// nodeNameBackoff governs the startup retry. The agent cannot attest anything
// without its node name, so it stays unready and keeps trying rather than
// starting with an empty store; the caller wires the failing readiness.
var nodeNameBackoff = wait.Backoff{
	Duration: 500 * time.Millisecond,
	Factor:   2.0,
	Jitter:   0.1,
	Steps:    8,
	Cap:      30 * time.Second,
}

// ResolveNodeNameWithRetry resolves the node name, retrying transient failures
// with backoff until it succeeds or ctx is done. An identity that is not a node,
// an empty node name included, stops the retry immediately: retrying cannot turn
// a ServiceAccount into a node.
func ResolveNodeNameWithRetry(ctx context.Context, clientset kubernetes.Interface) (string, error) {
	log := logger.FromContext(ctx)

	var nodeName string
	// lastErr is the cause a give-up reports: the backoff's own error says only that it timed out.
	var lastErr error
	err := wait.ExponentialBackoffWithContext(ctx, nodeNameBackoff, func(ctx context.Context) (bool, error) {
		name, err := ResolveNodeName(ctx, clientset)
		if err != nil {
			// A non-node identity is a hard configuration error; stop retrying.
			if errors.Is(err, errNotANode) {
				return false, err
			}
			lastErr = err
			log.Warnf("resolving node name, will retry: %v", err)
			return false, nil
		}
		nodeName = name
		return true, nil
	})
	if wait.Interrupted(err) && lastErr != nil {
		return "", fmt.Errorf("resolving node name: gave up retrying: %w", lastErr)
	}
	if err != nil {
		return "", fmt.Errorf("resolving node name: %w", err)
	}
	return nodeName, nil
}
