package credsretriever

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
)

var promChainedResult = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "pod_identity_chained_retriever_result",
	Help: "Credential returned by chained retriever",
}, []string{"source", "state"})

// expirationSkew is the buffer subtracted from credential expiration to account for clock skew.
const expirationSkew = 5 * time.Minute

// ErrAllDelegatesIrrecoverable is returned from chainedRetriever.GetIamCredentials
// when every delegate failed and each failure is irrecoverable per that
// delegate's own classifier.
var ErrAllDelegatesIrrecoverable = errors.New("chained retriever: all delegates returned irrecoverable errors")

// chainedRetriever queries its delegates in order and picks a result by this
// priority:
//   1. The first unexpired credential returned by any delegate.
//   2. Otherwise, the first (topmost) expired credential, if any.
//   3. Otherwise, an error joining every delegate's failure. When every
//      delegate failed and each classified its own error as irrecoverable
//      (via IsIrrecoverable), that error wraps ErrAllDelegatesIrrecoverable.
type chainedRetriever struct {
	delegates []credentials.CredentialRetriever
}

var _ credentials.CredentialRetriever = &chainedRetriever{}

// NewChainedRetriever creates a retriever that tries delegates in order.
func NewChainedRetriever(delegates ...credentials.CredentialRetriever) credentials.CredentialRetriever {
	return &chainedRetriever{delegates: delegates}
}

func (c *chainedRetriever) String() string { return "chained-retriever" }

// IsIrrecoverable returns true if the error wraps ErrAllDelegatesIrrecoverable,
// meaning every delegate in the chain classified its own error as irrecoverable.
func (c *chainedRetriever) IsIrrecoverable(err error) (string, bool) {
	if errors.Is(err, ErrAllDelegatesIrrecoverable) {
		return "AllDelegatesIrrecoverable", true
	}
	return "Unknown", false
}

func (c *chainedRetriever) GetIamCredentials(ctx context.Context,
	request *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
	log := logger.FromContext(ctx)

	var bestCred *credentials.EksCredentialsResponse
	var bestMeta credentials.ResponseMetadata
	var bestDelegate string
	var delegateErrs []error
	allIrrecoverable := true

	for _, d := range c.delegates {
		if d == nil {
			continue
		}
		log.WithField("delegate", d.String()).Info("attempting delegate")
		cred, meta, err := d.GetIamCredentials(ctx, request)

		// Delegate failed — log and try the next one.
		if err != nil {
			log.WithFields(logrus.Fields{"delegate": d.String(), "error": err}).Warn("Delegate error, trying next")
			delegateErrs = append(delegateErrs, err)
			if _, irrecoverable := d.IsIrrecoverable(err); !irrecoverable {
				allIrrecoverable = false
			}
			continue
		}

		// Got an unexpired credential — return immediately.
		if cred.Expiration.Time.After(time.Now().Add(expirationSkew)) {
			log.WithFields(logrus.Fields{"delegate": d.String(), "expiry": cred.Expiration.Time.Format(time.RFC3339)}).Info("Returning unexpired credential from delegate")
			promChainedResult.WithLabelValues(d.String(), "unexpired").Inc()
			return cred, meta, nil
		}

		// Expired credential — hold onto the topmost one as fallback.
		if bestCred == nil {
			bestCred = cred
			bestMeta = meta
			bestDelegate = d.String()
		}
	}

	if bestCred != nil {
		log.WithFields(logrus.Fields{"delegate": bestDelegate, "expiry": bestCred.Expiration.Time.Format(time.RFC3339), "expired": true}).Info("Returning fallback (expired) credential from delegate")
		promChainedResult.WithLabelValues(bestDelegate, "expired").Inc()
		return bestCred, bestMeta, nil
	}

	// No credential from any delegate. Return error(s).
	joined := errors.Join(delegateErrs...)
	if len(delegateErrs) > 0 && allIrrecoverable {
		return nil, credentials.CredentialMetadata{}, fmt.Errorf("%w: %w", ErrAllDelegatesIrrecoverable, joined)
	}

	return nil, credentials.CredentialMetadata{}, fmt.Errorf("chained retriever: all delegates failed: %w", joined)
}
