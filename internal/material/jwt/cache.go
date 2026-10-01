package jwt

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cache/expiring"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

type cacheKey struct {
	podUID    string
	audiences string
}

type entry struct {
	workload  *workloadidentity.Workload
	audiences []string
	svid      *jwtsvid.SVID
	renewAt   time.Time
}

type podIssueState struct {
	active      int
	invalidated bool
}

func (s *Source) store(w *workloadidentity.Workload, audiences []string, svid *jwtsvid.SVID, issuedAt time.Time) {
	now := s.now()
	renewAt := renewalPoint(issuedAt, svid.Expiry, s.renewalFraction, s.renewalJitter, s.draw)
	workloadCopy := *w
	s.cache.SetWithRefreshExpire(
		makeCacheKey(w.PodUID, audiences),
		&entry{workload: &workloadCopy, audiences: slices.Clone(audiences), svid: svid, renewAt: renewAt},
		renewalDelay(now, renewAt),
		svid.Expiry.Sub(now),
	)
}

func (s *Source) servable(svid *jwtsvid.SVID) bool {
	return svid != nil && s.now().Before(svid.Expiry)
}

// Invalidate removes every audience set belonging to a deleted pod. If an STS call
// is in flight, issueAndStore observes invalidated and cannot repopulate it.
func (s *Source) Invalidate(podUID string) {
	if podUID == "" {
		return
	}
	s.stateMu.Lock()
	s.invalidateLocked(podUID)
	s.stateMu.Unlock()
}

func (s *Source) invalidateLocked(podUID string) {
	if state := s.states[podUID]; state != nil {
		state.invalidated = true
	}
	s.cache.DeleteFunc(func(key cacheKey, _ expiring.Item[*entry]) (bool, bool) {
		return key.podUID == podUID, false
	})
}

func (s *Source) checkPod(podUID string) error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.checkPodLocked(podUID)
}

func (s *Source) checkPodLocked(podUID string) error {
	state := s.states[podUID]
	if state != nil && state.invalidated || !s.pods.HasPod(podUID) {
		s.invalidateLocked(podUID)
		return wierrors.ErrUnattestable.Wrapf(nil, "pod %s is no longer in the node-scoped store", podUID)
	}
	return nil
}

func (s *Source) reserveAudienceSet(key cacheKey) error {
	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	count := 0
	cached := s.cache.Items()
	for existing := range cached {
		if existing.podUID == key.podUID {
			count++
		}
	}
	for pending := range s.pending {
		if _, stored := cached[pending]; pending.podUID == key.podUID && !stored {
			count++
		}
	}
	if _, exists := cached[key]; !exists && count >= s.maxAudienceSetsPerPod {
		return wierrors.ErrInvalidAudience.Wrapf(nil,
			"pod %s already has the maximum of %d cached JWT-SVID audience sets", key.podUID, s.maxAudienceSetsPerPod)
	}
	s.pending[key] = struct{}{}
	return nil
}

func (s *Source) releaseAudienceSet(key cacheKey) {
	s.quotaMu.Lock()
	delete(s.pending, key)
	s.quotaMu.Unlock()
}

func (s *Source) beginUse(podUID string) error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if err := s.checkPodLocked(podUID); err != nil {
		return err
	}
	state := s.states[podUID]
	if state == nil {
		state = &podIssueState{}
		s.states[podUID] = state
	}
	state.active++
	return nil
}

func (s *Source) finishUse(podUID string) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	state := s.states[podUID]
	if state == nil {
		return
	}
	state.active--
	if state.active == 0 {
		delete(s.states, podUID)
	}
}

// Length prefixes keep canonical sets distinct even when audiences contain delimiters.
func makeCacheKey(podUID string, audiences []string) cacheKey {
	var encoded strings.Builder
	for _, audience := range audiences {
		encoded.WriteString(strconv.Itoa(len(audience)))
		encoded.WriteByte(':')
		encoded.WriteString(audience)
	}
	return cacheKey{podUID: podUID, audiences: encoded.String()}
}

func keyString(key cacheKey) string {
	return key.podUID + "\x00" + key.audiences
}
