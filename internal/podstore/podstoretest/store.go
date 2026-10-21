// Package podstoretest provides a fake podstore.Interface for tests.
package podstoretest

import (
	"sync"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/podstore"
)

// Store is a fake podstore.Interface that holds every pod until Remove
// or Delete is called for it. Remove makes HasPod say no without running the
// callbacks, which is the moment between client-go dropping a pod from its
// indexer and calling the handlers; Delete does both, in that order.
//
// Set RegisterErr before the fake is used.
type Store struct {
	// RegisterErr, when non-nil, is returned by OnPodDeleted, which then
	// registers nothing.
	RegisterErr error

	mu        sync.Mutex
	callbacks []func(podUID string)
	removed   map[string]bool
}

var _ podstore.Interface = (*Store)(nil)

// HasPod reports false only for a pod Remove or Delete was called for.
func (p *Store) HasPod(podUID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.removed[podUID]
}

// OnPodDeleted registers fn, or returns RegisterErr when it is set.
func (p *Store) OnPodDeleted(fn func(podUID string)) error {
	if p.RegisterErr != nil {
		return p.RegisterErr
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.callbacks = append(p.callbacks, fn)
	return nil
}

// Remove takes the pod out of the store without running any callback.
func (p *Store) Remove(podUID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.removed == nil {
		p.removed = make(map[string]bool)
	}
	p.removed[podUID] = true
}

// Delete removes the pod, then runs every registered callback for it, outside
// the fake's lock so a callback can call back into the fake.
func (p *Store) Delete(podUID string) {
	p.Remove(podUID)
	callbacks := func() []func(string) {
		p.mu.Lock()
		defer p.mu.Unlock()
		return append([]func(string){}, p.callbacks...)
	}()
	for _, fn := range callbacks {
		fn(podUID)
	}
}

// Registered reports how many callbacks OnPodDeleted has registered.
func (p *Store) Registered() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.callbacks)
}
