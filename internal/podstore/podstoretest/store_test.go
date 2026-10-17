package podstoretest

import (
	"errors"
	"testing"

	. "github.com/onsi/gomega"
)

func TestStore_RemoveHidesThePodWithoutCallbacks(t *testing.T) {
	g := NewWithT(t)
	var store Store
	var called []string
	g.Expect(store.OnPodDeleted(func(uid string) { called = append(called, uid) })).To(Succeed())

	g.Expect(store.HasPod("a")).To(BeTrue())
	store.Remove("a")
	g.Expect(store.HasPod("a")).To(BeFalse())
	g.Expect(store.HasPod("b")).To(BeTrue())
	g.Expect(called).To(BeEmpty())
}

func TestStore_DeleteRemovesThenRunsEveryCallback(t *testing.T) {
	g := NewWithT(t)
	var store Store
	var seen []bool
	for range 2 {
		g.Expect(store.OnPodDeleted(func(uid string) { seen = append(seen, store.HasPod(uid)) })).To(Succeed())
	}
	g.Expect(store.Registered()).To(Equal(2))

	store.Delete("a")
	g.Expect(seen).To(Equal([]bool{false, false}), "each callback runs after the pod left the store")
}

func TestStore_RegisterErrRefusesRegistration(t *testing.T) {
	g := NewWithT(t)
	refused := errors.New("no informer")
	store := Store{RegisterErr: refused}

	g.Expect(store.OnPodDeleted(func(string) {})).To(MatchError(refused))
	g.Expect(store.Registered()).To(BeZero())
	store.Delete("a")
}
