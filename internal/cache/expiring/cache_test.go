package expiring

import (
	"bytes"
	"fmt"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"
)

func wantKeys(t *testing.T, tc *Cache[string, any], want []string, dontWant []string) {
	t.Helper()

	for _, k := range want {
		_, ok := tc.Get(k)
		if !ok {
			t.Errorf("key not found: %q", k)
		}
	}

	for _, k := range dontWant {
		v, ok := tc.Get(k)
		if ok {
			t.Errorf("key %q found with value %v", k, v)
		}
		if v != nil {
			t.Error("v is not nil:", v)
		}
	}
}

func TestCache(t *testing.T) {
	tc := NewLru[string, any](100, DefaultExpiration, 0)

	a, found := tc.Get("a")
	if found || a != nil {
		t.Error("Getting A found value that shouldn't exist:", a)
	}

	b, found := tc.Get("b")
	if found || b != nil {
		t.Error("Getting B found value that shouldn't exist:", b)
	}

	c, found := tc.Get("c")
	if found || c != nil {
		t.Error("Getting C found value that shouldn't exist:", c)
	}

	tc.Set("a", 1)
	tc.Set("b", "b")
	tc.Set("c", 3.5)

	v, found := tc.Get("a")
	if !found {
		t.Error("a was not found while getting a2")
	}
	if v == nil {
		t.Error("v for a is nil")
	} else if a2 := v.(int); a2+2 != 3 {
		t.Error("a2 (which should be 1) plus 2 does not equal 3; value:", a2)
	}

	v, found = tc.Get("b")
	if !found {
		t.Error("b was not found while getting b2")
	}
	if v == nil {
		t.Error("v for b is nil")
	} else if b2 := v.(string); b2+"B" != "bB" {
		t.Error("b2 (which should be b) plus B does not equal bB; value:", b2)
	}

	v, found = tc.Get("c")
	if !found {
		t.Error("c was not found while getting c2")
	}
	if v == nil {
		t.Error("v for c is nil")
	} else if c2 := v.(float64); c2+1.2 != 4.7 {
		t.Error("c2 (which should be 3.5) plus 1.2 does not equal 4.7; value:", c2)
	}
}

func TestCacheTimes(t *testing.T) {
	var found bool

	tc := NewLru[string, int](100, 50*time.Millisecond, 1*time.Millisecond)
	tc.Set("a", 1)
	tc.SetWithExpire("b", 2, NoExpiration)
	tc.SetWithExpire("c", 3, 20*time.Millisecond)
	tc.SetWithExpire("d", 4, 70*time.Millisecond)

	<-time.After(25 * time.Millisecond)
	_, found = tc.Get("c")
	if found {
		t.Error("Found c when it should have been automatically deleted")
	}

	<-time.After(30 * time.Millisecond)
	_, found = tc.Get("a")
	if found {
		t.Error("Found a when it should have been automatically deleted")
	}

	_, found = tc.Get("b")
	if !found {
		t.Error("Did not find b even though it was set to never expire")
	}

	_, found = tc.Get("d")
	if !found {
		t.Error("Did not find d even though it was set to expire later than the default")
	}

	<-time.After(20 * time.Millisecond)
	_, found = tc.Get("d")
	if found {
		t.Error("Found d when it should have been automatically deleted (later than the default)")
	}
}

func TestStorePointerToStruct(t *testing.T) {
	type TestStruct struct {
		Num      int
		Children []*TestStruct
	}

	tc := NewLru[string, any](100, DefaultExpiration, 0)
	tc.Set("foo", &TestStruct{Num: 1})
	v, found := tc.Get("foo")
	if !found {
		t.Fatal("*TestStruct was not found for foo")
	}
	foo := v.(*TestStruct)
	foo.Num++

	y, found := tc.Get("foo")
	if !found {
		t.Fatal("*TestStruct was not found for foo (second time)")
	}
	bar := y.(*TestStruct)
	if bar.Num != 2 {
		t.Fatal("TestStruct.Num is not 2")
	}
}

func TestOnEvicted(t *testing.T) {
	tc := NewLru[string, int](100, DefaultExpiration, 0)
	tc.Set("foo", 3)
	if tc.onEvicted != nil {
		t.Fatal("tc.onEvicted is not nil")
	}
	works := false
	tc.OnEvicted(func(k string, v int) {
		if k == "foo" && v == 3 {
			works = true
		}
		tc.Set("bar", 4)
	})
	tc.Delete("foo")
	v, _ := tc.Get("bar")
	if !works {
		t.Error("works bool not true")
	}
	if v != 4 {
		t.Error("bar was not 4")
	}
}

func TestTouch(t *testing.T) {
	tc := NewLru[string, string](100, DefaultExpiration, 0)

	tc.SetWithExpire("a", "b", 5*time.Second)
	_, first, _ := tc.GetWithExpire("a")
	v, ok := tc.TouchWithExpire("a", 10*time.Second)
	if !ok {
		t.Fatal("!ok")
	}
	_, second, _ := tc.GetWithExpire("a")
	if v != "b" {
		t.Error("wrong value")
	}
	if first.Equal(second) {
		t.Errorf("not updated\nfirst:  %s\nsecond: %s", first, second)
	}
}

func TestGetWithExpire(t *testing.T) {
	tc := NewLru[string, any](100, DefaultExpiration, 0)

	a, expiration, ok := tc.GetWithExpire("a")
	if ok || a != nil || !expiration.IsZero() {
		t.Error("Getting A found value that shouldn't exist:", a)
	}

	b, expiration, ok := tc.GetWithExpire("b")
	if ok || b != nil || !expiration.IsZero() {
		t.Error("Getting B found value that shouldn't exist:", b)
	}

	c, expiration, ok := tc.GetWithExpire("c")
	if ok || c != nil || !expiration.IsZero() {
		t.Error("Getting C found value that shouldn't exist:", c)
	}

	tc.Set("a", 1)
	tc.Set("b", "b")
	tc.Set("c", 3.5)
	tc.SetWithExpire("d", 1, NoExpiration)
	tc.SetWithExpire("e", 1, 50*time.Millisecond)

	v, expiration, ok := tc.GetWithExpire("a")
	if !ok {
		t.Error("a was not found while getting a2")
	}
	if v == nil {
		t.Error("v for a is nil")
	} else if a2 := v.(int); a2+2 != 3 {
		t.Error("a2 (which should be 1) plus 2 does not equal 3; value:", a2)
	}
	if !expiration.IsZero() {
		t.Error("expiration for a is not a zeroed time")
	}

	v, expiration, ok = tc.GetWithExpire("b")
	if !ok {
		t.Error("b was not found while getting b2")
	}
	if v == nil {
		t.Error("v for b is nil")
	} else if b2 := v.(string); b2+"B" != "bB" {
		t.Error("b2 (which should be b) plus B does not equal bB; value:", b2)
	}
	if !expiration.IsZero() {
		t.Error("expiration for b is not a zeroed time")
	}

	v, expiration, ok = tc.GetWithExpire("c")
	if !ok {
		t.Error("c was not found while getting c2")
	}
	if v == nil {
		t.Error("v for c is nil")
	} else if c2 := v.(float64); c2+1.2 != 4.7 {
		t.Error("c2 (which should be 3.5) plus 1.2 does not equal 4.7; value:", c2)
	}
	if !expiration.IsZero() {
		t.Error("expiration for c is not a zeroed time")
	}

	v, expiration, ok = tc.GetWithExpire("d")
	if !ok {
		t.Error("d was not found while getting d2")
	}
	if v == nil {
		t.Error("v for d is nil")
	} else if d2 := v.(int); d2+2 != 3 {
		t.Error("d (which should be 1) plus 2 does not equal 3; value:", d2)
	}
	if !expiration.IsZero() {
		t.Error("expiration for d is not a zeroed time")
	}

	v, expiration, ok = tc.GetWithExpire("e")
	if !ok {
		t.Error("e was not found while getting e2")
	}
	if v == nil {
		t.Error("v for e is nil")
	} else if e2 := v.(int); e2+2 != 3 {
		t.Error("e (which should be 1) plus 2 does not equal 3; value:", e2)
	}
	if expiration.UnixNano() != tc.items["e"].Expiration {
		t.Error("expiration for e is not the correct time")
	}
	if expiration.UnixNano() < time.Now().UnixNano() {
		t.Error("expiration for e is in the past")
	}
}

func TestGetStale(t *testing.T) {
	tc := NewLru[string, any](100, 5*time.Millisecond, 0)

	tc.Set("x", "y")

	v, exp, ok := tc.GetStale("x")
	if !ok {
		t.Errorf("Did not get expired item: %v", v)
	}
	if exp {
		t.Error("exp set")
	}
	if v.(string) != "y" {
		t.Errorf("value wrong: %v", v)
	}

	time.Sleep(10 * time.Millisecond)

	v, ok = tc.Get("x")
	if ok || v != nil {
		t.Fatalf("Get retrieved expired item: %v", v)
	}

	v, exp, ok = tc.GetStale("x")
	if !ok {
		t.Errorf("Did not get expired item: %v", v)
	}
	if !exp {
		t.Error("exp not set")
	}
	if v.(string) != "y" {
		t.Errorf("value wrong: %v", v)
	}
}

func TestAdd(t *testing.T) {
	tc := NewLru[string, any](100, DefaultExpiration, 0)
	err := tc.Add("foo", "bar")
	if err != nil {
		t.Error("Couldn't add foo even though it shouldn't exist")
	}
	err = tc.Add("foo", "baz")
	if err == nil {
		t.Error("Successfully added another foo when it should have returned an error")
	}
}

func TestReplace(t *testing.T) {
	tc := NewLru[string, string](100, DefaultExpiration, 0)
	err := tc.Replace("foo", "bar")
	if err == nil {
		t.Error("Replaced foo when it shouldn't exist")
	}
	tc.Set("foo", "bar")
	err = tc.Replace("foo", "bar")
	if err != nil {
		t.Error("Couldn't replace existing key foo")
	}
}

func TestDelete(t *testing.T) {
	tc := NewLru[string, any](100, DefaultExpiration, 0)

	tc.Set("foo", "bar")
	tc.Delete("foo")
	wantKeys(t, tc, []string{}, []string{"foo"})
}

type onEvictTest struct {
	sync.Mutex
	items []struct {
		k string
		v interface{}
	}
}

func (o *onEvictTest) add(k string, v interface{}) {
	if k == "race" {
		return
	}
	o.Lock()
	o.items = append(o.items, struct {
		k string
		v interface{}
	}{k, v})
	o.Unlock()
}

func TestPop(t *testing.T) {
	tc := NewLru[string, any](100, DefaultExpiration, 0)

	var onEvict onEvictTest
	tc.OnEvicted(onEvict.add)

	tc.Set("foo", "val")

	v, ok := tc.Pop("foo")
	wantKeys(t, tc, []string{}, []string{"foo"})
	if !ok {
		t.Error("ok is false")
	}
	if v.(string) != "val" {
		t.Errorf("wrong value: %v", v)
	}

	v, ok = tc.Pop("nonexistent")
	if ok {
		t.Error("ok is true")
	}
	if v != nil {
		t.Errorf("v is not nil")
	}

	if fmt.Sprintf("%v", onEvict.items) != `[{foo val}]` {
		t.Errorf("onEvicted: %v", onEvict.items)
	}
}

func TestModify(t *testing.T) {
	tc := NewLru[string, []string](100, DefaultExpiration, 0)

	tc.Set("k", []string{"x"})
	v, ok := tc.Modify("k", func(v []string) []string {
		return append(v, "y")
	})
	if !ok {
		t.Error("ok is false")
	}
	if fmt.Sprintf("%v", v) != `[x y]` {
		t.Errorf("value wrong: %v", v)
	}

	_, ok = tc.Modify("doesntexist", func(v []string) []string {
		t.Error("should not be called")
		return nil
	})
	if ok {
		t.Error("ok is true")
	}

	v, ok = tc.Modify("k", func(v []string) []string { return nil })
	if !ok {
		t.Error("ok not set")
	}
	if v != nil {
		t.Error("v not nil")
	}
}

func TestModifyIncrement(t *testing.T) {
	tc := NewLru[string, int](100, DefaultExpiration, 0)
	tc.Set("one", 1)

	have, _ := tc.Modify("one", func(v int) int { return v + 2 })
	if have != 3 {
		t.Fatal()
	}

	have, _ = tc.Modify("one", func(v int) int { return v - 1 })
	if have != 2 {
		t.Fatal()
	}
}

func TestItems(t *testing.T) {
	tc := NewLru[string, any](100, DefaultExpiration, 1*time.Millisecond)
	tc.Set("foo", "1")
	tc.Set("bar", "2")
	tc.Set("baz", "3")
	tc.SetWithExpire("exp", "4", 1)
	time.Sleep(10 * time.Millisecond)
	if n := tc.ItemCount(); n != 3 {
		t.Errorf("Item count is not 3 but %d", n)
	}

	keys := tc.Keys()
	sort.Strings(keys)
	if fmt.Sprintf("%v", keys) != "[bar baz foo]" {
		t.Errorf("%v", keys)
	}

	want := map[string]Item[any]{
		"foo": {Object: "1"},
		"bar": {Object: "2"},
		"baz": {Object: "3"},
	}
	if !reflect.DeepEqual(tc.Items(), want) {
		t.Errorf("%v", tc.Items())
	}
}

func TestLruIntegration(t *testing.T) {
	tc := NewLru[string, any](10, DefaultExpiration, 1*time.Millisecond)
	for i := 0; i < 50; i++ {
		tc.Set(strconv.Itoa(i), i)
	}
	tc.Set("foo", "1")
	tc.Set("bar", "2")
	tc.Set("baz", "3")
	tc.SetWithExpire("exp", "4", 1)
	time.Sleep(10 * time.Millisecond)
	if n := tc.ItemCount(); n != 9 {
		t.Errorf("Item count is not 3 but %d", n)
	}

	keys := tc.Keys()
	sort.Strings(keys)
	if fmt.Sprintf("%v", keys) != "[44 45 46 47 48 49 bar baz foo]" {
		t.Errorf("%v", keys)
	}

	for i := 0; i < 50; i++ {
		tc.Delete(strconv.Itoa(i))
	}
	if len(tc.lru.cache) != 3 {
		t.Errorf("Expected internal lru cache to just have 3 items got %#v", tc.lru.cache)
	}

	if tc.lru.ll.Len() != 3 {
		t.Errorf("Expected internal lru linked list to just have 3 items got %d", tc.lru.ll.Len())
	}

	fmt.Printf("%#v\n size: %d \n", tc.lru.cache, len(tc.lru.cache))

	want := map[string]Item[any]{
		"foo": {Object: "1"},
		"bar": {Object: "2"},
		"baz": {Object: "3"},
	}
	if !reflect.DeepEqual(tc.Items(), want) {
		t.Errorf("%v", tc.Items())
	}
}

func TestReset(t *testing.T) {
	tc := NewLru[string, any](100, DefaultExpiration, 0)
	tc.Set("foo", "bar")
	tc.Set("baz", "yes")
	tc.Reset()
	v, found := tc.Get("foo")
	if found {
		t.Error("foo was found, but it should have been deleted")
	}
	if v != nil {
		t.Error("v is not nil:", v)
	}
	v, found = tc.Get("baz")
	if found {
		t.Error("baz was found, but it should have been deleted")
	}
	if v != nil {
		t.Error("v is not nil:", v)
	}
}

func TestDeleteAll(t *testing.T) {
	tc := NewLru[string, any](100, DefaultExpiration, 0)
	tc.Set("foo", 3)
	if tc.onEvicted != nil {
		t.Fatal("tc.onEvicted is not nil")
	}
	works := false
	tc.OnEvicted(func(k string, v interface{}) {
		if k == "foo" && v.(int) == 3 {
			works = true
		}
	})
	tc.DeleteAll()
	if !works {
		t.Error("works bool not true")
	}
}

func TestDeleteFunc(t *testing.T) {
	tc := NewLru[string, any](100, NoExpiration, 0)
	tc.Set("foo", 3)
	tc.Set("bar", 4)

	works := false
	tc.OnEvicted(func(k string, v interface{}) {
		if k == "foo" && v.(int) == 3 {
			works = true
		}
	})

	tc.DeleteFunc(func(k string, v Item[any]) (bool, bool) {
		return k == "foo" && v.Object.(int) == 3, false
	})

	if !works {
		t.Error("onEvicted isn't called for 'foo'")
	}

	_, found := tc.Get("bar")
	if !found {
		t.Error("bar shouldn't be removed from the cache")
	}

	tc.Set("boo", 5)

	count := tc.ItemCount()

	// Only one item should be deleted here
	tc.DeleteFunc(func(k string, v Item[any]) (bool, bool) {
		return true, true
	})

	if tc.ItemCount() != count-1 {
		t.Errorf("unexpected number of items in the cache. item count expected %d, found %d", count-1, tc.ItemCount())
	}
}

// Make sure the janitor is stopped after GC frees up.
func TestFinal(t *testing.T) {
	has := func() bool {
		s := make([]byte, 8192)
		runtime.Stack(s, true)
		return bytes.Contains(s, []byte("eks/eks-pod-identity-agent/internal/cache/expiring.(*janitor[...]).run"))
	}

	tc := NewLru[string, any](100, 10*time.Millisecond, 10*time.Millisecond)
	tc.Set("asd", "zxc")

	if !has() {
		t.Fatal("no janitor goroutine before GC")
	}
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	if has() {
		t.Fatal("still have janitor goroutine after GC")
	}
}

func TestRename(t *testing.T) {
	tc := NewLru[string, int](100, NoExpiration, 0)
	tc.Set("foo", 3)
	tc.SetWithExpire("bar", 4, 1)

	if tc.Rename("nonex", "asd") {
		t.Error()
	}
	if tc.Rename("bar", "expired") {
		t.Error()
	}
	if v, _, ok := tc.GetStale("bar"); !ok || v != 4 {
		t.Error()
	}

	if !tc.Rename("foo", "RENAME") {
		t.Error()
	}

	if v, ok := tc.Get("RENAME"); !ok || v != 3 {
		t.Error()
	}

	if _, ok := tc.Get("foo"); ok {
		t.Error()
	}
}
