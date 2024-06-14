package expiring

/*
Copyright 2013 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import "container/list"

// lruCache is an LRU cache. It is not safe for concurrent access.
type lruCache[K comparable, V any] struct {
	// MaxEntries is the maximum number of cache entries before
	// an item is evicted. Zero means no limit.
	MaxEntries int

	ll    *list.List
	cache map[K]*list.Element
}

type entry[K comparable, V any] struct {
	key   K
	value V
}

// newLRU creates a new lruCache.
// If maxEntries is zero, the cache has no limit, and it's assumed
// that eviction is done by the caller.
func newLRU[K comparable, V any](maxEntries int) *lruCache[K, V] {
	return &lruCache[K, V]{
		MaxEntries: maxEntries,
		ll:         list.New(),
		cache:      make(map[K]*list.Element),
	}
}

// Add adds a value to the cache. Returns
// true if an item was removed and the item.
func (c *lruCache[K, V]) Add(key K, value V) *entry[K, V] {
	if c.cache == nil {
		c.cache = make(map[K]*list.Element)
		c.ll = list.New()
	}
	if ee, ok := c.cache[key]; ok {
		c.ll.MoveToFront(ee)
		ee.Value.(*entry[K, V]).value = value
		return nil
	}
	ele := c.ll.PushFront(&entry[K, V]{key, value})
	c.cache[key] = ele
	if c.MaxEntries != 0 && c.ll.Len() > c.MaxEntries {
		return c.RemoveOldest()
	}
	return nil
}

// Get looks up a key's value from the cache.
func (c *lruCache[K, V]) Get(key K) (value interface{}, ok bool) {
	if c.cache == nil {
		return
	}
	if ele, hit := c.cache[key]; hit {
		c.ll.MoveToFront(ele)
		return ele.Value.(*entry[K, V]).value, true
	}
	return
}

// Remove removes the provided key from the cache. Returns
// true if an item was removed and the item.
func (c *lruCache[K, V]) Remove(key K) (*V, bool) {
	if c.cache == nil {
		return nil, false
	}
	if ele, hit := c.cache[key]; hit {
		c.removeElement(ele)
		return &ele.Value.(*entry[K, V]).value, true
	}
	return nil, false
}

// RemoveOldest removes the oldest item from the cache. Returns
// true if an item was removed and the item
func (c *lruCache[K, V]) RemoveOldest() *entry[K, V] {
	if c.cache == nil {
		return nil
	}
	ele := c.ll.Back()
	if ele != nil {
		c.removeElement(ele)
	}
	return ele.Value.(*entry[K, V])
}

func (c *lruCache[K, V]) removeElement(e *list.Element) {
	c.ll.Remove(e)
	kv := e.Value.(*entry[K, V])
	delete(c.cache, kv.key)
}

// Len returns the number of items in the cache.
func (c *lruCache[K, V]) Len() int {
	if c.cache == nil {
		return 0
	}
	return c.ll.Len()
}
