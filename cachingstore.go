/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package tessera

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// ErrNoStore is returned when a CachingStore has no backing store. It fails this
// way rather than reporting "no such session", because the two are opposite
// answers: one is an outage, the other authorises treating the caller as logged
// out, and a misconfigured gateway must not silently log everyone out.
var ErrNoStore = errors.New("tessera: caching store has no backing store")

// DefaultCacheTTL is how long a resolved session is reused when no TTL is given.
// It is short on purpose: the cache exists to spare a gateway one network round
// trip per request, not to hold authorisation state, and every second of TTL is a
// second a revocation made elsewhere has not taken effect here.
const DefaultCacheTTL = 30 * time.Second

// CachingStore wraps a SessionStore with a short read-through cache, for a
// gateway whose backing store is a network away: without it every request
// carrying a cookie pays a full round trip to resolve the same session again.
//
// It caches ONLY successful reads. A miss is never cached, so an unknown or
// forged session id costs a lookup every time rather than earning an entry —
// which also means cache growth is bounded by the number of real sessions, not by
// what a caller can invent.
//
// Every mutation evicts before it returns, so a logout or rotation takes effect
// on the next request rather than at the end of the TTL. WipeSubject clears the
// cache entirely: it removes sessions this layer cannot name, and evicting only
// what it can name would leave the rest validating.
type CachingStore struct {
	inner SessionStore
	ttl   time.Duration

	mu    sync.RWMutex
	cache map[string]cacheEntry

	hits   atomic.Uint64
	misses atomic.Uint64
}

type cacheEntry struct {
	session  *Session
	cachedAt time.Time
}

// NewCachingStore wraps inner. A ttl of zero or less uses DefaultCacheTTL.
func NewCachingStore(inner SessionStore, ttl time.Duration) *CachingStore {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &CachingStore{inner: inner, ttl: ttl, cache: map[string]cacheEntry{}}
}

// Stats reports cache hits and misses, so a gateway can surface whether the TTL
// suits its traffic instead of inferring it from latency. A high miss ratio means
// the TTL is short for the request pattern, or churn is evicting entries.
func (c *CachingStore) Stats() (hits, misses uint64) {
	if c == nil {
		return 0, 0
	}
	return c.hits.Load(), c.misses.Load()
}

// Get returns the session, from cache when a fresh entry exists.
//
// A cached entry is used only while it is BOTH within the cache TTL and still
// unexpired by its own ExpiresAt. The two are independent: a session expiring in
// five seconds must not be served for the cache's thirty, or the cache would
// extend the life of the session it is only supposed to remember.
func (c *CachingStore) Get(ctx context.Context, id string) (*Session, error) {
	if c == nil || c.inner == nil {
		return nil, ErrNoStore
	}
	if s, ok := c.lookup(id); ok {
		c.hits.Add(1)
		return s, nil
	}
	c.misses.Add(1)
	s, err := c.inner.Get(ctx, id)
	if err != nil || s == nil {
		return s, err
	}
	c.store(id, s)
	// Clone on the way out as well as in: a caller that mutates the returned
	// session must not reach the copy the next request will be served from.
	return s.Clone(), nil
}

func (c *CachingStore) lookup(id string) (*Session, bool) {
	c.mu.RLock()
	e, ok := c.cache[id]
	c.mu.RUnlock()
	if !ok || time.Since(e.cachedAt) >= c.ttl {
		return nil, false
	}
	if e.session.ExpiresAt != nil && !time.Now().Before(*e.session.ExpiresAt) {
		return nil, false
	}
	return e.session.Clone(), true
}

func (c *CachingStore) store(id string, s *Session) {
	c.mu.Lock()
	c.cache[id] = cacheEntry{session: s.Clone(), cachedAt: time.Now()}
	c.sweepLocked()
	c.mu.Unlock()
}

// sweepLocked drops entries past the TTL. It runs on insert rather than on a
// timer so the type owns no goroutine a caller would have to stop.
func (c *CachingStore) sweepLocked() {
	if len(c.cache) < 128 {
		return
	}
	now := time.Now()
	for k, e := range c.cache {
		if now.Sub(e.cachedAt) >= c.ttl {
			delete(c.cache, k)
		}
	}
}

func (c *CachingStore) evict(id string) {
	c.mu.Lock()
	delete(c.cache, id)
	c.mu.Unlock()
}

// Create writes through. Nothing is cached for a new id, so no eviction is needed.
func (c *CachingStore) Create(ctx context.Context, s *Session) (string, error) {
	if c == nil || c.inner == nil {
		return "", ErrNoStore
	}
	return c.inner.Create(ctx, s)
}

// Touch writes through and evicts, because the cached copy carries the old
// expiry and would otherwise be served with it until the TTL lapsed.
func (c *CachingStore) Touch(ctx context.Context, id string, newExpiry *time.Time) error {
	if c == nil || c.inner == nil {
		return ErrNoStore
	}
	err := c.inner.Touch(ctx, id, newExpiry)
	c.evict(id)
	return err
}

// Delete writes through and evicts. The eviction happens whether or not the
// delete succeeded: keeping a cached session after a failed delete would serve a
// session the caller has been told is gone, and a needless re-read is the
// cheaper mistake.
func (c *CachingStore) Delete(ctx context.Context, id string) error {
	if c == nil || c.inner == nil {
		return ErrNoStore
	}
	err := c.inner.Delete(ctx, id)
	c.evict(id)
	return err
}

// Rotate writes through and evicts the OLD id, which is the one that must stop
// resolving. The new id has no entry yet and will be read through on first use.
func (c *CachingStore) Rotate(ctx context.Context, id string) (string, error) {
	if c == nil || c.inner == nil {
		return "", ErrNoStore
	}
	newID, err := c.inner.Rotate(ctx, id)
	c.evict(id)
	return newID, err
}

// WipeSubject writes through and clears the WHOLE cache. It removes sessions by
// subject, and this layer indexes by session id alone, so it cannot name which
// entries the wipe covered — dropping only the ones it could name would leave
// the others resolving for a subject who was just signed out everywhere. An
// empty partition is refused here, before the cache is cleared, so a refused
// wipe changes nothing.
func (c *CachingStore) WipeSubject(ctx context.Context, partition, subject string) (int64, error) {
	if c == nil || c.inner == nil {
		return 0, ErrNoStore
	}
	if partition == "" {
		return 0, ErrPartitionRequired
	}
	n, err := c.inner.WipeSubject(ctx, partition, subject)
	c.mu.Lock()
	c.cache = map[string]cacheEntry{}
	c.mu.Unlock()
	return n, err
}

// ListSubjectSessions passes through uncached: it is an enumeration whose staleness
// would be visible to a person reading their own session list.
func (c *CachingStore) ListSubjectSessions(ctx context.Context, partition, subject string) ([]*Session, error) {
	if c == nil || c.inner == nil {
		return nil, ErrNoStore
	}
	if partition == "" {
		return nil, ErrPartitionRequired
	}
	return c.inner.ListSubjectSessions(ctx, partition, subject)
}

// GetByHandle passes through uncached. A handle lookup is the session check of a caller a signed
// token proved, which must see a revocation made elsewhere on its next request; and the cache
// indexes by session key alone.
func (c *CachingStore) GetByHandle(ctx context.Context, handle string) (*Session, error) {
	if c == nil || c.inner == nil {
		return nil, ErrNoStore
	}
	return c.inner.GetByHandle(ctx, handle)
}

// RotateByHandle writes through and evicts the entry of the session handle names, whose key the
// rotation dropped.
func (c *CachingStore) RotateByHandle(ctx context.Context, handle string) (string, error) {
	if c == nil || c.inner == nil {
		return "", ErrNoStore
	}
	newHandle, err := c.inner.RotateByHandle(ctx, handle)
	c.evictHandle(handle)
	return newHandle, err
}

// DeleteByHandle writes through and evicts the entry of the session handle names, whether or not
// the delete succeeded, as Delete does.
func (c *CachingStore) DeleteByHandle(ctx context.Context, handle string) error {
	if c == nil || c.inner == nil {
		return ErrNoStore
	}
	err := c.inner.DeleteByHandle(ctx, handle)
	c.evictHandle(handle)
	return err
}

// evictHandle drops every entry whose session carries handle. The cache is keyed by session key,
// so the entries are scanned; sweepLocked bounds how many there are.
func (c *CachingStore) evictHandle(handle string) {
	if handle == "" {
		return
	}
	c.mu.Lock()
	for k, e := range c.cache {
		if e.session.Handle == handle {
			delete(c.cache, k)
		}
	}
	c.mu.Unlock()
}

// CachingStore is a SessionStore.
var _ SessionStore = (*CachingStore)(nil)
