/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package tessera

import (
	"context"
	"errors"
	"testing"
	"time"
)

// countingStore records how often the backing store was actually reached.
type countingStore struct {
	sess     *Session
	getCalls int
	getErr   error
	delErr   error
	wiped    int64

	wipeCalls int
	listCalls int
}

func (c *countingStore) Create(context.Context, *Session) (string, error) { return "new", nil }
func (c *countingStore) Get(_ context.Context, _ string) (*Session, error) {
	c.getCalls++
	if c.getErr != nil {
		return nil, c.getErr
	}
	return c.sess.Clone(), nil
}
func (c *countingStore) Touch(context.Context, string, *time.Time) error { return nil }
func (c *countingStore) Delete(context.Context, string) error            { return c.delErr }
func (c *countingStore) Rotate(context.Context, string) (string, error)  { return "rotated", nil }
func (c *countingStore) GetByHandle(_ context.Context, _ string) (*Session, error) {
	c.getCalls++
	if c.getErr != nil {
		return nil, c.getErr
	}
	return c.sess.Clone(), nil
}
func (c *countingStore) RotateByHandle(context.Context, string) (string, error) {
	return "sess_rotated", nil
}
func (c *countingStore) DeleteByHandle(context.Context, string) error { return c.delErr }
func (c *countingStore) WipeSubject(context.Context, string, string) (int64, error) {
	c.wipeCalls++
	return c.wiped, nil
}
func (c *countingStore) ListSubjectSessions(context.Context, string, string) ([]*Session, error) {
	c.listCalls++
	return nil, nil
}

func liveSession(id string) *Session {
	exp := time.Now().Add(time.Hour)
	return &Session{ID: id, Subject: "u1", Partition: "p1", ExpiresAt: &exp}
}

func TestCachingStoreServesSecondReadFromCache(t *testing.T) {
	inner := &countingStore{sess: liveSession("s1")}
	c := NewCachingStore(inner, time.Minute)
	ctx := context.Background()
	if _, err := c.Get(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if inner.getCalls != 1 {
		t.Fatalf("backing store reached %d times, want 1 — the second read should be cached", inner.getCalls)
	}
	if h, m := c.Stats(); h != 1 || m != 1 {
		t.Fatalf("stats = %d hits / %d misses, want 1/1", h, m)
	}
}

func TestCachingStoreDoesNotCacheMisses(t *testing.T) {
	inner := &countingStore{getErr: errors.New("no such session")}
	c := NewCachingStore(inner, time.Minute)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := c.Get(ctx, "forged"); err == nil {
			t.Fatal("expected an error for an unknown session")
		}
	}
	if inner.getCalls != 3 {
		t.Fatalf("backing store reached %d times, want 3 — a forged id must not earn a cache entry", inner.getCalls)
	}
}

func TestCachingStoreNeverServesAnExpiredSession(t *testing.T) {
	past := time.Now().Add(-time.Second)
	inner := &countingStore{sess: &Session{ID: "s1", ExpiresAt: &past}}
	c := NewCachingStore(inner, time.Hour) // cache TTL far outlives the session
	ctx := context.Background()
	_, _ = c.Get(ctx, "s1")
	_, _ = c.Get(ctx, "s1")
	if inner.getCalls != 2 {
		t.Fatalf("backing store reached %d times, want 2 — a cache TTL must not extend a session past its own expiry", inner.getCalls)
	}
}

func TestCachingStoreDeleteEvictsSoLogoutTakesEffectAtOnce(t *testing.T) {
	inner := &countingStore{sess: liveSession("s1")}
	c := NewCachingStore(inner, time.Hour)
	ctx := context.Background()
	_, _ = c.Get(ctx, "s1")
	if err := c.Delete(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	_, _ = c.Get(ctx, "s1")
	if inner.getCalls != 2 {
		t.Fatalf("backing store reached %d times, want 2 — a deleted session was still served from cache", inner.getCalls)
	}
}

func TestCachingStoreDeleteEvictsEvenWhenTheDeleteFails(t *testing.T) {
	inner := &countingStore{sess: liveSession("s1"), delErr: errors.New("backend down")}
	c := NewCachingStore(inner, time.Hour)
	ctx := context.Background()
	_, _ = c.Get(ctx, "s1")
	if err := c.Delete(ctx, "s1"); err == nil {
		t.Fatal("expected the delete error to surface")
	}
	_, _ = c.Get(ctx, "s1")
	if inner.getCalls != 2 {
		t.Fatalf("backing store reached %d times, want 2 — a failed delete must still drop the cached copy", inner.getCalls)
	}
}

func TestCachingStoreRotateEvictsTheOldID(t *testing.T) {
	inner := &countingStore{sess: liveSession("s1")}
	c := NewCachingStore(inner, time.Hour)
	ctx := context.Background()
	_, _ = c.Get(ctx, "s1")
	if _, err := c.Rotate(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	_, _ = c.Get(ctx, "s1")
	if inner.getCalls != 2 {
		t.Fatalf("backing store reached %d times, want 2 — the rotated-away id kept resolving", inner.getCalls)
	}
}

func TestCachingStoreTouchUpdatesTheStaleExpiry(t *testing.T) {
	inner := &countingStore{sess: liveSession("s1")}
	c := NewCachingStore(inner, time.Hour)
	ctx := context.Background()
	_, _ = c.Get(ctx, "s1")
	later := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	if err := c.Touch(ctx, "s1", &later); err != nil {
		t.Fatal(err)
	}
	s, err := c.Get(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if inner.getCalls != 1 {
		t.Fatalf("backing store reached %d times, want 1 — a touch emptied the cache", inner.getCalls)
	}
	if s.ExpiresAt == nil || !s.ExpiresAt.Equal(later) {
		t.Fatalf("the cached copy carried the old expiry %v, want %v", s.ExpiresAt, later)
	}
}

func TestCachingStoreWipeSubjectClearsEverythingItCannotName(t *testing.T) {
	inner := &countingStore{sess: liveSession("s1")}
	c := NewCachingStore(inner, time.Hour)
	ctx := context.Background()
	_, _ = c.Get(ctx, "s1")
	_, _ = c.Get(ctx, "s2")
	before := inner.getCalls
	if _, err := c.WipeSubject(ctx, "p1", "u1"); err != nil {
		t.Fatal(err)
	}
	_, _ = c.Get(ctx, "s1")
	_, _ = c.Get(ctx, "s2")
	if inner.getCalls != before+2 {
		t.Fatalf("backing store reached %d more times, want 2 — a wipe left sessions resolving that it could not name", inner.getCalls-before)
	}
}

func TestCachingStoreReturnsCopiesNotTheCachedSession(t *testing.T) {
	inner := &countingStore{sess: liveSession("s1")}
	c := NewCachingStore(inner, time.Hour)
	ctx := context.Background()
	// The FIRST read is a miss and is cloned on the way out regardless, so mutating
	// it proves nothing. Mutate the second — a cache HIT — which is the read that
	// would hand back the stored pointer itself.
	if _, err := c.Get(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	hit, err := c.Get(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	hit.Subject = "attacker"
	third, _ := c.Get(ctx, "s1")
	if third.Subject != "u1" {
		t.Fatalf("later read saw Subject %q — a caller's mutation reached the cached copy", third.Subject)
	}
}

func TestCachingStoreWithNoBackingStoreFailsClosed(t *testing.T) {
	c := NewCachingStore(nil, time.Minute)
	if _, err := c.Get(context.Background(), "s1"); !errors.Is(err, ErrNoStore) {
		t.Fatalf("Get error = %v, want ErrNoStore — reporting no-session would log everyone out", err)
	}
	if err := c.Delete(context.Background(), "s1"); !errors.Is(err, ErrNoStore) {
		t.Fatalf("Delete error = %v, want ErrNoStore", err)
	}
}

func TestCachingStoreExpiresItsOwnEntriesAtTTL(t *testing.T) {
	inner := &countingStore{sess: liveSession("s1")}
	c := NewCachingStore(inner, 20*time.Millisecond)
	ctx := context.Background()
	_, _ = c.Get(ctx, "s1")
	time.Sleep(40 * time.Millisecond)
	_, _ = c.Get(ctx, "s1")
	if inner.getCalls != 2 {
		t.Fatalf("backing store reached %d times, want 2 — the entry outlived its TTL", inner.getCalls)
	}
}

func TestNewCachingStoreDefaultsTTLWhenNotPositive(t *testing.T) {
	if got := NewCachingStore(&countingStore{}, 0).ttl; got != DefaultCacheTTL {
		t.Fatalf("ttl = %v, want %v", got, DefaultCacheTTL)
	}
	if got := NewCachingStore(&countingStore{}, -time.Second).ttl; got != DefaultCacheTTL {
		t.Fatalf("negative ttl = %v, want %v", got, DefaultCacheTTL)
	}
}
