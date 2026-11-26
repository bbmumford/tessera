package tessera

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// AttachSession touches every session it attaches; the cache serves every request after the first
// from the entry the touch kept.
func TestCachingStoreHitsBehindAttachSession(t *testing.T) {
	now := time.Now()
	cache := NewCachingStore(NewMemStore(), time.Minute)
	m := logoutManager(t, cache, nil, now)
	key, err := cache.Create(context.Background(), &Session{Subject: "s", Partition: "p1"})
	if err != nil {
		t.Fatal(err)
	}
	h := m.AttachSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := FromContext(r); !ok {
			t.Error("no session attached")
		}
	}))
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
		req.AddCookie(&http.Cookie{Name: "sid", Value: key})
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	if hits, misses := cache.Stats(); hits != 4 || misses != 1 {
		t.Fatalf("hits=%d misses=%d over 5 attached requests, want 4 and 1", hits, misses)
	}
}

type failingTouchStore struct{ *countingStore }

func (failingTouchStore) Touch(context.Context, string, *time.Time) error {
	return errors.New("store unreachable")
}

// A touch the backing store refused evicts: the store may no longer hold the session.
func TestCachingStoreRefusedTouchEvicts(t *testing.T) {
	inner := failingTouchStore{&countingStore{sess: liveSession("s1")}}
	c := NewCachingStore(inner, time.Hour)
	ctx := context.Background()
	_, _ = c.Get(ctx, "s1")
	if err := c.Touch(ctx, "s1", nil); err == nil {
		t.Fatal("a refused touch reported success")
	}
	_, _ = c.Get(ctx, "s1")
	if inner.getCalls != 2 {
		t.Fatalf("backing store reached %d times, want 2 — a refused touch kept the entry", inner.getCalls)
	}
}
