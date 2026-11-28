/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package tessera

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func logoutManager(t *testing.T, store SessionStore, partition func(context.Context) string, now time.Time) *Manager {
	t.Helper()
	m, err := NewManager(Config{
		Store:                store,
		Domains:              StaticDomainResolver{Roots: []string{"example.com"}},
		CookieName:           "sid",
		PartitionFromContext: partition,
		Now:                  func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func logoutRequest(key string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://app.example.com/logout-all", nil)
	r.AddCookie(&http.Cookie{Name: "sid", Value: key})
	return r
}

// The request resolves to partition pb while the cookie names alice's session in pa: LogoutAll ends
// alice's sessions in pa, the cookie's, and leaves pb's session of the same subject string.
func TestLogoutAllWipesInThePartitionOfTheCookiesSession(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1000, 0)
	store := newTestStore(now)
	mine, _ := store.Create(ctx, &Session{Subject: "alice", Partition: "pa"})
	alsoMine, _ := store.Create(ctx, &Session{Subject: "alice", Partition: "pa"})
	other, _ := store.Create(ctx, &Session{Subject: "alice", Partition: "pb"})
	m := logoutManager(t, store, func(context.Context) string { return "pb" }, now)

	w := httptest.NewRecorder()
	if err := m.LogoutAll(w, logoutRequest(mine), nil); err != nil {
		t.Fatalf("LogoutAll: %v", err)
	}
	for _, key := range []string{mine, alsoMine} {
		if _, err := store.Get(ctx, key); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a session of the cookie's subject in its partition survived LogoutAll: %v", err)
		}
	}
	if _, err := store.Get(ctx, other); err != nil {
		t.Fatalf("another partition's session of the same subject string was deleted: %v", err)
	}
	if !strings.Contains(w.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("the cookie was not cleared: %q", w.Header().Get("Set-Cookie"))
	}
}

// A Manager with no partition resolver signs a caller out everywhere in the partition of the
// session its cookie names.
func TestLogoutAllNeedsNoPartitionResolver(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1000, 0)
	store := newTestStore(now)
	mine, _ := store.Create(ctx, &Session{Subject: "alice", Partition: "pa"})
	m := logoutManager(t, store, nil, now)
	if err := m.LogoutAll(httptest.NewRecorder(), logoutRequest(mine), nil); err != nil {
		t.Fatalf("LogoutAll: %v", err)
	}
	if _, err := store.Get(ctx, mine); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the cookie's session survived LogoutAll: %v", err)
	}
}

type failingWipeStore struct{ SessionStore }

func (failingWipeStore) WipeSubject(context.Context, string, string) (int64, error) {
	return 0, errors.New("store unreachable")
}

// A failed wipe is returned and leaves the cookie and the session in place.
func TestAFailedLogoutAllLeavesTheCookie(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1000, 0)
	inner := newTestStore(now)
	mine, _ := inner.Create(ctx, &Session{Subject: "alice", Partition: "pa"})
	m := logoutManager(t, failingWipeStore{inner}, nil, now)
	w := httptest.NewRecorder()
	if err := m.LogoutAll(w, logoutRequest(mine), nil); err == nil {
		t.Fatal("LogoutAll reported success when the wipe failed")
	}
	if sc := w.Header().Get("Set-Cookie"); sc != "" {
		t.Fatalf("a failed LogoutAll cleared the cookie: %q", sc)
	}
	if _, err := inner.Get(ctx, mine); err != nil {
		t.Fatalf("a failed LogoutAll removed the session: %v", err)
	}
}

// An expired session names no one: LogoutAll refuses and wipes nothing.
func TestLogoutAllRefusesAnExpiredSession(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1000, 0)
	store := newTestStore(now)
	past := now.Add(-time.Minute)
	stale, _ := store.Create(ctx, &Session{Subject: "alice", Partition: "pa", ExpiresAt: &past})
	live, _ := store.Create(ctx, &Session{Subject: "alice", Partition: "pa"})
	m := logoutManager(t, store, nil, now)
	if err := m.LogoutAll(httptest.NewRecorder(), logoutRequest(stale), nil); err == nil {
		t.Fatal("LogoutAll signed a subject out on an expired session")
	}
	if _, err := store.Get(ctx, live); err != nil {
		t.Fatalf("an expired session's LogoutAll removed a live session: %v", err)
	}
}
