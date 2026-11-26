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

// A key too long for a cookie leaves no live session behind: Mint and Rotate refuse it and delete
// the session the store made under it, and set no cookie.
func TestAnOversizeKeyLeavesNoSessionBehind(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1000, 0)
	store := newTestStore(now)
	m := logoutManager(t, store, nil, now)
	long := strings.Repeat("k", MaxCookieValueBytes+1)

	store.newID = func() string { return long }
	w := httptest.NewRecorder()
	if _, err := m.Mint(w, reqTo("app.example.com"), "u1", "email", "acme", nil); err == nil {
		t.Fatal("Mint accepted a key too long for a cookie")
	}
	if sc := w.Header().Get("Set-Cookie"); sc != "" {
		t.Fatalf("a refused Mint set a cookie: %q", sc)
	}
	if _, err := store.Get(ctx, long); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a refused Mint left its session live: %v", err)
	}

	store.newID = randomID
	key, err := store.Create(ctx, &Session{Subject: "u1", Partition: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	store.newID = func() string { return long }
	r := reqTo("app.example.com")
	r.AddCookie(&http.Cookie{Name: "sid", Value: key})
	if _, err := m.Rotate(httptest.NewRecorder(), r, nil); err == nil {
		t.Fatal("Rotate accepted a key too long for a cookie")
	}
	if _, err := store.Get(ctx, long); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a refused Rotate left its session live: %v", err)
	}
}
