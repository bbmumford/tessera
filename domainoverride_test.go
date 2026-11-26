package tessera

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// An Options.Domain override is held to the bound the derived domain is: within AllowedRoots and
// covering the request host. Mint and Rotate refuse any other, set no cookie and leave no session.
func TestADomainOverrideIsHeldToTheAllowedRoots(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1000, 0)
	store := newTestStore(now)
	m := logoutManager(t, store, nil, now)
	for _, d := range []string{"evil.com", ".com", "other.example.com", "example.org"} {
		w := httptest.NewRecorder()
		id, err := m.Mint(w, reqTo("app.example.com"), "u1", "email", "acme", &Options{Domain: d})
		if err == nil {
			t.Fatalf("Mint set a cookie on domain %q", d)
		}
		if sc := w.Header().Get("Set-Cookie"); sc != "" {
			t.Fatalf("a refused Mint set a cookie: %q", sc)
		}
		if id != "" {
			if _, err := store.Get(ctx, id); !errors.Is(err, ErrNotFound) {
				t.Fatalf("a refused Mint left a session: %v", err)
			}
		}
	}
	for _, d := range []string{"example.com", ".example.com", "app.example.com"} {
		if _, err := m.Mint(httptest.NewRecorder(), reqTo("app.example.com"), "u1", "email", "acme", &Options{Domain: d}); err != nil {
			t.Fatalf("Mint on the allowed domain %q: %v", d, err)
		}
	}
	key, err := store.Create(ctx, &Session{Subject: "u1", Partition: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	r := reqTo("app.example.com")
	r.AddCookie(&http.Cookie{Name: "sid", Value: key})
	if _, err := m.Rotate(httptest.NewRecorder(), r, &Options{Domain: "evil.com"}); err == nil {
		t.Fatal("Rotate set a cookie on a domain outside AllowedRoots")
	}
	if _, err := store.Get(ctx, key); err != nil {
		t.Fatalf("a refused Rotate dropped the session: %v", err)
	}
}
