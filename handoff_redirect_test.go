package tessera

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func serveHandoffTo(m *Manager, cfg HandoffConfig, r *http.Request) (*http.Response, bool) {
	reached := false
	rec := httptest.NewRecorder()
	m.HandoffRedemption(cfg)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })).ServeHTTP(rec, r)
	return rec.Result(), reached
}

// A redemption answers 303 to the same path and query with the token and audience taken off,
// carrying the minted cookie, so the token stays in no URL the browser keeps or sends on.
func TestARedeemedHandoffRedirectsWithoutTheToken(t *testing.T) {
	m, _ := testManager(t, handoffNow)
	red := &redeemsTo{h: Handoff{Subject: "usr_1", Partition: "acme"}, ok: true}
	r := httptest.NewRequest(http.MethodGet, "https://app.example.com/inbox?tab=new&handoff=tok-1&aud=app.example.com", nil)
	r.Host = "app.example.com"
	res, reached := serveHandoffTo(m, HandoffConfig{Redeemer: red}, r)
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("status %d, want 303", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/inbox?tab=new" {
		t.Fatalf("Location %q, want /inbox?tab=new", loc)
	}
	if mintedCookie(t, res, "orbtr_session") == nil {
		t.Fatal("the redirect carries no session cookie")
	}
	if reached {
		t.Fatal("the request carrying the token reached the next handler")
	}
}

// A browser that already holds a live session is not signed into the token's account: the token is
// not redeemed, no cookie is set, the session stays, and the token is cleared from the URL.
func TestAHandoffNeverReplacesALiveSession(t *testing.T) {
	m, store := testManager(t, handoffNow)
	key, err := store.Create(context.Background(), &Session{Subject: "usr_9", Partition: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	red := &redeemsTo{h: Handoff{Subject: "usr_attacker", Partition: "acme"}, ok: true}
	r := handoffReq("app.example.com", "handoff=tok-1&aud=app.example.com")
	r.AddCookie(&http.Cookie{Name: "orbtr_session", Value: key})
	res, _ := serveHandoffTo(m, HandoffConfig{Redeemer: red}, r)
	if red.calls != 0 {
		t.Fatalf("redeemer called %d times over a live session", red.calls)
	}
	if c := mintedCookie(t, res, "orbtr_session"); c != nil {
		t.Fatalf("a handoff over a live session set a cookie: %q", c.Value)
	}
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/" {
		t.Fatalf("status %d Location %q, want 303 to /", res.StatusCode, res.Header.Get("Location"))
	}
	if s, err := store.Get(context.Background(), key); err != nil || s.Subject != "usr_9" {
		t.Fatalf("the live session = %+v, %v; want it kept", s, err)
	}
}

// An expired session's cookie does not stop a redemption.
func TestAnExpiredSessionDoesNotStopAHandoff(t *testing.T) {
	m, store := testManager(t, handoffNow)
	past := handoffNow.Add(-time.Hour)
	key, err := store.Create(context.Background(), &Session{Subject: "usr_9", Partition: "acme", ExpiresAt: &past})
	if err != nil {
		t.Fatal(err)
	}
	red := &redeemsTo{h: Handoff{Subject: "usr_1", Partition: "acme"}, ok: true}
	r := handoffReq("app.example.com", "handoff=tok-1&aud=app.example.com")
	r.AddCookie(&http.Cookie{Name: "orbtr_session", Value: key})
	res, _ := serveHandoffTo(m, HandoffConfig{Redeemer: red}, r)
	if mintedCookie(t, res, "orbtr_session") == nil {
		t.Fatal("an expired session's cookie stopped the redemption")
	}
}
