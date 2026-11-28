/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package tessera

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// handoffNow is the clock the handoff cases share, so a minted session's expiry
// is arithmetic rather than wall time.
var handoffNow = time.Date(2026, 9, 14, 9, 0, 0, 0, time.UTC)

// redeemsTo is a Redeemer that proves one identity for any token, recording what
// it was asked so a test can assert the audience reaching it.
type redeemsTo struct {
	h             Handoff
	ok            bool
	askedToken    string
	askedAudience string
	calls         int
}

func (r *redeemsTo) Redeem(_ context.Context, token, audience string) (Handoff, bool) {
	r.calls++
	r.askedToken, r.askedAudience = token, audience
	return r.h, r.ok
}

// serveHandoff runs one request through the middleware and reports whether a
// session cookie was set and what the downstream handler saw.
func serveHandoff(t *testing.T, m *Manager, cfg HandoffConfig, r *http.Request) *http.Response {
	t.Helper()
	rec := httptest.NewRecorder()
	m.HandoffRedemption(cfg)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, r)
	return rec.Result()
}

func mintedCookie(t *testing.T, res *http.Response, name string) *http.Cookie {
	t.Helper()
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func handoffReq(host, query string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://"+host+"/?"+query, nil)
	r.Host = host
	return r
}

func TestHandoffRedeemsAndMintsForTheProvedIdentity(t *testing.T) {
	m, store := testManager(t, handoffNow)
	red := &redeemsTo{h: Handoff{Subject: "usr_1", Partition: "acme"}, ok: true}

	res := serveHandoff(t, m, HandoffConfig{Redeemer: red},
		handoffReq("app.example.com", "handoff=tok-1&aud=app.example.com"))

	c := mintedCookie(t, res, "orbtr_session")
	if c == nil {
		t.Fatal("a redeemed handoff must mint a session cookie")
	}
	if red.askedToken != "tok-1" || red.askedAudience != "app.example.com" {
		t.Fatalf("redeemer asked (%q,%q), want the token and audience from the request", red.askedToken, red.askedAudience)
	}
	s, err := store.Get(context.Background(), c.Value)
	if err != nil || s == nil {
		t.Fatalf("minted session must be readable: %v", err)
	}
	if s.Subject != "usr_1" || s.Partition != "acme" {
		t.Fatalf("session = {%q,%q}, want the REDEEMER's identity", s.Subject, s.Partition)
	}
}

// The negative leg. A token holder must not be able to choose whose session the
// handoff becomes, or which partition it lands in — both come from the redeemer,
// so request parameters naming either are ignored entirely.
func TestHandoffRequestCannotChooseSubjectOrPartition(t *testing.T) {
	m, store := testManager(t, handoffNow)
	red := &redeemsTo{h: Handoff{Subject: "usr_1", Partition: "acme"}, ok: true}

	res := serveHandoff(t, m, HandoffConfig{Redeemer: red},
		handoffReq("app.example.com",
			"handoff=tok-1&aud=app.example.com&subject=victim&partition=globex&userID=victim&tenant=globex"))

	c := mintedCookie(t, res, "orbtr_session")
	if c == nil {
		t.Fatal("the handoff must still redeem")
	}
	s, _ := store.Get(context.Background(), c.Value)
	if s == nil {
		t.Fatal("session must exist")
	}
	if s.Subject != "usr_1" {
		t.Fatalf("subject = %q, want usr_1 — the request must not name it", s.Subject)
	}
	if s.Partition != "acme" {
		t.Fatalf("partition = %q, want acme — the request must not name it", s.Partition)
	}
}

// A token minted for one endpoint must not be redeemable at another. This is the
// check the whole middleware exists to make: without it, any endpoint in the
// deployment could redeem any other's token.
func TestHandoffRefusesAnAudienceThatIsNotThisHost(t *testing.T) {
	m, _ := testManager(t, handoffNow)
	red := &redeemsTo{h: Handoff{Subject: "usr_1", Partition: "acme"}, ok: true}

	res := serveHandoff(t, m, HandoffConfig{Redeemer: red},
		handoffReq("devices.example.com", "handoff=tok-1&aud=app.example.com"))

	if c := mintedCookie(t, res, "orbtr_session"); c != nil {
		t.Fatal("a token for another endpoint's audience must not mint a session here")
	}
	if red.calls != 0 {
		t.Fatalf("redeemer called %d times; the audience must be refused BEFORE the token is spent", red.calls)
	}
}

// An audience outside the deployment's configured roots is refused even when it
// equals the request's own Host, because Host is attacker-supplied.
func TestHandoffRefusesAnAudienceOutsideTheAllowedRoots(t *testing.T) {
	m, _ := testManager(t, handoffNow)
	red := &redeemsTo{h: Handoff{Subject: "usr_1", Partition: "acme"}, ok: true}

	res := serveHandoff(t, m, HandoffConfig{Redeemer: red},
		handoffReq("evil.test", "handoff=tok-1&aud=evil.test"))

	if c := mintedCookie(t, res, "orbtr_session"); c != nil {
		t.Fatal("an audience outside the allowed roots must not mint a session")
	}
	if red.calls != 0 {
		t.Fatalf("redeemer called %d times; an unallowed root must be refused before redemption", red.calls)
	}
}

func TestHandoffPassesThroughWhenThereIsNothingToRedeem(t *testing.T) {
	red := &redeemsTo{h: Handoff{Subject: "usr_1", Partition: "acme"}, ok: true}
	cases := []struct {
		name string
		cfg  HandoffConfig
		req  *http.Request
	}{
		{"no redeemer configured", HandoffConfig{}, handoffReq("app.example.com", "handoff=t&aud=app.example.com")},
		{"not a GET", HandoffConfig{Redeemer: red}, func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, "https://app.example.com/?handoff=t&aud=app.example.com", nil)
			r.Host = "app.example.com"
			return r
		}()},
		{"no token", HandoffConfig{Redeemer: red}, handoffReq("app.example.com", "aud=app.example.com")},
		{"no audience", HandoffConfig{Redeemer: red}, handoffReq("app.example.com", "handoff=t")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, _ := testManager(t, handoffNow)
			if got := mintedCookie(t, serveHandoff(t, m, c.cfg, c.req), "orbtr_session"); got != nil {
				t.Fatal("nothing to redeem must mint nothing")
			}
		})
	}
}

// An unredeemable token leaves the request exactly as it arrived. A failed
// redemption must not itself deny a request that was never relying on one.
func TestHandoffUnredeemedRequestContinuesUntouched(t *testing.T) {
	m, _ := testManager(t, handoffNow)
	red := &redeemsTo{ok: false}

	reached := false
	rec := httptest.NewRecorder()
	m.HandoffRedemption(HandoffConfig{Redeemer: red})(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }),
	).ServeHTTP(rec, handoffReq("app.example.com", "handoff=bad&aud=app.example.com"))

	if !reached {
		t.Fatal("an unredeemed handoff must still reach the next handler")
	}
	if c := mintedCookie(t, rec.Result(), "orbtr_session"); c != nil {
		t.Fatal("an unredeemed handoff must mint nothing")
	}
}

// A redeemer that answers ok with an incomplete identity is not a redemption.
// Minting from it would produce a session with no subject or no partition, which
// the store refuses anyway — this refuses it one layer earlier, where the reason
// is legible.
func TestHandoffRefusesAnIncompleteRedemption(t *testing.T) {
	for _, c := range []struct {
		name string
		h    Handoff
	}{
		{"no subject", Handoff{Partition: "acme"}},
		{"no partition", Handoff{Subject: "usr_1"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			m, _ := testManager(t, handoffNow)
			res := serveHandoff(t, m, HandoffConfig{Redeemer: &redeemsTo{h: c.h, ok: true}},
				handoffReq("app.example.com", "handoff=t&aud=app.example.com"))
			if got := mintedCookie(t, res, "orbtr_session"); got != nil {
				t.Fatal("an incomplete redemption must mint nothing")
			}
		})
	}
}

// The audience is compared case-insensitively and a port on Host is ignored, so
// a legitimate redemption is not refused by cosmetics.
func TestHandoffNormalisesAudienceCaseAndHostPort(t *testing.T) {
	m, _ := testManager(t, handoffNow)
	red := &redeemsTo{h: Handoff{Subject: "usr_1", Partition: "acme"}, ok: true}

	r := httptest.NewRequest(http.MethodGet, "https://app.example.com/?handoff=t&aud="+strings.ToUpper("app.example.com"), nil)
	r.Host = "App.Example.com:8443"

	if c := mintedCookie(t, serveHandoff(t, m, HandoffConfig{Redeemer: red}, r), "orbtr_session"); c == nil {
		t.Fatal("case and port differences must not refuse a legitimate redemption")
	}
}
