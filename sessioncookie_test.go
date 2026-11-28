/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package tessera

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// SetSessionCookie writes a minted session's key with every attribute a session
// cookie carries and its absolute expiry, refuses an oversized key, and
// ClearSessionCookie expires it with the same attributes.
func TestTheStoreFreeSessionCookieCalls(t *testing.T) {
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	rec := httptest.NewRecorder()
	if err := SetSessionCookie(rec, "orbtr_session", "orbtr.io", "key123", &at); err != nil {
		t.Fatal(err)
	}
	if got, want := rec.Header().Get("Set-Cookie"), "orbtr_session=key123; Path=/; Domain=orbtr.io; Expires=Wed, 02 Jan 2030 03:04:05 GMT; HttpOnly; Secure; SameSite=Lax"; got != want {
		t.Errorf("Set-Cookie = %q, want %q", got, want)
	}
	rec = httptest.NewRecorder()
	if err := SetSessionCookie(rec, "orbtr_session", "orbtr.io", strings.Repeat("k", MaxCookieValueBytes+1), nil); err == nil || rec.Header().Get("Set-Cookie") != "" {
		t.Errorf("an oversized key: err %v, Set-Cookie %q; want a refusal and no cookie", err, rec.Header().Get("Set-Cookie"))
	}
	rec = httptest.NewRecorder()
	ClearSessionCookie(rec, "orbtr_session", "orbtr.io")
	if got, want := rec.Header().Get("Set-Cookie"), "orbtr_session=; Path=/; Domain=orbtr.io; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; HttpOnly; Secure; SameSite=Lax"; got != want {
		t.Errorf("clear Set-Cookie = %q, want %q", got, want)
	}
}
