/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package tessera

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type failingDeleteStore struct{ SessionStore }

func (failingDeleteStore) Delete(context.Context, string) error {
	return errors.New("store unreachable")
}

// A delete the store fails is returned, and the cookie stays: the session still validates
// server-side, so the browser is not told it signed out.
func TestLogoutCurrentReportsAFailedDelete(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1000, 0)
	inner := newTestStore(now)
	key, _ := inner.Create(ctx, &Session{Subject: "s", Partition: "p1"})
	m := logoutManager(t, failingDeleteStore{inner}, nil, now)
	w := httptest.NewRecorder()
	if err := m.LogoutCurrent(w, logoutRequest(key), nil); err == nil {
		t.Fatal("LogoutCurrent reported success when the delete failed")
	}
	if sc := w.Header().Get("Set-Cookie"); sc != "" {
		t.Fatalf("a failed LogoutCurrent cleared the cookie: %q", sc)
	}
	if _, err := inner.Get(ctx, key); err != nil {
		t.Fatalf("the session is gone: %v", err)
	}
}

// A cookie whose session the store no longer holds signs out cleanly: nothing is left to end.
func TestLogoutCurrentOfAGoneSessionClearsTheCookie(t *testing.T) {
	now := time.Unix(1000, 0)
	m := logoutManager(t, newTestStore(now), nil, now)
	w := httptest.NewRecorder()
	if err := m.LogoutCurrent(w, logoutRequest("no-such-session"), nil); err != nil {
		t.Fatalf("LogoutCurrent of a gone session = %v", err)
	}
	if !strings.Contains(w.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("the cookie was not cleared: %q", w.Header().Get("Set-Cookie"))
	}
}
