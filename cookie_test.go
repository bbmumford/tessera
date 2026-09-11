package tessera

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testManager(t *testing.T, now time.Time) (*Manager, *MemStore) {
	t.Helper()
	store := newTestStore(now)
	m, err := NewManager(Config{
		Store:                store,
		Domains:              StaticDomainResolver{Roots: []string{"example.com"}},
		CookieName:           "orbtr_session",
		PartitionFromContext: func(context.Context) string { return "acme" },
		Now:                  func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m, store
}

func reqTo(host string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
	r.Host = host
	return r
}

func TestNewManager_RequiredDeps(t *testing.T) {
	store := NewMemStore()
	dr := StaticDomainResolver{Roots: []string{"example.com"}}
	if _, err := NewManager(Config{Domains: dr, CookieName: "c"}); err == nil {
		t.Fatal("missing Store must error")
	}
	if _, err := NewManager(Config{Store: store, CookieName: "c"}); err == nil {
		t.Fatal("missing Domains must error")
	}
	if _, err := NewManager(Config{Store: store, Domains: dr}); err == nil {
		t.Fatal("missing CookieName must error")
	}
}

func TestStaticDomainResolver_LongestMatchAndReject(t *testing.T) {
	r := StaticDomainResolver{Roots: []string{"example.com", "sub.example.com"}}
	got, err := r.RootDomainForHost("a.sub.example.com")
	if err != nil || got != "sub.example.com" {
		t.Fatalf("longest root must win: got %q %v", got, err)
	}
	got, err = r.RootDomainForHost("app.example.com")
	if err != nil || got != "example.com" {
		t.Fatalf("subdomain must map to root: got %q %v", got, err)
	}
	if _, err := r.RootDomainForHost("evil.test"); err == nil {
		t.Fatal("host outside configured roots must error")
	}
}

func TestMint_SetsScopedHardenedCookie(t *testing.T) {
	m, _ := testManager(t, time.Unix(1000, 0))
	w := httptest.NewRecorder()
	id, err := m.Mint(w, reqTo("app.example.com"), "u1", "email", "acme", nil)
	if err != nil || id == "" {
		t.Fatalf("Mint: %q %v", id, err)
	}
	set := w.Header().Get("Set-Cookie")
	// deriveDomain scopes to ".example.com" for subdomain SSO; the stdlib strips the legacy leading
	// dot on write (an RFC 6265 Domain already covers subdomains), so the wire form is "example.com".
	for _, want := range []string{"orbtr_session=" + id, "Domain=example.com", "HttpOnly", "Secure", "SameSite=Lax", "Max-Age="} {
		if !strings.Contains(set, want) {
			t.Fatalf("Set-Cookie %q missing %q", set, want)
		}
	}
}

func TestMint_RejectsHostOutsideAllowedRoots(t *testing.T) {
	m, _ := testManager(t, time.Unix(1000, 0))
	w := httptest.NewRecorder()
	if _, err := m.Mint(w, reqTo("app.evil.test"), "u1", "email", "acme", nil); err == nil {
		t.Fatal("Mint on a host outside AllowedRoots must error and set no cookie")
	}
	if w.Header().Get("Set-Cookie") != "" {
		t.Fatal("no cookie may be written when domain derivation fails")
	}
}

func TestRotate_ReKeysCookieAndDropsOld(t *testing.T) {
	m, store := testManager(t, time.Unix(1000, 0))
	w1 := httptest.NewRecorder()
	id, _ := m.Mint(w1, reqTo("app.example.com"), "u1", "email", "acme", nil)

	r := reqTo("app.example.com")
	r.AddCookie(&http.Cookie{Name: "orbtr_session", Value: id})
	w2 := httptest.NewRecorder()
	newID, err := m.Rotate(w2, r, nil)
	if err != nil || newID == id || newID == "" {
		t.Fatalf("Rotate: %q %v", newID, err)
	}
	if !strings.Contains(w2.Header().Get("Set-Cookie"), "orbtr_session="+newID) {
		t.Fatal("Rotate must re-issue the cookie with the new id")
	}
	if _, err := store.Get(context.Background(), id); err == nil {
		t.Fatal("old session id must be gone after rotate")
	}
}

func TestLogoutCurrent_DeletesAndClears(t *testing.T) {
	m, store := testManager(t, time.Unix(1000, 0))
	w1 := httptest.NewRecorder()
	id, _ := m.Mint(w1, reqTo("app.example.com"), "u1", "email", "acme", nil)

	r := reqTo("app.example.com")
	r.AddCookie(&http.Cookie{Name: "orbtr_session", Value: id})
	w2 := httptest.NewRecorder()
	if err := m.LogoutCurrent(w2, r, nil); err != nil {
		t.Fatalf("LogoutCurrent: %v", err)
	}
	if _, err := store.Get(context.Background(), id); err == nil {
		t.Fatal("server-side session must be deleted")
	}
	if !strings.Contains(w2.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("cookie must be cleared (Max-Age=0): %q", w2.Header().Get("Set-Cookie"))
	}
}

func TestLogoutAll_WipesTheSubjectInItsPartition(t *testing.T) {
	m, store := testManager(t, time.Unix(1000, 0))
	// two sessions for acme/u1, one for a different partition
	w := httptest.NewRecorder()
	id, _ := m.Mint(w, reqTo("app.example.com"), "u1", "email", "acme", nil)
	m.Mint(httptest.NewRecorder(), reqTo("app.example.com"), "u1", "email", "acme", nil)
	store.Create(context.Background(), &Session{Subject: "u1", Partition: "globex"})

	r := reqTo("app.example.com")
	r.AddCookie(&http.Cookie{Name: "orbtr_session", Value: id})
	if err := m.LogoutAll(httptest.NewRecorder(), r, nil); err != nil {
		t.Fatalf("LogoutAll: %v", err)
	}
	if got, _ := store.ListSubjectSessions(context.Background(), "acme", "u1"); len(got) != 0 {
		t.Fatalf("acme/u1 sessions must be wiped; %d remain", len(got))
	}
	if got, _ := store.ListSubjectSessions(context.Background(), "globex", "u1"); len(got) != 1 {
		t.Fatal("a different partition is an independent partition and must survive LogoutAll")
	}
}

func TestAttachSession_AttachesLiveAndSoftTouches(t *testing.T) {
	now := time.Unix(1000, 0)
	m, store := testManager(t, now)
	id, _ := store.Create(context.Background(), &Session{Subject: "u1", Partition: "acme"})

	// advance both clocks so the soft-touch is observable
	later := time.Unix(2000, 0)
	store.now = fixedNow(later)
	m.now = func() time.Time { return later }

	r := reqTo("app.example.com")
	r.AddCookie(&http.Cookie{Name: "orbtr_session", Value: id})
	var seen *Session
	m.AttachSession(http.HandlerFunc(func(_ http.ResponseWriter, rr *http.Request) {
		s, ok := FromContext(rr)
		if ok {
			seen = s
		}
	})).ServeHTTP(httptest.NewRecorder(), r)

	if seen == nil || seen.Subject != "u1" {
		t.Fatal("live session must be attached to context")
	}
	got, _ := store.Get(context.Background(), id)
	if !got.LastUsedAt.Equal(later) {
		t.Fatalf("AttachSession must soft-touch LastUsedAt to now; got %v", got.LastUsedAt)
	}
}

func TestAttachSession_SkipsExpiredAndMissing(t *testing.T) {
	now := time.Unix(5000, 0)
	m, store := testManager(t, now)
	past := time.Unix(1000, 0)
	id, _ := store.Create(context.Background(), &Session{Subject: "u1", Partition: "acme", ExpiresAt: &past})

	run := func(r *http.Request) bool {
		attached := false
		m.AttachSession(http.HandlerFunc(func(_ http.ResponseWriter, rr *http.Request) {
			_, attached = FromContext(rr)
		})).ServeHTTP(httptest.NewRecorder(), r)
		return attached
	}

	rExpired := reqTo("app.example.com")
	rExpired.AddCookie(&http.Cookie{Name: "orbtr_session", Value: id})
	if run(rExpired) {
		t.Fatal("expired session must not attach")
	}
	if run(reqTo("app.example.com")) {
		t.Fatal("missing cookie must not attach")
	}
}

func TestProbeSession_LiveExpiredMissing(t *testing.T) {
	now := time.Unix(5000, 0)
	m, store := testManager(t, now)
	future := time.Unix(9000, 0)
	past := time.Unix(1000, 0)
	live, _ := store.Create(context.Background(), &Session{Subject: "u1", Partition: "acme", ExpiresAt: &future})
	dead, _ := store.Create(context.Background(), &Session{Subject: "u2", Partition: "acme", ExpiresAt: &past})

	if ok, _ := m.ProbeSession(context.Background(), live); !ok {
		t.Fatal("live session must probe true")
	}
	if ok, _ := m.ProbeSession(context.Background(), dead); ok {
		t.Fatal("expired session must probe false")
	}
	if ok, _ := m.ProbeSession(context.Background(), "nope"); ok {
		t.Fatal("missing session must probe false")
	}
}

func TestCreateAppSession_NeedsLocalStore(t *testing.T) {
	m, _ := testManager(t, time.Unix(1000, 0))
	key, num, err := m.CreateAppSession(context.Background(), "u1", "email", "curl", "mobile", "iOS", "acme", 0)
	if err != nil || key == "" || num == 0 {
		t.Fatalf("CreateAppSession over a LocalSessionStore must return key+numeric id: %q %d %v", key, num, err)
	}
}

func TestEnforceCookieSize(t *testing.T) {
	if err := enforceCookieSize(strings.Repeat("x", MaxCookieValueBytes)); err != nil {
		t.Fatal("value at the limit must pass")
	}
	if err := enforceCookieSize(strings.Repeat("x", MaxCookieValueBytes+1)); err == nil {
		t.Fatal("value over the limit must fail")
	}
}
