package tessera

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestEveryStoreRefusesAnEmptyPartition drives each store through the operations that write or
// select by partition. Each must answer ErrPartitionRequired, and the session created in a partition
// first must still resolve afterwards.
func TestEveryStoreRefusesAnEmptyPartition(t *testing.T) {
	ctx := context.Background()
	stores := map[string]SessionStore{
		"mem":     newTestStore(time.Unix(1000, 0)),
		"sql":     newSQLStore(t, time.Unix(1000, 0)),
		"caching": NewCachingStore(newTestStore(time.Unix(1000, 0)), time.Hour),
	}
	for name, s := range stores {
		t.Run(name, func(t *testing.T) {
			kept, err := s.Create(ctx, &Session{Subject: "u1", Partition: "acme"})
			if err != nil {
				t.Fatalf("Create in a partition: %v", err)
			}
			if _, err := s.Create(ctx, &Session{Subject: "u1"}); !errors.Is(err, ErrPartitionRequired) {
				t.Fatalf("Create with no partition = %v, want ErrPartitionRequired", err)
			}
			if n, err := s.WipeSubject(ctx, "", "u1"); !errors.Is(err, ErrPartitionRequired) || n != 0 {
				t.Fatalf("WipeSubject with no partition = (%d, %v), want (0, ErrPartitionRequired)", n, err)
			}
			if got, err := s.ListSubjectSessions(ctx, "", "u1"); !errors.Is(err, ErrPartitionRequired) || got != nil {
				t.Fatalf("ListSubjectSessions with no partition = (%d sessions, %v), want (none, ErrPartitionRequired)", len(got), err)
			}
			if local, ok := s.(LocalSessionStore); ok {
				if _, _, err := local.CreateWithID(ctx, &Session{Subject: "u1"}); !errors.Is(err, ErrPartitionRequired) {
					t.Fatalf("CreateWithID with no partition = %v, want ErrPartitionRequired", err)
				}
			}
			if _, err := s.Get(ctx, kept); err != nil {
				t.Fatalf("the session created in a partition must still resolve: %v", err)
			}
		})
	}
}

// TestSQLStore_SchemaRefusesAnEmptyPartition checks the table itself, below the store's own check:
// a row written by anything other than SQLStore still cannot be unpartitioned.
func TestSQLStore_SchemaRefusesAnEmptyPartition(t *testing.T) {
	s := newSQLStore(t, time.Unix(1000, 0))
	if _, err := s.db.Exec(`INSERT INTO tessera_sessions (session_key, subject, partition) VALUES ('k1', 'u1', 'acme')`); err != nil {
		t.Fatalf("a partitioned row must insert: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO tessera_sessions (session_key, subject, partition) VALUES ('k2', 'u1', '')`); err == nil {
		t.Fatal("the table accepted an empty partition")
	}
	if _, err := s.db.Exec(`INSERT INTO tessera_sessions (session_key, subject) VALUES ('k3', 'u1')`); err == nil {
		t.Fatal("the table accepted a row with no partition")
	}
}

// TestCachingStoreRefusesBeforeReachingTheStoreOrClearingTheCache uses a backing store that accepts
// everything, so only the caching layer's own check can produce the refusal.
func TestCachingStoreRefusesBeforeReachingTheStoreOrClearingTheCache(t *testing.T) {
	inner := &countingStore{sess: liveSession("s1")}
	c := NewCachingStore(inner, time.Hour)
	ctx := context.Background()
	_, _ = c.Get(ctx, "s1")

	if _, err := c.WipeSubject(ctx, "", "u1"); !errors.Is(err, ErrPartitionRequired) {
		t.Fatalf("WipeSubject with no partition = %v, want ErrPartitionRequired", err)
	}
	if _, err := c.ListSubjectSessions(ctx, "", "u1"); !errors.Is(err, ErrPartitionRequired) {
		t.Fatalf("ListSubjectSessions with no partition = %v, want ErrPartitionRequired", err)
	}
	if inner.wipeCalls != 0 || inner.listCalls != 0 {
		t.Fatalf("refused calls reached the backing store (wipe %d, list %d)", inner.wipeCalls, inner.listCalls)
	}
	_, _ = c.Get(ctx, "s1")
	if inner.getCalls != 1 {
		t.Fatalf("backing store reached %d times, want 1 — a refused wipe cleared the cache", inner.getCalls)
	}
}

func TestMint_RefusesAnEmptyPartitionAndSetsNoCookie(t *testing.T) {
	m, _ := testManager(t, time.Unix(1000, 0))
	w := httptest.NewRecorder()
	if _, err := m.Mint(w, reqTo("app.example.com"), "u1", "email", "", nil); !errors.Is(err, ErrPartitionRequired) {
		t.Fatalf("Mint with no partition = %v, want ErrPartitionRequired", err)
	}
	if sc := w.Header().Get("Set-Cookie"); sc != "" {
		t.Fatalf("a refused mint set a cookie: %q", sc)
	}
}

// TestManagerWithoutPartitionResolverCannotListOrWipe: a Manager built with no
// PartitionFromContext still mints in the partition it is given, but its list and wipe resolve to
// an empty partition and must fail, leaving the session and its cookie in place.
func TestManagerWithoutPartitionResolverCannotListOrWipe(t *testing.T) {
	now := time.Unix(1000, 0)
	store := newTestStore(now)
	m, err := NewManager(Config{
		Store:      store,
		Domains:    StaticDomainResolver{Roots: []string{"example.com"}},
		CookieName: "orbtr_session",
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	id, err := m.Mint(httptest.NewRecorder(), reqTo("app.example.com"), "u1", "email", "acme", nil)
	if err != nil {
		t.Fatalf("Mint in a partition: %v", err)
	}

	r := reqTo("app.example.com")
	r.AddCookie(&http.Cookie{Name: "orbtr_session", Value: id})
	w := httptest.NewRecorder()
	if err := m.LogoutAll(w, r, nil); !errors.Is(err, ErrPartitionRequired) {
		t.Fatalf("LogoutAll with no partition resolver = %v, want ErrPartitionRequired", err)
	}
	if sc := w.Header().Get("Set-Cookie"); sc != "" {
		t.Fatalf("a failed LogoutAll cleared the cookie: %q", sc)
	}
	if _, err := store.Get(context.Background(), id); err != nil {
		t.Fatalf("a failed LogoutAll removed the session: %v", err)
	}
	if _, err := m.GetSubjectSessions(context.Background(), "u1"); !errors.Is(err, ErrPartitionRequired) {
		t.Fatalf("GetSubjectSessions with no partition resolver = %v, want ErrPartitionRequired", err)
	}
}
