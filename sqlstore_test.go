package tessera

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// keyedSQLStore opens a store over db under a fixed current digest key.
func keyedSQLStore(t *testing.T, db *sql.DB) *SQLStore {
	t.Helper()
	s, err := OpenSQLStore(db, DigestKeys{Current: digestKey('t')})
	if err != nil {
		t.Fatalf("OpenSQLStore: %v", err)
	}
	return s
}

func newSQLStore(t *testing.T, now time.Time) *SQLStore {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1) // keep the :memory: DB on one connection
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("db.Close: %v", err)
		}
	})
	s := keyedSQLStore(t, db)
	s.now = func() time.Time { return now }
	if err := s.InitSchema(context.Background()); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return s
}

func TestSQLStore_CreateGetRoundTripAllFields(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1000, 0)
	s := newSQLStore(t, now)
	exp := time.Unix(9000, 0)
	in := &Session{
		Subject: "u1", Partition: "acme", AudienceRoot: "app.example.com", Provider: "email",
		ExpiresAt: &exp, Browser: "curl", DeviceType: "cli", Platform: "linux",
		AllowedApps: []string{"a", "b"}, AllowedProviders: []string{"email"}, RequireMFA: true,
	}
	id, err := s.Create(ctx, in)
	if err != nil || id == "" {
		t.Fatalf("Create: %q %v", id, err)
	}
	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "u1" || got.Partition != "acme" || got.AudienceRoot != "app.example.com" ||
		got.Provider != "email" || got.Browser != "curl" || got.DeviceType != "cli" || got.Platform != "linux" ||
		!got.RequireMFA || len(got.AllowedApps) != 2 || len(got.AllowedProviders) != 1 {
		t.Fatalf("round-trip lost a field: %+v", got)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) {
		t.Fatalf("expiry must round-trip; got %v", got.ExpiresAt)
	}
	if !got.IssuedAt.Equal(now) || !got.LastUsedAt.Equal(now) {
		t.Fatalf("issued/last-used stamped at now; got %v %v", got.IssuedAt, got.LastUsedAt)
	}
	if _, err := s.Get(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown key must be ErrNotFound")
	}
}

func TestSQLStore_CreateWithIDNumeric(t *testing.T) {
	ctx := context.Background()
	s := newSQLStore(t, time.Unix(1000, 0))
	key, num, err := s.CreateWithID(ctx, &Session{Subject: "u1", Partition: "acme"})
	if err != nil || key == "" || num == 0 {
		t.Fatalf("CreateWithID must return key + numeric id; %q %d %v", key, num, err)
	}
}

func TestSQLStore_RotateReKeysAndDropsOld(t *testing.T) {
	ctx := context.Background()
	s := newSQLStore(t, time.Unix(1000, 0))
	id, _ := s.Create(ctx, &Session{Subject: "u1", Partition: "acme"})
	newID, err := s.Rotate(ctx, id)
	if err != nil || newID == id || newID == "" {
		t.Fatalf("Rotate: %q %v", newID, err)
	}
	if _, err := s.Get(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatal("old key must be gone after rotate")
	}
	if got, err := s.Get(ctx, newID); err != nil || got.Subject != "u1" {
		t.Fatalf("record must survive under the new key: %+v %v", got, err)
	}
	if _, err := s.Rotate(ctx, "nope"); err == nil {
		t.Fatal("rotating an unknown key must error")
	}
}

func TestSQLStore_WipeAndListSelectOnPartitionAndSubject(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1000, 0)
	s := newSQLStore(t, now)
	if _, err := s.Create(ctx, &Session{Subject: "u1", Partition: "acme"}); err != nil {
		t.Fatalf("s.Create: %v", err)
	}
	if _, err := s.Create(ctx, &Session{Subject: "u1", Partition: "acme"}); err != nil {
		t.Fatalf("s.Create: %v", err)
	}
	if _, err := s.Create(ctx, &Session{Subject: "u1", Partition: "globex"}); err != nil {
		t.Fatalf("s.Create: %v", err)
	} // same subject, different partition
	if got, _ := s.ListSubjectSessions(ctx, "acme", "u1"); len(got) != 2 {
		t.Fatalf("acme/u1 must have 2 live sessions; got %d", len(got))
	}
	n, _ := s.WipeSubject(ctx, "acme", "u1")
	if n != 2 {
		t.Fatalf("WipeSubject removed %d, want 2", n)
	}
	if got, _ := s.ListSubjectSessions(ctx, "globex", "u1"); len(got) != 1 {
		t.Fatal("a different partition is an independent partition")
	}
}

func TestSQLStore_ListExcludesExpiredAndPurge(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(5000, 0)
	s := newSQLStore(t, now)
	past := time.Unix(1000, 0)
	future := time.Unix(9000, 0)
	if _, err := s.Create(ctx, &Session{Subject: "u1", Partition: "acme", ExpiresAt: &past}); err != nil {
		t.Fatalf("s.Create: %v", err)
	} // expired
	if _, err := s.Create(ctx, &Session{Subject: "u1", Partition: "acme", ExpiresAt: &future}); err != nil {
		t.Fatalf("s.Create: %v", err)
	} // live
	if _, err := s.Create(ctx, &Session{Subject: "u1", Partition: "acme"}); err != nil {
		t.Fatalf("s.Create: %v", err)
	} // no expiry → live
	if got, _ := s.ListSubjectSessions(ctx, "acme", "u1"); len(got) != 2 {
		t.Fatalf("ListSubjectSessions must exclude the expired one; got %d", len(got))
	}
	n, _ := s.PurgeExpired(ctx, now)
	if n != 1 {
		t.Fatalf("PurgeExpired removed %d, want 1 (only the past-expiry one)", n)
	}
}

func TestSQLStore_TouchUpdatesLastUsedAndExpiry(t *testing.T) {
	ctx := context.Background()
	s := newSQLStore(t, time.Unix(1000, 0))
	id, _ := s.Create(ctx, &Session{Subject: "u1", Partition: "acme"})
	s.now = func() time.Time { return time.Unix(2000, 0) }
	newExp := time.Unix(9000, 0)
	if err := s.Touch(ctx, id, &newExp); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(ctx, id)
	if !got.LastUsedAt.Equal(time.Unix(2000, 0)) || got.ExpiresAt == nil || !got.ExpiresAt.Equal(newExp) {
		t.Fatalf("Touch must update last-used + expiry: %+v", got)
	}
	if err := s.Touch(ctx, "nope", nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("touching an unknown key must be ErrNotFound")
	}
}
