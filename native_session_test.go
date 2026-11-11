package tessera

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// A session minted by CreateNativeAppSession is stored and read back with
// Native set and SecondFactor unset, sessions minted by CreateAppSession and
// CreateSecondFactorAppSession without Native, and a rotation keeps the value
// the row was created with.
func TestNativeIsStoredAtCreationAndKeptByRotate(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1000, 0)
	store := newSQLStore(t, now)
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

	native, _, err := m.CreateNativeAppSession(ctx, "u1", "email", "", "", "", "acme", 0)
	if err != nil {
		t.Fatalf("CreateNativeAppSession: %v", err)
	}
	plain, _, err := m.CreateAppSession(ctx, "u1", "email", "", "", "", "acme", 0)
	if err != nil {
		t.Fatalf("CreateAppSession: %v", err)
	}
	factored, _, err := m.CreateSecondFactorAppSession(ctx, "u1", "email", "", "", "", "acme", 0)
	if err != nil {
		t.Fatalf("CreateSecondFactorAppSession: %v", err)
	}
	for id, want := range map[string][2]bool{native: {true, false}, plain: {false, false}, factored: {false, true}} {
		got, err := store.Get(ctx, id)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Native != want[0] || got.SecondFactor != want[1] {
			t.Fatalf("Native, SecondFactor = %v, %v; want %v, %v", got.Native, got.SecondFactor, want[0], want[1])
		}
	}

	rotated, err := store.Rotate(ctx, native)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	got, err := store.Get(ctx, rotated)
	if err != nil || !got.Native {
		t.Fatalf("after Rotate: Native = %v, %v; want true", got != nil && got.Native, err)
	}
}

// InitSchema over a tessera_sessions table holding second_factor but not
// native adds native, a row already there reads as not native, and a second
// InitSchema leaves the table as it is.
func TestInitSchemaAddsNativeToAnOlderTable(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if _, err := db.ExecContext(ctx, `CREATE TABLE tessera_sessions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_key TEXT UNIQUE NOT NULL,
		subject TEXT NOT NULL,
		partition TEXT NOT NULL CHECK (partition <> ''),
		audience_root TEXT NOT NULL DEFAULT '',
		provider TEXT NOT NULL DEFAULT '',
		issued_at INTEGER NOT NULL DEFAULT 0,
		expires_at INTEGER,
		last_used_at INTEGER NOT NULL DEFAULT 0,
		browser TEXT NOT NULL DEFAULT '',
		device_type TEXT NOT NULL DEFAULT '',
		platform TEXT NOT NULL DEFAULT '',
		allowed_apps TEXT NOT NULL DEFAULT '[]',
		allowed_providers TEXT NOT NULL DEFAULT '[]',
		require_mfa INTEGER NOT NULL DEFAULT 0,
		second_factor INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO tessera_sessions (session_key, subject, partition, second_factor) VALUES ('k-old', 'u1', 'acme', 1)`); err != nil {
		t.Fatal(err)
	}
	s := NewSQLStore(db)
	for i := 0; i < 2; i++ {
		if err := s.InitSchema(ctx); err != nil {
			t.Fatalf("InitSchema #%d: %v", i+1, err)
		}
	}
	got, err := s.Get(ctx, "k-old")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Native || !got.SecondFactor {
		t.Fatalf("a row from before the column reads Native %v, SecondFactor %v; want false, true", got.Native, got.SecondFactor)
	}
}
