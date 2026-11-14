package tessera

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// A session minted by CreateSecondFactorAppSession is stored and read back with
// SecondFactor set, one minted by CreateAppSession without it, and a rotation
// keeps the value the row was created with.
func TestSecondFactorIsStoredAtCreationAndKeptByRotate(t *testing.T) {
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

	with, _, err := m.CreateSecondFactorAppSession(ctx, "u1", "email", "", "", "", "acme", 0)
	if err != nil {
		t.Fatalf("CreateSecondFactorAppSession: %v", err)
	}
	without, _, err := m.CreateAppSession(ctx, "u1", "email", "", "", "", "acme", 0)
	if err != nil {
		t.Fatalf("CreateAppSession: %v", err)
	}
	for id, want := range map[string]bool{with: true, without: false} {
		got, err := store.Get(ctx, id)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.SecondFactor != want {
			t.Fatalf("SecondFactor = %v, want %v", got.SecondFactor, want)
		}
	}

	rotated, err := store.Rotate(ctx, with)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	got, err := store.Get(ctx, rotated)
	if err != nil || !got.SecondFactor {
		t.Fatalf("after Rotate: SecondFactor = %v, %v; want true", got != nil && got.SecondFactor, err)
	}
}

// InitSchema over a tesseraSessions table created without secondFactor adds
// the column, rows already there read as minted without a second factor, and a
// second InitSchema leaves the table as it is.
func TestInitSchemaAddsSecondFactorToAnOlderTable(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if _, err := db.ExecContext(ctx, `CREATE TABLE tesseraSessions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sessionKey TEXT UNIQUE NOT NULL,
		subject TEXT NOT NULL,
		partition TEXT NOT NULL CHECK (partition <> ''),
		audienceRoot TEXT NOT NULL DEFAULT '',
		provider TEXT NOT NULL DEFAULT '',
		issuedAt INTEGER NOT NULL DEFAULT 0,
		expiresAt INTEGER,
		lastUsedAt INTEGER NOT NULL DEFAULT 0,
		browser TEXT NOT NULL DEFAULT '',
		deviceType TEXT NOT NULL DEFAULT '',
		platform TEXT NOT NULL DEFAULT '',
		allowedApps TEXT NOT NULL DEFAULT '[]',
		allowedProviders TEXT NOT NULL DEFAULT '[]',
		requireMfa INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO tesseraSessions (sessionKey, subject, partition) VALUES ('k-old', 'u1', 'acme')`); err != nil {
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
	if got.SecondFactor {
		t.Fatal("a row from before the column reads as minted with a second factor")
	}
}
