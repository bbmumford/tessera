/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package tessera

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// A session minted by CreateAppSessionWith, or by MintWith with its cookie, is
// stored and read back with the PartitionVia its creator named, alongside the
// creation marks; the other CreateAppSession variants name none; a rotation
// keeps the row's value. The same holds over the MemStore.
func TestPartitionViaIsStoredAtCreationAndKeptByRotate(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1000, 0)
	for name, store := range map[string]LocalSessionStore{"sql": newSQLStore(t, now), "mem": NewMemStore()} {
		m, err := NewManager(Config{
			Store:                store,
			Domains:              StaticDomainResolver{Roots: []string{"example.com"}},
			CookieName:           "orbtr_session",
			PartitionFromContext: func(context.Context) string { return "acme" },
			Now:                  func() time.Time { return now },
		})
		if err != nil {
			t.Fatalf("%s: NewManager: %v", name, err)
		}
		with, _, err := m.CreateAppSessionWith(ctx, AppSession{Subject: "u1", Provider: "email", Partition: "acme", PartitionVia: "lastUsed", SecondFactor: true})
		if err != nil {
			t.Fatalf("%s: CreateAppSessionWith: %v", name, err)
		}
		without, _, err := m.CreateAppSession(ctx, "u1", "email", "", "", "", "acme", 0)
		if err != nil {
			t.Fatalf("%s: CreateAppSession: %v", name, err)
		}
		for id, want := range map[string]string{with: "lastUsed", without: ""} {
			got, err := store.Get(ctx, id)
			if err != nil {
				t.Fatalf("%s: Get: %v", name, err)
			}
			if got.PartitionVia != want || got.SecondFactor != (want != "") {
				t.Fatalf("%s: PartitionVia %q, SecondFactor %v; want %q, %v", name, got.PartitionVia, got.SecondFactor, want, want != "")
			}
		}
		cookie, err := m.MintWith(httptest.NewRecorder(), httptest.NewRequest("GET", "https://app.example.com/", nil),
			AppSession{Subject: "u1", Provider: "google", Partition: "acme", PartitionVia: "hint"}, nil)
		if err != nil {
			t.Fatalf("%s: MintWith: %v", name, err)
		}
		if got, err := store.Get(ctx, cookie); err != nil || got.PartitionVia != "hint" {
			t.Fatalf("%s: a cookie session: %+v, %v; want PartitionVia hint", name, got, err)
		}
		rotated, err := store.Rotate(ctx, with)
		if err != nil {
			t.Fatalf("%s: Rotate: %v", name, err)
		}
		got, err := store.Get(ctx, rotated)
		if err != nil || got.PartitionVia != "lastUsed" {
			t.Fatalf("%s: after Rotate: %+v, %v; want PartitionVia lastUsed", name, got, err)
		}
	}
}

// InitSchema over a tesseraSessions table created without partitionVia adds
// the column, a row already there reads "", and a second InitSchema leaves the
// table as it is.
func TestInitSchemaAddsPartitionViaToAnOlderTable(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("db.Close: %v", err)
		}
	})
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
		requireMfa INTEGER NOT NULL DEFAULT 0,
		secondFactor INTEGER NOT NULL DEFAULT 0,
		native INTEGER NOT NULL DEFAULT 0,
		handle TEXT,
		proofSecret TEXT NOT NULL DEFAULT ''
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO tesseraSessions (sessionKey, subject, partition) VALUES ('k-old', 'u1', 'acme')`); err != nil {
		t.Fatal(err)
	}
	s := keyedSQLStore(t, db)
	for i := 0; i < 2; i++ {
		if err := s.InitSchema(ctx); err != nil {
			t.Fatalf("InitSchema #%d: %v", i+1, err)
		}
	}
	got, err := s.Get(ctx, "k-old")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.PartitionVia != "" {
		t.Fatalf("an older row's PartitionVia = %q, want none", got.PartitionVia)
	}
}
