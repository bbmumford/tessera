package tessera

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// tableText is every value of every tesseraSessions row, as text.
func tableText(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT * FROM tesseraSessions`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			t.Errorf("rows.Close: %v", err)
		}
	}()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		for _, v := range vals {
			if b, ok := v.([]byte); ok {
				v = string(b)
			}
			out = append(out, fmt.Sprint(v))
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// holdsKey fails the test when any stored value contains one of keys.
func holdsKey(t *testing.T, db *sql.DB, keys ...string) {
	t.Helper()
	for _, v := range tableText(t, db) {
		for _, k := range keys {
			if strings.Contains(v, k) {
				t.Errorf("a tesseraSessions value holds the session key %q", k)
			}
		}
	}
}

// A session key is a bearer secret: the SQL store keeps no key a cookie or an app carries, at
// creation or after a rotation, and every lookup by key still answers.
func TestSQLStoreKeepsNoSessionKey(t *testing.T) {
	ctx := context.Background()
	s := newSQLStore(t, time.Unix(1000, 0))
	cookieKey, err := s.Create(ctx, &Session{Subject: "u1", Partition: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	appKey, _, err := s.CreateWithID(ctx, &Session{Subject: "u1", Partition: "acme", Native: true})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := s.Rotate(ctx, cookieKey)
	if err != nil {
		t.Fatal(err)
	}
	holdsKey(t, s.db, cookieKey, appKey, rotated)

	got, err := s.Get(ctx, rotated)
	if err != nil || got.ID != rotated || got.Subject != "u1" {
		t.Fatalf("Get(rotated key) = %+v, %v; want the session, answered with its key", got, err)
	}
	if _, err := s.Get(ctx, cookieKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(key before rotation) err = %v, want ErrNotFound", err)
	}
	if err := s.Touch(ctx, rotated, nil); err != nil {
		t.Fatalf("Touch(rotated key): %v", err)
	}
	if err := s.Delete(ctx, appKey); err != nil {
		t.Fatalf("Delete(app key): %v", err)
	}
	if _, err := s.Get(ctx, appKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(deleted app key) err = %v, want ErrNotFound", err)
	}

	// A rotation by handle chooses a key no caller is told; the store keeps none of it either.
	const chosen = "0123456789abcdef0123456789abcdef0123456789abcdef"
	s.newID = func() string { return chosen }
	if _, err := s.RotateByHandle(ctx, got.Handle); err != nil {
		t.Fatalf("RotateByHandle: %v", err)
	}
	holdsKey(t, s.db, chosen)
	if again, err := s.Get(ctx, chosen); err != nil || again.Subject != "u1" {
		t.Fatalf("Get(key RotateByHandle chose) = %+v, %v; want the session", again, err)
	}
}

// A session read by its handle or listed for its subject carries no key, in either store: the key
// leaves a store only from the call that made it.
func TestNoSessionReadByHandleOrSubjectCarriesItsKey(t *testing.T) {
	ctx := context.Background()
	for name, store := range handleStores(t) {
		t.Run(name, func(t *testing.T) {
			key, err := store.Create(ctx, &Session{Subject: "u1", Partition: "acme"})
			if err != nil {
				t.Fatal(err)
			}
			s, err := store.Get(ctx, key)
			if err != nil {
				t.Fatal(err)
			}
			byHandle, err := store.GetByHandle(ctx, s.Handle)
			if err != nil {
				t.Fatalf("GetByHandle: %v", err)
			}
			if byHandle.ID != "" || byHandle.Subject != "u1" {
				t.Fatalf("GetByHandle answered ID %q subject %q; want no key and the session", byHandle.ID, byHandle.Subject)
			}
			listed, err := store.ListSubjectSessions(ctx, "acme", "u1")
			if err != nil || len(listed) != 1 {
				t.Fatalf("ListSubjectSessions = %d sessions, %v; want 1", len(listed), err)
			}
			if listed[0].ID != "" || listed[0].Handle != s.Handle {
				t.Fatalf("listed session ID %q handle %q; want no key and handle %q", listed[0].ID, listed[0].Handle, s.Handle)
			}
		})
	}
}

// A table whose key column is sessionKey holds each key itself. InitSchema replaces every such key
// with its digest, run once or again, and every session stays valid under its key.
func TestInitSchemaReplacesTheKeysAnOlderTableHolds(t *testing.T) {
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
	keys := []string{"0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a6978", "k-two"}
	for _, k := range keys {
		if _, err := db.ExecContext(ctx, `INSERT INTO tesseraSessions (sessionKey, subject, partition) VALUES (?, 'u1', 'acme')`, k); err != nil {
			t.Fatal(err)
		}
	}
	s := keyedSQLStore(t, db)
	for i := 0; i < 2; i++ {
		if err := s.InitSchema(ctx); err != nil {
			t.Fatalf("InitSchema #%d: %v", i+1, err)
		}
	}
	holdsKey(t, db, keys...)
	for _, k := range keys {
		got, err := s.Get(ctx, k)
		if err != nil || got.Subject != "u1" || got.Handle == "" {
			t.Fatalf("Get(%q) after InitSchema = %+v, %v; want the session kept", k, got, err)
		}
	}
}
