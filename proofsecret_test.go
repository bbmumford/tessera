package tessera

import (
	"context"
	"database/sql"
	"testing"
)

// Every session holds a proof secret the store chose, apart from any the caller
// sent and from every other session's, and both rotations replace it with the key.
func TestEverySessionHoldsItsOwnProofSecretReplacedAtRotation(t *testing.T) {
	ctx := context.Background()
	for name, store := range handleStores(t) {
		t.Run(name, func(t *testing.T) {
			a, err := store.Create(ctx, &Session{Subject: "u1", Partition: "acme", ProofSecret: "chosen-by-the-caller"})
			if err != nil {
				t.Fatal(err)
			}
			b, _ := store.Create(ctx, &Session{Subject: "u1", Partition: "acme"})
			sa, err := store.Get(ctx, a)
			if err != nil {
				t.Fatal(err)
			}
			sb, _ := store.Get(ctx, b)
			if len(sa.ProofSecret) != 43 || sa.ProofSecret == "chosen-by-the-caller" || sa.ProofSecret == sb.ProofSecret {
				t.Fatalf("secrets %q and %q; want two distinct store-chosen 32-byte secrets", sa.ProofSecret, sb.ProofSecret)
			}
			rotated, err := store.Rotate(ctx, a)
			if err != nil {
				t.Fatal(err)
			}
			sr, _ := store.Get(ctx, rotated)
			if sr.ProofSecret == "" || sr.ProofSecret == sa.ProofSecret {
				t.Fatalf("rotation kept secret %q", sr.ProofSecret)
			}
			handle, err := store.RotateByHandle(ctx, sb.Handle)
			if err != nil {
				t.Fatal(err)
			}
			sh, _ := store.GetByHandle(ctx, handle)
			if sh.ProofSecret == "" || sh.ProofSecret == sb.ProofSecret {
				t.Fatalf("rotation by handle kept secret %q", sh.ProofSecret)
			}
		})
	}
}

// A table created before proof secrets gains the column, and every row already
// there is given its own secret, so its session proves a change without signing
// in again.
func TestInitSchemaGivesEveryOlderRowAProofSecret(t *testing.T) {
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
		second_factor INTEGER NOT NULL DEFAULT 0,
		native INTEGER NOT NULL DEFAULT 0,
		handle TEXT
	)`); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"k-one", "k-two"} {
		if _, err := db.ExecContext(ctx, `INSERT INTO tessera_sessions (session_key, subject, partition) VALUES (?, 'u1', 'acme')`, k); err != nil {
			t.Fatal(err)
		}
	}
	s := NewSQLStore(db)
	for i := 0; i < 2; i++ {
		if err := s.InitSchema(ctx); err != nil {
			t.Fatalf("InitSchema #%d: %v", i+1, err)
		}
	}
	one, err := s.Get(ctx, "k-one")
	if err != nil {
		t.Fatal(err)
	}
	two, _ := s.Get(ctx, "k-two")
	if one.ProofSecret == "" || two.ProofSecret == "" || one.ProofSecret == two.ProofSecret {
		t.Fatalf("older rows read secrets %q and %q; want two distinct secrets", one.ProofSecret, two.ProofSecret)
	}
}
