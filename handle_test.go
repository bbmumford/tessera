package tessera

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// handleStores are the two stores every handle test runs over, so the reference store and the
// SQL store answer one contract.
func handleStores(t *testing.T) map[string]SessionStore {
	t.Helper()
	return map[string]SessionStore{
		"mem": NewMemStore(),
		"sql": newSQLStore(t, time.Unix(1000, 0)),
	}
}

func TestEverySessionHasAPublicHandleApartFromItsKey(t *testing.T) {
	ctx := context.Background()
	for name, store := range handleStores(t) {
		t.Run(name, func(t *testing.T) {
			key, err := store.Create(ctx, &Session{Subject: "u1", Partition: "acme", Handle: "sess_chosen"})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			got, err := store.Get(ctx, key)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if !strings.HasPrefix(got.Handle, handlePrefix) || got.Handle == key || got.Handle == "sess_chosen" {
				t.Fatalf("handle %q for key %q: want a fresh %q value the store chose", got.Handle, key, handlePrefix)
			}
			byHandle, err := store.GetByHandle(ctx, got.Handle)
			if err != nil || byHandle.ID != "" || byHandle.Subject != "u1" || byHandle.Handle != got.Handle {
				t.Fatalf("GetByHandle = %+v, %v; want the session of key %q, with no key", byHandle, err, key)
			}
			if _, err := store.Get(ctx, got.Handle); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Get(handle) err = %v; a handle must never select as a key", err)
			}
			if _, err := store.GetByHandle(ctx, key); !errors.Is(err, ErrNotFound) {
				t.Fatalf("GetByHandle(key) err = %v; a key must never select as a handle", err)
			}
			if _, err := store.GetByHandle(ctx, ""); !errors.Is(err, ErrNotFound) {
				t.Fatalf("GetByHandle(\"\") err = %v; want ErrNotFound", err)
			}
			other, err := store.Create(ctx, &Session{Subject: "u1", Partition: "acme"})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			second, _ := store.Get(ctx, other)
			if second.Handle == got.Handle {
				t.Fatalf("two sessions share the handle %q", got.Handle)
			}
		})
	}
}

func TestARotationByHandleIsSingleUseAndReplacesKeyAndHandle(t *testing.T) {
	ctx := context.Background()
	for name, store := range handleStores(t) {
		t.Run(name, func(t *testing.T) {
			key, _ := store.Create(ctx, &Session{Subject: "u1", Partition: "acme", Native: true})
			old, _ := store.Get(ctx, key)
			newHandle, err := store.RotateByHandle(ctx, old.Handle)
			if err != nil {
				t.Fatalf("RotateByHandle: %v", err)
			}
			if newHandle == old.Handle || !strings.HasPrefix(newHandle, handlePrefix) {
				t.Fatalf("new handle %q after %q: want a fresh handle", newHandle, old.Handle)
			}
			rotated, err := store.GetByHandle(ctx, newHandle)
			if err != nil {
				t.Fatalf("GetByHandle(new): %v", err)
			}
			if rotated.ID != "" || !rotated.Native || rotated.Subject != "u1" {
				t.Fatalf("rotated record %+v: want the record kept, with no key", rotated)
			}
			if _, err := store.GetByHandle(ctx, old.Handle); !errors.Is(err, ErrNotFound) {
				t.Fatalf("old handle err = %v; want ErrNotFound", err)
			}
			if _, err := store.Get(ctx, key); !errors.Is(err, ErrNotFound) {
				t.Fatalf("old key err = %v; want ErrNotFound", err)
			}
			if _, err := store.RotateByHandle(ctx, old.Handle); !errors.Is(err, ErrNotFound) {
				t.Fatalf("a second rotation of one handle err = %v; want ErrNotFound", err)
			}
		})
	}
}

func TestARotationByKeyReplacesTheHandleToo(t *testing.T) {
	ctx := context.Background()
	for name, store := range handleStores(t) {
		t.Run(name, func(t *testing.T) {
			key, _ := store.Create(ctx, &Session{Subject: "u1", Partition: "acme"})
			old, _ := store.Get(ctx, key)
			newKey, err := store.Rotate(ctx, key)
			if err != nil {
				t.Fatalf("Rotate: %v", err)
			}
			rotated, _ := store.Get(ctx, newKey)
			if rotated == nil || rotated.Handle == old.Handle || rotated.Handle == "" {
				t.Fatalf("rotated record %+v: want a fresh handle beside the fresh key", rotated)
			}
			if _, err := store.GetByHandle(ctx, old.Handle); !errors.Is(err, ErrNotFound) {
				t.Fatalf("old handle after a key rotation err = %v; want ErrNotFound", err)
			}
		})
	}
}

func TestADeleteByHandleEndsTheSession(t *testing.T) {
	ctx := context.Background()
	for name, store := range handleStores(t) {
		t.Run(name, func(t *testing.T) {
			key, _ := store.Create(ctx, &Session{Subject: "u1", Partition: "acme"})
			s, _ := store.Get(ctx, key)
			if err := store.DeleteByHandle(ctx, s.Handle); err != nil {
				t.Fatalf("DeleteByHandle: %v", err)
			}
			if _, err := store.Get(ctx, key); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Get after DeleteByHandle err = %v; want ErrNotFound", err)
			}
			if err := store.DeleteByHandle(ctx, s.Handle); !errors.Is(err, ErrNotFound) {
				t.Fatalf("second DeleteByHandle err = %v; want ErrNotFound", err)
			}
		})
	}
}

func TestInitSchemaGivesEveryOlderRowAHandle(t *testing.T) {
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
		requireMfa INTEGER NOT NULL DEFAULT 0,
		secondFactor INTEGER NOT NULL DEFAULT 0,
		native INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"k-one", "k-two"} {
		if _, err := db.ExecContext(ctx, `INSERT INTO tesseraSessions (sessionKey, subject, partition) VALUES (?, 'u1', 'acme')`, k); err != nil {
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
		t.Fatalf("Get: %v", err)
	}
	two, _ := s.Get(ctx, "k-two")
	if !strings.HasPrefix(one.Handle, handlePrefix) || one.Handle == two.Handle {
		t.Fatalf("older rows read handles %q and %q; want two distinct handles", one.Handle, two.Handle)
	}
	if got, err := s.GetByHandle(ctx, one.Handle); err != nil || got.Subject != "u1" || got.Handle != one.Handle {
		t.Fatalf("GetByHandle(backfilled) = %+v, %v; want k-one's session", got, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE tesseraSessions SET handle = ? WHERE handle = ?`, one.Handle, two.Handle); err == nil {
		t.Fatal("two rows took one handle: the unique index is missing")
	}
}

func TestTheCachingStoreForgetsASessionEndedByHandle(t *testing.T) {
	ctx := context.Background()
	inner := NewMemStore()
	key, _ := inner.Create(ctx, &Session{Subject: "u1", Partition: "acme"})
	c := NewCachingStore(inner, time.Minute)
	s, err := c.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if err := c.DeleteByHandle(ctx, s.Handle); err != nil {
		t.Fatalf("DeleteByHandle: %v", err)
	}
	if _, err := c.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after DeleteByHandle err = %v; the cached entry outlived the session", err)
	}
	key, _ = inner.Create(ctx, &Session{Subject: "u1", Partition: "acme"})
	s, _ = c.Get(ctx, key)
	if _, err := c.RotateByHandle(ctx, s.Handle); err != nil {
		t.Fatalf("RotateByHandle: %v", err)
	}
	if _, err := c.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(old key) after RotateByHandle err = %v; the cached entry outlived the rotation", err)
	}
}

func TestACookieNeverAttachesANativeSession(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1000, 0)
	store := NewMemStore()
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
	native, _, err := m.CreateNativeAppSession(ctx, "u1", "google", "", "", "", "acme", 3600)
	if err != nil {
		t.Fatalf("CreateNativeAppSession: %v", err)
	}
	browser, _, err := m.CreateAppSession(ctx, "u1", "google", "", "", "", "acme", 3600)
	if err != nil {
		t.Fatalf("CreateAppSession: %v", err)
	}
	attached := func(key string) bool {
		var got bool
		h := m.AttachSession(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			_, got = FromContext(r)
		}))
		r := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
		r.AddCookie(&http.Cookie{Name: "orbtr_session", Value: key})
		h.ServeHTTP(httptest.NewRecorder(), r)
		return got
	}
	if attached(native) {
		t.Fatal("a cookie carrying a native session's key attached it")
	}
	if !attached(browser) {
		t.Fatal("a cookie carrying a browser session's key did not attach it")
	}
}
