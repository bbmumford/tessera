package tessera

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// digestKey is a MinDigestKeyBytes key made of one repeated byte, so two of them differ.
func digestKey(b byte) []byte {
	return []byte(strings.Repeat(string(rune(b)), MinDigestKeyBytes))
}

func hmacHex(key []byte, sessionKey string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(sessionKey))
	return hex.EncodeToString(mac.Sum(nil))
}

func sha256Hex(sessionKey string) string {
	sum := sha256.Sum256([]byte(sessionKey))
	return hex.EncodeToString(sum[:])
}

func openSessionsDB(t *testing.T) *sql.DB {
	t.Helper()
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
	return db
}

// openKeyed opens a store over db under keys whose clock reads *now.
func openKeyed(t *testing.T, db *sql.DB, keys DigestKeys, now *time.Time) *SQLStore {
	t.Helper()
	s, err := OpenSQLStore(db, keys)
	if err != nil {
		t.Fatalf("OpenSQLStore: %v", err)
	}
	s.now = func() time.Time { return *now }
	if err := s.InitSchema(context.Background()); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return s
}

// storedDigests is every sessionKeyDigest the table holds.
func storedDigests(t *testing.T, db *sql.DB) map[string]bool {
	t.Helper()
	rows, err := db.Query(`SELECT sessionKeyDigest FROM tesseraSessions`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			t.Errorf("rows.Close: %v", err)
		}
	}()
	out := map[string]bool{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			t.Fatal(err)
		}
		out[d] = true
	}
	return out
}

// A store opened with DigestKeys keeps HMAC-SHA256 of each session key under the current key, never
// a digest the key alone yields, and answers every lookup by key through it.
func TestOpenSQLStoreKeepsEachKeysHMACUnderTheCurrentKey(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1000, 0)
	db := openSessionsDB(t)
	k := digestKey('a')
	s := openKeyed(t, db, DigestKeys{Current: k}, &now)
	key, err := s.Create(ctx, &Session{Subject: "u1", Partition: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	stored := storedDigests(t, db)
	if !stored[hmacHex(k, key)] {
		t.Fatalf("the table holds %v; want the key's HMAC-SHA256 under the current key", stored)
	}
	if stored[sha256Hex(key)] {
		t.Fatal("the table holds the key's SHA-256, which the key alone yields")
	}
	holdsKey(t, db, key)
	if got, err := s.Get(ctx, key); err != nil || got.Subject != "u1" {
		t.Fatalf("Get = %+v, %v; want the session", got, err)
	}

	// A store over the same database under another key finds none of these sessions.
	other := openKeyed(t, db, DigestKeys{Current: digestKey('b')}, &now)
	if _, err := other.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get under another key err = %v, want ErrNotFound", err)
	}
	// Every process opening the database with the same key reads what another wrote.
	same := openKeyed(t, db, DigestKeys{Current: k}, &now)
	if _, err := same.Get(ctx, key); err != nil {
		t.Fatalf("Get under the same key: %v", err)
	}
}

func TestOpenSQLStoreRefusesKeysItCannotDigestUnder(t *testing.T) {
	end := time.Unix(5000, 0)
	cases := map[string]DigestKeys{
		"no current key":                  {},
		"a current key too short":         {Current: digestKey('a')[:MinDigestKeyBytes-1]},
		"a previous key with no end":      {Current: digestKey('a'), Previous: digestKey('b')},
		"an end with no previous key":     {Current: digestKey('a'), PreviousUntil: end},
		"a previous key too short":        {Current: digestKey('a'), Previous: digestKey('b')[:MinDigestKeyBytes-1], PreviousUntil: end},
		"a previous key equal to current": {Current: digestKey('a'), Previous: digestKey('a'), PreviousUntil: end},
	}
	for name, keys := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := OpenSQLStore(openSessionsDB(t), keys)
			if !errors.Is(err, ErrDigestKey) || s != nil {
				t.Fatalf("OpenSQLStore = %v, %v; want nil, ErrDigestKey", s, err)
			}
		})
	}
	// Each refusal names what is wrong with the keys.
	for keys, says := range map[*DigestKeys]string{
		{Current: digestKey('a'), PreviousUntil: end}:       "an end time is set with no previous key",
		{Current: digestKey('a'), Previous: digestKey('b')}: "a previous key is set with no end time",
	} {
		if _, err := OpenSQLStore(openSessionsDB(t), *keys); err == nil || !strings.Contains(err.Error(), says) {
			t.Errorf("OpenSQLStore(%+v) err = %v, want one saying %q", *keys, err, says)
		}
	}
	for name, keys := range map[string]DigestKeys{
		"a current key":                {Current: digestKey('a')},
		"a current and a previous key": {Current: digestKey('a'), Previous: digestKey('b'), PreviousUntil: end},
	} {
		if _, err := OpenSQLStore(openSessionsDB(t), keys); err != nil {
			t.Errorf("%s: OpenSQLStore: %v", name, err)
		}
	}
}

// After the digest key changes, a lookup by key finds a session stored under the previous key until
// the end time DigestKeys states, re-keying it under the current key, so a session used inside the
// window outlives it and one not used is not found after it.
func TestAPreviousDigestKeyFindsItsSessionsUntilItsEndTime(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1000, 0)
	db := openSessionsDB(t)
	k1, k2 := digestKey('a'), digestKey('b')
	before := openKeyed(t, db, DigestKeys{Current: k1}, &now)
	keys := map[string]string{}
	for _, name := range []string{"read", "touched", "rotated", "deleted", "unused"} {
		key, err := before.Create(ctx, &Session{Subject: name, Partition: "acme"})
		if err != nil {
			t.Fatal(err)
		}
		keys[name] = key
	}

	end := now.Add(time.Hour)
	after := openKeyed(t, db, DigestKeys{Current: k2, Previous: k1, PreviousUntil: end}, &now)
	if got, err := after.Get(ctx, keys["read"]); err != nil || got.Subject != "read" || got.ID != keys["read"] {
		t.Fatalf("Get inside the window = %+v, %v; want the session", got, err)
	}
	if err := after.Touch(ctx, keys["touched"], nil); err != nil {
		t.Fatalf("Touch inside the window: %v", err)
	}
	rotated, err := after.Rotate(ctx, keys["rotated"])
	if err != nil {
		t.Fatalf("Rotate inside the window: %v", err)
	}
	if err := after.Delete(ctx, keys["deleted"]); err != nil {
		t.Fatalf("Delete inside the window: %v", err)
	}
	stored := storedDigests(t, db)
	for _, want := range []string{hmacHex(k2, keys["read"]), hmacHex(k2, keys["touched"]), hmacHex(k2, rotated), hmacHex(k1, keys["unused"])} {
		if !stored[want] {
			t.Errorf("the table lacks digest %s; holds %v", want, stored)
		}
	}
	for _, gone := range []string{hmacHex(k1, keys["read"]), hmacHex(k1, keys["touched"]), hmacHex(k1, keys["rotated"]), hmacHex(k1, keys["deleted"])} {
		if stored[gone] {
			t.Errorf("the table still holds the previous key's digest %s", gone)
		}
	}

	now = end
	for _, name := range []string{"read", "touched"} {
		if got, err := after.Get(ctx, keys[name]); err != nil || got.Subject != name {
			t.Errorf("Get(%s) after the window = %+v, %v; want the session it re-keyed", name, got, err)
		}
	}
	if _, err := after.Get(ctx, rotated); err != nil {
		t.Errorf("Get(rotated key) after the window: %v", err)
	}
	if _, err := after.Get(ctx, keys["unused"]); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get(unused) after the window err = %v, want ErrNotFound", err)
	}
	if err := after.Touch(ctx, keys["unused"], nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("Touch(unused) after the window err = %v, want ErrNotFound", err)
	}
	if err := after.Delete(ctx, keys["unused"]); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete(unused) after the window err = %v, want ErrNotFound", err)
	}
	if _, err := after.Rotate(ctx, keys["unused"]); !errors.Is(err, ErrNotFound) {
		t.Errorf("Rotate(unused) after the window err = %v, want ErrNotFound", err)
	}
}

// The in-memory store keys its digests by a key it draws for itself, so no digest it holds is one
// the session key alone yields, and two stores digest one key differently.
func TestMemStoreDigestsUnderAKeyOfItsOwn(t *testing.T) {
	ctx := context.Background()
	a, b := NewMemStore(), NewMemStore()
	key, err := a.Create(ctx, &Session{Subject: "u1", Partition: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.byDigest[sha256Hex(key)]; ok {
		t.Fatal("the store holds the key's SHA-256, which the key alone yields")
	}
	if a.digests.digest(key) == b.digests.digest(key) {
		t.Fatal("two stores digest one session key alike")
	}
	if got, err := a.Get(ctx, key); err != nil || got.Subject != "u1" {
		t.Fatalf("Get = %+v, %v; want the session", got, err)
	}
}
