package tessera

import (
	"context"
	"errors"
	"testing"
	"time"
)

func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

func newTestStore(now time.Time) *MemStore {
	m := NewMemStore()
	m.now = fixedNow(now)
	return m
}

func sample(owner, user string) *Session {
	return &Session{UserID: user, Owner: owner, Provider: "email", Browser: "curl", AllowedApps: []string{"app1"}}
}

func TestCreateGet_RoundTrip(t *testing.T) {
	ctx := context.Background()
	m := newTestStore(time.Unix(1000, 0))
	id, err := m.Create(ctx, sample("acme", "u1"))
	if err != nil || id == "" {
		t.Fatalf("Create: %q %v", id, err)
	}
	got, err := m.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != "u1" || got.Owner != "acme" || got.ID != id {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.IssuedAt.IsZero() || !got.LastUsedAt.Equal(got.IssuedAt) {
		t.Fatal("IssuedAt/LastUsedAt must be stamped at create")
	}
}

func TestGet_Unknown(t *testing.T) {
	if _, err := NewMemStore().Get(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown id must be ErrNotFound")
	}
}

func TestRotate_ReKeysAndDropsOld(t *testing.T) {
	ctx := context.Background()
	m := newTestStore(time.Unix(1000, 0))
	id, _ := m.Create(ctx, sample("acme", "u1"))
	newID, err := m.Rotate(ctx, id)
	if err != nil || newID == id || newID == "" {
		t.Fatalf("Rotate: %q %v", newID, err)
	}
	if _, err := m.Get(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatal("old id must be gone after rotate (session-fixation defense)")
	}
	got, err := m.Get(ctx, newID)
	if err != nil || got.UserID != "u1" {
		t.Fatalf("rotated session must survive under the new id: %+v %v", got, err)
	}
}

// TestOpaqueOwner_WipeAndList: the store keys wipe/list by the OPAQUE (owner, user) pair and never
// interprets owner — a different owner value is a distinct partition.
func TestOpaqueOwner_WipeAndList(t *testing.T) {
	ctx := context.Background()
	m := newTestStore(time.Unix(1000, 0))
	m.Create(ctx, sample("acme", "u1"))
	m.Create(ctx, sample("acme", "u1"))
	m.Create(ctx, sample("globex", "u1")) // same user, DIFFERENT owner → separate partition
	acme, _ := m.ListUserSessions(ctx, "acme", "u1")
	if len(acme) != 2 {
		t.Fatalf("acme/u1 should have 2 sessions; got %d", len(acme))
	}
	n, _ := m.WipeUser(ctx, "acme", "u1")
	if n != 2 {
		t.Fatalf("WipeUser removed %d, want 2", n)
	}
	// globex/u1 is untouched — owner is an opaque partition.
	globex, _ := m.ListUserSessions(ctx, "globex", "u1")
	if len(globex) != 1 {
		t.Fatalf("a different owner must be an independent partition; globex/u1 has %d", len(globex))
	}
}

func TestPurgeExpired(t *testing.T) {
	ctx := context.Background()
	m := newTestStore(time.Unix(1000, 0))
	past := time.Unix(500, 0)
	future := time.Unix(5000, 0)
	s1 := sample("acme", "u1")
	s1.ExpiresAt = &past
	s2 := sample("acme", "u2")
	s2.ExpiresAt = &future
	s3 := sample("acme", "u3") // nil expiry → MaxAge, never purged
	m.Create(ctx, s1)
	m.Create(ctx, s2)
	m.Create(ctx, s3)
	n, _ := m.PurgeExpired(ctx, time.Unix(1000, 0))
	if n != 1 {
		t.Fatalf("PurgeExpired removed %d, want 1 (only the past-expiry one)", n)
	}
}

func TestClone_NoAliasing(t *testing.T) {
	ctx := context.Background()
	m := newTestStore(time.Unix(1000, 0))
	src := sample("acme", "u1")
	id, _ := m.Create(ctx, src)
	src.AllowedApps[0] = "MUTATED" // mutate the caller's slice after create
	got, _ := m.Get(ctx, id)
	if got.AllowedApps[0] != "app1" {
		t.Fatal("a caller mutation after Create must not alias stored state (Clone)")
	}
}

func TestTouch_UpdatesExpiryAndLastUsed(t *testing.T) {
	ctx := context.Background()
	m := newTestStore(time.Unix(1000, 0))
	id, _ := m.Create(ctx, sample("acme", "u1"))
	m.now = fixedNow(time.Unix(2000, 0))
	newExp := time.Unix(9000, 0)
	if err := m.Touch(ctx, id, &newExp); err != nil {
		t.Fatal(err)
	}
	got, _ := m.Get(ctx, id)
	if !got.LastUsedAt.Equal(time.Unix(2000, 0)) || got.ExpiresAt == nil || !got.ExpiresAt.Equal(newExp) {
		t.Fatalf("Touch must update LastUsedAt + ExpiresAt: %+v", got)
	}
}
