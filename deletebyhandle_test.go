package tessera

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Manager.DeleteSessionByHandle ends the session its handle names and no other; a handle it does
// not know, or a session key in its place, is ErrNotFound and ends nothing.
func TestManagerDeletesASessionByItsHandle(t *testing.T) {
	ctx := context.Background()
	m, store := testManager(t, time.Unix(1000, 0))
	key, err := store.Create(ctx, &Session{Subject: "u1", Partition: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	other, _ := store.Create(ctx, &Session{Subject: "u1", Partition: "acme"})
	s, err := store.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteSessionByHandle(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete by a key in place of a handle: err = %v, want ErrNotFound", err)
	}
	if err := m.DeleteSessionByHandle(ctx, "sess_unknown"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete by an unknown handle: err = %v, want ErrNotFound", err)
	}
	if err := m.DeleteSessionByHandle(ctx, s.Handle); err != nil {
		t.Fatalf("DeleteSessionByHandle: %v", err)
	}
	if _, err := store.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the deleted session still reads: err = %v", err)
	}
	if _, err := store.Get(ctx, other); err != nil {
		t.Fatalf("another session was ended too: %v", err)
	}
}
