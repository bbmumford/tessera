package tessera

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// A key a caller chose is stored only when it has the form the store mints; any other is refused
// and nothing is stored under it.
func TestSQLStoreRefusesAChosenKeyNotOfTheMintedForm(t *testing.T) {
	ctx := context.Background()
	s := newSQLStore(t, time.Unix(1000, 0))
	for _, key := range []string{
		"x",
		strings.Repeat("a", 47),
		strings.Repeat("a", 49),
		strings.Repeat("A", 48),
		strings.Repeat("g", 48),
	} {
		if got, err := s.Create(ctx, &Session{ID: key, Subject: "s", Partition: "p1"}); err == nil {
			t.Fatalf("Create kept the chosen key %q (got %q)", key, got)
		}
		if _, _, err := s.CreateWithID(ctx, &Session{ID: key, Subject: "s", Partition: "p1"}); err == nil {
			t.Fatalf("CreateWithID kept the chosen key %q", key)
		}
		if _, err := s.Get(ctx, key); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a refused key %q names a session: %v", key, err)
		}
	}
	minted := strings.Repeat("0123456789abcdef", 3)
	got, err := s.Create(ctx, &Session{ID: minted, Subject: "s", Partition: "p1"})
	if err != nil || got != minted {
		t.Fatalf("Create of a minted-form key = %q, %v", got, err)
	}
	if sess, err := s.Get(ctx, minted); err != nil || sess.Subject != "s" {
		t.Fatalf("Get(minted-form key) = %+v, %v", sess, err)
	}
}
