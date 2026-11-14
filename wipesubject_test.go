package tessera

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"
)

// WipeSubject deletes every session of the subject in the request's partition, the
// set GetSubjectSessions lists, and answers the count; another partition's session
// of the same subject stays. With no partition resolver it is refused, as the list
// is.
func TestManagerWipeSubjectEndsTheSubjectsSessionsInThePartition(t *testing.T) {
	now := time.Unix(1000, 0)
	store := newTestStore(now)
	m, err := NewManager(Config{
		Store:                store,
		Domains:              StaticDomainResolver{Roots: []string{"example.com"}},
		CookieName:           "orbtr_session",
		Now:                  func() time.Time { return now },
		PartitionFromContext: func(context.Context) string { return "acme" },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	for _, partition := range []string{"acme", "acme", "other"} {
		if _, err := m.Mint(httptest.NewRecorder(), reqTo("app.example.com"), "u1", "email", partition, nil); err != nil {
			t.Fatalf("Mint in %s: %v", partition, err)
		}
	}
	n, err := m.WipeSubject(context.Background(), "u1")
	if err != nil || n != 2 {
		t.Fatalf("WipeSubject = %d, %v, want 2", n, err)
	}
	if left, err := m.GetSubjectSessions(context.Background(), "u1"); err != nil || len(left) != 0 {
		t.Fatalf("after the wipe the partition lists %d sessions, %v", len(left), err)
	}
	if left, err := store.ListSubjectSessions(context.Background(), "other", "u1"); err != nil || len(left) != 1 {
		t.Fatalf("the other partition's session: %d, %v, want it kept", len(left), err)
	}

	bare, err := NewManager(Config{Store: store, Domains: StaticDomainResolver{Roots: []string{"example.com"}}, CookieName: "orbtr_session"})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if _, err := bare.WipeSubject(context.Background(), "u1"); !errors.Is(err, ErrPartitionRequired) {
		t.Fatalf("WipeSubject with no partition resolver = %v, want ErrPartitionRequired", err)
	}
}
