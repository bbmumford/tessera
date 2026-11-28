/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package tessera

import (
	"context"
	"testing"
	"time"
)

// Both stores list a subject's unexpired sessions only, so a consumer tested against MemStore sees
// what SQLStore answers.
func TestEveryStoreListsOnlyUnexpiredSessions(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(10_000, 0)
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	stores := map[string]SessionStore{"MemStore": newTestStore(now), "SQLStore": newSQLStore(t, now)}
	for name, store := range stores {
		t.Run(name, func(t *testing.T) {
			for _, exp := range []*time.Time{&past, &future, nil} {
				if _, err := store.Create(ctx, &Session{Subject: "s", Partition: "p1", ExpiresAt: exp}); err != nil {
					t.Fatal(err)
				}
			}
			got, err := store.ListSubjectSessions(ctx, "p1", "s")
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 2 {
				t.Fatalf("%s lists %d sessions, want the 2 unexpired ones", name, len(got))
			}
			for _, s := range got {
				if s.ExpiresAt != nil && !s.ExpiresAt.After(now) {
					t.Fatalf("%s listed an expired session (expires %v)", name, s.ExpiresAt)
				}
			}
		})
	}
}
