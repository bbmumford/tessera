/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package tessera

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// Past 128 entries a read-through miss does not scan the whole map again within one TTL of the last
// scan: an entry already past its age stays in the map (lookup refuses it by age) until the next
// scheduled sweep.
func TestTheCacheScansAtMostOncePerTTL(t *testing.T) {
	ctx := context.Background()
	inner := NewMemStore()
	cache := NewCachingStore(inner, time.Hour)
	read := func(i int) {
		t.Helper()
		key, err := inner.Create(ctx, &Session{Subject: fmt.Sprintf("s%d", i), Partition: "p1"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cache.Get(ctx, key); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 128; i++ {
		read(i)
	}
	cache.mu.Lock()
	cache.cache["aged"] = cacheEntry{session: &Session{Subject: "aged", Partition: "p1"}, cachedAt: time.Now().Add(-2 * time.Hour)}
	cache.mu.Unlock()
	for i := 128; i < 160; i++ {
		read(i)
	}
	cache.mu.RLock()
	_, kept := cache.cache["aged"]
	cache.mu.RUnlock()
	if !kept {
		t.Fatal("a miss within one TTL of the last scan scanned the map again")
	}
	if _, ok := cache.lookup("aged"); ok {
		t.Fatal("an entry past its age was served")
	}
}
