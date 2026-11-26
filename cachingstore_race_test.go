package tessera

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// blockingGetStore holds its first Get open, after the backing read, until release is closed.
type blockingGetStore struct {
	SessionStore
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (b *blockingGetStore) Get(ctx context.Context, id string) (*Session, error) {
	s, err := b.SessionStore.Get(ctx, id)
	b.once.Do(func() {
		close(b.entered)
		<-b.release
	})
	return s, err
}

// Each mutation that lands while a read-through Get is in flight stays in effect: the read's
// answer is not cached, and the next Get reaches the backing store and finds the session gone.
func TestCachingStoreKeepsAMutationThatLandsDuringARead(t *testing.T) {
	cases := map[string]func(ctx context.Context, c *CachingStore, key, handle string) error{
		"Delete": func(ctx context.Context, c *CachingStore, key, _ string) error { return c.Delete(ctx, key) },
		"Rotate": func(ctx context.Context, c *CachingStore, key, _ string) error {
			_, err := c.Rotate(ctx, key)
			return err
		},
		"WipeSubject": func(ctx context.Context, c *CachingStore, _, _ string) error {
			_, err := c.WipeSubject(ctx, "p1", "s")
			return err
		},
		"DeleteByHandle": func(ctx context.Context, c *CachingStore, _, handle string) error {
			return c.DeleteByHandle(ctx, handle)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			inner := &blockingGetStore{SessionStore: NewMemStore(), entered: make(chan struct{}), release: make(chan struct{})}
			cache := NewCachingStore(inner, time.Minute)
			key, err := cache.Create(ctx, &Session{Subject: "s", Partition: "p1"})
			if err != nil {
				t.Fatal(err)
			}
			held, err := inner.SessionStore.Get(ctx, key)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { _, _ = cache.Get(ctx, key); close(done) }()
			<-inner.entered
			if err := mutate(ctx, cache, key, held.Handle); err != nil {
				t.Fatal(err)
			}
			close(inner.release)
			<-done
			if s, err := cache.Get(ctx, key); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Get after %s during a read = %+v, %v; want ErrNotFound", name, s, err)
			}
		})
	}
}
