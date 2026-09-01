package tessera

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// ErrNotFound is returned by store ops for an unknown session id.
var ErrNotFound = errors.New("tessera: session not found")

// MemStore is an in-memory reference LocalSessionStore — a working default and the test/dev
// backend. Production wires a durable SessionStore (Turso/tursokv/mesh-RPC) with identical
// semantics behind the same interface. Thread-safe. Clock injectable for deterministic tests.
type MemStore struct {
	mu      sync.Mutex
	byID    map[string]*Session
	nextNum int64
	now     func() time.Time
	newID   func() string
}

// NewMemStore builds an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{byID: map[string]*Session{}, now: time.Now, newID: randomID}
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var _ LocalSessionStore = (*MemStore)(nil)

func (m *MemStore) Create(_ context.Context, s *Session) (string, error) {
	id, _, err := m.create(s)
	return id, err
}

func (m *MemStore) CreateWithID(_ context.Context, s *Session) (string, int64, error) {
	return m.create(s)
}

func (m *MemStore) create(s *Session) (string, int64, error) {
	if s == nil {
		return "", 0, errors.New("tessera: nil session")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.newID()
	m.nextNum++
	cp := s.Clone()
	cp.ID = id
	if cp.IssuedAt.IsZero() {
		cp.IssuedAt = m.now()
	}
	cp.LastUsedAt = cp.IssuedAt
	m.byID[id] = cp
	return id, m.nextNum, nil
}

func (m *MemStore) Get(_ context.Context, id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	return s.Clone(), nil
}

func (m *MemStore) Touch(_ context.Context, id string, newExpiry *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[id]
	if !ok {
		return ErrNotFound
	}
	s.LastUsedAt = m.now()
	if newExpiry != nil {
		e := *newExpiry
		s.ExpiresAt = &e
	}
	return nil
}

func (m *MemStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[id]; !ok {
		return ErrNotFound
	}
	delete(m.byID, id)
	return nil
}

// Rotate re-keys a session under a fresh ID and drops the old key (session-fixation defense),
// preserving the record. Returns the new ID.
func (m *MemStore) Rotate(_ context.Context, id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[id]
	if !ok {
		return "", ErrNotFound
	}
	newID := m.newID()
	s.ID = newID
	s.LastUsedAt = m.now()
	m.byID[newID] = s
	delete(m.byID, id)
	return newID, nil
}

// WipeUser deletes every session for (partition, userID). partition is the opaque partition-scope.
func (m *MemStore) WipeUser(_ context.Context, partition, userID string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for id, s := range m.byID {
		if s.Partition == partition && s.UserID == userID {
			delete(m.byID, id)
			n++
		}
	}
	return n, nil
}

// ListUserSessions returns every session for (partition, userID).
func (m *MemStore) ListUserSessions(_ context.Context, partition, userID string) ([]*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Session
	for _, s := range m.byID {
		if s.Partition == partition && s.UserID == userID {
			out = append(out, s.Clone())
		}
	}
	return out, nil
}

// PurgeExpired deletes sessions whose ExpiresAt is before `before` (a nil ExpiresAt uses MaxAge
// semantics and is never purged here). Returns the count removed.
func (m *MemStore) PurgeExpired(_ context.Context, before time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for id, s := range m.byID {
		if s.ExpiresAt != nil && s.ExpiresAt.Before(before) {
			delete(m.byID, id)
			n++
		}
	}
	return n, nil
}
