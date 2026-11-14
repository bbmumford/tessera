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
	// newHandle makes each public handle; randomHandle outside a test.
	newHandle func() string
}

// NewMemStore builds an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{byID: map[string]*Session{}, now: time.Now, newID: randomID, newHandle: randomHandle}
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
	if s.Partition == "" {
		return "", 0, ErrPartitionRequired
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.newID()
	m.nextNum++
	cp := s.Clone()
	cp.ID = id
	cp.Handle = m.newHandle()
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
// preserving the record. The handle is replaced with the key. Returns the new ID.
func (m *MemStore) Rotate(_ context.Context, id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[id]
	if !ok {
		return "", ErrNotFound
	}
	newID := m.newID()
	s.ID = newID
	s.Handle = m.newHandle()
	s.LastUsedAt = m.now()
	m.byID[newID] = s
	delete(m.byID, id)
	return newID, nil
}

// keyOfLocked returns the key of the session handle names. The caller holds m.mu. The scan is
// over every session because this store is the reference and test backend, whose session count
// is small; SQLStore answers the same lookup from its handle index.
func (m *MemStore) keyOfLocked(handle string) (string, bool) {
	if handle == "" {
		return "", false
	}
	for id, s := range m.byID {
		if s.Handle == handle {
			return id, true
		}
	}
	return "", false
}

// GetByHandle loads the session handle names.
func (m *MemStore) GetByHandle(_ context.Context, handle string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.keyOfLocked(handle)
	if !ok {
		return nil, ErrNotFound
	}
	return m.byID[id].Clone(), nil
}

// RotateByHandle re-keys the session handle names under a fresh key and a fresh handle, dropping
// both old values, and returns the new handle.
func (m *MemStore) RotateByHandle(_ context.Context, handle string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.keyOfLocked(handle)
	if !ok {
		return "", ErrNotFound
	}
	s := m.byID[id]
	newID := m.newID()
	s.ID = newID
	s.Handle = m.newHandle()
	s.LastUsedAt = m.now()
	m.byID[newID] = s
	delete(m.byID, id)
	return s.Handle, nil
}

// DeleteByHandle removes the session handle names.
func (m *MemStore) DeleteByHandle(_ context.Context, handle string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.keyOfLocked(handle)
	if !ok {
		return ErrNotFound
	}
	delete(m.byID, id)
	return nil
}

// WipeSubject deletes every session for (partition, subject).
func (m *MemStore) WipeSubject(_ context.Context, partition, subject string) (int64, error) {
	if partition == "" {
		return 0, ErrPartitionRequired
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for id, s := range m.byID {
		if s.Partition == partition && s.Subject == subject {
			delete(m.byID, id)
			n++
		}
	}
	return n, nil
}

// ListSubjectSessions returns every session for (partition, subject).
func (m *MemStore) ListSubjectSessions(_ context.Context, partition, subject string) ([]*Session, error) {
	if partition == "" {
		return nil, ErrPartitionRequired
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Session
	for _, s := range m.byID {
		if s.Partition == partition && s.Subject == subject {
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
