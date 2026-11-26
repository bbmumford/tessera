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
	mu sync.Mutex
	// byDigest holds each session under its key's digest (digestUnder), with an empty ID:
	// like SQLStore, the store keeps no key.
	byDigest map[string]*Session
	// digests keys every digest under a key the store drew for itself: its sessions never leave
	// the process, so no other store needs to digest as it does.
	digests *sessionKeyDigests
	nextNum int64
	now     func() time.Time
	newID   func() string
	// newHandle makes each public handle; randomHandle outside a test.
	newHandle func() string
}

// NewMemStore builds an empty in-memory store, whose session-key digests are keyed by
// MinDigestKeyBytes random bytes it draws for itself.
func NewMemStore() *MemStore {
	key := make([]byte, MinDigestKeyBytes)
	_, _ = rand.Read(key)
	return &MemStore{byDigest: map[string]*Session{}, now: time.Now, newID: randomID, newHandle: randomHandle,
		digests: newSessionKeyDigests(DigestKeys{Current: key})}
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
	cp.ID = ""
	cp.Handle = m.newHandle()
	cp.ProofSecret = randomProofSecret()
	if cp.IssuedAt.IsZero() {
		cp.IssuedAt = m.now()
	}
	cp.LastUsedAt = cp.IssuedAt
	m.byDigest[m.digests.digest(id)] = cp
	return id, m.nextNum, nil
}

// Get loads a session by key, selecting on the key's digest; the session answers with id as its ID.
func (m *MemStore) Get(_ context.Context, id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byDigest[m.digests.digest(id)]
	if !ok {
		return nil, ErrNotFound
	}
	cp := s.Clone()
	cp.ID = id
	return cp, nil
}

func (m *MemStore) Touch(_ context.Context, id string, newExpiry *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byDigest[m.digests.digest(id)]
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
	digest := m.digests.digest(id)
	if _, ok := m.byDigest[digest]; !ok {
		return ErrNotFound
	}
	delete(m.byDigest, digest)
	return nil
}

// Rotate re-keys a session under a fresh ID and drops the old key (session-fixation defense),
// preserving the record. The handle is replaced with the key. Returns the new ID.
func (m *MemStore) Rotate(_ context.Context, id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	digest := m.digests.digest(id)
	s, ok := m.byDigest[digest]
	if !ok {
		return "", ErrNotFound
	}
	newID := m.newID()
	s.Handle = m.newHandle()
	s.ProofSecret = randomProofSecret()
	s.LastUsedAt = m.now()
	m.byDigest[m.digests.digest(newID)] = s
	delete(m.byDigest, digest)
	return newID, nil
}

// digestOfLocked returns the key digest of the session handle names. The caller holds m.mu. The
// scan is over every session because this store is the reference and test backend, whose session
// count is small; SQLStore answers the same lookup from its handle index.
func (m *MemStore) digestOfLocked(handle string) (string, bool) {
	if handle == "" {
		return "", false
	}
	for digest, s := range m.byDigest {
		if s.Handle == handle {
			return digest, true
		}
	}
	return "", false
}

// GetByHandle loads the session handle names, with no key (an empty ID).
func (m *MemStore) GetByHandle(_ context.Context, handle string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	digest, ok := m.digestOfLocked(handle)
	if !ok {
		return nil, ErrNotFound
	}
	return m.byDigest[digest].Clone(), nil
}

// RotateByHandle re-keys the session handle names under a fresh key and a fresh handle, dropping
// both old values, and returns the new handle.
func (m *MemStore) RotateByHandle(_ context.Context, handle string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	digest, ok := m.digestOfLocked(handle)
	if !ok {
		return "", ErrNotFound
	}
	s := m.byDigest[digest]
	s.Handle = m.newHandle()
	s.ProofSecret = randomProofSecret()
	s.LastUsedAt = m.now()
	m.byDigest[m.digests.digest(m.newID())] = s
	delete(m.byDigest, digest)
	return s.Handle, nil
}

// DeleteByHandle removes the session handle names.
func (m *MemStore) DeleteByHandle(_ context.Context, handle string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	digest, ok := m.digestOfLocked(handle)
	if !ok {
		return ErrNotFound
	}
	delete(m.byDigest, digest)
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
	for digest, s := range m.byDigest {
		if s.Partition == partition && s.Subject == subject {
			delete(m.byDigest, digest)
			n++
		}
	}
	return n, nil
}

// ListSubjectSessions returns every unexpired session for (partition, subject) at the store's
// current instant, each with no key (an empty ID): the set SQLStore lists, so a consumer tested
// against this store sees what the durable one answers.
func (m *MemStore) ListSubjectSessions(_ context.Context, partition, subject string) ([]*Session, error) {
	if partition == "" {
		return nil, ErrPartitionRequired
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	var out []*Session
	for _, s := range m.byDigest {
		if s.Partition == partition && s.Subject == subject && (s.ExpiresAt == nil || s.ExpiresAt.After(now)) {
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
	for digest, s := range m.byDigest {
		if s.ExpiresAt != nil && s.ExpiresAt.Before(before) {
			delete(m.byDigest, digest)
			n++
		}
	}
	return n, nil
}
