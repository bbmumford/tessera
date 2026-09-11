// Package tessera is the session system. It defines the SessionStore contract and a neutral Session
// record, so a consumer maps its own session type to tessera.Session at its boundary. A session binds
// a subject to a partition; both are opaque strings the store keys on and never interprets.
//
// The whole session system is ONE package: the store contract (this file), an in-memory store
// (memstore.go), a database/sql store (sqlstore.go), a read-through cache for a gateway whose store is
// remote (cachingstore.go), and the HTTP cookie lifecycle and attach middleware (cookie.go,
// middleware.go) driven by a Manager over an injected store, DomainResolver and partition resolver.
package tessera

import (
	"context"
	"errors"
	"time"
)

// ErrPartitionRequired is returned by every store operation that writes or selects sessions by
// partition when the partition is empty. The check runs before any row is read or written, so an
// unresolved partition can neither create an unpartitioned session nor list or wipe one.
var ErrPartitionRequired = errors.New("tessera: partition is required")

// Session is the neutral session record. Subject is the authenticated principal's subject and
// Partition the partition the session was minted in; the store keys on both and interprets neither.
// ExpiresAt is a pointer: nil means MaxAge/rolling semantics (no fixed expiry).
type Session struct {
	ID               string
	Subject          string
	Partition        string // required: Create refuses an empty one
	AudienceRoot     string // eTLD+1 for app-local sessions; empty for central
	Provider         string // auth provider (email/github/google/msft/…)
	IssuedAt         time.Time
	ExpiresAt        *time.Time // nil ⇒ MaxAge semantics
	LastUsedAt       time.Time
	Browser          string
	DeviceType       string
	Platform         string
	AllowedApps      []string
	AllowedProviders []string
	RequireMFA       bool
}

// Clone returns a deep copy (slices copied) so a caller mutation cannot alias stored state.
func (s *Session) Clone() *Session {
	if s == nil {
		return nil
	}
	cp := *s
	if s.ExpiresAt != nil {
		e := *s.ExpiresAt
		cp.ExpiresAt = &e
	}
	cp.AllowedApps = append([]string(nil), s.AllowedApps...)
	cp.AllowedProviders = append([]string(nil), s.AllowedProviders...)
	return &cp
}

// SessionStore is the universal session-persistence API — every operation works from every
// endpoint, whether or not the caller owns the platform DB. A thin gateway gets a mesh-RPC-backed
// implementation; the auth node gets a Turso-backed one. Callers program against this type.
// Create, WipeSubject and ListSubjectSessions return ErrPartitionRequired for an empty partition
// before touching any row; Get, Touch, Delete and Rotate select by session key alone, because the
// key is the bearer secret the cookie carries.
type SessionStore interface {
	Create(ctx context.Context, s *Session) (id string, err error)
	Get(ctx context.Context, id string) (*Session, error)
	Touch(ctx context.Context, id string, newExpiry *time.Time) error
	Delete(ctx context.Context, id string) error
	Rotate(ctx context.Context, id string) (newID string, err error)
	WipeSubject(ctx context.Context, partition, subject string) (int64, error)
	ListSubjectSessions(ctx context.Context, partition, subject string) ([]*Session, error)
}

// LocalSessionStore extends SessionStore with auth-node-only operations that need a numeric DB id
// or a fleet-wide janitorial pass, so a thin gateway does not implement them. Type-assert from
// SessionStore where these are needed.
type LocalSessionStore interface {
	SessionStore
	// CreateWithID creates a session and returns both the session key and numeric ID (for
	// app/JWT logins whose tokens link to sessions without browser cookies).
	CreateWithID(ctx context.Context, s *Session) (sessionKey string, sessionID int64, err error)
	// PurgeExpired deletes sessions whose ExpiresAt is before the given instant.
	PurgeExpired(ctx context.Context, before time.Time) (int64, error)
}
