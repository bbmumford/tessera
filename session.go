// Package tessera is the scope-agnostic session system. It defines the universal SessionStore
// contract + a neutral Session record decoupled from any domain proto, so a consumer maps its own
// session type ↔ tessera.Session at the boundary. The org axis is opaque: a session's Owner is a
// scope string the store never interprets. The concrete store (a *sql.DB store, tursokv, or a
// mesh-RPC gateway) is a consumer-supplied SessionStore implementation; this package owns the
// contract + lifecycle, not the backend.
//
// The whole session system is ONE package: the neutral store contract (this file), an in-memory
// reference store (memstore.go), and the HTTP cookie/session lifecycle + attach middleware
// (cookie.go, middleware.go) driven by a Manager over an injected store, DomainResolver, and owner
// axis. A durable store is the one thing a consumer supplies. Every session field
// (id/user/owner/audience/provider/timestamps/device/allowed-apps+providers/mfa) and every operation
// (expiry/rotation/wipe/list) is preserved; only the type is neutral and the axis is opaque.
package tessera

import (
	"context"
	"time"
)

// Session is the neutral session record. Owner is the OPAQUE owner-scope; the store never interprets
// it. ExpiresAt is a pointer: nil means MaxAge/rolling semantics (no fixed expiry).
type Session struct {
	ID               string
	UserID           string
	Owner            string // opaque owner-scope (was ActiveOrgID) — meaning is the consumer's
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
// implementation; the auth node gets a Turso-backed one. Callers program against this type. The
// `owner` argument on WipeUser/ListUserSessions is the OPAQUE owner-scope (was tenantID).
type SessionStore interface {
	Create(ctx context.Context, s *Session) (id string, err error)
	Get(ctx context.Context, id string) (*Session, error)
	Touch(ctx context.Context, id string, newExpiry *time.Time) error
	Delete(ctx context.Context, id string) error
	Rotate(ctx context.Context, id string) (newID string, err error)
	WipeUser(ctx context.Context, owner, userID string) (int64, error)
	ListUserSessions(ctx context.Context, owner, userID string) ([]*Session, error)
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

// Backend is the legacy name for SessionStore, kept as an alias so existing callers compile.
type Backend = SessionStore
