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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ErrPartitionRequired is returned by every store operation that writes or selects sessions by
// partition when the partition is empty. The check runs before any row is read or written, so an
// unresolved partition can neither create an unpartitioned session nor list or wipe one.
var ErrPartitionRequired = errors.New("tessera: partition is required")

// Session is the neutral session record. Subject is the authenticated principal's subject and
// Partition the partition the session was minted in; the store keys on both and interprets neither.
// ExpiresAt is a pointer: nil means MaxAge/rolling semantics (no fixed expiry).
//
// ID is the session key: the secret a browser's cookie carries, which proves the session by
// itself. A store keeps only the key's digest (digestUnder), never the key: Create,
// CreateWithID and Rotate return the key, Get answers with the key it was given, and a session
// read by its handle or listed for its subject carries no key (ID is empty). Handle is the
// session's public handle: a second value, not secret, which a signed token
// carries as its sid and which every record a session is named in outside the store holds. A
// handle proves nothing alone; it selects the record for a caller a token already proved. The
// store sets it at creation, ignoring any value the caller supplies, and replaces it together with
// the key at every rotation, so nothing that named the old session names the new one.
type Session struct {
	ID               string
	Handle           string
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
	// SecondFactor is true when the sign-in that minted the session completed a
	// second factor in it. Only creation sets it (Manager.CreateSecondFactorAppSession);
	// Touch and Rotate keep the row's value, so a session minted without one never
	// gains it.
	SecondFactor bool
	// Native is true when the session was minted for a native app at its sign-in code exchange
	// (Manager.CreateNativeAppSession): the app holds its id inside a bearer token, not a browser
	// cookie. Only creation sets it, and Touch and Rotate keep the row's value. An edge that admits
	// only a browser session refuses one carrying it, whatever carried its id to the edge.
	Native bool
	// ProofSecret keys the anti-CSRF proof a cookie-authenticated change carries (library
	// security/requestproof): the page the platform serves holds it and MACs each change with it,
	// and library httpscope RequireRequestProof verifies that MAC against this value. The store sets
	// it at creation, ignoring any value the caller supplies, and replaces it with the key at every
	// rotation, so a page holding the old session's secret proves nothing for the new one. It is
	// never a credential alone: a proof is checked only on a request the session's cookie proved.
	ProofSecret string
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
// key is the bearer secret the cookie carries. A store selects on the key's digest
// (digestUnder) and keeps no key, so a session it answers by handle or by subject has an empty
// ID.
//
// GetByHandle, RotateByHandle and DeleteByHandle select by the session's public handle instead:
// the session check, rotation and revoke of a caller a signed token proved, whose token names the
// session by its handle and never by its key. Rotate and RotateByHandle both replace the key and
// the handle; RotateByHandle returns the new handle. An unknown handle is ErrNotFound.
type SessionStore interface {
	Create(ctx context.Context, s *Session) (id string, err error)
	Get(ctx context.Context, id string) (*Session, error)
	Touch(ctx context.Context, id string, newExpiry *time.Time) error
	Delete(ctx context.Context, id string) error
	Rotate(ctx context.Context, id string) (newID string, err error)
	WipeSubject(ctx context.Context, partition, subject string) (int64, error)
	ListSubjectSessions(ctx context.Context, partition, subject string) ([]*Session, error)
	GetByHandle(ctx context.Context, handle string) (*Session, error)
	RotateByHandle(ctx context.Context, handle string) (newHandle string, err error)
	DeleteByHandle(ctx context.Context, handle string) error
}

// MinDigestKeyBytes is the shortest key a store digests session keys under: the width of the
// HMAC-SHA256 output, so a key is never the weaker half of the digest.
const MinDigestKeyBytes = 32

// ErrDigestKey is returned by OpenSQLStore for DigestKeys no store digests under: a current key
// shorter than MinDigestKeyBytes, or a previous key without its end time (or the reverse), shorter
// than MinDigestKeyBytes or equal to the current key.
var ErrDigestKey = errors.New("tessera: session-key digest keys are not usable")

// DigestKeys are the keys a store digests session keys under. Current keys every digest the store
// writes and is the first a lookup by key tries. Previous is the key Current replaced: until
// PreviousUntil a lookup that finds no session under Current tries Previous, and a session found
// under it is re-keyed under Current in the same call, so changing the key ends no session that is
// used before PreviousUntil. Every process that opens one sessions database holds the same keys,
// because each selects a session by the digest another wrote.
type DigestKeys struct {
	Current       []byte
	Previous      []byte
	PreviousUntil time.Time
}

// check reports why k cannot key a store's digests, or nil.
func (k DigestKeys) check() error {
	if len(k.Current) < MinDigestKeyBytes {
		return fmt.Errorf("%w: the current key holds %d bytes, fewer than %d", ErrDigestKey, len(k.Current), MinDigestKeyBytes)
	}
	switch {
	case len(k.Previous) == 0 && k.PreviousUntil.IsZero():
		return nil
	case len(k.Previous) == 0:
		return fmt.Errorf("%w: an end time is set with no previous key", ErrDigestKey)
	case k.PreviousUntil.IsZero():
		return fmt.Errorf("%w: a previous key is set with no end time", ErrDigestKey)
	case len(k.Previous) < MinDigestKeyBytes:
		return fmt.Errorf("%w: the previous key holds %d bytes, fewer than %d", ErrDigestKey, len(k.Previous), MinDigestKeyBytes)
	case hmac.Equal(k.Previous, k.Current):
		return fmt.Errorf("%w: the previous key equals the current key", ErrDigestKey)
	}
	return nil
}

// sessionKeyDigests is a store's copy of its DigestKeys, the one source of every digest the store
// writes or selects on.
type sessionKeyDigests struct {
	current       []byte
	previous      []byte
	previousUntil time.Time
}

func newSessionKeyDigests(k DigestKeys) *sessionKeyDigests {
	d := &sessionKeyDigests{current: append([]byte(nil), k.Current...)}
	if len(k.Previous) > 0 {
		d.previous = append([]byte(nil), k.Previous...)
		d.previousUntil = k.PreviousUntil
	}
	return d
}

// digest is the digest a store writes for key: the digest under the current key.
func (d *sessionKeyDigests) digest(key string) string {
	return digestUnder(d.current, key)
}

// lookups are the digests a lookup of key tries at now, in order: the current key's, then, before
// previousUntil, the previous key's. A store re-keys a session it finds under any but the first.
func (d *sessionKeyDigests) lookups(key string, now time.Time) []string {
	out := []string{digestUnder(d.current, key)}
	if len(d.previous) > 0 && now.Before(d.previousUntil) {
		out = append(out, digestUnder(d.previous, key))
	}
	return out
}

// digestUnder is what a store keeps of a session key, and what it selects the key's session by:
// HMAC-SHA256 of the key under digestKey, in hex. A party who can read the table, a backup or a
// replica learns no session from a row, and a party who can write it cannot place a row for a key
// of its choosing, since neither can compute a digest without digestKey. A lookup by key digests
// the key it is given and selects on the digest, so the key is compared nowhere, in the store's
// code or its database. A nil digestKey is the store NewSQLStore opens, whose digest is the key's
// SHA-256 in hex.
//
// TODO: the nil digestKey form goes when every opener of a sessions database passes DigestKeys to
// OpenSQLStore.
func digestUnder(digestKey []byte, key string) string {
	if digestKey == nil {
		sum := sha256.Sum256([]byte(key))
		return hex.EncodeToString(sum[:])
	}
	mac := hmac.New(sha256.New, digestKey)
	mac.Write([]byte(key))
	return hex.EncodeToString(mac.Sum(nil))
}

// handlePrefix begins every handle, so a handle read in a log or a record is never taken for a
// session key, which is hex alone.
const handlePrefix = "sess_"

// randomHandle is a fresh public handle: handlePrefix and 16 random bytes in hex. It is random
// rather than a counter so a handle says nothing about how many sessions exist or when one began.
func randomHandle() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return handlePrefix + hex.EncodeToString(b)
}

// randomProofSecret is a fresh proof secret: 32 random bytes in unpadded base64url, the form a
// page imports as an HMAC key from its UTF-8 bytes.
func randomProofSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
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
