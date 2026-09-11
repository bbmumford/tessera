package tessera

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// SQLStore is the durable LocalSessionStore over any database/sql driver. The package imports only
// database/sql; the app supplies the opened *sql.DB and registers the driver (go-libsql/Turso,
// modernc SQLite, Postgres, …), so tessera pulls in no driver dependency. It persists every Session
// field. Partition and subject are plain columns the store never interprets; WipeSubject and
// ListSubjectSessions select on the pair. The SessionStore interface admits a mesh-gateway or
// in-memory (MemStore) backend instead. Times are Unix seconds; a nil ExpiresAt is stored NULL
// (MaxAge/rolling).
type SQLStore struct {
	db    *sql.DB
	now   func() time.Time
	newID func() string
}

// NewSQLStore builds a store over an opened *sql.DB. Call InitSchema once before use.
func NewSQLStore(db *sql.DB) *SQLStore {
	return &SQLStore{db: db, now: time.Now, newID: randomSessionKey}
}

var (
	_ SessionStore      = (*SQLStore)(nil)
	_ LocalSessionStore = (*SQLStore)(nil)
)

func randomSessionKey() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// InitSchema creates the sessions table + indexes (idempotent); run once at boot before use.
func (s *SQLStore) InitSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS tessera_sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_key TEXT UNIQUE NOT NULL,
			subject TEXT NOT NULL,
			partition TEXT NOT NULL CHECK (partition <> ''),
			audience_root TEXT NOT NULL DEFAULT '',
			provider TEXT NOT NULL DEFAULT '',
			issued_at INTEGER NOT NULL DEFAULT 0,
			expires_at INTEGER,
			last_used_at INTEGER NOT NULL DEFAULT 0,
			browser TEXT NOT NULL DEFAULT '',
			device_type TEXT NOT NULL DEFAULT '',
			platform TEXT NOT NULL DEFAULT '',
			allowed_apps TEXT NOT NULL DEFAULT '[]',
			allowed_providers TEXT NOT NULL DEFAULT '[]',
			require_mfa INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_tessera_sessions_partition_subject ON tessera_sessions(partition, subject)`,
		`CREATE INDEX IF NOT EXISTS idx_tessera_sessions_expires ON tessera_sessions(expires_at)`,
	}
	for _, q := range stmts {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func jsonStrings(ss []string) string {
	if ss == nil {
		ss = []string{}
	}
	b, _ := json.Marshal(ss)
	return string(b)
}

func unjsonStrings(s string) []string {
	var out []string
	if s == "" || json.Unmarshal([]byte(s), &out) != nil {
		return nil
	}
	return out
}

func expiryArg(e *time.Time) any {
	if e == nil {
		return nil
	}
	return e.Unix()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *SQLStore) insert(ctx context.Context, sess *Session) (key string, numID int64, err error) {
	if sess == nil {
		return "", 0, errors.New("tessera: nil session")
	}
	if sess.Partition == "" {
		return "", 0, ErrPartitionRequired
	}
	cp := sess.Clone()
	key = cp.ID
	if key == "" {
		key = s.newID()
	}
	now := s.now()
	if cp.IssuedAt.IsZero() {
		cp.IssuedAt = now
	}
	if cp.LastUsedAt.IsZero() {
		cp.LastUsedAt = cp.IssuedAt
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO tessera_sessions
			(session_key, subject, partition, audience_root, provider, issued_at, expires_at, last_used_at, browser, device_type, platform, allowed_apps, allowed_providers, require_mfa)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key, cp.Subject, cp.Partition, cp.AudienceRoot, cp.Provider, cp.IssuedAt.Unix(), expiryArg(cp.ExpiresAt), cp.LastUsedAt.Unix(),
		cp.Browser, cp.DeviceType, cp.Platform, jsonStrings(cp.AllowedApps), jsonStrings(cp.AllowedProviders), boolToInt(cp.RequireMFA))
	if err != nil {
		return "", 0, err
	}
	numID, _ = res.LastInsertId()
	return key, numID, nil
}

// Create inserts a session and returns its key (the cookie value).
func (s *SQLStore) Create(ctx context.Context, sess *Session) (string, error) {
	key, _, err := s.insert(ctx, sess)
	return key, err
}

// CreateWithID inserts a session and returns both the key and the numeric row id (for app/JWT logins
// whose tokens link to the session without a browser cookie).
func (s *SQLStore) CreateWithID(ctx context.Context, sess *Session) (string, int64, error) {
	return s.insert(ctx, sess)
}

const sessionSelect = `SELECT session_key, subject, partition, audience_root, provider, issued_at, expires_at, last_used_at, browser, device_type, platform, allowed_apps, allowed_providers, require_mfa FROM tessera_sessions`

func scanSession(sc interface{ Scan(...any) error }) (*Session, error) {
	var v Session
	var issued, lastUsed int64
	var expires sql.NullInt64
	var apps, providers string
	var mfa int64
	if err := sc.Scan(&v.ID, &v.Subject, &v.Partition, &v.AudienceRoot, &v.Provider, &issued, &expires, &lastUsed,
		&v.Browser, &v.DeviceType, &v.Platform, &apps, &providers, &mfa); err != nil {
		return nil, err
	}
	v.IssuedAt = time.Unix(issued, 0)
	v.LastUsedAt = time.Unix(lastUsed, 0)
	if expires.Valid {
		t := time.Unix(expires.Int64, 0)
		v.ExpiresAt = &t
	}
	v.AllowedApps = unjsonStrings(apps)
	v.AllowedProviders = unjsonStrings(providers)
	v.RequireMFA = mfa != 0
	return &v, nil
}

// Get loads a session by key.
func (s *SQLStore) Get(ctx context.Context, id string) (*Session, error) {
	v, err := scanSession(s.db.QueryRowContext(ctx, sessionSelect+` WHERE session_key = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

// Touch refreshes last_used_at and, when newExpiry is non-nil, the expiry.
func (s *SQLStore) Touch(ctx context.Context, id string, newExpiry *time.Time) error {
	var res sql.Result
	var err error
	if newExpiry != nil {
		res, err = s.db.ExecContext(ctx, `UPDATE tessera_sessions SET last_used_at = ?, expires_at = ? WHERE session_key = ?`, s.now().Unix(), newExpiry.Unix(), id)
	} else {
		res, err = s.db.ExecContext(ctx, `UPDATE tessera_sessions SET last_used_at = ? WHERE session_key = ?`, s.now().Unix(), id)
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes a session by key.
func (s *SQLStore) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM tessera_sessions WHERE session_key = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Rotate re-keys a session under a fresh key and drops the old key (session-fixation defense),
// preserving the record. Returns the new key.
func (s *SQLStore) Rotate(ctx context.Context, id string) (string, error) {
	newID := s.newID()
	res, err := s.db.ExecContext(ctx, `UPDATE tessera_sessions SET session_key = ?, last_used_at = ? WHERE session_key = ?`, newID, s.now().Unix(), id)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrNotFound
	}
	return newID, nil
}

// WipeSubject deletes every session for (partition, subject).
func (s *SQLStore) WipeSubject(ctx context.Context, partition, subject string) (int64, error) {
	if partition == "" {
		return 0, ErrPartitionRequired
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM tessera_sessions WHERE partition = ? AND subject = ?`, partition, subject)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ListSubjectSessions returns every unexpired session for (partition, subject) at the current instant.
func (s *SQLStore) ListSubjectSessions(ctx context.Context, partition, subject string) ([]*Session, error) {
	if partition == "" {
		return nil, ErrPartitionRequired
	}
	rows, err := s.db.QueryContext(ctx, sessionSelect+` WHERE partition = ? AND subject = ? AND (expires_at IS NULL OR expires_at > ?)`, partition, subject, s.now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Session
	for rows.Next() {
		v, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// PurgeExpired deletes sessions whose expires_at is before the given instant (a NULL expiry is
// MaxAge/rolling and never purged).
func (s *SQLStore) PurgeExpired(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM tessera_sessions WHERE expires_at IS NOT NULL AND expires_at < ?`, before.Unix())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
