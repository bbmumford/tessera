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
	// newHandle makes each public handle; randomHandle outside a test.
	newHandle func() string
}

// NewSQLStore builds a store over an opened *sql.DB. Call InitSchema once before use.
func NewSQLStore(db *sql.DB) *SQLStore {
	return &SQLStore{db: db, now: time.Now, newID: randomSessionKey, newHandle: randomHandle}
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
			require_mfa INTEGER NOT NULL DEFAULT 0,
			second_factor INTEGER NOT NULL DEFAULT 0,
			native INTEGER NOT NULL DEFAULT 0,
			handle TEXT,
			proofSecret TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_tessera_sessions_partition_subject ON tessera_sessions(partition, subject)`,
		`CREATE INDEX IF NOT EXISTS idx_tessera_sessions_expires ON tessera_sessions(expires_at)`,
	}
	for _, q := range stmts {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	for _, column := range markColumns {
		if err := s.addMarkColumn(ctx, column); err != nil {
			return err
		}
	}
	if err := s.addHandles(ctx); err != nil {
		return err
	}
	return s.addProofSecrets(ctx)
}

// addHandles leaves every tessera_sessions table InitSchema ran over holding a public handle on
// every row and a unique index over them. A table created before the column gains it, and each row
// without a handle is given one, so a session minted before handles existed is named by its token's
// next refresh like any other. The column is nullable because SQLite adds no column with a UNIQUE
// constraint; the index tesseraSessionsHandle holds the uniqueness instead, and every insert and
// rotation writes a handle. The rows are read first and written after, so no row is updated while
// its query is still open.
func (s *SQLStore) addHandles(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT handle FROM tessera_sessions LIMIT 0`)
	if err == nil {
		err = rows.Close()
	} else {
		_, err = s.db.ExecContext(ctx, `ALTER TABLE tessera_sessions ADD COLUMN handle TEXT`)
	}
	if err != nil {
		return err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT id FROM tessera_sessions WHERE handle IS NULL OR handle = ''`)
	if err != nil {
		return err
	}
	var bare []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		bare = append(bare, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, id := range bare {
		if _, err := s.db.ExecContext(ctx, `UPDATE tessera_sessions SET handle = ? WHERE id = ? AND (handle IS NULL OR handle = '')`, s.newHandle(), id); err != nil {
			return err
		}
	}
	_, err = s.db.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS tesseraSessionsHandle ON tessera_sessions(handle)`)
	return err
}

// addProofSecrets leaves every tessera_sessions table InitSchema ran over holding a proof secret
// (Session.ProofSecret) on every row: a table created before the column gains it, and each row
// whose secret is empty is given a fresh one, so a session minted before secrets existed can prove
// a change from its next page load without signing in again. The rows are read first and written
// after, so no row is updated while its query is still open.
func (s *SQLStore) addProofSecrets(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT proofSecret FROM tessera_sessions LIMIT 0`)
	if err == nil {
		err = rows.Close()
	} else {
		_, err = s.db.ExecContext(ctx, `ALTER TABLE tessera_sessions ADD COLUMN proofSecret TEXT NOT NULL DEFAULT ''`)
	}
	if err != nil {
		return err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT id FROM tessera_sessions WHERE proofSecret = ''`)
	if err != nil {
		return err
	}
	var bare []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		bare = append(bare, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, id := range bare {
		if _, err := s.db.ExecContext(ctx, `UPDATE tessera_sessions SET proofSecret = ? WHERE id = ? AND proofSecret = ''`, randomProofSecret(), id); err != nil {
			return err
		}
	}
	return nil
}

// markColumns are the creation marks a tessera_sessions table created before
// them lacks: Session.SecondFactor and Session.Native. Each is an INTEGER
// NOT NULL DEFAULT 0, so a row already there reads false.
var markColumns = []string{"second_factor", "native"}

// addMarkColumn adds column to a tessera_sessions table created without it, so
// InitSchema leaves every table it ran over holding the columns insert and
// sessionSelect name. A table holding the column is left as it is. The probe is
// a SELECT rather than a catalog read because the store runs over any
// database/sql driver, and each names its catalog differently. column is one of
// markColumns, never caller input.
func (s *SQLStore) addMarkColumn(ctx context.Context, column string) error {
	rows, err := s.db.QueryContext(ctx, `SELECT `+column+` FROM tessera_sessions LIMIT 0`)
	if err == nil {
		return rows.Close()
	}
	_, err = s.db.ExecContext(ctx, `ALTER TABLE tessera_sessions ADD COLUMN `+column+` INTEGER NOT NULL DEFAULT 0`)
	return err
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
			(session_key, handle, subject, partition, audience_root, provider, issued_at, expires_at, last_used_at, browser, device_type, platform, allowed_apps, allowed_providers, require_mfa, second_factor, native, proofSecret)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key, s.newHandle(), cp.Subject, cp.Partition, cp.AudienceRoot, cp.Provider, cp.IssuedAt.Unix(), expiryArg(cp.ExpiresAt), cp.LastUsedAt.Unix(),
		cp.Browser, cp.DeviceType, cp.Platform, jsonStrings(cp.AllowedApps), jsonStrings(cp.AllowedProviders), boolToInt(cp.RequireMFA), boolToInt(cp.SecondFactor), boolToInt(cp.Native), randomProofSecret())
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

const sessionSelect = `SELECT session_key, handle, subject, partition, audience_root, provider, issued_at, expires_at, last_used_at, browser, device_type, platform, allowed_apps, allowed_providers, require_mfa, second_factor, native, proofSecret FROM tessera_sessions`

func scanSession(sc interface{ Scan(...any) error }) (*Session, error) {
	var v Session
	var issued, lastUsed int64
	var expires sql.NullInt64
	var apps, providers string
	var mfa, secondFactor, native int64
	var handle sql.NullString
	if err := sc.Scan(&v.ID, &handle, &v.Subject, &v.Partition, &v.AudienceRoot, &v.Provider, &issued, &expires, &lastUsed,
		&v.Browser, &v.DeviceType, &v.Platform, &apps, &providers, &mfa, &secondFactor, &native, &v.ProofSecret); err != nil {
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
	v.SecondFactor = secondFactor != 0
	v.Native = native != 0
	v.Handle = handle.String
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
// preserving the record. The handle and the proof secret are replaced with the key. Returns the
// new key.
func (s *SQLStore) Rotate(ctx context.Context, id string) (string, error) {
	newID := s.newID()
	res, err := s.db.ExecContext(ctx, `UPDATE tessera_sessions SET session_key = ?, handle = ?, proofSecret = ?, last_used_at = ? WHERE session_key = ?`, newID, s.newHandle(), randomProofSecret(), s.now().Unix(), id)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrNotFound
	}
	return newID, nil
}

// GetByHandle loads the session handle names. An empty handle names none.
func (s *SQLStore) GetByHandle(ctx context.Context, handle string) (*Session, error) {
	if handle == "" {
		return nil, ErrNotFound
	}
	v, err := scanSession(s.db.QueryRowContext(ctx, sessionSelect+` WHERE handle = ?`, handle))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

// RotateByHandle re-keys the session handle names under a fresh key and a fresh handle in one
// statement, dropping both old values, and returns the new handle. The single UPDATE is what makes
// a token refresh single use: of two refreshes presenting one handle, one updates the row and the
// other finds no row to update.
func (s *SQLStore) RotateByHandle(ctx context.Context, handle string) (string, error) {
	if handle == "" {
		return "", ErrNotFound
	}
	newHandle := s.newHandle()
	res, err := s.db.ExecContext(ctx, `UPDATE tessera_sessions SET session_key = ?, handle = ?, proofSecret = ?, last_used_at = ? WHERE handle = ?`, s.newID(), newHandle, randomProofSecret(), s.now().Unix(), handle)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrNotFound
	}
	return newHandle, nil
}

// DeleteByHandle removes the session handle names.
func (s *SQLStore) DeleteByHandle(ctx context.Context, handle string) error {
	if handle == "" {
		return ErrNotFound
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM tessera_sessions WHERE handle = ?`, handle)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
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
