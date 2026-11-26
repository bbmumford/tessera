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
// (MaxAge/rolling). A row holds its session key's digest (digestUnder), never the key, and
// every lookup by key selects on the digest.
type SQLStore struct {
	db    *sql.DB
	now   func() time.Time
	newID func() string
	// newHandle makes each public handle; randomHandle outside a test.
	newHandle func() string
	// digests holds the keys every session-key digest is made under.
	digests *sessionKeyDigests
}

// NewSQLStore builds a store over an opened *sql.DB whose digests are keyed by nothing: each row
// holds its key's SHA-256. Call InitSchema once before use.
//
// TODO: NewSQLStore goes, and a store opened without DigestKeys is refused, once every opener of a
// sessions database calls OpenSQLStore.
func NewSQLStore(db *sql.DB) *SQLStore {
	return &SQLStore{db: db, now: time.Now, newID: randomSessionKey, newHandle: randomHandle, digests: &sessionKeyDigests{}}
}

// OpenSQLStore builds a store over an opened *sql.DB that keeps HMAC-SHA256 digests of its session
// keys under keys (DigestKeys), or returns ErrDigestKey for keys it cannot digest under. Every
// process opening one sessions database passes the same keys. Call InitSchema once before use.
func OpenSQLStore(db *sql.DB, keys DigestKeys) (*SQLStore, error) {
	if err := keys.check(); err != nil {
		return nil, err
	}
	s := NewSQLStore(db)
	s.digests = newSessionKeyDigests(keys)
	return s, nil
}

var (
	_ SessionStore      = (*SQLStore)(nil)
	_ LocalSessionStore = (*SQLStore)(nil)
)

// sessionKeyBytes is how many random bytes a session key SQLStore mints holds; the key is their
// lower-case hex.
const sessionKeyBytes = 24

// ErrSessionKeyForm is returned by Create and CreateWithID for a session whose ID, the key a caller
// chose for it, is not the form the store mints: sessionKeyBytes random bytes in lower-case hex.
// A store that kept any caller-chosen key would let a consumer that forwards a client's value into
// Session.ID mint a session under a key the client already knows.
var ErrSessionKeyForm = errors.New("tessera: a chosen session key is not the minted form")

func randomSessionKey() string {
	b := make([]byte, sessionKeyBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// mintedKeyForm reports whether key has the form randomSessionKey mints.
func mintedKeyForm(key string) bool {
	if len(key) != 2*sessionKeyBytes {
		return false
	}
	for i := 0; i < len(key); i++ {
		if c := key[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// InitSchema creates the sessions table + indexes (idempotent); run once at boot before use.
func (s *SQLStore) InitSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS tesseraSessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			sessionKeyDigest TEXT UNIQUE NOT NULL,
			subject TEXT NOT NULL,
			partition TEXT NOT NULL CHECK (partition <> ''),
			audienceRoot TEXT NOT NULL DEFAULT '',
			provider TEXT NOT NULL DEFAULT '',
			issuedAt INTEGER NOT NULL DEFAULT 0,
			expiresAt INTEGER,
			lastUsedAt INTEGER NOT NULL DEFAULT 0,
			browser TEXT NOT NULL DEFAULT '',
			deviceType TEXT NOT NULL DEFAULT '',
			platform TEXT NOT NULL DEFAULT '',
			allowedApps TEXT NOT NULL DEFAULT '[]',
			allowedProviders TEXT NOT NULL DEFAULT '[]',
			requireMfa INTEGER NOT NULL DEFAULT 0,
			secondFactor INTEGER NOT NULL DEFAULT 0,
			native INTEGER NOT NULL DEFAULT 0,
			handle TEXT,
			proofSecret TEXT NOT NULL DEFAULT '',
			partitionVia TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idxTesseraSessionsPartitionSubject ON tesseraSessions(partition, subject)`,
		`CREATE INDEX IF NOT EXISTS idxTesseraSessionsExpires ON tesseraSessions(expiresAt)`,
	}
	for _, q := range stmts {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	if err := s.digestSessionKeys(ctx); err != nil {
		return err
	}
	for _, column := range markColumns {
		if err := s.addMarkColumn(ctx, column); err != nil {
			return err
		}
	}
	if err := s.addHandles(ctx); err != nil {
		return err
	}
	if err := s.addPartitionVia(ctx); err != nil {
		return err
	}
	return s.addProofSecrets(ctx)
}

// addPartitionVia adds Session.PartitionVia's column to a tesseraSessions table created without
// it, so InitSchema leaves every table it ran over holding the columns insert and sessionSelect
// name; a row already there reads "", a session whose creator named no rung. A table holding the
// column is left as it is, probed by a SELECT as addMarkColumn's are.
func (s *SQLStore) addPartitionVia(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT partitionVia FROM tesseraSessions LIMIT 0`)
	if err == nil {
		return rows.Close()
	}
	_, err = s.db.ExecContext(ctx, `ALTER TABLE tesseraSessions ADD COLUMN partitionVia TEXT NOT NULL DEFAULT ''`)
	return err
}

// digestSessionKeys leaves every tesseraSessions table InitSchema ran over keeping session-key
// digests alone. A table whose key column is sessionKey holds each key itself: in one transaction
// that column is renamed sessionKeyDigest and each row's key is replaced by its digest, so every
// session stays valid under the cookie that carries its key and no key is left in the table. A
// table holding sessionKeyDigest is left as it is; one holding neither column fails the rename, and
// InitSchema returns that error. The rows are read first and written after, so no row is updated
// while its query is still open.
func (s *SQLStore) digestSessionKeys(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT sessionKeyDigest FROM tesseraSessions LIMIT 0`)
	if err == nil {
		return rows.Close()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `ALTER TABLE tesseraSessions RENAME COLUMN sessionKey TO sessionKeyDigest`); err != nil {
		return err
	}
	rows, err = tx.QueryContext(ctx, `SELECT id, sessionKeyDigest FROM tesseraSessions`)
	if err != nil {
		return err
	}
	type keyedRow struct {
		id  int64
		key string
	}
	var keyed []keyedRow
	for rows.Next() {
		var r keyedRow
		if err := rows.Scan(&r.id, &r.key); err != nil {
			_ = rows.Close()
			return err
		}
		keyed = append(keyed, r)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, r := range keyed {
		if _, err := tx.ExecContext(ctx, `UPDATE tesseraSessions SET sessionKeyDigest = ? WHERE id = ?`, s.digests.digest(r.key), r.id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// addHandles leaves every tesseraSessions table InitSchema ran over holding a public handle on
// every row and a unique index over them. A table created before the column gains it, and each row
// without a handle is given one, so a session minted before handles existed is named by its token's
// next refresh like any other. The column is nullable because SQLite adds no column with a UNIQUE
// constraint; the index tesseraSessionsHandle holds the uniqueness instead, and every insert and
// rotation writes a handle. The rows are read first and written after, so no row is updated while
// its query is still open.
func (s *SQLStore) addHandles(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT handle FROM tesseraSessions LIMIT 0`)
	if err == nil {
		err = rows.Close()
	} else {
		_, err = s.db.ExecContext(ctx, `ALTER TABLE tesseraSessions ADD COLUMN handle TEXT`)
	}
	if err != nil {
		return err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT id FROM tesseraSessions WHERE handle IS NULL OR handle = ''`)
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
		if _, err := s.db.ExecContext(ctx, `UPDATE tesseraSessions SET handle = ? WHERE id = ? AND (handle IS NULL OR handle = '')`, s.newHandle(), id); err != nil {
			return err
		}
	}
	_, err = s.db.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS tesseraSessionsHandle ON tesseraSessions(handle)`)
	return err
}

// addProofSecrets leaves every tesseraSessions table InitSchema ran over holding a proof secret
// (Session.ProofSecret) on every row: a table created before the column gains it, and each row
// whose secret is empty is given a fresh one, so a session minted before secrets existed can prove
// a change from its next page load without signing in again. The rows are read first and written
// after, so no row is updated while its query is still open.
func (s *SQLStore) addProofSecrets(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT proofSecret FROM tesseraSessions LIMIT 0`)
	if err == nil {
		err = rows.Close()
	} else {
		_, err = s.db.ExecContext(ctx, `ALTER TABLE tesseraSessions ADD COLUMN proofSecret TEXT NOT NULL DEFAULT ''`)
	}
	if err != nil {
		return err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT id FROM tesseraSessions WHERE proofSecret = ''`)
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
		if _, err := s.db.ExecContext(ctx, `UPDATE tesseraSessions SET proofSecret = ? WHERE id = ? AND proofSecret = ''`, randomProofSecret(), id); err != nil {
			return err
		}
	}
	return nil
}

// markColumns are the creation marks a tesseraSessions table created before
// them lacks: Session.SecondFactor and Session.Native. Each is an INTEGER
// NOT NULL DEFAULT 0, so a row already there reads false.
var markColumns = []string{"secondFactor", "native"}

// addMarkColumn adds column to a tesseraSessions table created without it, so
// InitSchema leaves every table it ran over holding the columns insert and
// sessionSelect name. A table holding the column is left as it is. The probe is
// a SELECT rather than a catalog read because the store runs over any
// database/sql driver, and each names its catalog differently. column is one of
// markColumns, never caller input.
func (s *SQLStore) addMarkColumn(ctx context.Context, column string) error {
	rows, err := s.db.QueryContext(ctx, `SELECT `+column+` FROM tesseraSessions LIMIT 0`)
	if err == nil {
		return rows.Close()
	}
	_, err = s.db.ExecContext(ctx, `ALTER TABLE tesseraSessions ADD COLUMN `+column+` INTEGER NOT NULL DEFAULT 0`)
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
	} else if !mintedKeyForm(key) {
		return "", 0, ErrSessionKeyForm
	}
	now := s.now()
	if cp.IssuedAt.IsZero() {
		cp.IssuedAt = now
	}
	if cp.LastUsedAt.IsZero() {
		cp.LastUsedAt = cp.IssuedAt
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO tesseraSessions
			(sessionKeyDigest, handle, subject, partition, audienceRoot, provider, issuedAt, expiresAt, lastUsedAt, browser, deviceType, platform, allowedApps, allowedProviders, requireMfa, secondFactor, native, proofSecret, partitionVia)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.digests.digest(key), s.newHandle(), cp.Subject, cp.Partition, cp.AudienceRoot, cp.Provider, cp.IssuedAt.Unix(), expiryArg(cp.ExpiresAt), cp.LastUsedAt.Unix(),
		cp.Browser, cp.DeviceType, cp.Platform, jsonStrings(cp.AllowedApps), jsonStrings(cp.AllowedProviders), boolToInt(cp.RequireMFA), boolToInt(cp.SecondFactor), boolToInt(cp.Native), randomProofSecret(), cp.PartitionVia)
	if err != nil {
		return "", 0, err
	}
	numID, _ = res.LastInsertId()
	return key, numID, nil
}

// Create inserts a session and returns its key (the cookie value): a key the store mints, or the
// session's ID when the caller chose one of the minted form, which is refused (ErrSessionKeyForm)
// otherwise.
func (s *SQLStore) Create(ctx context.Context, sess *Session) (string, error) {
	key, _, err := s.insert(ctx, sess)
	return key, err
}

// CreateWithID inserts a session and returns both the key and the numeric row id (for app/JWT logins
// whose tokens link to the session without a browser cookie).
func (s *SQLStore) CreateWithID(ctx context.Context, sess *Session) (string, int64, error) {
	return s.insert(ctx, sess)
}

// sessionSelect reads every Session field a row holds. A row holds no session key, so a session it
// scans has an empty ID until Get sets the key it was asked for.
const sessionSelect = `SELECT handle, subject, partition, audienceRoot, provider, issuedAt, expiresAt, lastUsedAt, browser, deviceType, platform, allowedApps, allowedProviders, requireMfa, secondFactor, native, proofSecret, partitionVia FROM tesseraSessions`

func scanSession(sc interface{ Scan(...any) error }) (*Session, error) {
	var v Session
	var issued, lastUsed int64
	var expires sql.NullInt64
	var apps, providers string
	var mfa, secondFactor, native int64
	var handle sql.NullString
	if err := sc.Scan(&handle, &v.Subject, &v.Partition, &v.AudienceRoot, &v.Provider, &issued, &expires, &lastUsed,
		&v.Browser, &v.DeviceType, &v.Platform, &apps, &providers, &mfa, &secondFactor, &native, &v.ProofSecret, &v.PartitionVia); err != nil {
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

// execByKey runs one statement for the session key id names, once per digest a lookup of id
// tries (sessionKeyDigests.lookups), its last argument the digest, until one run changes a row.
// It reports whether any did. Get, Touch, Delete and Rotate select by key through it, so a session
// stored under the previous digest key is found until the end time DigestKeys states.
func (s *SQLStore) execByKey(ctx context.Context, id, query string, args ...any) (bool, error) {
	for _, digest := range s.digests.lookups(id, s.now()) {
		res, err := s.db.ExecContext(ctx, query, append(args, digest)...)
		if err != nil {
			return false, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			return true, nil
		}
	}
	return false, nil
}

// Get loads a session by key, selecting on the key's digest; the session answers with id as its ID.
// A session found under the previous digest key is re-keyed under the current one before it is
// answered, so it outlives the previous key's end time.
func (s *SQLStore) Get(ctx context.Context, id string) (*Session, error) {
	for i, digest := range s.digests.lookups(id, s.now()) {
		v, err := scanSession(s.db.QueryRowContext(ctx, sessionSelect+` WHERE sessionKeyDigest = ?`, digest))
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if i > 0 {
			if _, err := s.db.ExecContext(ctx, `UPDATE tesseraSessions SET sessionKeyDigest = ? WHERE sessionKeyDigest = ?`, s.digests.digest(id), digest); err != nil {
				return nil, err
			}
		}
		v.ID = id
		return v, nil
	}
	return nil, ErrNotFound
}

// Touch refreshes lastUsedAt and, when newExpiry is non-nil, the expiry, and keeps the row under
// the current digest key.
func (s *SQLStore) Touch(ctx context.Context, id string, newExpiry *time.Time) error {
	var found bool
	var err error
	if newExpiry != nil {
		found, err = s.execByKey(ctx, id, `UPDATE tesseraSessions SET lastUsedAt = ?, expiresAt = ?, sessionKeyDigest = ? WHERE sessionKeyDigest = ?`, s.now().Unix(), newExpiry.Unix(), s.digests.digest(id))
	} else {
		found, err = s.execByKey(ctx, id, `UPDATE tesseraSessions SET lastUsedAt = ?, sessionKeyDigest = ? WHERE sessionKeyDigest = ?`, s.now().Unix(), s.digests.digest(id))
	}
	if err != nil {
		return err
	}
	if !found {
		return ErrNotFound
	}
	return nil
}

// Delete removes a session by key.
func (s *SQLStore) Delete(ctx context.Context, id string) error {
	found, err := s.execByKey(ctx, id, `DELETE FROM tesseraSessions WHERE sessionKeyDigest = ?`)
	if err != nil {
		return err
	}
	if !found {
		return ErrNotFound
	}
	return nil
}

// Rotate re-keys a session under a fresh key and drops the old key (session-fixation defense),
// preserving the record. The handle and the proof secret are replaced with the key. Returns the
// new key.
func (s *SQLStore) Rotate(ctx context.Context, id string) (string, error) {
	newID := s.newID()
	found, err := s.execByKey(ctx, id, `UPDATE tesseraSessions SET sessionKeyDigest = ?, handle = ?, proofSecret = ?, lastUsedAt = ? WHERE sessionKeyDigest = ?`, s.digests.digest(newID), s.newHandle(), randomProofSecret(), s.now().Unix())
	if err != nil {
		return "", err
	}
	if !found {
		return "", ErrNotFound
	}
	return newID, nil
}

// GetByHandle loads the session handle names, with no key (an empty ID). An empty handle names none.
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
	res, err := s.db.ExecContext(ctx, `UPDATE tesseraSessions SET sessionKeyDigest = ?, handle = ?, proofSecret = ?, lastUsedAt = ? WHERE handle = ?`, s.digests.digest(s.newID()), newHandle, randomProofSecret(), s.now().Unix(), handle)
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
	res, err := s.db.ExecContext(ctx, `DELETE FROM tesseraSessions WHERE handle = ?`, handle)
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
	res, err := s.db.ExecContext(ctx, `DELETE FROM tesseraSessions WHERE partition = ? AND subject = ?`, partition, subject)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ListSubjectSessions returns every unexpired session for (partition, subject) at the current
// instant, each with no key (an empty ID).
func (s *SQLStore) ListSubjectSessions(ctx context.Context, partition, subject string) ([]*Session, error) {
	if partition == "" {
		return nil, ErrPartitionRequired
	}
	rows, err := s.db.QueryContext(ctx, sessionSelect+` WHERE partition = ? AND subject = ? AND (expiresAt IS NULL OR expiresAt > ?)`, partition, subject, s.now().Unix())
	if err != nil {
		return nil, err
	}
	defer closeRows(rows)
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

// PurgeExpired deletes sessions whose expiresAt is before the given instant (a NULL expiry is
// MaxAge/rolling and never purged).
func (s *SQLStore) PurgeExpired(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM tesseraSessions WHERE expiresAt IS NOT NULL AND expiresAt < ?`, before.Unix())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// closeRows is the deferred Close of every query's rows in this package.
// database/sql closes rows itself once Next reports the end, so a normal return
// leaves nothing to close, and an early return already carries the error that
// stopped the read; its result is dropped.
func closeRows(rows *sql.Rows) { _ = rows.Close() }
