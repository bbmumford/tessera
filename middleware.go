package tessera

import (
	"context"
	"net/http"
)

type ctxKey string

// sessionCtxKey stores the attached *Session in the request context. AttachSession puts it; the
// FromContext family reads it.
const sessionCtxKey ctxKey = "tessera_session"

// SessionCtxKey returns the context key AttachSession uses, so a consumer can read the session from
// contexts this package populated without importing the unexported key.
func SessionCtxKey() ctxKey { return sessionCtxKey }

// AttachSession validates the request's session cookie and, when it names a live unexpired session,
// attaches that session to the request context and soft-touches its LastUsedAt (without extending
// expiry). A missing/invalid cookie, an unknown session, or an expired one all fall through to next
// with no session attached — never an error to the client. Diagnostic detail goes to the Manager's
// optional Logf.
func (m *Manager) AttachSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(m.cookieName)
		if err != nil || c == nil || c.Value == "" {
			m.logf("attach: skip path=%s reason=no_cookie err=%v", r.URL.Path, err)
			next.ServeHTTP(w, r)
			return
		}
		sess, err := m.store.Get(r.Context(), c.Value)
		if err != nil || sess == nil {
			m.logf("attach: get failed path=%s err=%v sessNil=%v", r.URL.Path, err, sess == nil)
			next.ServeHTTP(w, r)
			return
		}
		if sess.ExpiresAt != nil && sess.ExpiresAt.Before(m.now()) {
			m.logf("attach: expired path=%s userID=%q", r.URL.Path, sess.UserID)
			next.ServeHTTP(w, r)
			return
		}
		// Soft-touch: refresh LastUsedAt without extending an existing expiry.
		_ = m.store.Touch(r.Context(), c.Value, sess.ExpiresAt)

		ctx := context.WithValue(r.Context(), sessionCtxKey, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// FromContext returns the session attached to the request by AttachSession, if any.
func FromContext(r *http.Request) (*Session, bool) {
	return GetSessionFromContext(r.Context())
}

// GetSessionFromContext extracts the attached session from a bare context (for protocol-agnostic
// handlers that receive context.Context rather than *http.Request).
func GetSessionFromContext(ctx context.Context) (*Session, bool) {
	v := ctx.Value(sessionCtxKey)
	if v == nil {
		return nil, false
	}
	s, ok := v.(*Session)
	return s, ok && s != nil
}

// GetSessionIDFromContext extracts just the attached session's id.
func GetSessionIDFromContext(ctx context.Context) (string, bool) {
	s, ok := GetSessionFromContext(ctx)
	if !ok || s == nil {
		return "", false
	}
	return s.ID, true
}
