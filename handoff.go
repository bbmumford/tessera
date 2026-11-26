package tessera

import (
	"context"
	"net/http"
	"strings"
)

// Handoff is what a redeemer resolved a single-use cross-domain token into: the
// subject the token was issued for and the partition it was issued in.
//
// Both are the redeemer's to establish. This package mints a session from them
// and never reads either from the request, so a token holder cannot choose whose
// session it becomes or which partition it lands in.
type Handoff struct {
	Subject   string
	Partition string
}

// Redeemer exchanges a single-use handoff token for the identity it stands for,
// for delivery to the named audience. ok is false when the token is unknown,
// spent, expired, or was not issued for this audience — none of which is an
// error the caller distinguishes, because a redemption that did not succeed is
// the same outcome however it failed.
//
// The consumer implements it over whatever issued the token. This package holds
// no issuing side and no transport: a handoff is meaningless without the system
// that minted it, and that system is never this one.
type Redeemer interface {
	Redeem(ctx context.Context, token, audience string) (Handoff, bool)
}

// RedeemerFunc adapts a plain func to Redeemer.
type RedeemerFunc func(ctx context.Context, token, audience string) (Handoff, bool)

// Redeem calls f.
func (f RedeemerFunc) Redeem(ctx context.Context, token, audience string) (Handoff, bool) {
	return f(ctx, token, audience)
}

// HandoffConfig wires HandoffRedemption.
type HandoffConfig struct {
	// Redeemer exchanges the token. nil disables redemption entirely: every
	// request falls through untouched, which is the correct behaviour for an
	// endpoint that participates in no handoff.
	Redeemer Redeemer

	// TokenParam and AudienceParam name the query parameters carrying the token
	// and the intended audience. Empty ⇒ "handoff" and "aud".
	TokenParam    string
	AudienceParam string

	// Provider labels the minted session's origin. Empty ⇒ "handoff".
	Provider string

	// Options are the cookie options for the minted session; nil ⇒ the Manager's
	// defaults.
	Options *Options
}

// HandoffRedemption redeems a cross-domain single-use token on a GET request and
// mints a local session from what the redeemer proved.
//
// The audience must name a root this Manager's DomainResolver already allows, and
// it must match the host being requested. That is the load-bearing check: a token
// minted for one endpoint must not be redeemable at another, so a request whose
// audience is absent, unknown, or different from its own host is passed through
// unredeemed rather than being honoured for whoever asked.
//
// A redemption answers 303 See Other to the same URL with the token and audience
// parameters taken off, carrying the minted cookie, so the token leaves the
// address bar, the history and the Referer a page would send, and the next
// request arrives with the session. A request whose cookie already names a live
// session is never redeemed: a handoff does not replace a signed-in browser's
// session, so a link carrying someone else's token cannot sign that browser into
// another account. It is answered with the same clean redirect, and the token is
// left unspent.
//
// Every other refusal is a pass-through, never an error to the client. A handoff
// that cannot be redeemed leaves the request exactly as it arrived, so the
// endpoint's ordinary authentication decides what happens next — a failed
// redemption must not itself deny a request that was never relying on one.
func (m *Manager) HandoffRedemption(cfg HandoffConfig) func(http.Handler) http.Handler {
	tokenParam := cfg.TokenParam
	if tokenParam == "" {
		tokenParam = "handoff"
	}
	audParam := cfg.AudienceParam
	if audParam == "" {
		audParam = "aud"
	}
	provider := cfg.Provider
	if provider == "" {
		provider = "handoff"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.Redeemer == nil || r.Method != http.MethodGet {
				next.ServeHTTP(w, r)
				return
			}
			q := r.URL.Query()
			token := strings.TrimSpace(q.Get(tokenParam))
			audience := strings.ToLower(strings.TrimSpace(q.Get(audParam)))
			if token == "" || audience == "" {
				next.ServeHTTP(w, r)
				return
			}
			if !m.audienceIsThisHost(r, audience) {
				m.logf("handoff: refuse audience=%q host=%q", audience, r.Host)
				next.ServeHTTP(w, r)
				return
			}
			if m.holdsLiveSession(r, cfg.Options) {
				m.logf("handoff: not redeemed over a live session audience=%q", audience)
				http.Redirect(w, r, withoutParams(r, tokenParam, audParam), http.StatusSeeOther)
				return
			}

			h, ok := cfg.Redeemer.Redeem(r.Context(), token, audience)
			if !ok || h.Subject == "" || h.Partition == "" {
				m.logf("handoff: not redeemed audience=%q", audience)
				next.ServeHTTP(w, r)
				return
			}
			if _, err := m.Mint(w, r, h.Subject, provider, h.Partition, cfg.Options); err != nil {
				// The token is spent either way — a redeemer consumes it — so a
				// mint failure must not look like a request that carried none.
				// It falls through unauthenticated and the endpoint's own auth
				// answers, which is the same outcome as an expired token.
				m.logf("handoff: mint failed audience=%q: %v", audience, err)
				next.ServeHTTP(w, r)
				return
			}
			http.Redirect(w, r, withoutParams(r, tokenParam, audParam), http.StatusSeeOther)
		})
	}
}

// holdsLiveSession reports whether the request's session cookie names a session the store holds
// and that has not expired.
func (m *Manager) holdsLiveSession(r *http.Request, opts *Options) bool {
	c, err := r.Cookie(m.effectiveOptions(opts, "").CookieName)
	if err != nil || c == nil || c.Value == "" {
		return false
	}
	s, err := m.store.Get(r.Context(), c.Value)
	if err != nil || s == nil {
		return false
	}
	return s.ExpiresAt == nil || s.ExpiresAt.After(m.now())
}

// withoutParams is r's path and query with the named query parameters taken off, the target of
// the redirect that clears a handoff token from the URL. It is a path, never an absolute URL, so
// the redirect cannot leave the host the request reached.
func withoutParams(r *http.Request, names ...string) string {
	q := r.URL.Query()
	for _, n := range names {
		q.Del(n)
	}
	target := r.URL.EscapedPath()
	if target == "" || target[0] != '/' || strings.HasPrefix(target, "//") {
		target = "/"
	}
	if enc := q.Encode(); enc != "" {
		target += "?" + enc
	}
	return target
}

// audienceIsThisHost reports whether the claimed audience is both a root this
// Manager is configured to serve and the host actually being requested.
//
// Both halves are required and they refuse different attacks: the allowed-roots
// check stops a token being redeemed for a domain this deployment does not own,
// and the host comparison stops a token minted for one of its endpoints being
// replayed at another. Checking only the first would let any endpoint in the
// deployment redeem any other's token.
func (m *Manager) audienceIsThisHost(r *http.Request, audience string) bool {
	host := hostWithoutPort(strings.ToLower(r.Host))
	if host == "" || audience != host {
		return false
	}
	if m.domains == nil {
		return false
	}
	roots, err := m.domains.AllowedRoots()
	if err != nil {
		// The audience cannot be validated, so it is not validated. Refusing here
		// costs a redemption during a config outage; admitting would accept an
		// unverifiable audience for its duration.
		return false
	}
	for _, root := range roots {
		root = strings.ToLower(strings.TrimPrefix(root, "."))
		if root == "" {
			continue
		}
		if audience == root || strings.HasSuffix(audience, "."+root) {
			return true
		}
	}
	return false
}
