package tessera

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// MaxCookieValueBytes bounds a session-id cookie value; a longer value is rejected before
// Set-Cookie so an oversized id never produces a silently-dropped cookie or a 431 at the client.
const MaxCookieValueBytes = 1024

// enforceCookieSize rejects a cookie value that would exceed MaxCookieValueBytes. Mint/Rotate call
// it before writing Set-Cookie so the caller learns the id is too large instead of the browser
// dropping the cookie.
func enforceCookieSize(value string) error {
	if len(value) <= MaxCookieValueBytes {
		return nil
	}
	return fmt.Errorf("tessera: cookie value exceeds %d bytes", MaxCookieValueBytes)
}

// Options control cookie emission and TTL. Zero fields fall back to the Manager defaults; Secure and
// HTTPOnly are hardened on and cannot be weakened through Options (the cookie carries a live session
// id). SameSite==0 means "unset, use the default".
type Options struct {
	CookieName    string
	MaxAgeSeconds int
	Domain        string
	Secure        bool
	HTTPOnly      bool
	SameSite      http.SameSite
}

// DomainResolver derives and validates the registrable root domain a session cookie is scoped to.
// It is the injected seam that replaces a platform-specific endpoint registry: RootDomainForHost
// maps an HTTP Host to its registrable root (app.example.com → example.com) and AllowedRoots returns
// the set the cookie may legally be scoped to, so a host outside the operator's domains is rejected
// before any Set-Cookie. Supply a StaticDomainResolver for the common case, or a consumer resolver
// backed by an authoritative registry.
type DomainResolver interface {
	RootDomainForHost(host string) (string, error)
	AllowedRoots() ([]string, error)
}

// StaticDomainResolver is a dependency-free DomainResolver over an explicit set of registrable roots.
// RootDomainForHost returns the longest configured root that the host equals or is a subdomain of, so
// it both derives and constrains in one step; AllowedRoots reports the same set. A leading dot on a
// configured root is tolerated. This is the working default when the operator's domains are known at
// wiring time; swap in a registry-backed resolver when they are not.
type StaticDomainResolver struct {
	Roots []string
}

// AllowedRoots reports the configured registrable roots.
func (s StaticDomainResolver) AllowedRoots() ([]string, error) { return s.Roots, nil }

// RootDomainForHost returns the longest configured root the host matches, or an error when none does.
func (s StaticDomainResolver) RootDomainForHost(host string) (string, error) {
	h := hostWithoutPort(host)
	var best string
	for _, root := range s.Roots {
		r := strings.TrimPrefix(strings.TrimSpace(root), ".")
		if r == "" {
			continue
		}
		if strings.EqualFold(h, r) || strings.HasSuffix(strings.ToLower(h), "."+strings.ToLower(r)) {
			if len(r) > len(best) {
				best = r
			}
		}
	}
	if best == "" {
		return "", fmt.Errorf("tessera: no configured root matches host %q", host)
	}
	return best, nil
}

func hostWithoutPort(host string) string {
	if i := strings.IndexByte(host, ':'); i >= 0 {
		return host[:i]
	}
	return host
}

// Config wires a Manager. Store and Domains are required; PartitionFromContext and Logf are optional.
type Config struct {
	// Store persists sessions. Required. An auth node supplies a LocalSessionStore (Turso/tursokv);
	// a thin gateway supplies a mesh-RPC-backed SessionStore. Both satisfy the same contract.
	Store SessionStore
	// Domains derives and validates the cookie's root domain. Required.
	Domains DomainResolver
	// CookieName is the default cookie name (e.g. "orbtr_session"). Required and non-empty; an
	// Options.CookieName overrides it per call.
	CookieName string
	// PartitionFromContext resolves the partition LogoutAll and GetSubjectSessions select on from the
	// request context. Nil resolves every request to an empty partition, which the store refuses, so a
	// Manager without it can mint, rotate and delete sessions but cannot list or wipe them.
	PartitionFromContext func(context.Context) string
	// DefaultMaxAgeSeconds overrides the 30-day cookie/session lifetime default when > 0.
	DefaultMaxAgeSeconds int
	// Now is the clock (default time.Now); injectable for deterministic tests.
	Now func() time.Time
	// Logf is an optional diagnostic sink for the attach middleware; nil ⇒ silent.
	Logf func(string, ...any)
}

// Manager owns the HTTP cookie/session lifecycle over an injected SessionStore. Every dependency
// (store, domain resolver, partition axis, clock, logger) is supplied at construction — no package-global
// singleton — so two Managers with different stores coexist and no hidden global state is shared.
// HTTP ceremony (Set-Cookie, domain scoping, size guard) lives here; persistence lives behind Store.
type Manager struct {
	store        SessionStore
	domains      DomainResolver
	cookieName   string
	partitionCtx func(context.Context) string
	defaultTTL   int
	now          func() time.Time
	logf         func(string, ...any)
}

// NewManager validates the config and returns a Manager. It errors when Store, Domains, or a
// non-empty CookieName is missing rather than panicking later at first mint.
func NewManager(c Config) (*Manager, error) {
	if c.Store == nil {
		return nil, errors.New("tessera: Config.Store is required")
	}
	if c.Domains == nil {
		return nil, errors.New("tessera: Config.Domains is required")
	}
	if strings.TrimSpace(c.CookieName) == "" {
		return nil, errors.New("tessera: Config.CookieName is required")
	}
	m := &Manager{
		store:        c.Store,
		domains:      c.Domains,
		cookieName:   c.CookieName,
		partitionCtx: c.PartitionFromContext,
		defaultTTL:   c.DefaultMaxAgeSeconds,
		now:          c.Now,
		logf:         c.Logf,
	}
	if m.defaultTTL <= 0 {
		m.defaultTTL = 86400 * 30 // 30 days
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.logf == nil {
		m.logf = func(string, ...any) {}
	}
	return m, nil
}

// partition resolves the request's partition, or "" when no resolver is wired; the store refuses "".
func (m *Manager) partition(ctx context.Context) string {
	if m.partitionCtx == nil {
		return ""
	}
	return m.partitionCtx(ctx)
}

// effectiveOptions folds per-call Options over the Manager defaults. Secure/HTTPOnly stay hardened
// on; SameSite defaults to Lax.
func (m *Manager) effectiveOptions(opts *Options, defaultDomain string) *Options {
	o := &Options{
		CookieName:    m.cookieName,
		MaxAgeSeconds: m.defaultTTL,
		Domain:        defaultDomain,
		Secure:        true,
		HTTPOnly:      true,
		SameSite:      http.SameSiteLaxMode,
	}
	if opts == nil {
		return o
	}
	if strings.TrimSpace(opts.CookieName) != "" {
		o.CookieName = opts.CookieName
	}
	if opts.MaxAgeSeconds > 0 {
		o.MaxAgeSeconds = opts.MaxAgeSeconds
	}
	if strings.TrimSpace(opts.Domain) != "" {
		o.Domain = opts.Domain
	}
	if opts.SameSite != 0 {
		o.SameSite = opts.SameSite
	}
	return o
}

// deriveDomain extracts the root domain from the request host, validates it against AllowedRoots, and
// returns it with a leading dot so the cookie is shared across subdomains (SSO across *.root).
func (m *Manager) deriveDomain(r *http.Request) (string, error) {
	rootDomain, err := m.domains.RootDomainForHost(r.Host)
	if err != nil {
		return "", fmt.Errorf("tessera: extract root domain from %q: %w", r.Host, err)
	}
	allowed, err := m.domains.AllowedRoots()
	if err != nil {
		return "", fmt.Errorf("tessera: allowed roots: %w", err)
	}
	ok := false
	for _, a := range allowed {
		if strings.EqualFold(rootDomain, strings.TrimPrefix(strings.TrimSpace(a), ".")) {
			ok = true
			break
		}
	}
	if !ok {
		return "", fmt.Errorf("tessera: root domain %q is not in AllowedRoots", rootDomain)
	}
	if !strings.HasPrefix(rootDomain, ".") {
		return "." + rootDomain, nil
	}
	return rootDomain, nil
}

func (m *Manager) setCookie(w http.ResponseWriter, eff *Options, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     eff.CookieName,
		Value:    value,
		Path:     "/",
		Domain:   eff.Domain,
		MaxAge:   eff.MaxAgeSeconds,
		HttpOnly: eff.HTTPOnly,
		Secure:   eff.Secure,
		SameSite: eff.SameSite,
	})
}

func (m *Manager) expiry(maxAgeSeconds int) *time.Time {
	if maxAgeSeconds <= 0 {
		return nil
	}
	e := m.now().Add(time.Duration(maxAgeSeconds) * time.Second)
	return &e
}

// Mint creates a session and issues its cookie, scoping the cookie to the request's validated root
// domain. partition is stamped on the session; an empty one is refused by the store and no cookie is
// set.
func (m *Manager) Mint(w http.ResponseWriter, r *http.Request, subject, provider, partition string, opts *Options) (string, error) {
	domain, err := m.deriveDomain(r)
	if err != nil {
		return "", fmt.Errorf("derive domain: %w", err)
	}
	eff := m.effectiveOptions(opts, domain)
	now := m.now()
	s := &Session{
		Subject:    subject,
		Provider:   provider,
		Partition:  partition,
		IssuedAt:   now,
		LastUsedAt: now,
		ExpiresAt:  m.expiry(eff.MaxAgeSeconds),
	}
	id, err := m.store.Create(r.Context(), s)
	if err != nil {
		return "", err
	}
	if err := enforceCookieSize(id); err != nil {
		return "", err
	}
	m.setCookie(w, eff, id)
	return id, nil
}

// MintWithMeta is Mint plus captured client metadata (browser/device/platform). HTTP ceremony is
// identical regardless of which store owns the row.
func (m *Manager) MintWithMeta(w http.ResponseWriter, r *http.Request, subject, provider, browser, deviceType, platform, partition string, opts *Options) (string, error) {
	domain, err := m.deriveDomain(r)
	if err != nil {
		return "", fmt.Errorf("derive domain: %w", err)
	}
	eff := m.effectiveOptions(opts, domain)
	now := m.now()
	s := &Session{
		Subject:    subject,
		Provider:   provider,
		Partition:  partition,
		IssuedAt:   now,
		LastUsedAt: now,
		ExpiresAt:  m.expiry(eff.MaxAgeSeconds),
		Browser:    browser,
		DeviceType: deviceType,
		Platform:   platform,
	}
	id, err := m.store.Create(r.Context(), s)
	if err != nil {
		return "", err
	}
	if err := enforceCookieSize(id); err != nil {
		return "", err
	}
	m.setCookie(w, eff, id)
	return id, nil
}

// CreateAppSession creates a server-side session for a mobile/desktop login without a browser cookie
// and returns the session key plus numeric id (for linking JWT/app tokens). It requires the Store to
// be a LocalSessionStore, because the numeric id has no mesh-RPC equivalent — a thin gateway gets an
// error. maxAgeSeconds<=0 defaults to 30 days.
func (m *Manager) CreateAppSession(ctx context.Context, subject, provider, browser, deviceType, platform, partition string, maxAgeSeconds int) (sessionKey string, sessionID int64, err error) {
	local, ok := m.store.(LocalSessionStore)
	if !ok {
		return "", 0, errors.New("tessera: CreateAppSession requires a LocalSessionStore (auth node only)")
	}
	if maxAgeSeconds <= 0 {
		maxAgeSeconds = 86400 * 30
	}
	now := m.now()
	s := &Session{
		Subject:    subject,
		Provider:   provider,
		Partition:  partition,
		IssuedAt:   now,
		LastUsedAt: now,
		ExpiresAt:  m.expiry(maxAgeSeconds),
		Browser:    browser,
		DeviceType: deviceType,
		Platform:   platform,
	}
	return local.CreateWithID(ctx, s)
}

// Rotate re-keys the current session (session-fixation defense) and updates the cookie, preserving
// the server-side record. Returns the new id.
func (m *Manager) Rotate(w http.ResponseWriter, r *http.Request, opts *Options) (string, error) {
	domain, err := m.deriveDomain(r)
	if err != nil {
		return "", fmt.Errorf("derive domain: %w", err)
	}
	eff := m.effectiveOptions(opts, domain)
	c, err := r.Cookie(eff.CookieName)
	if err != nil || c == nil || c.Value == "" {
		return "", errors.New("tessera: no session cookie to rotate")
	}
	newID, err := m.store.Rotate(r.Context(), c.Value)
	if err != nil {
		return "", err
	}
	if err := enforceCookieSize(newID); err != nil {
		return "", err
	}
	m.setCookie(w, eff, newID)
	return newID, nil
}

// LogoutCurrent deletes the current server-side session and clears its cookie. A missing cookie is a
// no-op (nil error).
func (m *Manager) LogoutCurrent(w http.ResponseWriter, r *http.Request, opts *Options) error {
	domain, err := m.deriveDomain(r)
	if err != nil {
		domain = "" // clear with a domainless cookie when derivation fails
	}
	eff := m.effectiveOptions(opts, domain)
	c, err := r.Cookie(eff.CookieName)
	if err != nil || c == nil || c.Value == "" {
		return nil
	}
	_ = m.store.Delete(r.Context(), c.Value)
	m.clearCookie(w, eff.CookieName, domain)
	return nil
}

// LogoutAll wipes every session of the current subject in the request's partition and clears the
// cookie. The subject is resolved from context first, then from the cookie's session. A failed wipe
// is returned with the cookie left in place: the caller asked for every session to end, and reporting
// success while the others still validate would tell them it had.
func (m *Manager) LogoutAll(w http.ResponseWriter, r *http.Request, opts *Options) error {
	domain, err := m.deriveDomain(r)
	if err != nil {
		domain = ""
	}
	eff := m.effectiveOptions(opts, domain)

	var subject string
	if s, ok := FromContext(r); ok && s != nil {
		subject = s.Subject
	}
	if subject == "" {
		if c, err := r.Cookie(eff.CookieName); err == nil && c != nil && c.Value != "" {
			if s, err := m.store.Get(r.Context(), c.Value); err == nil && s != nil {
				subject = s.Subject
			}
		}
	}
	if subject == "" {
		return errors.New("tessera: no session subject found to wipe")
	}
	if _, err := m.store.WipeSubject(r.Context(), m.partition(r.Context()), subject); err != nil {
		return fmt.Errorf("tessera: wipe sessions: %w", err)
	}
	m.clearCookie(w, eff.CookieName, domain)
	return nil
}

func (m *Manager) clearCookie(w http.ResponseWriter, name, domain string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Domain:   domain,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// GetSession loads a session by id.
func (m *Manager) GetSession(ctx context.Context, id string) (*Session, error) {
	return m.store.Get(ctx, id)
}

// ProbeSession is a read-only existence+expiry check (no touch). It returns false (nil error) when
// the session is missing or expired.
func (m *Manager) ProbeSession(ctx context.Context, id string) (bool, error) {
	s, err := m.store.Get(ctx, id)
	if err != nil || s == nil {
		return false, nil
	}
	if s.ExpiresAt != nil && s.ExpiresAt.Before(m.now()) {
		return false, nil
	}
	return true, nil
}

// GetSubjectSessions lists every session of subject in the request's partition.
func (m *Manager) GetSubjectSessions(ctx context.Context, subject string) ([]*Session, error) {
	return m.store.ListSubjectSessions(ctx, m.partition(ctx), subject)
}

// DeleteSession deletes a session by id.
func (m *Manager) DeleteSession(ctx context.Context, id string) error {
	return m.store.Delete(ctx, id)
}
