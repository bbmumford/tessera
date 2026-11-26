# tessera

The session system: the server-side record a browser cookie or an app token points at, binding a signed-in subject to the partition the sign-in established.

- **`SessionStore`**: one store contract, with an in-memory store (`NewMemStore`), a `database/sql` store (`OpenSQLStore`, which keeps only an HMAC-SHA256 digest of each session key under the `DigestKeys` every opener of one sessions database shares) and a short read-through cache over either (`NewCachingStore`).
- **`Manager`**: mints, rotates and clears the session cookie on a validated root domain (`DomainResolver`; `StaticDomainResolver` for a fixed list), creates app and native-app sessions, and logs out one session or all of a subject's.
- **Middleware**: `AttachSession` puts the request's session on its context for `FromContext` and `GetSessionFromContext`; `HandoffRedemption` redeems a cross-domain single-use token into a local session, only for an audience that names an allowed root and matches the requested host.

## Use

```sh
go get github.com/bbmumford/tessera
```

```go
store, err := tessera.OpenSQLStore(db, tessera.DigestKeys{Current: lookupKey}) // any database/sql driver; lookupKey >= 32 bytes
if err != nil { /* ... */ }
if err := store.InitSchema(ctx); err != nil { /* ... */ } // idempotent; once at boot

m, err := tessera.NewManager(tessera.Config{
	Store:   tessera.NewCachingStore(store, 5*time.Second),
	Domains: tessera.StaticDomainResolver{Roots: []string{"example.com"}},
})

// after the sign-in has been proved:
id, err := m.Mint(w, r, subject, "password", partition, nil)

// on every request:
handler = m.AttachSession(handler)
if s, ok := tessera.FromContext(r); ok { /* s.Subject, s.Partition ... */ }
```

`NewManager` refuses a config without a store or a domain resolver, and a session's partition is required: `Create` refuses an empty one.

## Consumers

ORBTR library, the api.orbtr.ai and node.orbtr.ai endpoints and ai cortex, and the node.orbtr.io endpoint and io tools.
