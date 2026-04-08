# AuthGuard - Go Authentication & Authorization Library

**Module**: `github.com/tiagoposse/authguard`
**Go Version**: 1.25
**Only dependency**: `github.com/google/uuid`

## What This Is

A stateless, token-based auth/authz library for Go. Framework-agnostic (works with net/http, Gin, Echo, etc.) and ORM-agnostic (optional Ent integration). All auth data is embedded in tokens — zero DB queries at request time.

## File Map

| File | Purpose |
|------|---------|
| `tokens.go` | `TokenService` — token generation, validation, HMAC-SHA256 signing |
| `context.go` | Context getters/setters for user ID, roles, scopes, device ID, subscription tier, token expiry |
| `guards.go` | Authorization system — `GuardFunc` type, built-in guards, composition (All/Any/Not), global registry |
| `middleware.go` | HTTP middleware — auth validation, admin elevation, token refresh, API key validation |
| `revocation.go` | In-memory `RevocationStore` — per-token, per-user, per-device revocation with TTL cleanup |
| `errors.go` | `GuardError` type, pre-defined errors (ErrNotAuthenticated, ErrNotAdmin, ErrElevationRequired) |
| `annotations.go` | `GuardAnnotation` for Ent schema integration — declares guards per CRUD operation |

## Token Types

All tokens: `<hexPayload>.<hmac-sha256-signature>`

| Token | TTL | Payload Format | Generator |
|-------|-----|----------------|-----------|
| **Access** | Configurable | `userID\|roles,scopes\|expiry[\|dev:deviceID]` | `GenerateTokens()` |
| **Refresh** | 7 days (hardcoded) | `userID\|roles,scopes\|expiry\|refresh[\|dev:deviceID]` | `GenerateTokens()` |
| **Admin Elevation** | 1 hour (hardcoded) | `admin\|userID\|expiry` | `GenerateAdminToken()` |
| **API Key** | Custom | `userID\|roles,scope:s1,scope:s2\|expiry\|apikey` | `GenerateAPIKey()` |

## Key Types & Functions

### TokenService (`tokens.go`)
```go
ts := authguard.NewTokenService(secret, expiration, roleFetcher)
ts.SetScopeResolver(fn)       // maps roles -> scopes
ts.SetRevocationStore(store)   // attach revocation tracking

// Generate
access, refresh, err := ts.GenerateTokens(userID, roles)
access, refresh, err := ts.GenerateTokensWithDevice(userID, roles, deviceID)
access, refresh, err := ts.GenerateTokensForUser(ctx, userID)  // uses roleFetcher
adminToken, expiresAt := ts.GenerateAdminToken(userID)
apiKey, err := ts.GenerateAPIKey(userID, roles, scopes, expiry)

// Validate
claims, err := ts.ValidateTokenClaims(token)  // -> *TokenClaims
userID, roles, err := ts.ValidateToken(token)
userID, roles, err := ts.ValidateRefreshToken(token)
userID, err := ts.ValidateAdminToken(token)
```

### TokenClaims (`tokens.go`)
```go
type TokenClaims struct {
    UserID    uuid.UUID
    Roles     []string   // includes "sub:tier" entries
    Scopes    []string   // parsed from "scope:X" entries
    DeviceID  string
    ExpiresAt time.Time
}
```

### Function Types
```go
type RoleFetcher   func(ctx context.Context, userID uuid.UUID) ([]string, error)
type ScopeResolver func(roles []string) []string
type GuardFunc     func(ctx context.Context, client interface{}) error
```

### Guards (`guards.go`)
```go
// Built-in guards
authguard.RequiresAuth(ctx, client)
authguard.RequiresElevation(ctx, client)
authguard.RequiresAnyRole("admin", "editor")(ctx, client)
authguard.RequiresAnyScope("read", "write")(ctx, client)
authguard.RequiresAllScopes("read", "write")(ctx, client)
authguard.RequiresSubscription("pro", "enterprise")(ctx, client)
authguard.RequiresScope("read")(ctx, client)

// Composition
authguard.All("requiresAuth", "requiresRole:admin")(ctx, client)
authguard.Any("requiresRole:admin", "requiresScope:write")(ctx, client)
authguard.Not("requiresRole:banned")(ctx, client)

// String resolution (for Ent annotations)
guard := authguard.Resolve("requiresRole:admin,editor")

// Register custom guards
authguard.RegisterGuard("isOwner", myOwnerCheckFunc)

// Helpers
userID, err := authguard.RequireAuth(ctx)   // returns error if not authed
userID, err := authguard.RequireAdmin(ctx)  // requires auth + admin role + elevation
userID := authguard.OptionalAuth(ctx)       // returns uuid.Nil if not authed
```

### Context (`context.go`)
```go
// All follow Set/Get pattern. Getters return (value, bool).
authguard.SetUserID(ctx, id)       / authguard.GetUserID(ctx)
authguard.SetAdminUserID(ctx, id)  / authguard.GetAdminUserID(ctx)
authguard.SetRoles(ctx, roles)     / authguard.GetRoles(ctx)
authguard.SetScopes(ctx, scopes)   / authguard.GetScopes(ctx)
authguard.SetSubscriptionTier(ctx, tier) / authguard.GetSubscriptionTier(ctx)
authguard.SetDeviceID(ctx, id)     / authguard.GetDeviceID(ctx)
authguard.SetTokenExpiry(ctx, t)   / authguard.GetTokenExpiry(ctx)

// Convenience checks
authguard.HasRole(ctx, "admin")    // bool
authguard.HasScope(ctx, "write")   // bool, supports "*" wildcard
```

### Middleware (`middleware.go`)
```go
// Auth modes for classifier function
const AuthRequired, AuthOptional, AuthNone AuthMode

// Main auth middleware — classifier determines per-request auth mode
ts.AuthMiddleware(func(r *http.Request) AuthMode { ... })

// Token validation (used inside middleware or standalone)
ctx = ts.ValidateAndSetUser(ctx, authHeader)         // silent fail
ctx, err = ts.ValidateAndSetUserStrict(ctx, authHeader) // returns error
ctx = ts.ValidateAndSetAdmin(ctx, adminToken)        // X-Admin-Token header
ctx = ts.ValidateAPIKey(ctx, apiKey)                 // X-API-Key header

// Auto-refresh middleware — sets X-Refreshed-Token header
ts.RefreshMiddleware(threshold time.Duration)
```

### Revocation (`revocation.go`)
```go
store := authguard.NewRevocationStore()  // starts cleanup goroutine (60s interval)
store.RevokeToken(signature, expiresAt)  // block specific token
store.RevokeAllForUser(userID)           // "logout everywhere"
store.RevokeAllForDevice(userID, deviceID)
store.IsRevoked(claims, signature) bool  // called automatically by ValidateTokenClaims

sig := authguard.TokenSignature(rawToken) // extract signature from token
```

### Ent Annotations (`annotations.go`)
```go
// In Ent schema:
func (User) Annotations() []schema.Annotation {
    return []schema.Annotation{
        authguard.Guards().
            OnCreate("requiresAuth").
            OnRead("requiresAuth").
            OnUpdate("requiresRole:admin").
            OnDelete("requiresRole:admin").
            OnList("requiresAuth"),
    }
}
```

## Design Patterns

- **Stateless tokens**: Claims embedded in token, no server-side session store needed
- **Scopes resolved at generation**: `ScopeResolver` runs once at token creation, scopes baked into token
- **Subscription tiers**: Roles with "sub:" prefix auto-extracted as subscription tier in context
- **Guard composition**: Guards are functions composed via All/Any/Not
- **Context propagation**: All auth data flows through `context.Context`
- **Optional features**: Revocation store, scope resolver, role fetcher are all opt-in

## Examples

| Directory | What It Shows |
|-----------|---------------|
| `examples/basic/` | Minimal login + protected endpoint |
| `examples/guards/` | Custom guards, composition, subscription tiers |
| `examples/middleware/` | Full middleware stack with refresh + API keys |
| `examples/apikeys/` | API key generation with scopes, wildcard scope |
| `examples/revocation/` | Token/user/device revocation patterns |
| `examples/entapi-integration/` | Full Ent ORM integration with sessions |

## Common Integration Pattern

```go
ts := authguard.NewTokenService(os.Getenv("AUTH_SECRET"), 15*time.Minute, roleFetcher)
ts.SetScopeResolver(func(roles []string) []string { /* map roles to scopes */ })

store := authguard.NewRevocationStore()
ts.SetRevocationStore(store)

mux := http.NewServeMux()
handler := ts.AuthMiddleware(func(r *http.Request) authguard.AuthMode {
    if r.URL.Path == "/login" { return authguard.AuthNone }
    return authguard.AuthRequired
})(mux)
```
