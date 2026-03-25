# entauth

A Go authentication and authorization library for any API. Provides JWT and API key authentication with role-based access control, scopes, and a composable guard system. Framework-agnostic — works with any Go HTTP framework and any ORM (or none). Optional integration with [Ent](https://entgo.io) via schema annotations.

## Features

- **JWT Tokens** — HMAC-SHA256 signed access and refresh tokens with embedded roles and scopes
- **API Keys** — Long-lived tokens with restricted scopes for service-to-service communication
- **Guards** — Declarative authorization functions that compose with AND/OR/NOT logic
- **Scopes** — Fine-grained permissions resolved from roles and embedded in tokens (no DB lookup at request time)
- **Admin Elevation** — Temporary elevated-access tokens (1-hour TTL)
- **Token Revocation** — In-memory revocation store with automatic TTL-based cleanup
- **Device Tracking** — Per-device session management and revocation
- **Ent Integration** (optional) — Schema annotations to declare guards on CRUD operations

## Examples

Runnable examples are in the [`examples/`](examples/) directory:

| Example | Description |
|---------|-------------|
| [basic](examples/basic) | Minimal HTTP server with JWT login and protected endpoints |
| [guards](examples/guards) | Custom guards, role/scope checks, and guard composition |
| [apikeys](examples/apikeys) | API key generation and validation for service-to-service auth |
| [revocation](examples/revocation) | Token revocation: single token, all sessions, per-device |
| [middleware](examples/middleware) | Full middleware stack: JWT + API keys + admin elevation + auto-refresh |
| [entapi-integration](examples/entapi-integration) | Full Ent + entapi integration: schemas, guards, API keys, sessions |

```bash
go run ./examples/basic
```

## Installation

```bash
go get github.com/tiagoposse/entauth
```

## Quick Start

```go
package main

import (
    "context"
    "time"

    "github.com/google/uuid"
    "github.com/tiagoposse/entauth"
)

func main() {
    // Create a token service
    ts := entauth.NewTokenService(
        "your-secret-key",
        15*time.Minute, // access token TTL
        func(ctx context.Context, userID uuid.UUID) ([]string, error) {
            return fetchUserRoles(userID) // fetch from DB
        },
    )

    // Map roles to scopes
    ts.SetScopeResolver(func(roles []string) []string {
        var scopes []string
        for _, role := range roles {
            switch role {
            case "admin":
                scopes = append(scopes, "read", "write", "delete", "manage-users")
            case "editor":
                scopes = append(scopes, "read", "write")
            default:
                scopes = append(scopes, "read")
            }
        }
        return scopes
    })

    // Generate tokens
    userID := uuid.New()
    accessToken, refreshToken, err := ts.GenerateTokensForUser(context.Background(), userID)
}
```

## Token Types

| Type | TTL | Format | Use Case |
|------|-----|--------|----------|
| Access Token | Configurable | `userID\|roles,scopes\|expiry` | Short-lived request auth |
| Refresh Token | 7 days | `userID\|roles,scopes\|expiry\|refresh` | Token renewal |
| Admin Token | 1 hour | `admin\|userID\|expiry` | Temporary elevated access |
| API Key | Custom | `userID\|roles,scopes\|expiry\|apikey` | Service-to-service auth |

All tokens are hex-encoded payloads with an HMAC-SHA256 signature: `hexPayload.signature`.

### Generating Tokens

```go
// Standard access + refresh tokens
access, refresh, err := ts.GenerateTokens(userID, []string{"editor"})

// With device tracking
access, refresh, err := ts.GenerateTokensWithDevice(userID, roles, "mobile-1")

// Using RoleFetcher to resolve roles from DB
access, refresh, err := ts.GenerateTokensForUser(ctx, userID)

// Admin elevation token
adminToken, expiresAt := ts.GenerateAdminToken(userID)

// API key with restricted scopes
apiKey, err := ts.GenerateAPIKey(userID, []string{"bot"}, []string{"read"}, 365*24*time.Hour)
```

### Validating Tokens

```go
// Basic validation — returns userID and roles
userID, roles, err := ts.ValidateToken(token)

// Full claims
claims, err := ts.ValidateTokenClaims(token)
// claims.UserID, claims.Roles, claims.Scopes, claims.DeviceID, claims.ExpiresAt

// Refresh token validation
userID, roles, err := ts.ValidateRefreshToken(token)

// Admin token validation
userID, err := ts.ValidateAdminToken(token)
```

## Middleware

### Authentication Middleware

Use `ValidateAndSetUser` and `ValidateAndSetAdmin` to populate the request context:

```go
func authMiddleware(ts *entauth.TokenService) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            ctx := r.Context()

            // JWT from Authorization header
            ctx = ts.ValidateAndSetUser(ctx, r.Header.Get("Authorization"))

            // Optional admin elevation
            ctx = ts.ValidateAndSetAdmin(ctx, r.Header.Get("X-Admin-Token"))

            // Or API key
            if r.Header.Get("Authorization") == "" {
                ctx = ts.ValidateAPIKey(ctx, r.Header.Get("X-API-Key"))
            }

            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

### Refresh Middleware

Automatically refreshes tokens nearing expiration:

```go
handler := ts.RefreshMiddleware(5 * time.Minute)(yourHandler)
// Sets X-New-Access-Token and X-New-Refresh-Token headers when refreshed
```

## Guards

Guards are authorization functions with the signature:

```go
type GuardFunc func(ctx context.Context, client interface{}) error
```

Return `nil` to allow, or a `*GuardError` to reject.

### Built-in Guards

| Guard | Description |
|-------|-------------|
| `requiresAuth` | User must be authenticated |
| `requiresElevation` | User must have an admin elevation token |
| `requiresRole:role1,role2` | User must have one of the specified roles |
| `requiresScope:scope1,scope2` | Token must have one of the specified scopes |
| `requiresSubscription:tier1,tier2` | User's subscription must match one of the tiers |

### Custom Guards

```go
entauth.RegisterGuard("isPremium", func(ctx context.Context, client interface{}) error {
    tier, ok := entauth.GetSubscriptionTier(ctx)
    if !ok || (tier != "pro" && tier != "enterprise") {
        return entauth.Errorf(403, "premium subscription required")
    }
    return nil
})
```

### Composing Guards

```go
// All must pass (AND)
adminGuard := entauth.All("requiresAuth", "requiresRole:admin", "requiresElevation")

// Any must pass (OR)
accessGuard := entauth.Any("isPremium", "requiresRole:admin")

// Negation
notReadOnly := entauth.Not("readOnlyMode")
```

### Resolving Guards by Name

```go
guard := entauth.Resolve("requiresRole:admin,editor")
err := guard(ctx, client)
```

### Helper Functions

```go
// Require auth — returns user ID or error
userID, err := entauth.RequireAuth(ctx)

// Require admin elevation
adminID, err := entauth.RequireAdmin(ctx)

// Optional auth — returns uuid.Nil if unauthenticated
userID := entauth.OptionalAuth(ctx)

// Check role or scope
if entauth.HasRole(ctx, "admin") { ... }
if entauth.HasScope(ctx, "write") { ... }
```

## Ent Schema Annotations (Optional)

If you use [Ent](https://entgo.io), you can declare guards directly on entity CRUD operations:

```go
func (User) Annotations() []schema.Annotation {
    return []schema.Annotation{
        entauth.Guards().
            OnCreate("requiresAuth").
            OnRead("requiresAuth").
            OnUpdate("requiresRole:admin").
            OnDelete("requiresRole:admin").
            OnList("requiresAuth"),
    }
}
```

These annotations are consumed by code generation extensions (e.g., `entapi`) to enforce guards automatically on generated CRUD handlers.

## Token Revocation

```go
store := entauth.NewRevocationStore()
ts.SetRevocationStore(store)

// Revoke a specific token
sig := entauth.TokenSignature(rawToken)
store.RevokeToken(sig, claims.ExpiresAt)

// Revoke all tokens for a user
store.RevokeAllForUser(userID)

// Revoke all tokens for a specific device
store.RevokeAllForDevice(userID, "mobile-1")

// Check if revoked (called automatically during validation)
store.IsRevoked(claims, sig)
```

Revoked entries are automatically cleaned up after their original expiration time.

## Context Utilities

All auth data flows through `context.Context`:

```go
// Identity
ctx = entauth.SetUserID(ctx, userID)
userID, ok := entauth.GetUserID(ctx)

// Roles and scopes
ctx = entauth.SetRoles(ctx, []string{"admin"})
roles := entauth.GetRoles(ctx)

ctx = entauth.SetScopes(ctx, []string{"read", "write"})
scopes := entauth.GetScopes(ctx)

// Subscription tier (extracted from "sub:" prefixed roles)
ctx = entauth.SetSubscriptionTier(ctx, "pro")
tier, ok := entauth.GetSubscriptionTier(ctx)

// Device tracking
ctx = entauth.SetDeviceID(ctx, "mobile-1")
deviceID, ok := entauth.GetDeviceID(ctx)

// Admin elevation
ctx = entauth.SetAdminUserID(ctx, userID)
adminID, ok := entauth.GetAdminUserID(ctx)
```

## License

See [LICENSE](LICENSE) for details.
