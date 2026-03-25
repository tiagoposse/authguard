package entauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ValidateAndSetUser validates a Bearer token from the Authorization header
// and returns a context with the user ID, roles, permissions, device ID, and
// token expiry set. If validation fails, returns the original context unchanged.
func (t *TokenService) ValidateAndSetUser(ctx context.Context, authHeader string) context.Context {
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return ctx
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := t.ValidateTokenClaims(token)
	if err != nil {
		return ctx
	}
	ctx = SetUserID(ctx, claims.UserID)
	ctx = SetRoles(ctx, claims.Roles)
	ctx = SetTokenExpiry(ctx, claims.ExpiresAt)
	if len(claims.Scopes) > 0 {
		ctx = SetScopes(ctx, claims.Scopes)
	}
	if claims.DeviceID != "" {
		ctx = SetDeviceID(ctx, claims.DeviceID)
	}
	// Extract subscription tier from roles if present (format: "sub:pro").
	for _, role := range claims.Roles {
		if strings.HasPrefix(role, "sub:") {
			ctx = SetSubscriptionTier(ctx, strings.TrimPrefix(role, "sub:"))
			break
		}
	}
	return ctx
}

// ValidateAndSetAdmin validates an X-Admin-Token header and returns a context
// with the admin user ID set. If validation fails, returns the original context.
func (t *TokenService) ValidateAndSetAdmin(ctx context.Context, adminToken string) context.Context {
	if adminToken == "" {
		return ctx
	}
	adminUserID, err := t.ValidateAdminToken(adminToken)
	if err != nil {
		return ctx
	}
	return SetAdminUserID(ctx, adminUserID)
}

// RefreshMiddleware returns an HTTP middleware that auto-refreshes near-expiry tokens.
// When a valid token is within `threshold` of expiration, a new token is generated
// and returned in the X-Refreshed-Token response header. The client picks it up
// transparently and uses it for subsequent requests.
func (t *TokenService) RefreshMiddleware(threshold time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
				token := strings.TrimPrefix(authHeader, "Bearer ")
				claims, err := t.ValidateTokenClaims(token)
				if err == nil && time.Until(claims.ExpiresAt) < threshold {
					// Token is near expiry — generate a fresh one
					newToken, _, genErr := t.GenerateTokensWithDevice(claims.UserID, claims.Roles, claims.DeviceID)
					if genErr == nil {
						w.Header().Set("X-Refreshed-Token", newToken)
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ValidateAPIKey validates an API key from a request header and returns a context
// with the user ID, roles, permissions, and scopes set. API keys use the same token
// format but are long-lived and scoped to specific endpoints.
// If validation fails, returns the original context unchanged.
func (t *TokenService) ValidateAPIKey(ctx context.Context, apiKey string) context.Context {
	if apiKey == "" {
		return ctx
	}
	claims, err := t.ValidateTokenClaims(apiKey)
	if err != nil {
		return ctx
	}
	ctx = SetUserID(ctx, claims.UserID)
	ctx = SetRoles(ctx, claims.Roles)
	if len(claims.Scopes) > 0 {
		ctx = SetScopes(ctx, claims.Scopes)
	}
	if claims.DeviceID != "" {
		ctx = SetDeviceID(ctx, claims.DeviceID)
	}
	return ctx
}

// GenerateAPIKey creates a long-lived API key for service-to-service or bot integrations.
// The key carries the given roles and a restricted set of scopes.
// Use "*" as a scope for unrestricted access.
func (t *TokenService) GenerateAPIKey(userID uuid.UUID, roles []string, scopes []string, expiry time.Duration) (string, error) {
	allEntries := make([]string, 0, len(roles)+len(scopes))
	allEntries = append(allEntries, roles...)
	for _, s := range scopes {
		allEntries = append(allEntries, "scope:"+s)
	}
	rolesStr := strings.Join(allEntries, ",")

	expiryUnix := time.Now().Add(expiry).Unix()
	payload := fmt.Sprintf("%s|%s|%d|apikey", userID.String(), rolesStr, expiryUnix)
	return t.signToken(payload), nil
}
