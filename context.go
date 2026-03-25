package authguard

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type contextKey string

const (
	userIDKey           contextKey = "userID"
	adminUserIDKey      contextKey = "adminUserID"
	rolesKey            contextKey = "roles"
	scopesKey           contextKey = "scopes"
	subscriptionTierKey contextKey = "subscriptionTier"
	deviceIDKey         contextKey = "deviceID"
	tokenExpiryKey      contextKey = "tokenExpiry"
)

// SetUserID stores the authenticated user ID in context.
func SetUserID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, userIDKey, id)
}

// GetUserID extracts the authenticated user ID from context.
func GetUserID(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(userIDKey).(uuid.UUID)
	return id, ok
}

// SetAdminUserID stores the elevated admin user ID in context.
func SetAdminUserID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, adminUserIDKey, id)
}

// GetAdminUserID extracts the elevated admin user ID from context.
func GetAdminUserID(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(adminUserIDKey).(uuid.UUID)
	return id, ok
}

// SetRoles stores the user's roles in context.
func SetRoles(ctx context.Context, roles []string) context.Context {
	return context.WithValue(ctx, rolesKey, roles)
}

// GetRoles extracts the user's roles from context.
func GetRoles(ctx context.Context) []string {
	roles, _ := ctx.Value(rolesKey).([]string)
	return roles
}

// HasRole checks whether the context contains a specific role.
func HasRole(ctx context.Context, role string) bool {
	for _, r := range GetRoles(ctx) {
		if r == role {
			return true
		}
	}
	return false
}

// SetSubscriptionTier stores the user's subscription tier in context.
func SetSubscriptionTier(ctx context.Context, tier string) context.Context {
	return context.WithValue(ctx, subscriptionTierKey, tier)
}

// GetSubscriptionTier extracts the user's subscription tier from context.
func GetSubscriptionTier(ctx context.Context) (string, bool) {
	tier, ok := ctx.Value(subscriptionTierKey).(string)
	return tier, ok
}

// SetScopes stores the token's scopes in context.
// Regular JWTs carry the full scope set from the ScopeResolver.
// API keys carry a restricted subset.
func SetScopes(ctx context.Context, scopes []string) context.Context {
	return context.WithValue(ctx, scopesKey, scopes)
}

// GetScopes extracts the token's scopes from context.
func GetScopes(ctx context.Context) []string {
	scopes, _ := ctx.Value(scopesKey).([]string)
	return scopes
}

// HasScope checks whether the context contains a specific scope.
func HasScope(ctx context.Context, scope string) bool {
	for _, s := range GetScopes(ctx) {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

// SetDeviceID stores the device/session identifier in context.
func SetDeviceID(ctx context.Context, deviceID string) context.Context {
	return context.WithValue(ctx, deviceIDKey, deviceID)
}

// GetDeviceID extracts the device/session identifier from context.
func GetDeviceID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(deviceIDKey).(string)
	return id, ok
}

// SetTokenExpiry stores the token expiry time in context (used by refresh middleware).
func SetTokenExpiry(ctx context.Context, expiry time.Time) context.Context {
	return context.WithValue(ctx, tokenExpiryKey, expiry)
}

// GetTokenExpiry extracts the token expiry time from context.
func GetTokenExpiry(ctx context.Context) (time.Time, bool) {
	t, ok := ctx.Value(tokenExpiryKey).(time.Time)
	return t, ok
}
