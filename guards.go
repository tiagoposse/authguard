package entauth

import (
	"context"
	"strings"

	"github.com/google/uuid"
)

// GuardFunc is a function that validates authorization before a handler runs.
// Return nil to allow, or an error (ideally *GuardError) to reject.
// The client parameter is an interface{} to avoid circular imports with ent.
type GuardFunc func(ctx context.Context, client interface{}) error

// registry maps guard names to their implementations.
var registry = map[string]GuardFunc{
	"requiresAuth":      RequiresAuth,
	"requiresElevation": RequiresElevation,
}

// RegisterGuard registers a custom guard function by name.
func RegisterGuard(name string, fn GuardFunc) {
	registry[name] = fn
}

// Resolve returns the GuardFunc for a given name.
// Supports parameterized guards: "requiresRole:admin,editor" → RequiresAnyRole("admin", "editor")
func Resolve(name string) GuardFunc {
	// Check for parameterized guard: "guardName:param1,param2"
	if idx := strings.Index(name, ":"); idx >= 0 {
		guardName := name[:idx]
		params := strings.Split(name[idx+1:], ",")
		switch guardName {
		case "requiresRole":
			return RequiresAnyRole(params...)
		case "requiresScope":
			return RequiresAnyScope(params...)
		case "requiresSubscription":
			return RequiresSubscription(params...)
		}
	}

	if fn, ok := registry[name]; ok {
		return fn
	}
	return func(ctx context.Context, client interface{}) error {
		return Errorf(500, "unknown guard: %s", name)
	}
}

// RequiresAuth is a guard that ensures the request has a valid authenticated user.
func RequiresAuth(ctx context.Context, client interface{}) error {
	_, ok := GetUserID(ctx)
	if !ok {
		return ErrNotAuthenticated
	}
	return nil
}

// RequireAuth is a convenience function that extracts the user ID or returns a GuardError.
func RequireAuth(ctx context.Context) (uuid.UUID, error) {
	id, ok := GetUserID(ctx)
	if !ok {
		return uuid.Nil, ErrNotAuthenticated
	}
	return id, nil
}

// OptionalAuth extracts the user ID if present, returns uuid.Nil if not.
func OptionalAuth(ctx context.Context) uuid.UUID {
	id, _ := GetUserID(ctx)
	return id
}

// RequiresElevation is a guard that checks the user has admin elevation (X-Admin-Token).
// The admin user ID must match the authenticated user ID.
func RequiresElevation(ctx context.Context, client interface{}) error {
	userID, ok := GetUserID(ctx)
	if !ok {
		return ErrNotAuthenticated
	}
	adminID, ok := GetAdminUserID(ctx)
	if !ok || adminID != userID {
		return ErrElevationRequired
	}
	return nil
}

// RequireAdmin validates admin role + elevation and returns the admin user ID.
// Use this in custom handlers that need the admin ID (e.g., for audit logging).
func RequireAdmin(ctx context.Context) (uuid.UUID, error) {
	userID, err := RequireAuth(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	if !HasRole(ctx, "admin") {
		return uuid.Nil, ErrNotAdmin
	}
	adminID, ok := GetAdminUserID(ctx)
	if !ok || adminID != userID {
		return uuid.Nil, ErrElevationRequired
	}
	return userID, nil
}

// RequiresAnyRole creates a guard that checks for ANY of the specified roles.
func RequiresAnyRole(roles ...string) GuardFunc {
	return func(ctx context.Context, client interface{}) error {
		for _, role := range roles {
			if HasRole(ctx, role) {
				return nil
			}
		}
		return Errorf(403, "one of roles %v required", roles)
	}
}

// RequiresSubscription creates a guard that checks if the user's subscription tier
// is one of the allowed tiers. The tier is read from context (set by middleware).
func RequiresSubscription(tiers ...string) GuardFunc {
	return func(ctx context.Context, client interface{}) error {
		_, ok := GetUserID(ctx)
		if !ok {
			return ErrNotAuthenticated
		}

		tier, ok := GetSubscriptionTier(ctx)
		if !ok {
			// No subscription tier in context; default to "free"
			tier = "free"
		}

		for _, allowed := range tiers {
			if tier == allowed {
				return nil
			}
		}
		return Errorf(403, "subscription tier %v required", tiers)
	}
}

// --- Scope guards ---

// RequiresScope creates a guard that checks for a specific scope.
func RequiresScope(scope string) GuardFunc {
	return func(ctx context.Context, client interface{}) error {
		if !HasScope(ctx, scope) {
			return Errorf(403, "scope %q required", scope)
		}
		return nil
	}
}

// RequiresAnyScope creates a guard that checks for ANY of the specified scopes.
func RequiresAnyScope(scopes ...string) GuardFunc {
	return func(ctx context.Context, client interface{}) error {
		for _, scope := range scopes {
			if HasScope(ctx, scope) {
				return nil
			}
		}
		return Errorf(403, "one of scopes %v required", scopes)
	}
}

// RequiresAllScopes creates a guard that checks for ALL specified scopes.
func RequiresAllScopes(scopes ...string) GuardFunc {
	return func(ctx context.Context, client interface{}) error {
		for _, scope := range scopes {
			if !HasScope(ctx, scope) {
				return Errorf(403, "scope %q required", scope)
			}
		}
		return nil
	}
}

// --- Guard composition helpers ---

// All creates a guard that requires ALL inner guards to pass (AND logic).
func All(names ...string) GuardFunc {
	return func(ctx context.Context, client interface{}) error {
		for _, name := range names {
			if err := Resolve(name)(ctx, client); err != nil {
				return err
			}
		}
		return nil
	}
}

// Any creates a guard that requires at least one inner guard to pass (OR logic).
func Any(names ...string) GuardFunc {
	return func(ctx context.Context, client interface{}) error {
		var lastErr error
		for _, name := range names {
			if err := Resolve(name)(ctx, client); err == nil {
				return nil
			} else {
				lastErr = err
			}
		}
		if lastErr != nil {
			return lastErr
		}
		return Errorf(403, "none of guards %v passed", names)
	}
}

// Not creates a guard that passes only if the inner guard fails (negate).
func Not(name string) GuardFunc {
	return func(ctx context.Context, client interface{}) error {
		if err := Resolve(name)(ctx, client); err == nil {
			return Errorf(403, "guard %q must not pass", name)
		}
		return nil
	}
}
