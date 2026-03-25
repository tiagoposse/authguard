// Example: guards
//
// Demonstrates built-in guards, custom guards, and guard composition.
// Shows how to protect routes with role checks, scope checks, subscription
// tiers, and combined logic.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/tiagoposse/authguard"
)

var tokenService *authguard.TokenService

func main() {
	tokenService = authguard.NewTokenService("secret", 15*time.Minute, nil)
	tokenService.SetScopeResolver(func(roles []string) []string {
		m := map[string][]string{
			"admin":  {"read", "write", "delete", "users:manage"},
			"editor": {"read", "write"},
			"viewer": {"read"},
		}
		var scopes []string
		for _, r := range roles {
			scopes = append(scopes, m[r]...)
		}
		return scopes
	})

	// Register custom guards.
	authguard.RegisterGuard("isPremium", func(ctx context.Context, client interface{}) error {
		tier, ok := authguard.GetSubscriptionTier(ctx)
		if !ok || (tier != "pro" && tier != "enterprise") {
			return authguard.Errorf(403, "premium subscription required")
		}
		return nil
	})

	authguard.RegisterGuard("isOwner", func(ctx context.Context, client interface{}) error {
		// In a real app, compare the authenticated user ID with the resource owner.
		// Here we just check auth is present.
		_, ok := authguard.GetUserID(ctx)
		if !ok {
			return authguard.ErrNotAuthenticated
		}
		return nil
	})

	// Composed guards.
	authguard.RegisterGuard("canManageUsers",
		authguard.All("requiresAuth", "requiresRole:admin", "requiresScope:users:manage"),
	)
	authguard.RegisterGuard("canEditOrAdmin",
		authguard.Any("requiresRole:editor", "requiresRole:admin"),
	)
	authguard.RegisterGuard("premiumOrAdmin",
		authguard.Any("isPremium", "requiresRole:admin"),
	)

	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("GET /public", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "public endpoint — no auth required")
	})

	// Requires authentication
	mux.HandleFunc("GET /dashboard", guarded("requiresAuth", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"user":   authguard.OptionalAuth(r.Context()),
			"roles":  authguard.GetRoles(r.Context()),
			"scopes": authguard.GetScopes(r.Context()),
		})
	}))

	// Requires admin role
	mux.HandleFunc("GET /admin/users", guarded("canManageUsers", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "user management panel")
	}))

	// Requires write scope
	mux.HandleFunc("POST /articles", guarded("requiresScope:write", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "article created")
	}))

	// Requires premium OR admin
	mux.HandleFunc("GET /premium-feature", guarded("premiumOrAdmin", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "premium content")
	}))

	handler := authMiddleware(mux)

	// Print demo tokens for testing.
	printDemoTokens()

	fmt.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

// guarded wraps a handler with a named guard.
func guarded(guardName string, handler http.HandlerFunc) http.HandlerFunc {
	guard := authguard.Resolve(guardName)
	return func(w http.ResponseWriter, r *http.Request) {
		if err := guard(r.Context(), nil); err != nil {
			if ge, ok := err.(*authguard.GuardError); ok {
				http.Error(w, ge.Message, ge.Code)
			} else {
				http.Error(w, err.Error(), http.StatusForbidden)
			}
			return
		}
		handler(w, r)
	}
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := tokenService.ValidateAndSetUser(r.Context(), r.Header.Get("Authorization"))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func printDemoTokens() {
	adminID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	editorID := uuid.MustParse("00000000-0000-0000-0000-000000000002")
	viewerID := uuid.MustParse("00000000-0000-0000-0000-000000000003")

	adminToken, _, _ := tokenService.GenerateTokens(adminID, []string{"admin", "sub:enterprise"})
	editorToken, _, _ := tokenService.GenerateTokens(editorID, []string{"editor", "sub:pro"})
	viewerToken, _, _ := tokenService.GenerateTokens(viewerID, []string{"viewer", "sub:free"})

	fmt.Println("Demo tokens:")
	fmt.Printf("  admin:  %s\n", adminToken)
	fmt.Printf("  editor: %s\n", editorToken)
	fmt.Printf("  viewer: %s\n", viewerToken)
	fmt.Println()
}
