// Example: basic
//
// Minimal HTTP server with JWT authentication. Shows how to set up a
// TokenService, generate tokens at login, and protect endpoints.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/tiagoposse/entauth"
)

// Fake user store.
var users = map[string]struct {
	ID       uuid.UUID
	Password string
	Roles    []string
}{
	"alice": {ID: uuid.MustParse("00000000-0000-0000-0000-000000000001"), Password: "secret", Roles: []string{"admin"}},
	"bob":   {ID: uuid.MustParse("00000000-0000-0000-0000-000000000002"), Password: "secret", Roles: []string{"viewer"}},
}

var tokenService *entauth.TokenService

func main() {
	// 1. Create the token service with a 15-minute access token TTL.
	tokenService = entauth.NewTokenService(
		"my-hmac-secret",
		15*time.Minute,
		nil, // no role fetcher — we pass roles directly
	)

	// 2. Optionally resolve scopes from roles.
	tokenService.SetScopeResolver(func(roles []string) []string {
		scopes := []string{}
		for _, r := range roles {
			switch r {
			case "admin":
				scopes = append(scopes, "read", "write", "delete")
			case "viewer":
				scopes = append(scopes, "read")
			}
		}
		return scopes
	})

	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", loginHandler)
	mux.HandleFunc("GET /me", meHandler)

	// 3. Wrap everything with auth middleware.
	handler := authMiddleware(mux)

	fmt.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

// authMiddleware validates the Bearer token and populates the request context.
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := tokenService.ValidateAndSetUser(r.Context(), r.Header.Get("Authorization"))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// loginHandler authenticates credentials and returns access + refresh tokens.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	user, ok := users[body.Username]
	if !ok || user.Password != body.Password {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	access, refresh, err := tokenService.GenerateTokens(user.ID, user.Roles)
	if err != nil {
		http.Error(w, "token generation failed", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  access,
		"refresh_token": refresh,
	})
}

// meHandler returns the authenticated user's info.
func meHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := entauth.RequireAuth(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_id": userID,
		"roles":   entauth.GetRoles(r.Context()),
		"scopes":  entauth.GetScopes(r.Context()),
	})
}

// Try it:
//
//	curl -s -X POST localhost:8080/login -d '{"username":"alice","password":"secret"}' | jq .
//	curl -s localhost:8080/me -H "Authorization: Bearer <access_token>" | jq .

