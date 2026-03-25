// Example: apikeys
//
// Shows how to generate and validate API keys for service-to-service
// communication. API keys are long-lived tokens with restricted scopes.
package main

import (
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
		return []string{"read", "write", "delete", "webhooks"}
	})

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api-keys", createAPIKeyHandler)
	mux.HandleFunc("GET /webhooks", webhookHandler)
	mux.HandleFunc("GET /data", dataHandler)

	// Middleware: check Bearer token first, fall back to X-API-Key header.
	handler := authMiddleware(mux)

	// Generate a demo API key with only "read" and "webhooks" scopes.
	serviceUserID := uuid.MustParse("00000000-0000-0000-0000-000000000099")
	apiKey, _ := tokenService.GenerateAPIKey(
		serviceUserID,
		[]string{"service"},
		[]string{"read", "webhooks"},
		365*24*time.Hour,
	)
	fmt.Printf("Demo API key (read + webhooks only):\n  %s\n\n", apiKey)

	// Generate a wildcard API key.
	wildcardKey, _ := tokenService.GenerateAPIKey(
		serviceUserID,
		[]string{"service"},
		[]string{"*"}, // unrestricted
		30*24*time.Hour,
	)
	fmt.Printf("Wildcard API key (unrestricted):\n  %s\n\n", wildcardKey)

	fmt.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Try Bearer token first.
		if auth := r.Header.Get("Authorization"); auth != "" {
			ctx = tokenService.ValidateAndSetUser(ctx, auth)
		} else if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
			// Fall back to API key.
			ctx = tokenService.ValidateAPIKey(ctx, apiKey)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// createAPIKeyHandler generates a new API key with the requested scopes.
func createAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	// In production, this should require admin auth.
	var body struct {
		UserID   string   `json:"user_id"`
		Roles    []string `json:"roles"`
		Scopes   []string `json:"scopes"`
		ExpiryDays int    `json:"expiry_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	uid, err := uuid.Parse(body.UserID)
	if err != nil {
		http.Error(w, "invalid user_id", http.StatusBadRequest)
		return
	}

	expiry := time.Duration(body.ExpiryDays) * 24 * time.Hour
	if expiry == 0 {
		expiry = 90 * 24 * time.Hour // default 90 days
	}

	apiKey, err := tokenService.GenerateAPIKey(uid, body.Roles, body.Scopes, expiry)
	if err != nil {
		http.Error(w, "key generation failed", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"api_key": apiKey})
}

// webhookHandler requires the "webhooks" scope.
func webhookHandler(w http.ResponseWriter, r *http.Request) {
	if err := authguard.RequiresScope("webhooks")(r.Context(), nil); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"webhooks": []string{"push", "pull_request", "release"},
		"caller":   authguard.OptionalAuth(r.Context()),
		"scopes":   authguard.GetScopes(r.Context()),
	})
}

// dataHandler requires the "read" scope.
func dataHandler(w http.ResponseWriter, r *http.Request) {
	if err := authguard.RequiresScope("read")(r.Context(), nil); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"data": "some data"})
}

// Try it:
//
//	# With the demo API key (has read + webhooks scopes):
//	curl -s localhost:8080/webhooks -H "X-API-Key: <api_key>" | jq .
//	curl -s localhost:8080/data -H "X-API-Key: <api_key>" | jq .
//
//	# Create a new API key:
//	curl -s -X POST localhost:8080/api-keys \
//	  -d '{"user_id":"00000000-0000-0000-0000-000000000099","roles":["bot"],"scopes":["read"],"expiry_days":30}' | jq .
