// Example: revocation
//
// Demonstrates token revocation patterns: single token logout, logout
// from all devices, and per-device session revocation.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tiagoposse/authguard"
)

var (
	tokenService    *authguard.TokenService
	revocationStore *authguard.RevocationStore
)

func main() {
	// 1. Create the revocation store and token service.
	revocationStore = authguard.NewRevocationStore()

	tokenService = authguard.NewTokenService("secret", 15*time.Minute, nil)
	tokenService.SetRevocationStore(revocationStore)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /me", meHandler)
	mux.HandleFunc("POST /logout", logoutHandler)
	mux.HandleFunc("POST /logout-all", logoutAllHandler)
	mux.HandleFunc("POST /logout-device", logoutDeviceHandler)

	handler := authMiddleware(mux)

	// Generate demo tokens with device IDs.
	userID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	mobileToken, _, _ := tokenService.GenerateTokensWithDevice(userID, []string{"user"}, "mobile")
	desktopToken, _, _ := tokenService.GenerateTokensWithDevice(userID, []string{"user"}, "desktop")
	tabletToken, _, _ := tokenService.GenerateTokensWithDevice(userID, []string{"user"}, "tablet")

	fmt.Println("Demo tokens (all for the same user):")
	fmt.Printf("  mobile:  %s\n", mobileToken)
	fmt.Printf("  desktop: %s\n", desktopToken)
	fmt.Printf("  tablet:  %s\n", tabletToken)
	fmt.Println()

	fmt.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := tokenService.ValidateAndSetUser(r.Context(), r.Header.Get("Authorization"))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// meHandler shows the authenticated user info (or 401 if token was revoked).
func meHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := authguard.RequireAuth(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	deviceID, _ := authguard.GetDeviceID(r.Context())
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_id":  userID,
		"device":   deviceID,
		"roles":    authguard.GetRoles(r.Context()),
	})
}

// logoutHandler revokes the current token only.
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	rawToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if rawToken == "" {
		http.Error(w, "no token", http.StatusBadRequest)
		return
	}

	claims, err := tokenService.ValidateTokenClaims(rawToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	sig := authguard.TokenSignature(rawToken)
	revocationStore.RevokeToken(sig, claims.ExpiresAt)

	fmt.Fprintln(w, "token revoked")
}

// logoutAllHandler revokes all tokens for the authenticated user.
func logoutAllHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := authguard.RequireAuth(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	revocationStore.RevokeAllForUser(userID)
	fmt.Fprintln(w, "all sessions revoked")
}

// logoutDeviceHandler revokes all tokens for a specific device.
func logoutDeviceHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := authguard.RequireAuth(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var body struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.DeviceID == "" {
		http.Error(w, "device_id required", http.StatusBadRequest)
		return
	}

	revocationStore.RevokeAllForDevice(userID, body.DeviceID)
	fmt.Fprintf(w, "device %q sessions revoked\n", body.DeviceID)
}

// Try it:
//
//	# Verify token works:
//	curl -s localhost:8080/me -H "Authorization: Bearer <mobile_token>" | jq .
//
//	# Revoke just the mobile token:
//	curl -s -X POST localhost:8080/logout -H "Authorization: Bearer <mobile_token>"
//	curl -s localhost:8080/me -H "Authorization: Bearer <mobile_token>"  # → 401
//	curl -s localhost:8080/me -H "Authorization: Bearer <desktop_token>" | jq .  # → still works
//
//	# Revoke a specific device (tablet):
//	curl -s -X POST localhost:8080/logout-device \
//	  -H "Authorization: Bearer <desktop_token>" \
//	  -d '{"device_id":"tablet"}'
//	curl -s localhost:8080/me -H "Authorization: Bearer <tablet_token>"  # → 401
//
//	# Revoke ALL sessions:
//	curl -s -X POST localhost:8080/logout-all -H "Authorization: Bearer <desktop_token>"
//	curl -s localhost:8080/me -H "Authorization: Bearer <desktop_token>"  # → 401
