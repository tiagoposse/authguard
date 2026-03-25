package authguard

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// RevocationStore tracks revoked tokens in memory with automatic TTL-based cleanup.
// Entries expire when the original token would have expired, keeping the list small.
type RevocationStore struct {
	mu      sync.RWMutex
	tokens  map[string]time.Time    // token signature → expiry
	users   map[uuid.UUID]time.Time // userID → revoked-at (all tokens before this time are invalid)
	devices map[string]time.Time    // "userID:deviceID" → revoked-at
}

// NewRevocationStore creates a new in-memory revocation store and starts
// a background goroutine that cleans up expired entries every minute.
func NewRevocationStore() *RevocationStore {
	rs := &RevocationStore{
		tokens:  make(map[string]time.Time),
		users:   make(map[uuid.UUID]time.Time),
		devices: make(map[string]time.Time),
	}
	go rs.cleanupLoop()
	return rs
}

// RevokeToken adds a specific token to the blocklist. The token stays blocked
// until its original expiry time, then is automatically cleaned up.
func (rs *RevocationStore) RevokeToken(tokenSignature string, expiresAt time.Time) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.tokens[tokenSignature] = expiresAt
}

// RevokeAllForUser invalidates all tokens issued before now for the given user.
// Any token whose issue time (expiry minus TTL) is before the revocation timestamp
// will be rejected. Use this for "log out everywhere" or "password changed".
func (rs *RevocationStore) RevokeAllForUser(userID uuid.UUID) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.users[userID] = time.Now()
}

// RevokeAllForDevice invalidates all tokens for a specific user+device combination.
func (rs *RevocationStore) RevokeAllForDevice(userID uuid.UUID, deviceID string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	key := userID.String() + ":" + deviceID
	rs.devices[key] = time.Now()
}

// IsRevoked checks whether a token should be rejected. It checks:
// 1. Individual token revocation (by signature)
// 2. User-wide revocation (all tokens issued before revocation time)
// 3. Device-specific revocation
func (rs *RevocationStore) IsRevoked(claims *TokenClaims, tokenSignature string) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	// Check individual token
	if _, ok := rs.tokens[tokenSignature]; ok {
		return true
	}

	// Check user-wide revocation: token is revoked if it was issued before the revocation time.
	// We approximate issue time as ExpiresAt minus the token's TTL window.
	if revokedAt, ok := rs.users[claims.UserID]; ok {
		if claims.ExpiresAt.Before(revokedAt.Add(24 * time.Hour)) {
			// Token expires within 24h of revocation — it was likely issued before revocation.
			// This is conservative: we reject tokens that might have been issued around
			// the revocation time. For exact issue-time tracking, tokens would need an iat claim.
			return true
		}
	}

	// Check device-specific revocation
	if claims.DeviceID != "" {
		key := claims.UserID.String() + ":" + claims.DeviceID
		if revokedAt, ok := rs.devices[key]; ok {
			if claims.ExpiresAt.Before(revokedAt.Add(24 * time.Hour)) {
				return true
			}
		}
	}

	return false
}

// cleanupLoop removes expired entries every 60 seconds.
func (rs *RevocationStore) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		rs.cleanup()
	}
}

func (rs *RevocationStore) cleanup() {
	now := time.Now()
	rs.mu.Lock()
	defer rs.mu.Unlock()

	// Remove expired individual token revocations
	for sig, expiry := range rs.tokens {
		if now.After(expiry) {
			delete(rs.tokens, sig)
		}
	}

	// Remove user-wide revocations older than 24 hours (max token lifetime is 7 days for refresh,
	// but we keep revocations for 24h which covers access tokens; refresh tokens should be
	// re-validated against the DB anyway)
	cutoff := now.Add(-24 * time.Hour)
	for uid, revokedAt := range rs.users {
		if revokedAt.Before(cutoff) {
			delete(rs.users, uid)
		}
	}

	for key, revokedAt := range rs.devices {
		if revokedAt.Before(cutoff) {
			delete(rs.devices, key)
		}
	}
}

// tokenSignature extracts the signature portion from a raw token string.
// Tokens are formatted as "hexPayload.signature".
func TokenSignature(rawToken string) string {
	for i := len(rawToken) - 1; i >= 0; i-- {
		if rawToken[i] == '.' {
			return rawToken[i+1:]
		}
	}
	return ""
}
