package entauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// RoleFetcher is a function that retrieves roles for a given user ID.
type RoleFetcher func(ctx context.Context, userID uuid.UUID) ([]string, error)

// ScopeResolver maps roles to scopes. Given a set of roles, it returns
// the full set of scopes the user has access to. This is called at token
// generation time so scopes are embedded in the token — no DB query needed at request time.
type ScopeResolver func(roles []string) []string

// TokenService handles token generation and validation.
type TokenService struct {
	secret          string
	expiration      time.Duration
	roleFetcher     RoleFetcher
	scopeResolver   ScopeResolver
	revocationStore *RevocationStore
}

// NewTokenService creates a new TokenService. roleFetcher and permissionResolver may be nil.
func NewTokenService(secret string, expiration time.Duration, roleFetcher RoleFetcher) *TokenService {
	return &TokenService{
		secret:      secret,
		expiration:  expiration,
		roleFetcher: roleFetcher,
	}
}

// SetScopeResolver configures how roles map to scopes.
// Scopes are embedded in tokens alongside roles.
func (t *TokenService) SetScopeResolver(resolver ScopeResolver) {
	t.scopeResolver = resolver
}

// SetRevocationStore attaches an in-memory revocation store for token invalidation.
func (t *TokenService) SetRevocationStore(store *RevocationStore) {
	t.revocationStore = store
}

// RevocationStore returns the attached revocation store, or nil if none is configured.
func (t *TokenService) RevocationStore() *RevocationStore {
	return t.revocationStore
}

// Expiration returns the configured access token expiration duration.
func (t *TokenService) Expiration() time.Duration {
	return t.expiration
}

// TokenClaims holds the parsed claims from a validated token.
type TokenClaims struct {
	UserID    uuid.UUID
	Roles     []string
	Scopes    []string // fine-grained access control; JWTs get full set, API keys get a subset
	DeviceID  string
	ExpiresAt time.Time
}

// GenerateTokens creates an access token and refresh token for the given user
// with the specified roles encoded in the payload.
func (t *TokenService) GenerateTokens(userID uuid.UUID, roles []string) (string, string, error) {
	return t.GenerateTokensWithDevice(userID, roles, "")
}

// GenerateTokensWithDevice creates tokens with an optional device/session identifier.
func (t *TokenService) GenerateTokensWithDevice(userID uuid.UUID, roles []string, deviceID string) (string, string, error) {
	now := time.Now()

	// Resolve scopes from roles if resolver is configured
	allRoles := roles
	if t.scopeResolver != nil {
		scopes := t.scopeResolver(roles)
		for _, s := range scopes {
			allRoles = append(allRoles, "scope:"+s)
		}
	}

	rolesStr := strings.Join(allRoles, ",")

	// Access token: userID|roles|expiry[|dev:deviceID]
	expiry := now.Add(t.expiration).Unix()
	payload := fmt.Sprintf("%s|%s|%d", userID.String(), rolesStr, expiry)
	if deviceID != "" {
		payload += "|dev:" + deviceID
	}
	token := t.signToken(payload)

	// Refresh token: userID|roles|expiry|refresh[|dev:deviceID] (longer lived)
	refreshExpiry := now.Add(7 * 24 * time.Hour).Unix()
	refreshPayload := fmt.Sprintf("%s|%s|%d|refresh", userID.String(), rolesStr, refreshExpiry)
	if deviceID != "" {
		refreshPayload += "|dev:" + deviceID
	}
	refreshToken := t.signToken(refreshPayload)

	return token, refreshToken, nil
}

// GenerateTokensForUser fetches roles via the RoleFetcher and then generates tokens.
// If no RoleFetcher is configured, tokens are generated with empty roles.
func (t *TokenService) GenerateTokensForUser(ctx context.Context, userID uuid.UUID) (string, string, error) {
	return t.GenerateTokensForUserWithDevice(ctx, userID, "")
}

// GenerateTokensForUserWithDevice fetches roles and generates tokens with a device ID.
func (t *TokenService) GenerateTokensForUserWithDevice(ctx context.Context, userID uuid.UUID, deviceID string) (string, string, error) {
	var roles []string
	if t.roleFetcher != nil {
		var err error
		roles, err = t.roleFetcher(ctx, userID)
		if err != nil {
			return "", "", fmt.Errorf("fetching roles: %w", err)
		}
	}
	return t.GenerateTokensWithDevice(userID, roles, deviceID)
}

// ValidateToken validates an access or refresh token and returns the user ID and roles.
// This is the backward-compatible signature; use ValidateTokenClaims for full claims.
func (t *TokenService) ValidateToken(token string) (uuid.UUID, []string, error) {
	claims, err := t.ValidateTokenClaims(token)
	if err != nil {
		return uuid.Nil, nil, err
	}
	return claims.UserID, claims.Roles, nil
}

// ValidateTokenClaims validates a token and returns full claims including permissions and device ID.
// Also checks the revocation store if one is configured.
func (t *TokenService) ValidateTokenClaims(token string) (*TokenClaims, error) {
	parts := splitToken(token)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	payloadBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid token encoding")
	}
	payload := string(payloadBytes)

	// Verify signature
	mac := hmac.New(sha256.New, []byte(t.secret))
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
		return nil, fmt.Errorf("invalid token signature")
	}

	// Parse payload: split by "|"
	segments := strings.Split(payload, "|")
	if len(segments) < 2 {
		return nil, fmt.Errorf("invalid token payload")
	}

	userIDStr := segments[0]

	var allEntries []string
	var expiry int64
	var deviceID string

	if len(segments) >= 3 {
		// Try new format: segments[1] is roles, segments[2] is expiry
		_, parseErr := fmt.Sscanf(segments[2], "%d", &expiry)
		if parseErr == nil {
			if segments[1] != "" {
				allEntries = strings.Split(segments[1], ",")
			}
		} else {
			// Old format: segments[1] is expiry
			fmt.Sscanf(segments[1], "%d", &expiry)
		}
	} else {
		// Old format: userID|expiry
		fmt.Sscanf(segments[1], "%d", &expiry)
	}

	// Scan remaining segments for device ID and "refresh" marker
	for i := 3; i < len(segments); i++ {
		if strings.HasPrefix(segments[i], "dev:") {
			deviceID = strings.TrimPrefix(segments[i], "dev:")
		}
	}

	if expiry == 0 {
		return nil, fmt.Errorf("invalid token payload")
	}

	if time.Now().Unix() > expiry {
		return nil, fmt.Errorf("token expired")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in token")
	}

	// Separate roles and scopes (scope: prefix)
	var roles []string
	var scopes []string
	for _, entry := range allEntries {
		if strings.HasPrefix(entry, "scope:") {
			scopes = append(scopes, strings.TrimPrefix(entry, "scope:"))
		} else if strings.HasPrefix(entry, "perm:") {
			// Backward compat: treat old perm: entries as scopes
			scopes = append(scopes, strings.TrimPrefix(entry, "perm:"))
		} else {
			roles = append(roles, entry)
		}
	}

	claims := &TokenClaims{
		UserID:    userID,
		Roles:     roles,
		Scopes:    scopes,
		DeviceID:  deviceID,
		ExpiresAt: time.Unix(expiry, 0),
	}

	// Check revocation store
	if t.revocationStore != nil {
		sig := TokenSignature(token)
		if sig != "" && t.revocationStore.IsRevoked(claims, sig) {
			return nil, fmt.Errorf("token revoked")
		}
	}

	return claims, nil
}

// ValidateRefreshToken validates a refresh token and returns the user ID and roles.
func (t *TokenService) ValidateRefreshToken(token string) (uuid.UUID, []string, error) {
	return t.ValidateToken(token)
}

// GenerateAdminToken creates a short-lived admin elevation token (1 hour).
func (t *TokenService) GenerateAdminToken(userID uuid.UUID) (string, time.Time) {
	expiry := time.Now().Add(1 * time.Hour)
	payload := fmt.Sprintf("admin|%s|%d", userID.String(), expiry.Unix())
	return t.signToken(payload), expiry
}

// ValidateAdminToken verifies an admin elevation token and returns the admin's user ID.
func (t *TokenService) ValidateAdminToken(token string) (uuid.UUID, error) {
	parts := splitToken(token)
	if len(parts) != 2 {
		return uuid.Nil, fmt.Errorf("invalid admin token format")
	}

	payloadBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid admin token encoding")
	}
	payload := string(payloadBytes)

	// Verify signature
	mac := hmac.New(sha256.New, []byte(t.secret))
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
		return uuid.Nil, fmt.Errorf("invalid admin token signature")
	}

	// Parse payload: "admin|uuid|expiry"
	var prefix, userIDStr string
	var expiry int64
	n, _ := fmt.Sscanf(payload, "%5s|%36s|%d", &prefix, &userIDStr, &expiry)
	if n < 3 || prefix != "admin" {
		return uuid.Nil, fmt.Errorf("invalid admin token payload")
	}

	if time.Now().Unix() > expiry {
		return uuid.Nil, fmt.Errorf("admin token expired")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user ID in admin token")
	}

	return userID, nil
}

func (t *TokenService) signToken(payload string) string {
	mac := hmac.New(sha256.New, []byte(t.secret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return hex.EncodeToString([]byte(payload)) + "." + sig
}

func splitToken(token string) []string {
	for i := len(token) - 1; i >= 0; i-- {
		if token[i] == '.' {
			return []string{token[:i], token[i+1:]}
		}
	}
	return nil
}
