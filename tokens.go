package authguard

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
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

// TokenKind says what a token may be used for. Each validator accepts
// exactly one kind, so a refresh token can't authenticate a request and an
// access token can't be exchanged for a new pair.
type TokenKind string

const (
	KindAccess  TokenKind = "access"
	KindRefresh TokenKind = "refresh"
	KindAPIKey  TokenKind = "apikey"
)

// RefreshTokenTTL is how long a refresh token is valid.
const RefreshTokenTTL = 7 * 24 * time.Hour

// TokenClaims holds the parsed claims from a validated token.
type TokenClaims struct {
	UserID    uuid.UUID
	Roles     []string
	Scopes    []string // fine-grained access control; JWTs get full set, API keys get a subset
	DeviceID  string
	Kind      TokenKind
	ExpiresAt time.Time
	// IssuedAt is when this token was signed. Zero for tokens issued before
	// the field existed.
	IssuedAt time.Time
	// AuthTime is when the user last authenticated (logged in), carried
	// unchanged through refreshes so a caller can cap a session's total age.
	// Zero for tokens issued before the field existed, and for API keys.
	AuthTime time.Time
}

// TokenOptions are the optional inputs to token generation.
type TokenOptions struct {
	DeviceID string
	// AuthTime is the original login time. Leave zero on login (it becomes
	// now); on refresh, pass the AuthTime of the refresh token being used.
	AuthTime time.Time
}

// GenerateTokens creates an access token and refresh token for the given user
// with the specified roles encoded in the payload.
func (t *TokenService) GenerateTokens(userID uuid.UUID, roles []string) (string, string, error) {
	return t.GenerateTokensWithOptions(userID, roles, TokenOptions{})
}

// GenerateTokensWithDevice creates tokens with an optional device/session identifier.
func (t *TokenService) GenerateTokensWithDevice(userID uuid.UUID, roles []string, deviceID string) (string, string, error) {
	return t.GenerateTokensWithOptions(userID, roles, TokenOptions{DeviceID: deviceID})
}

// GenerateTokensWithOptions creates an access and a refresh token.
func (t *TokenService) GenerateTokensWithOptions(userID uuid.UUID, roles []string, opts TokenOptions) (string, string, error) {
	now := time.Now()
	authTime := opts.AuthTime
	if authTime.IsZero() {
		authTime = now
	}

	allRoles := slices.Clone(roles)
	if t.scopeResolver != nil {
		for _, s := range t.scopeResolver(roles) {
			allRoles = append(allRoles, "scope:"+s)
		}
	}
	if err := checkPayloadFields(opts.DeviceID, allRoles); err != nil {
		return "", "", err
	}
	rolesStr := strings.Join(allRoles, ",")

	// The kind marker sits at segment 3 so tokens from older versions, which
	// put it (or the device ID) there too, still parse.
	// Access:  userID|roles|expiry|iat:N|auth:N[|dev:deviceID]
	// Refresh: userID|roles|expiry|refresh|iat:N|auth:N[|dev:deviceID]
	tail := fmt.Sprintf("|iat:%d|auth:%d", now.Unix(), authTime.Unix())
	if opts.DeviceID != "" {
		tail += "|dev:" + opts.DeviceID
	}
	access := t.signToken(fmt.Sprintf("%s|%s|%d%s", userID, rolesStr, now.Add(t.expiration).Unix(), tail))
	refresh := t.signToken(fmt.Sprintf("%s|%s|%d|refresh%s", userID, rolesStr, now.Add(RefreshTokenTTL).Unix(), tail))
	return access, refresh, nil
}

// "|" separates payload segments and "," separates roles, so a value
// containing either could forge a kind marker, an auth time or a scope.
func checkPayloadFields(deviceID string, roles []string) error {
	if strings.Contains(deviceID, "|") {
		return fmt.Errorf("device ID must not contain %q", "|")
	}
	for _, r := range roles {
		if strings.ContainsAny(r, "|,") {
			return fmt.Errorf("role %q must not contain %q or %q", r, "|", ",")
		}
	}
	return nil
}

// GenerateTokensForUser fetches roles via the RoleFetcher and then generates tokens.
// If no RoleFetcher is configured, tokens are generated with empty roles.
func (t *TokenService) GenerateTokensForUser(ctx context.Context, userID uuid.UUID) (string, string, error) {
	return t.GenerateTokensForUserWithOptions(ctx, userID, TokenOptions{})
}

// GenerateTokensForUserWithDevice fetches roles and generates tokens with a device ID.
func (t *TokenService) GenerateTokensForUserWithDevice(ctx context.Context, userID uuid.UUID, deviceID string) (string, string, error) {
	return t.GenerateTokensForUserWithOptions(ctx, userID, TokenOptions{DeviceID: deviceID})
}

// GenerateTokensForUserWithOptions fetches roles and generates tokens.
func (t *TokenService) GenerateTokensForUserWithOptions(ctx context.Context, userID uuid.UUID, opts TokenOptions) (string, string, error) {
	var roles []string
	if t.roleFetcher != nil {
		var err error
		roles, err = t.roleFetcher(ctx, userID)
		if err != nil {
			return "", "", fmt.Errorf("fetching roles: %w", err)
		}
	}
	return t.GenerateTokensWithOptions(userID, roles, opts)
}

// ValidateToken validates an access token and returns the user ID and roles.
// This is the backward-compatible signature; use ValidateTokenClaims for full claims.
func (t *TokenService) ValidateToken(token string) (uuid.UUID, []string, error) {
	claims, err := t.ValidateTokenClaims(token)
	if err != nil {
		return uuid.Nil, nil, err
	}
	return claims.UserID, claims.Roles, nil
}

// ValidateTokenClaims validates an access token and returns its claims.
// Refresh tokens and API keys are rejected; use ValidateRefreshTokenClaims
// or ValidateAPIKeyClaims for those.
func (t *TokenService) ValidateTokenClaims(token string) (*TokenClaims, error) {
	return t.validateKind(token, KindAccess)
}

// ValidateRefreshToken validates a refresh token and returns the user ID and roles.
func (t *TokenService) ValidateRefreshToken(token string) (uuid.UUID, []string, error) {
	claims, err := t.ValidateRefreshTokenClaims(token)
	if err != nil {
		return uuid.Nil, nil, err
	}
	return claims.UserID, claims.Roles, nil
}

// ValidateRefreshTokenClaims validates a refresh token and returns its claims.
func (t *TokenService) ValidateRefreshTokenClaims(token string) (*TokenClaims, error) {
	return t.validateKind(token, KindRefresh)
}

// ValidateAPIKeyClaims validates an API key and returns its claims.
func (t *TokenService) ValidateAPIKeyClaims(token string) (*TokenClaims, error) {
	return t.validateKind(token, KindAPIKey)
}

func (t *TokenService) validateKind(token string, want TokenKind) (*TokenClaims, error) {
	claims, err := t.parseToken(token)
	if err != nil {
		return nil, err
	}
	if claims.Kind != want {
		return nil, fmt.Errorf("expected %s token, got %s", want, claims.Kind)
	}
	return claims, nil
}

// parseToken verifies the signature, expiry and revocation of any kind of
// token. Callers must check Kind.
func (t *TokenService) parseToken(token string) (*TokenClaims, error) {
	parts := splitToken(token)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	payloadBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid token encoding")
	}
	payload := string(payloadBytes)

	mac := hmac.New(sha256.New, []byte(t.secret))
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
		return nil, fmt.Errorf("invalid token signature")
	}

	segments := strings.Split(payload, "|")
	if len(segments) < 2 {
		return nil, fmt.Errorf("invalid token payload")
	}

	userIDStr := segments[0]

	var allEntries []string
	var expiry int64

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

	claims := &TokenClaims{Kind: KindAccess}
	for i := 3; i < len(segments); i++ {
		seg := segments[i]
		switch {
		case i == 3 && seg == string(KindRefresh):
			claims.Kind = KindRefresh
		case i == 3 && seg == string(KindAPIKey):
			claims.Kind = KindAPIKey
		case strings.HasPrefix(seg, "dev:"):
			claims.DeviceID = strings.TrimPrefix(seg, "dev:")
		case strings.HasPrefix(seg, "iat:"):
			claims.IssuedAt, err = parseUnix(strings.TrimPrefix(seg, "iat:"))
		case strings.HasPrefix(seg, "auth:"):
			claims.AuthTime, err = parseUnix(strings.TrimPrefix(seg, "auth:"))
		}
		if err != nil {
			return nil, fmt.Errorf("invalid token payload")
		}
	}

	if expiry == 0 {
		return nil, fmt.Errorf("invalid token payload")
	}

	if time.Now().Unix() > expiry {
		return nil, fmt.Errorf("token expired")
	}

	claims.UserID, err = uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in token")
	}
	claims.ExpiresAt = time.Unix(expiry, 0)

	for _, entry := range allEntries {
		if strings.HasPrefix(entry, "scope:") {
			claims.Scopes = append(claims.Scopes, strings.TrimPrefix(entry, "scope:"))
		} else if strings.HasPrefix(entry, "perm:") {
			// Backward compat: treat old perm: entries as scopes
			claims.Scopes = append(claims.Scopes, strings.TrimPrefix(entry, "perm:"))
		} else {
			claims.Roles = append(claims.Roles, entry)
		}
	}

	if t.revocationStore != nil {
		sig := TokenSignature(token)
		if sig != "" && t.revocationStore.IsRevoked(claims, sig) {
			return nil, fmt.Errorf("token revoked")
		}
	}

	return claims, nil
}

func parseUnix(s string) (time.Time, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(n, 0), nil
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
