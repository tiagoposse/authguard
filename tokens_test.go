package authguard

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newTestService() *TokenService {
	return NewTokenService("test-secret", 15*time.Minute, nil)
}

func TestEachValidatorAcceptsOnlyItsKind(t *testing.T) {
	ts := newTestService()
	uid := uuid.New()
	access, refresh, err := ts.GenerateTokens(uid, []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	apiKey, err := ts.GenerateAPIKey(uid, nil, []string{"read"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	validators := map[TokenKind]func(string) (*TokenClaims, error){
		KindAccess:  ts.ValidateTokenClaims,
		KindRefresh: ts.ValidateRefreshTokenClaims,
		KindAPIKey:  ts.ValidateAPIKeyClaims,
	}
	tokens := map[TokenKind]string{KindAccess: access, KindRefresh: refresh, KindAPIKey: apiKey}

	for vKind, validate := range validators {
		for tKind, tok := range tokens {
			claims, err := validate(tok)
			if vKind == tKind {
				if err != nil {
					t.Errorf("%s validator rejected its own kind: %v", vKind, err)
				} else if claims.Kind != tKind || claims.UserID != uid {
					t.Errorf("%s claims = %+v", vKind, claims)
				}
			} else if err == nil {
				t.Errorf("%s validator accepted a %s token", vKind, tKind)
			}
		}
	}

	if _, _, err := ts.ValidateRefreshToken(access); err == nil {
		t.Error("ValidateRefreshToken accepted an access token")
	}
	if ctx := ts.ValidateAndSetUser(context.Background(), "Bearer "+refresh); OptionalAuth(ctx) != uuid.Nil {
		t.Error("a refresh token authenticated a bearer request")
	}
	if ctx := ts.ValidateAPIKey(context.Background(), access); OptionalAuth(ctx) != uuid.Nil {
		t.Error("an access token was accepted as an API key")
	}
}

func TestAuthTimeSurvivesRefresh(t *testing.T) {
	ts := newTestService()
	uid := uuid.New()
	login := time.Now().Add(-3 * time.Hour).Truncate(time.Second)

	_, refresh, err := ts.GenerateTokensWithOptions(uid, nil, TokenOptions{DeviceID: "laptop", AuthTime: login})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ts.ValidateRefreshTokenClaims(refresh)
	if err != nil {
		t.Fatal(err)
	}
	if !claims.AuthTime.Equal(login) || claims.DeviceID != "laptop" {
		t.Fatalf("claims = %+v, want auth time %v and device laptop", claims, login)
	}
	if time.Since(claims.IssuedAt) > time.Minute {
		t.Fatalf("issued at = %v, want about now", claims.IssuedAt)
	}

	access, _, err := ts.GenerateTokensWithOptions(uid, nil, TokenOptions{DeviceID: claims.DeviceID, AuthTime: claims.AuthTime})
	if err != nil {
		t.Fatal(err)
	}
	next, err := ts.ValidateTokenClaims(access)
	if err != nil {
		t.Fatal(err)
	}
	if !next.AuthTime.Equal(login) {
		t.Fatalf("auth time after refresh = %v, want %v", next.AuthTime, login)
	}
}

func TestZeroAuthTimeMeansNow(t *testing.T) {
	ts := newTestService()
	access, _, err := ts.GenerateTokens(uuid.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ts.ValidateTokenClaims(access)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(claims.AuthTime) > time.Minute {
		t.Fatalf("auth time = %v, want about now", claims.AuthTime)
	}
}

func TestSeparatorsInFieldsAreRejected(t *testing.T) {
	ts := newTestService()
	uid := uuid.New()
	if _, _, err := ts.GenerateTokensWithDevice(uid, nil, "x|refresh"); err == nil {
		t.Error("a device ID containing | was accepted")
	}
	if _, _, err := ts.GenerateTokens(uid, []string{"user,scope:*"}); err == nil {
		t.Error("a role containing , was accepted")
	}
	if _, err := ts.GenerateAPIKey(uid, nil, []string{"read|refresh"}, time.Hour); err == nil {
		t.Error("a scope containing | was accepted")
	}
}

func TestScopeResolverDoesNotMutateRoles(t *testing.T) {
	ts := newTestService()
	ts.SetScopeResolver(func([]string) []string { return []string{"write"} })
	roles := make([]string, 1, 4)
	roles[0] = "editor"
	if _, _, err := ts.GenerateTokens(uuid.New(), roles); err != nil {
		t.Fatal(err)
	}
	if got := roles[:cap(roles)][1]; got != "" {
		t.Fatalf("caller's roles backing array was written: %q", got)
	}
}

// signLegacy builds a token in the pre-TokenKind payload format.
func signLegacy(ts *TokenService, payload string) string {
	return ts.signToken(payload)
}

func TestLegacyTokensStillParse(t *testing.T) {
	ts := newTestService()
	uid := uuid.New()
	exp := time.Now().Add(time.Hour).Unix()

	cases := []struct {
		payload string
		kind    TokenKind
		device  string
	}{
		{fmt.Sprintf("%s|admin|%d", uid, exp), KindAccess, ""},
		{fmt.Sprintf("%s|admin|%d|dev:phone", uid, exp), KindAccess, "phone"},
		{fmt.Sprintf("%s|admin|%d|refresh|dev:phone", uid, exp), KindRefresh, "phone"},
		{fmt.Sprintf("%s|scope:read|%d|apikey", uid, exp), KindAPIKey, ""},
	}
	for _, c := range cases {
		claims, err := ts.parseToken(signLegacy(ts, c.payload))
		if err != nil {
			t.Errorf("%s: %v", c.payload, err)
			continue
		}
		if claims.Kind != c.kind || claims.DeviceID != c.device || !claims.IssuedAt.IsZero() || !claims.AuthTime.IsZero() {
			t.Errorf("%s: claims = %+v", c.payload, claims)
		}
	}
}

func TestTamperedTokenIsRejected(t *testing.T) {
	ts := newTestService()
	access, _, err := ts.GenerateTokens(uuid.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	parts := splitToken(access)
	raw, _ := hex.DecodeString(parts[0])
	forged := hex.EncodeToString(append(raw, []byte("|refresh")...)) + "." + parts[1]
	if _, err := ts.ValidateRefreshTokenClaims(forged); err == nil {
		t.Fatal("a payload edited without re-signing was accepted")
	}
}
