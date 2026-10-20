package authguard

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func newStore() *RevocationStore {
	return &RevocationStore{
		tokens:  map[string]time.Time{},
		users:   map[uuid.UUID]time.Time{},
		devices: map[string]time.Time{},
	}
}

func TestRevokeAllForUserBlocksRefreshTokens(t *testing.T) {
	ts := newTestService()
	rs := newStore()
	ts.SetRevocationStore(rs)
	uid := uuid.New()

	access, refresh, err := ts.GenerateTokens(uid, nil)
	if err != nil {
		t.Fatal(err)
	}
	rs.RevokeAllForUser(uid)

	if _, err := ts.ValidateTokenClaims(access); err == nil {
		t.Error("access token issued before the revocation still works")
	}
	if _, err := ts.ValidateRefreshTokenClaims(refresh); err == nil {
		t.Error("refresh token issued before the revocation still works")
	}
}

func TestUserRevocationLeavesAPIKeys(t *testing.T) {
	ts := newTestService()
	rs := newStore()
	ts.SetRevocationStore(rs)
	uid := uuid.New()

	key, err := ts.GenerateAPIKey(uid, nil, []string{"read"}, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rs.RevokeAllForUser(uid)
	if _, err := ts.ValidateAPIKeyClaims(key); err != nil {
		t.Fatalf("api key after a user revocation: %v", err)
	}

	rs.RevokeToken(TokenSignature(key), time.Now().Add(365*24*time.Hour))
	if _, err := ts.ValidateAPIKeyClaims(key); err == nil {
		t.Fatal("api key revoked by signature still works")
	}
}

func TestTokensIssuedAfterRevocationWork(t *testing.T) {
	ts := newTestService()
	rs := newStore()
	ts.SetRevocationStore(rs)
	uid := uuid.New()

	rs.users[uid] = time.Now().Add(-2 * time.Second)
	rs.devices[uid.String()+":phone"] = time.Now().Add(-2 * time.Second)

	access, refresh, err := ts.GenerateTokensWithDevice(uid, nil, "phone")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.ValidateTokenClaims(access); err != nil {
		t.Errorf("new access token after a revocation: %v", err)
	}
	if _, err := ts.ValidateRefreshTokenClaims(refresh); err != nil {
		t.Errorf("new refresh token after a revocation: %v", err)
	}
}

func TestRevokeAllForDeviceLeavesOtherDevices(t *testing.T) {
	ts := newTestService()
	rs := newStore()
	ts.SetRevocationStore(rs)
	uid := uuid.New()

	phone, _, _ := ts.GenerateTokensWithDevice(uid, nil, "phone")
	laptop, _, _ := ts.GenerateTokensWithDevice(uid, nil, "laptop")
	rs.RevokeAllForDevice(uid, "phone")

	if _, err := ts.ValidateTokenClaims(phone); err == nil {
		t.Error("revoked device's token still works")
	}
	if _, err := ts.ValidateTokenClaims(laptop); err != nil {
		t.Errorf("other device's token: %v", err)
	}
}

func TestUserRevocationOutlivesRefreshTokens(t *testing.T) {
	rs := newStore()
	uid := uuid.New()
	rs.users[uid] = time.Now().Add(-48 * time.Hour)
	rs.cleanup()
	if _, ok := rs.users[uid]; !ok {
		t.Fatal("a 2-day-old user revocation was dropped while 7-day refresh tokens from before it are still valid")
	}
	rs.users[uid] = time.Now().Add(-RefreshTokenTTL - time.Minute)
	rs.cleanup()
	if _, ok := rs.users[uid]; ok {
		t.Fatal("a revocation older than the refresh TTL was kept")
	}
}
