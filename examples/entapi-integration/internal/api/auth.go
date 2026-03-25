//go:build ignore

package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	auth "github.com/tiagoposse/entauth"
	"github.com/yourorg/yourapp/ent"
	"github.com/yourorg/yourapp/ent/session"
	entuser "github.com/yourorg/yourapp/ent/user"
	"golang.org/x/crypto/bcrypt"
)

// login authenticates a user and creates a session.
func (s *Server) login(ctx context.Context, _ *ent.Client, request LoginRequestObject) (LoginResponseObject, error) {
	if request.Body == nil {
		return Login400JSONResponse{Error: "request body required"}, nil
	}

	user, err := s.client.User.Query().
		Where(entuser.EmailEQ(request.Body.Email)).
		Only(ctx)
	if err != nil {
		return Login401JSONResponse{Error: "invalid credentials"}, nil
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(request.Body.Password)); err != nil {
		return Login401JSONResponse{Error: "invalid credentials"}, nil
	}

	// Generate tokens with device tracking.
	deviceID := request.Body.DeviceId
	if deviceID == "" {
		deviceID = uuid.New().String() // auto-generate if not provided
	}

	access, refresh, err := s.tokenService.GenerateTokensForUserWithDevice(ctx, user.ID, deviceID)
	if err != nil {
		return nil, fmt.Errorf("generating tokens: %w", err)
	}

	// Persist the session in the database.
	refreshHash := hashToken(refresh)
	_, err = s.client.Session.Create().
		SetUserID(user.ID).
		SetDeviceID(deviceID).
		SetDeviceName(request.Body.DeviceName).
		SetIPAddress(request.Body.IpAddress).
		SetRefreshTokenHash(refreshHash).
		SetExpiresAt(time.Now().Add(7 * 24 * time.Hour)).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	return Login200JSONResponse(AuthResponse{
		AccessToken:  access,
		RefreshToken: refresh,
		User:         toAuthUser(user),
	}), nil
}

// register creates a new user account and session.
func (s *Server) register(ctx context.Context, _ *ent.Client, request RegisterRequestObject) (RegisterResponseObject, error) {
	if request.Body == nil {
		return Register400JSONResponse{Error: "request body required"}, nil
	}

	if len(request.Body.Password) < 8 {
		return Register400JSONResponse{Error: "password must be at least 8 characters"}, nil
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Body.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	user, err := s.client.User.Create().
		SetEmail(request.Body.Email).
		SetUsername(request.Body.Username).
		SetPasswordHash(string(hashedPassword)).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return Register409JSONResponse{Error: "email or username already exists"}, nil
		}
		return nil, err
	}

	deviceID := uuid.New().String()
	access, refresh, err := s.tokenService.GenerateTokensForUserWithDevice(ctx, user.ID, deviceID)
	if err != nil {
		return nil, fmt.Errorf("generating tokens: %w", err)
	}

	// Create initial session.
	s.client.Session.Create().
		SetUserID(user.ID).
		SetDeviceID(deviceID).
		SetRefreshTokenHash(hashToken(refresh)).
		SetExpiresAt(time.Now().Add(7 * 24 * time.Hour)).
		Save(ctx) //nolint:errcheck

	return Register201JSONResponse(AuthResponse{
		AccessToken:  access,
		RefreshToken: refresh,
		User:         toAuthUser(user),
	}), nil
}

// refreshToken exchanges a valid refresh token for new access + refresh tokens.
func (s *Server) refreshToken(ctx context.Context, _ *ent.Client, request RefreshTokenRequestObject) (RefreshTokenResponseObject, error) {
	if request.Body == nil {
		return RefreshToken401JSONResponse{Error: "request body required"}, nil
	}

	userID, _, err := s.tokenService.ValidateRefreshToken(request.Body.RefreshToken)
	if err != nil {
		return RefreshToken401JSONResponse{Error: "invalid refresh token"}, nil
	}

	// Verify the session still exists and isn't revoked.
	oldHash := hashToken(request.Body.RefreshToken)
	sess, err := s.client.Session.Query().
		Where(
			session.UserIDEQ(userID),
			session.RefreshTokenHashEQ(oldHash),
			session.RevokedAtIsNil(),
		).
		Only(ctx)
	if err != nil {
		return RefreshToken401JSONResponse{Error: "session not found or revoked"}, nil
	}

	// Generate new tokens with the same device ID.
	access, refresh, err := s.tokenService.GenerateTokensForUserWithDevice(ctx, userID, sess.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("generating tokens: %w", err)
	}

	// Rotate the refresh token hash in the session.
	sess.Update().
		SetRefreshTokenHash(hashToken(refresh)).
		SetLastActiveAt(time.Now()).
		SetExpiresAt(time.Now().Add(7 * 24 * time.Hour)).
		Save(ctx) //nolint:errcheck

	user, _ := s.client.User.Get(ctx, userID)
	return RefreshToken200JSONResponse(AuthResponse{
		AccessToken:  access,
		RefreshToken: refresh,
		User:         toAuthUser(user),
	}), nil
}

// logout revokes the current access token.
func (s *Server) logout(ctx context.Context, _ *ent.Client, request LogoutRequestObject) (LogoutResponseObject, error) {
	rawToken := request.Body.Token
	if rawToken == "" {
		return Logout400JSONResponse{Error: "token required"}, nil
	}

	claims, err := s.tokenService.ValidateTokenClaims(rawToken)
	if err != nil {
		return Logout401JSONResponse{Error: "invalid token"}, nil
	}

	// Revoke the token in the in-memory store.
	sig := auth.TokenSignature(rawToken)
	s.revocationStore.RevokeToken(sig, claims.ExpiresAt)

	// Mark the session as revoked in the database.
	if claims.DeviceID != "" {
		s.client.Session.Update().
			Where(
				session.UserIDEQ(claims.UserID),
				session.DeviceIDEQ(claims.DeviceID),
				session.RevokedAtIsNil(),
			).
			SetRevokedAt(time.Now()).
			Save(ctx) //nolint:errcheck
	}

	return Logout200JSONResponse{Message: "logged out"}, nil
}

// logoutAll revokes all sessions for the authenticated user.
func (s *Server) logoutAll(ctx context.Context, _ *ent.Client, request LogoutAllRequestObject) (LogoutAllResponseObject, error) {
	userID, err := auth.RequireAuth(ctx)
	if err != nil {
		return LogoutAll401JSONResponse{Error: "authentication required"}, nil
	}

	// Revoke all tokens in the in-memory store.
	s.revocationStore.RevokeAllForUser(userID)

	// Mark all sessions as revoked in the database.
	s.client.Session.Update().
		Where(session.UserIDEQ(userID), session.RevokedAtIsNil()).
		SetRevokedAt(time.Now()).
		Save(ctx) //nolint:errcheck

	return LogoutAll200JSONResponse{Message: "all sessions revoked"}, nil
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func toAuthUser(u *ent.User) AuthUser {
	return AuthUser{
		Id:       u.ID,
		Email:    u.Email,
		Username: u.Username,
		Role:     string(u.Role),
	}
}

// listSessions returns active sessions for the authenticated user.
func (s *Server) listSessions(ctx context.Context, _ *ent.Client, request ListSessionsRequestObject) (ListSessionsResponseObject, error) {
	userID, err := auth.RequireAuth(ctx)
	if err != nil {
		return ListSessions401JSONResponse{Error: "authentication required"}, nil
	}

	sessions, err := s.client.Session.Query().
		Where(session.UserIDEQ(userID), session.RevokedAtIsNil()).
		All(ctx)
	if err != nil {
		return nil, err
	}

	// Determine which session is "current" by matching the device ID.
	currentDevice, _ := auth.GetDeviceID(ctx)

	items := make([]SessionItem, len(sessions))
	for i, sess := range sessions {
		items[i] = SessionItem{
			Id:           sess.ID,
			DeviceId:     sess.DeviceID,
			DeviceName:   sess.DeviceName,
			IpAddress:    sess.IPAddress,
			LastActiveAt: sess.LastActiveAt,
			CreatedAt:    sess.CreatedAt,
			IsCurrent:    sess.DeviceID == currentDevice,
		}
	}

	return ListSessions200JSONResponse(items), nil
}

// revokeSession revokes a specific session by ID.
func (s *Server) revokeSession(ctx context.Context, _ *ent.Client, request RevokeSessionRequestObject) (RevokeSessionResponseObject, error) {
	userID, err := auth.RequireAuth(ctx)
	if err != nil {
		return RevokeSession401JSONResponse{Error: "authentication required"}, nil
	}

	sess, err := s.client.Session.Get(ctx, request.Id)
	if err != nil {
		return RevokeSession404JSONResponse{Error: "session not found"}, nil
	}

	// Only allow revoking your own sessions (unless admin).
	if sess.UserID != userID && !auth.HasRole(ctx, "admin") {
		return RevokeSession403JSONResponse{Error: "not your session"}, nil
	}

	// Revoke in the in-memory store by device.
	s.revocationStore.RevokeAllForDevice(sess.UserID, sess.DeviceID)

	// Mark as revoked in the database.
	sess.Update().SetRevokedAt(time.Now()).Save(ctx) //nolint:errcheck

	return RevokeSession200JSONResponse{Message: fmt.Sprintf("session %s revoked", sess.DeviceID)}, nil
}

// Placeholder types — these would be generated by oapi-codegen from the OpenAPI spec.
// Included here for illustration only.

type AuthResponse struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	User         AuthUser `json:"user"`
}

type AuthUser struct {
	Id       uuid.UUID `json:"id"`
	Email    string    `json:"email"`
	Username string    `json:"username"`
	Role     string    `json:"role"`
}

type SessionItem struct {
	Id           uuid.UUID `json:"id"`
	DeviceId     string    `json:"device_id"`
	DeviceName   string    `json:"device_name,omitempty"`
	IpAddress    string    `json:"ip_address,omitempty"`
	LastActiveAt time.Time `json:"last_active_at"`
	CreatedAt    time.Time `json:"created_at"`
	IsCurrent    bool      `json:"is_current"`
}

// Placeholder request/response types — generated by oapi-codegen.
type (
	LoginRequestObject          struct{ Body *LoginRequest }
	LoginRequest                struct{ Email, Password, DeviceId, DeviceName, IpAddress string }
	Login200JSONResponse        AuthResponse
	Login400JSONResponse        struct{ Error string }
	Login401JSONResponse        struct{ Error string }
	LoginResponseObject         interface{ VisitLoginResponse(http.ResponseWriter) error }

	RegisterRequestObject       struct{ Body *RegisterRequest }
	RegisterRequest             struct{ Email, Username, Password string }
	Register201JSONResponse     AuthResponse
	Register400JSONResponse     struct{ Error string }
	Register409JSONResponse     struct{ Error string }
	RegisterResponseObject      interface{ VisitRegisterResponse(http.ResponseWriter) error }

	RefreshTokenRequestObject   struct{ Body *RefreshTokenRequest }
	RefreshTokenRequest         struct{ RefreshToken string }
	RefreshToken200JSONResponse AuthResponse
	RefreshToken401JSONResponse struct{ Error string }
	RefreshTokenResponseObject  interface{ VisitRefreshTokenResponse(http.ResponseWriter) error }

	LogoutRequestObject         struct{ Body *LogoutRequest }
	LogoutRequest               struct{ Token string }
	Logout200JSONResponse       struct{ Message string }
	Logout400JSONResponse       struct{ Error string }
	Logout401JSONResponse       struct{ Error string }
	LogoutResponseObject        interface{ VisitLogoutResponse(http.ResponseWriter) error }

	LogoutAllRequestObject      struct{}
	LogoutAll200JSONResponse    struct{ Message string }
	LogoutAll401JSONResponse    struct{ Error string }
	LogoutAllResponseObject     interface{ VisitLogoutAllResponse(http.ResponseWriter) error }

	AdminElevateRequestObject       struct{ Body *AdminElevateRequest }
	AdminElevateRequest             struct{ Password string }
	AdminElevateResponse            struct{ AdminToken string; ExpiresAt time.Time }
	AdminElevate200JSONResponse     AdminElevateResponse
	AdminElevate401JSONResponse     struct{ Error string }
	AdminElevate403JSONResponse     struct{ Error string }
	AdminElevateResponseObject      interface{ VisitAdminElevateResponse(http.ResponseWriter) error }

	ListSessionsRequestObject       struct{}
	ListSessions200JSONResponse     []SessionItem
	ListSessions401JSONResponse     struct{ Error string }
	ListSessionsResponseObject      interface{ VisitListSessionsResponse(http.ResponseWriter) error }

	RevokeSessionRequestObject      struct{ Id uuid.UUID }
	RevokeSession200JSONResponse    struct{ Message string }
	RevokeSession401JSONResponse    struct{ Error string }
	RevokeSession403JSONResponse    struct{ Error string }
	RevokeSession404JSONResponse    struct{ Error string }
	RevokeSessionResponseObject     interface{ VisitRevokeSessionResponse(http.ResponseWriter) error }
)
