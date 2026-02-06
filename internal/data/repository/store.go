package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/pkg/crypto"
	"github.com/ory/fosite"
	"gorm.io/gorm"
)

type SQLStore struct {
	DB *gorm.DB
}

func NewSQLStore(db *gorm.DB) *SQLStore {
	return &SQLStore{DB: db}
}

// --- ClientManager Implementation ---

func (s *SQLStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	var clientModel models.OAuth2Client
	if err := s.DB.WithContext(ctx).First(&clientModel, "id = ?", id).Error; err != nil {
		return nil, fosite.ErrNotFound
	}

	return &fosite.DefaultClient{
		ID:            clientModel.ID,
		Secret:        []byte(clientModel.Secret),
		RedirectURIs:  clientModel.RedirectURIs,
		GrantTypes:    clientModel.GrantTypes,
		ResponseTypes: clientModel.ResponseTypes,
		Scopes:        clientModel.Scopes,
		Public:        clientModel.Public,
	}, nil
}

func (s *SQLStore) ClientAssertionJWTValid(_ context.Context, _ string) error            { return nil }
func (s *SQLStore) SetClientAssertionJWT(_ context.Context, _ string, _ time.Time) error { return nil }

// --- Resource Owner Password Credentials Grant Storage (ROPC) ---

func (s *SQLStore) Authenticate(ctx context.Context, name string, secret string) error {
	var user models.User
	if err := s.DB.WithContext(ctx).Where("email = ?", name).First(&user).Error; err != nil {
		return fosite.ErrRequestUnauthorized
	}

	if !crypto.CheckPasswordHash(secret, user.PasswordHash) {
		return fosite.ErrRequestUnauthorized
	}

	return nil
}

// --- RFC7523 Key Storage (JWT Bearer Grant) ---

func (s *SQLStore) GetPublicKey(ctx context.Context, issuer string, subject string, keyId string) (*jose.JSONWebKey, error) {
	return nil, fosite.ErrNotFound
}

func (s *SQLStore) GetPublicKeys(ctx context.Context, issuer string, subject string) (*jose.JSONWebKeySet, error) {
	return &jose.JSONWebKeySet{}, fosite.ErrNotFound
}

func (s *SQLStore) GetPublicKeyScopes(ctx context.Context, issuer string, subject string, keyId string) ([]string, error) {
	return []string{}, nil
}

func (s *SQLStore) IsJWTUsed(ctx context.Context, jti string) (bool, error) {
	return false, nil
}

func (s *SQLStore) MarkJWTUsedForTime(ctx context.Context, jti string, exp time.Time) error {
	return nil
}

// --- Storage Implementation (Common) ---

func (s *SQLStore) createSession(ctx context.Context, signature string, request fosite.Requester, tokenType string) error {
	sessionJSON, err := json.Marshal(request.GetSession())
	if err != nil {
		return err
	}

	sess := models.OAuth2Session{
		Signature:   signature,
		RequestID:   request.GetID(),
		ClientID:    request.GetClient().GetID(),
		Type:        tokenType,
		SessionData: sessionJSON,
		Active:      true,
		CreatedAt:   time.Now(),
	}
	return s.DB.WithContext(ctx).Create(&sess).Error
}

func (s *SQLStore) getSession(ctx context.Context, signature string, session fosite.Session, tokenType string) (fosite.Requester, error) {
	var sess models.OAuth2Session
	if err := s.DB.WithContext(ctx).First(&sess, "signature = ? AND type = ?", signature, tokenType).Error; err != nil {
		return nil, fosite.ErrNotFound
	}
	if !sess.Active {
		return nil, fosite.ErrNotFound
	}

	if err := json.Unmarshal(sess.SessionData, session); err != nil {
		return nil, err
	}

	client, err := s.GetClient(ctx, sess.ClientID)
	if err != nil {
		return nil, err
	}

	req := &fosite.Request{
		ID:          sess.RequestID,
		Client:      client,
		Session:     session,
		RequestedAt: sess.CreatedAt,
	}
	return req, nil
}

func (s *SQLStore) deleteSession(ctx context.Context, signature string) error {
	return s.DB.WithContext(ctx).Where("signature = ?", signature).Delete(&models.OAuth2Session{}).Error
}

// --- Access Token ---

func (s *SQLStore) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createSession(ctx, signature, request, "access_token")
}

func (s *SQLStore) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getSession(ctx, signature, session, "access_token")
}

func (s *SQLStore) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.deleteSession(ctx, signature)
}

// --- Refresh Token ---

func (s *SQLStore) CreateRefreshTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createSession(ctx, signature, request, "refresh_token")
}

func (s *SQLStore) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getSession(ctx, signature, session, "refresh_token")
}

func (s *SQLStore) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.deleteSession(ctx, signature)
}

// --- Authorize Code ---

func (s *SQLStore) CreateAuthorizeCodeSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createSession(ctx, signature, request, "authorize_code")
}

func (s *SQLStore) GetAuthorizeCodeSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getSession(ctx, signature, session, "authorize_code")
}

func (s *SQLStore) InvalidateAuthorizeCodeSession(ctx context.Context, signature string) error {
	return s.deleteSession(ctx, signature)
}

// --- Revocation ---

func (s *SQLStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return s.RevokeAccessToken(ctx, requestID)
}

func (s *SQLStore) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, signature string) error {
	return s.RevokeRefreshToken(ctx, requestID)
}

func (s *SQLStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	return s.DB.WithContext(ctx).Where("request_id = ?", requestID).Delete(&models.OAuth2Session{}).Error
}

func (s *SQLStore) RevokeAccessTokenMaybeGracePeriod(ctx context.Context, requestID string, signature string) error {
	return s.RevokeAccessToken(ctx, requestID)
}

// --- PKCE (UPDATED METHOD NAMES) ---
// Fosite expects CreatePKCERequestSession, GetPKCERequestSession, DeletePKCERequestSession

func (s *SQLStore) CreatePKCERequestSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createSession(ctx, signature, request, "pkce")
}

func (s *SQLStore) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getSession(ctx, signature, session, "pkce")
}

func (s *SQLStore) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return s.deleteSession(ctx, signature)
}

// --- OpenID Connect ---

func (s *SQLStore) CreateOpenIDConnectSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createSession(ctx, signature, request, "oidc")
}

func (s *SQLStore) GetOpenIDConnectSession(ctx context.Context, signature string, request fosite.Requester) (fosite.Requester, error) {
	return s.getSession(ctx, signature, request.GetSession(), "oidc")
}

func (s *SQLStore) DeleteOpenIDConnectSession(ctx context.Context, signature string) error {
	return s.deleteSession(ctx, signature)
}
