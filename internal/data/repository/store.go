package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/ory/fosite"
	"gorm.io/gorm"
)

type SQLStore struct {
	DB *gorm.DB
}

func NewSQLStore(db *gorm.DB) *SQLStore {
	return &SQLStore{DB: db}
}

// --- ClientManager ---

func (s *SQLStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	var clientModel models.OAuth2Client
	// Note: We don't filter by tenant here because Fosite interface is generic.
	// We should validate tenant match in the Authorize Endpoint logic.
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
		// We can attach TenantID to metadata if needed later, but Fosite DefaultClient doesn't support custom fields easily.
	}, nil
}

func (s *SQLStore) ClientAssertionJWTValid(_ context.Context, _ string) error            { return nil }
func (s *SQLStore) SetClientAssertionJWT(_ context.Context, _ string, _ time.Time) error { return nil }

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
func (s *SQLStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	return s.DB.WithContext(ctx).Where("request_id = ?", requestID).Delete(&models.OAuth2Session{}).Error
}

// --- PKCE & OpenID Connect ---
func (s *SQLStore) CreatePKCESession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createSession(ctx, signature, request, "pkce")
}
func (s *SQLStore) GetPKCESession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getSession(ctx, signature, session, "pkce")
}
func (s *SQLStore) DeletePKCESession(ctx context.Context, signature string) error {
	return s.deleteSession(ctx, signature)
}
func (s *SQLStore) CreateOpenIDConnectSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createSession(ctx, signature, request, "oidc")
}
func (s *SQLStore) GetOpenIDConnectSession(ctx context.Context, signature string, request fosite.Requester) (fosite.Requester, error) {
	return s.getSession(ctx, signature, request.GetSession(), "oidc")
}
func (s *SQLStore) DeleteOpenIDConnectSession(ctx context.Context, signature string) error {
	return s.deleteSession(ctx, signature)
}
