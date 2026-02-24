package repository

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/lib/pq"
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

// --- ClientManager Implementation ---

func (s *SQLStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	var clientModel models.OAuth2Client
	if err := s.DB.WithContext(ctx).First(&clientModel, "id = ?", id).Error; err != nil {
		return nil, fosite.ErrNotFound
	}

	var responseModes []fosite.ResponseModeType
	for _, rm := range clientModel.ResponseModes {
		responseModes = append(responseModes, fosite.ResponseModeType(rm))
	}

	return &models.ExtendedClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            clientModel.ID,
			Secret:        []byte(clientModel.Secret),
			RedirectURIs:  clientModel.RedirectURIs,
			GrantTypes:    clientModel.GrantTypes,
			ResponseTypes: clientModel.ResponseTypes,
			Scopes:        clientModel.Scopes,
			Audience:      clientModel.Audience,
			Public:        clientModel.Public,
		},
		JSONWebKeys:             clientModel.JSONWebKeys,
		PostLogoutRedirectURIs:  clientModel.PostLogoutRedirectURIs,
		TokenEndpointAuthMethod: clientModel.TokenEndpointAuthMethod,
		ResponseModes:           responseModes,
	}, nil
}

func (s *SQLStore) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	isUsed, err := s.IsJWTUsed(ctx, jti)
	if err != nil {
		return err
	}
	if isUsed {
		return fosite.ErrJTIKnown
	}
	return nil
}

// SetClientAssertionJWT marks a JTI as used until it expires.
func (s *SQLStore) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return s.MarkJWTUsedForTime(ctx, jti, exp)
}

// --- Resource Owner Password Credentials Grant Storage (ROPC) ---

func (s *SQLStore) Authenticate(ctx context.Context, name string, secret string) error {
	return fosite.ErrRequestUnauthorized
}

// --- RFC7523 Key Storage (JWT Bearer Grant) ---

func (s *SQLStore) GetPublicKey(ctx context.Context, issuer string, subject string, keyId string) (*jose.JSONWebKey, error) {
	clientID := issuer

	var client models.OAuth2Client
	if err := s.DB.WithContext(ctx).First(&client, "id = ?", clientID).Error; err != nil {
		return nil, fosite.ErrNotFound
	}

	if client.JSONWebKeys == nil {
		return nil, fosite.ErrNotFound
	}

	keys := client.JSONWebKeys.Key(keyId)
	if len(keys) == 0 {
		return nil, fosite.ErrNotFound
	}

	return &keys[0], nil
}

func (s *SQLStore) GetPublicKeys(ctx context.Context, issuer string, subject string) (*jose.JSONWebKeySet, error) {
	clientID := issuer
	var client models.OAuth2Client
	if err := s.DB.WithContext(ctx).First(&client, "id = ?", clientID).Error; err != nil {
		return nil, fosite.ErrNotFound
	}

	if client.JSONWebKeys == nil {
		return &jose.JSONWebKeySet{}, nil
	}

	return client.JSONWebKeys, nil
}

// GetPublicKeyScopes returns the scopes that a specific key is allowed to request.
func (s *SQLStore) GetPublicKeyScopes(ctx context.Context, issuer string, subject string, keyId string) ([]string, error) {
	return []string{}, nil
}

func (s *SQLStore) IsJWTUsed(ctx context.Context, jti string) (bool, error) {
	var count int64
	if err := s.DB.WithContext(ctx).Model(&models.BlacklistedJTI{}).Where("jti = ?", jti).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *SQLStore) MarkJWTUsedForTime(ctx context.Context, jti string, exp time.Time) error {
	blacklisted := models.BlacklistedJTI{
		JTI:       jti,
		ExpiresAt: exp,
	}
	return s.DB.WithContext(ctx).Create(&blacklisted).Error
}

// --- Storage Implementation (Common) ---

type persistedRequest struct {
	RequestedAt time.Time  `json:"requested_at"`
	Form        url.Values `json:"form,omitempty"`
	RedirectURI string     `json:"redirect_uri,omitempty"`
}

type expiresGetter interface {
	GetExpiresAt(fosite.TokenType) time.Time
}
type subjectGetter interface{ GetSubject() string }

func tokenTypeToFositeTokenType(tokenType string) (fosite.TokenType, bool) {
	switch tokenType {
	case "access_token":
		return fosite.AccessToken, true
	case "refresh_token":
		return fosite.RefreshToken, true
	case "authorize_code":
		return fosite.AuthorizeCode, true
	case "pkce":
		return fosite.AuthorizeCode, true
	case "oidc":
		return fosite.AuthorizeCode, true
	default:
		return "", false
	}
}
func newTokenFamilyID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *SQLStore) getOrCreateRefreshFamilyID(ctx context.Context, requestID string) (string, error) {
	var existing models.OAuth2Session
	err := s.DB.WithContext(ctx).
		Select("token_family_id").
		Where("request_id = ? AND type = ? AND token_family_id <> ''", requestID, "refresh_token").
		Order("created_at DESC").
		Limit(1).
		Find(&existing).Error
	if err != nil {
		return "", err
	}
	if existing.TokenFamilyID != "" {
		return existing.TokenFamilyID, nil
	}
	return newTokenFamilyID()
}

func (s *SQLStore) createSession(ctx context.Context, signature string, request fosite.Requester, tokenType string) error {
	sessionJSON, err := json.Marshal(request.GetSession())
	if err != nil {
		return err
	}

	pr := persistedRequest{
		RequestedAt: request.GetRequestedAt(),
		Form:        request.GetRequestForm(),
		RedirectURI: request.GetRequestForm().Get("redirect_uri"),
	}
	requestJSON, err := json.Marshal(&pr)
	if err != nil {
		return err
	}

	var expiresAt time.Time
	if tt, ok := tokenTypeToFositeTokenType(tokenType); ok {
		if eg, ok := request.GetSession().(expiresGetter); ok {
			expiresAt = eg.GetExpiresAt(tt)
		}
	}

	var subject string
	if sg, ok := request.GetSession().(subjectGetter); ok {
		subject = sg.GetSubject()
	}

	var tokenFamilyID string
	if tokenType == "refresh_token" {
		tokenFamilyID, err = s.getOrCreateRefreshFamilyID(ctx, request.GetID())
		if err != nil {
			return err
		}
	}

	sess := models.OAuth2Session{
		Signature:     signature,
		RequestID:     request.GetID(),
		ClientID:      request.GetClient().GetID(),
		Subject:       subject,
		Type:          tokenType,
		TokenFamilyID: tokenFamilyID,
		RequestData:   requestJSON,
		SessionData:   sessionJSON,
		GrantedScopes: pq.StringArray(request.GetGrantedScopes()),
		Active:        true,
		ExpiresAt:     expiresAt,
		CreatedAt:     time.Now(),
	}
	return s.DB.WithContext(ctx).Create(&sess).Error
}

func (s *SQLStore) getSession(ctx context.Context, signature string, session fosite.Session, tokenType string) (fosite.Requester, error) {
	var sess models.OAuth2Session
	if err := s.DB.WithContext(ctx).First(&sess, "signature = ? AND type = ?", signature, tokenType).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	now := time.Now()
	if !sess.ExpiresAt.IsZero() && now.After(sess.ExpiresAt) {
		return nil, fosite.ErrNotFound
	}

	if tokenType == "refresh_token" && !sess.Active {
		if sess.GraceExpiresAt == nil || now.After(*sess.GraceExpiresAt) {
			return nil, fosite.ErrNotFound
		}

		err := s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			res := tx.Model(&models.OAuth2Session{}).
				Where("signature = ? AND type = ? AND grace_used_at IS NULL", signature, "refresh_token").
				Update("grace_used_at", now)
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected == 1 {
				return nil
			}

			_ = tx.Model(&models.OAuth2Session{}).
				Where("signature = ? AND type = ?", signature, "refresh_token").
				Update("reuse_detected_at", now).Error

			return s.revokeRefreshFamilyTx(ctx, tx, sess.TokenFamilyID, sess.RequestID)
		})
		if err != nil {
			return nil, fosite.ErrNotFound
		}
	} else if !sess.Active && tokenType != "authorize_code" {
		return nil, fosite.ErrNotFound
	}

	if len(sess.SessionData) == 0 {
		return nil, fosite.ErrNotFound
	}

	if session == nil {
		session = models.NewJWTSession("")
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

	if len(sess.RequestData) > 0 {
		var pr persistedRequest
		if err := json.Unmarshal(sess.RequestData, &pr); err == nil {
			if !pr.RequestedAt.IsZero() {
				req.RequestedAt = pr.RequestedAt
			}
			if pr.Form != nil {
				req.Form = pr.Form
			}
			if pr.RedirectURI != "" {
				if u, err := url.Parse(pr.RedirectURI); err == nil {
					req.GetRequestForm().Set("redirect_uri", u.String())
				}
			}
		}
	}

	for _, scope := range sess.GrantedScopes {
		req.GrantScope(scope)
	}

	if tokenType == "authorize_code" && (!sess.Active || sess.UsedAt != nil) {
		return req, fosite.ErrInvalidatedAuthorizeCode
	}

	return req, nil
}

func (s *SQLStore) deleteSessionTyped(ctx context.Context, signature string, tokenType string) error {
	return s.DB.WithContext(ctx).
		Where("signature = ? AND type = ?", signature, tokenType).
		Delete(&models.OAuth2Session{}).Error
}

// --- Access Token ---

func (s *SQLStore) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createSession(ctx, signature, request, "access_token")
}

func (s *SQLStore) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getSession(ctx, signature, session, "access_token")
}

func (s *SQLStore) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.deleteSessionTyped(ctx, signature, "access_token")
}

// --- Refresh Token ---

func (s *SQLStore) CreateRefreshTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createSession(ctx, signature, request, "refresh_token")
}

func (s *SQLStore) RotateRefreshToken(ctx context.Context, requestID string, signature string) error {
	graceDuration := 60 * time.Second
	graceEnd := time.Now().Add(graceDuration)
	return s.DB.WithContext(ctx).
		Model(&models.OAuth2Session{}).
		Where("request_id = ? AND signature = ? AND type = ?", requestID, signature, "refresh_token").
		Updates(map[string]any{
			"active":           false,
			"grace_expires_at": &graceEnd,
			"expires_at":       graceEnd,
		}).Error
}

func (s *SQLStore) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getSession(ctx, signature, session, "refresh_token")
}

func (s *SQLStore) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.deleteSessionTyped(ctx, signature, "refresh_token")
}

// --- Authorize Code ---

func (s *SQLStore) CreateAuthorizeCodeSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createSession(ctx, signature, request, "authorize_code")
}

func (s *SQLStore) GetAuthorizeCodeSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getSession(ctx, signature, session, "authorize_code")
}

func (s *SQLStore) InvalidateAuthorizeCodeSession(ctx context.Context, signature string) error {
	now := time.Now()
	return s.DB.WithContext(ctx).
		Model(&models.OAuth2Session{}).
		Where("signature = ? AND type = ?", signature, "authorize_code").
		Updates(map[string]any{
			"active":     false,
			"used_at":    &now,
			"expires_at": now,
		}).Error
}

// --- Revocation ---
func (s *SQLStore) revokeRefreshFamilyTx(ctx context.Context, tx *gorm.DB, familyID string, requestID string) error {
	now := time.Now()
	if familyID != "" {
		if err := tx.Model(&models.OAuth2Session{}).
			Where("token_family_id = ? AND type = ?", familyID, "refresh_token").
			Updates(map[string]any{
				"active":           false,
				"grace_expires_at": nil,
				"expires_at":       now,
			}).Error; err != nil {
			return err
		}

	}
	return tx.Model(&models.OAuth2Session{}).
		Where("request_id = ? AND type = ?", requestID, "access_token").
		Updates(map[string]any{
			"active":     false,
			"expires_at": now,
		}).Error
}

func (s *SQLStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	now := time.Now()
	if err := s.DB.WithContext(ctx).
		Model(&models.OAuth2Session{}).
		Where("request_id = ? AND type = ?", requestID, "refresh_token").
		Updates(map[string]any{"active": false, "grace_expires_at": nil, "expires_at": now}).Error; err != nil {
		return err
	}
	return s.DB.WithContext(ctx).
		Model(&models.OAuth2Session{}).
		Where("request_id = ? AND type = ?", requestID, "access_token").
		Updates(map[string]any{"active": false, "expires_at": now}).Error
}

func (s *SQLStore) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, signature string) error {
	graceDuration := 15 * time.Second
	graceEnd := time.Now().Add(graceDuration)

	return s.DB.WithContext(ctx).
		Model(&models.OAuth2Session{}).
		Where("request_id = ? AND signature = ? AND type = ?", requestID, signature, "refresh_token").
		Updates(map[string]any{
			"active":           false,
			"grace_expires_at": &graceEnd,
			"expires_at":       graceEnd,
		}).Error
}

func (s *SQLStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	now := time.Now()
	return s.DB.WithContext(ctx).
		Model(&models.OAuth2Session{}).
		Where("request_id = ? AND type = ?", requestID, "access_token").
		Updates(map[string]any{"active": false, "expires_at": now}).Error
}

func (s *SQLStore) RevokeAccessTokenMaybeGracePeriod(ctx context.Context, requestID string, _ string) error {
	return s.RevokeAccessToken(ctx, requestID)
}

// --- PKCE ---

func (s *SQLStore) CreatePKCERequestSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createSession(ctx, signature, request, "pkce")
}

func (s *SQLStore) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getSession(ctx, signature, session, "pkce")
}

func (s *SQLStore) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return s.deleteSessionTyped(ctx, signature, "pkce")
}

// --- OpenID Connect ---

func (s *SQLStore) CreateOpenIDConnectSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createSession(ctx, signature, request, "oidc")
}

func (s *SQLStore) GetOpenIDConnectSession(ctx context.Context, signature string, request fosite.Requester) (fosite.Requester, error) {
	return s.getSession(ctx, signature, request.GetSession(), "oidc")
}

func (s *SQLStore) DeleteOpenIDConnectSession(ctx context.Context, signature string) error {
	return s.deleteSessionTyped(ctx, signature, "oidc")
}
