package iam

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/Shyntr/shyntr/pkg/constants"
	"github.com/go-jose/go-jose/v3"
	"github.com/lib/pq"
	"github.com/ory/fosite"
	"gorm.io/gorm"
)

type FositeStore struct {
	db         *gorm.DB
	clientRepo port.OAuth2ClientRepository
	jtiRepo    port.BlacklistedJTIRepository
}

func NewFositeStore(db *gorm.DB, clientRepo port.OAuth2ClientRepository, jtiRepo port.BlacklistedJTIRepository) *FositeStore {
	return &FositeStore{
		db:         db,
		clientRepo: clientRepo,
		jtiRepo:    jtiRepo,
	}
}

// --- CLIENT MANAGER IMPLEMENTATION ---

func (s *FositeStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	tenantID, ok := ctx.Value(constants.ContextKeyTenantID).(string)
	if !ok || tenantID == "" {
		return nil, errors.New("tenant context is missing in Fosite Store")
	}

	clientDomain, err := s.clientRepo.GetByTenantAndID(ctx, tenantID, id)
	if err != nil {
		return nil, fosite.ErrNotFound
	}

	return ToFositeClient(clientDomain), nil
}

func (s *FositeStore) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	exists, err := s.jtiRepo.Exists(ctx, jti)
	if err != nil {
		return err
	}
	if exists {
		return fosite.ErrJTIKnown
	}
	return nil
}

func (s *FositeStore) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	jtiEntity := &model.BlacklistedJTI{
		JTI:       jti,
		ExpiresAt: exp,
	}
	return s.jtiRepo.Save(ctx, jtiEntity)
}

// --- Resource Owner Password Credentials Grant Storage (ROPC) ---

func (s *FositeStore) Authenticate(ctx context.Context, name string, secret string) error {
	return fosite.ErrRequestUnauthorized
}

// --- RFC7523 Key Storage (JWT Bearer Grant) ---

func (s *FositeStore) GetPublicKey(ctx context.Context, issuer string, subject string, keyId string) (*jose.JSONWebKey, error) {
	clientID := issuer
	client, err := s.clientRepo.GetByID(ctx, clientID)
	if err != nil {
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

func (s *FositeStore) GetPublicKeys(ctx context.Context, issuer string, subject string) (*jose.JSONWebKeySet, error) {
	clientID := issuer
	client, err := s.clientRepo.GetByID(ctx, clientID)
	if err != nil {
		return nil, fosite.ErrNotFound
	}

	if client.JSONWebKeys == nil {
		return &jose.JSONWebKeySet{}, nil
	}

	return client.JSONWebKeys, nil
}

func (s *FositeStore) GetPublicKeyScopes(ctx context.Context, issuer string, subject string, keyId string) ([]string, error) {
	return []string{}, nil
}

func (s *FositeStore) IsJWTUsed(ctx context.Context, jti string) (bool, error) {
	exists, err := s.jtiRepo.Exists(ctx, jti)
	return exists, err
}

func (s *FositeStore) MarkJWTUsedForTime(ctx context.Context, jti string, exp time.Time) error {
	blacklisted := &model.BlacklistedJTI{
		JTI:       jti,
		ExpiresAt: exp,
	}
	return s.jtiRepo.Save(ctx, blacklisted)
}

// --- CORE STORAGE HELPER ---
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

func (s *FositeStore) getOrCreateRefreshFamilyID(ctx context.Context, requestID string) (string, error) {
	var existing models.OAuth2SessionGORM
	err := s.db.WithContext(ctx).
		Select("token_family_id").
		Where("request_id = ? AND token_type = ? AND token_family_id <> ''", requestID, "refresh_token").
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

func (s *FositeStore) createSession(ctx context.Context, signature, tokenType, familyID string, req fosite.Requester) error {
	tenantID, _ := ctx.Value(constants.ContextKeyTenantID).(string)
	if tenantID == "" {
		return errors.New("tenant context missing for session creation")
	}

	sessionData, err := json.Marshal(req.GetSession())
	if err != nil {
		return err
	}

	pr := persistedRequest{
		RequestedAt: req.GetRequestedAt(),
		Form:        req.GetRequestForm(),
		RedirectURI: req.GetRequestForm().Get("redirect_uri"),
	}
	requestJSON, err := json.Marshal(&pr)

	if err != nil {
		return err
	}
	var expiresAt time.Time
	if tt, ok := tokenTypeToFositeTokenType(tokenType); ok {
		if eg, ok := req.GetSession().(expiresGetter); ok {
			expiresAt = eg.GetExpiresAt(tt)
		}
	}

	var subject string
	if sg, ok := req.GetSession().(subjectGetter); ok {
		subject = sg.GetSubject()
	}

	var tokenFamilyID string
	if tokenType == "refresh_token" {
		tokenFamilyID, err = s.getOrCreateRefreshFamilyID(ctx, req.GetID())
		if err != nil {
			return err
		}
	}

	sess := models.OAuth2SessionGORM{
		Signature:     signature,
		RequestID:     req.GetID(),
		TenantID:      tenantID,
		ClientID:      req.GetClient().GetID(),
		Subject:       subject,
		TokenType:     tokenType,
		TokenFamilyID: tokenFamilyID,
		RequestData:   requestJSON,
		SessionData:   sessionData,
		GrantedScopes: pq.StringArray(req.GetGrantedScopes()),
		Active:        true,
		ExpiresAt:     expiresAt,
		CreatedAt:     time.Now(),
	}
	return s.db.WithContext(ctx).Create(&sess).Error
}

func (s *FositeStore) getSession(ctx context.Context, signature, tokenType string, session fosite.Session) (fosite.Requester, error) {
	tenantID, _ := ctx.Value(constants.ContextKeyTenantID).(string)
	var sess models.OAuth2SessionGORM

	query := s.db.WithContext(ctx).Where("signature = ? AND token_type = ?", signature, tokenType)
	if tenantID != "" {
		query = query.Where("tenant_id = ?", tenantID)
	}

	if err := query.First(&sess).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	now := time.Now()
	if !sess.ExpiresAt.IsZero() && now.After(sess.ExpiresAt) {
		return nil, fosite.ErrNotFound
	}

	if !sess.Active {
		return nil, fosite.ErrInactiveToken
	}

	if tokenType == "refresh_token" && !sess.Active {
		if sess.GraceExpiresAt == nil || now.After(*sess.GraceExpiresAt) {
			return nil, fosite.ErrNotFound
		}

		err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			res := tx.Model(&models.OAuth2SessionGORM{}).
				Where("signature = ? AND token_type = ? AND grace_used_at IS NULL", signature, "refresh_token").
				Update("grace_used_at", now)
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected == 1 {
				return nil
			}

			_ = tx.Model(&models.OAuth2SessionGORM{}).
				Where("signature = ? AND token_type = ?", signature, "refresh_token").
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
		session = model.NewJWTSession("")
	}

	if err := json.Unmarshal(sess.SessionData, session); err != nil {
		return nil, err
	}
	clientDomain, err := s.clientRepo.GetByTenantAndID(ctx, tenantID, sess.ClientID)
	if err != nil {
		return nil, err
	}
	fositeClient := ToFositeClient(clientDomain)
	req := fosite.NewAccessRequest(session)
	req.SetID(sess.RequestID)
	req.Client = fositeClient
	req.Session = session
	req.RequestedAt = sess.CreatedAt

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

func (s *FositeStore) deleteSession(ctx context.Context, signature, tokenType string) error {
	return s.db.WithContext(ctx).Where("signature = ? AND token_type = ?", signature, tokenType).Delete(&models.OAuth2SessionGORM{}).Error
}

// --- ACCESS TOKEN STORAGE ---

func (s *FositeStore) CreateAccessTokenSession(ctx context.Context, signature string, req fosite.Requester) (err error) {
	return s.createSession(ctx, signature, "access_token", "", req)
}

func (s *FositeStore) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getSession(ctx, signature, "access_token", session)
}

func (s *FositeStore) DeleteAccessTokenSession(ctx context.Context, signature string) (err error) {
	return s.deleteSession(ctx, signature, "access_token")
}

// --- Revocation ---
func (s *FositeStore) revokeRefreshFamilyTx(ctx context.Context, tx *gorm.DB, familyID string, requestID string) error {
	now := time.Now()
	if familyID != "" {
		if err := tx.Model(&models.OAuth2SessionGORM{}).
			Where("token_family_id = ? AND token_type = ?", familyID, "refresh_token").
			Updates(map[string]any{
				"active":           false,
				"grace_expires_at": nil,
				"expires_at":       now,
			}).Error; err != nil {
			return err
		}
	}

	return tx.Model(&models.OAuth2SessionGORM{}).
		Where("request_id = ? AND token_type = ?", requestID, "access_token").
		Updates(map[string]any{
			"active":     false,
			"expires_at": now,
		}).Error
}

func (s *FositeStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	return s.db.WithContext(ctx).Model(&models.OAuth2SessionGORM{}).
		Where("request_id = ? AND token_type = ?", requestID, "access_token").
		Updates(map[string]interface{}{"active": false}).Error
}

// --- REFRESH TOKEN & REPLAY DETECTION ---

func (s *FositeStore) CreateRefreshTokenSession(ctx context.Context, signature string, req fosite.Requester) (err error) {
	familyID, _ := ctx.Value("token_family_id").(string)
	if familyID == "" {
		familyID = req.GetID()
	}
	return s.createSession(ctx, signature, "refresh_token", familyID, req)
}

func (s *FositeStore) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	tenantID, _ := ctx.Value(constants.ContextKeyTenantID).(string)
	if tenantID == "" {
		return nil, errors.New("tenant context missing")
	}
	var dbModel models.OAuth2SessionGORM

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		query := tx.Where("signature = ? AND token_type = ?", signature, "refresh_token")
		if tenantID != "" {
			query = query.Where("tenant_id = ?", tenantID)
		}

		if err := query.First(&dbModel).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fosite.ErrNotFound
			}
			return err
		}

		if !dbModel.Active {
			if dbModel.GraceExpiresAt != nil && dbModel.GraceExpiresAt.After(time.Now().UTC()) {
				return nil
			}
			tx.Model(&models.OAuth2SessionGORM{}).
				Where("token_family_id = ? AND tenant_id = ?", dbModel.TokenFamilyID, tenantID).
				Updates(map[string]interface{}{"active": false})
			return fosite.ErrInactiveToken
		}
		return nil
	})

	if err != nil && !errors.Is(err, fosite.ErrInactiveToken) {
		return nil, err
	}

	clientDomain, clientErr := s.clientRepo.GetByTenantAndID(ctx, tenantID, dbModel.ClientID)
	if clientErr != nil {
		return nil, clientErr
	}
	req := fosite.NewAccessRequest(session)
	req.SetID(dbModel.RequestID)
	req.Client = ToFositeClient(clientDomain)

	for _, scope := range dbModel.GrantedScopes {
		req.GrantScope(scope)
	}

	type persistedRequest struct {
		Form url.Values `json:"form"`
	}
	var pr persistedRequest
	if jsonErr := json.Unmarshal(dbModel.RequestData, &pr); jsonErr == nil {
		req.Form = pr.Form
	}

	if session != nil && len(dbModel.SessionData) > 0 {
		if jsonErr := json.Unmarshal(dbModel.SessionData, session); jsonErr != nil {
			return nil, jsonErr
		}
	}

	return req, err
}

func (s *FositeStore) DeleteRefreshTokenSession(ctx context.Context, signature string) (err error) {
	graceEnd := time.Now().UTC().Add(15 * time.Second)
	return s.db.WithContext(ctx).Model(&models.OAuth2SessionGORM{}).
		Where("signature = ? AND token_type = ?", signature, "refresh_token").
		Updates(map[string]interface{}{
			"active":           false,
			"grace_expires_at": graceEnd,
		}).Error
}

func (s *FositeStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	tenantID, _ := ctx.Value(constants.ContextKeyTenantID).(string)
	if tenantID == "" {
		return errors.New("tenant context missing")
	}
	return s.db.WithContext(ctx).Model(&models.OAuth2SessionGORM{}).
		Where("request_id = ? AND token_type IN ? AND tenant_id = ?", requestID, []string{"access_token", "refresh_token"}, tenantID).
		Updates(map[string]interface{}{"active": false}).Error
}

func (s *FositeStore) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, signature string) error {
	tenantID, _ := ctx.Value(constants.ContextKeyTenantID).(string)
	if tenantID == "" {
		return errors.New("tenant context missing")
	}

	graceExp := time.Now().UTC().Add(time.Minute * 5)

	return s.db.WithContext(ctx).Model(&models.OAuth2SessionGORM{}).
		Where("signature = ? AND token_type = ? AND tenant_id = ?", signature, "refresh_token", tenantID).
		Updates(map[string]interface{}{
			"grace_expires_at": graceExp,
		}).Error
}

// --- AUTHORIZE CODE STORAGE ---

func (s *FositeStore) CreateAuthorizeCodeSession(ctx context.Context, signature string, req fosite.Requester) (err error) {
	return s.createSession(ctx, signature, "code", "", req)
}

func (s *FositeStore) GetAuthorizeCodeSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getSession(ctx, signature, "code", session)
}

func (s *FositeStore) InvalidateAuthorizeCodeSession(ctx context.Context, signature string) (err error) {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.OAuth2SessionGORM{}).
		Where("signature = ? AND token_type = ?", signature, "code").
		Updates(map[string]interface{}{"active": false,
			"used_at":    &now,
			"expires_at": now}).Error
}

// --- PKCE STORAGE ---

func (s *FositeStore) CreatePKCERequestSession(ctx context.Context, signature string, req fosite.Requester) (err error) {
	return s.createSession(ctx, signature, "pkce", "", req)
}

func (s *FositeStore) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getSession(ctx, signature, "pkce", session)
}

func (s *FositeStore) DeletePKCERequestSession(ctx context.Context, signature string) (err error) {
	return s.deleteSession(ctx, signature, "pkce")
}

// --- OPENID CONNECT STORAGE ---

func (s *FositeStore) CreateOpenIDConnectSession(ctx context.Context, signature string, req fosite.Requester) error {
	return s.createSession(ctx, signature, "oidc", "", req)
}

func (s *FositeStore) GetOpenIDConnectSession(ctx context.Context, signature string, req fosite.Requester) (fosite.Requester, error) {
	return s.getSession(ctx, signature, "oidc", req.GetSession())
}

func (s *FositeStore) DeleteOpenIDConnectSession(ctx context.Context, signature string) error {
	return s.deleteSession(ctx, signature, "oidc")
}
