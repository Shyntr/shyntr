package usecase

import (
	"context"

	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/entity"
)

type OAuth2SessionUseCase interface {
	GetBySubject(ctx context.Context, subject, clientID string) (*entity.OAuth2Session, error)
	DeleteBySubject(ctx context.Context, subject, clientID string) error
	RecordAuthorization(ctx context.Context, requestID, clientID, actorIP, userAgent string, grantedScopes []string)
	RecordTokenIssuance(ctx context.Context, requestID, clientID, actorIP, userAgent string, grantedScopes []string)
	RecordLogout(ctx context.Context, subject, actorIP, userAgent string, hasHint bool)
	RecordRevocation(ctx context.Context, actorIP, userAgent string, status bool)
}

type oauth2SessionUseCase struct {
	repo  port.OAuth2SessionRepository
	audit port.AuditLogger
}

func NewOAuth2SessionUseCase(repo port.OAuth2SessionRepository, audit port.AuditLogger) OAuth2SessionUseCase {
	return &oauth2SessionUseCase{
		repo:  repo,
		audit: audit,
	}
}

func (o *oauth2SessionUseCase) GetBySubject(ctx context.Context, subject, clientID string) (*entity.OAuth2Session, error) {
	return o.repo.GetBySubjectAndClient(ctx, subject, clientID)
}

func (o *oauth2SessionUseCase) DeleteBySubject(ctx context.Context, subject, clientID string) error {
	return o.repo.DeleteBySubjectAndClient(ctx, subject, clientID)
}

func (u *oauth2SessionUseCase) RecordAuthorization(ctx context.Context, requestID, clientID, actorIP, userAgent string, grantedScopes []string) {
	u.audit.Log("default", "system", "auth.authorize.success", actorIP, userAgent, map[string]interface{}{
		"client_id":      clientID,
		"granted_scopes": grantedScopes,
	})
}

func (u *oauth2SessionUseCase) RecordTokenIssuance(ctx context.Context, requestID, clientID, actorIP, userAgent string, grantedScopes []string) {
	u.audit.Log("default", "system", "auth.token.issued", actorIP, userAgent, map[string]interface{}{
		"client_id":      clientID,
		"granted_scopes": grantedScopes,
	})
}

func (u *oauth2SessionUseCase) RecordLogout(ctx context.Context, subject, actorIP, userAgent string, hasHint bool) {
	u.audit.Log("default", subject, "auth.logout", actorIP, userAgent, map[string]interface{}{
		"id_token_hint_provided": hasHint,
	})
}

func (u *oauth2SessionUseCase) RecordRevocation(ctx context.Context, actorIP, userAgent string, status bool) {
	u.audit.Log("default", "unknown", "auth.token.revoke", actorIP, userAgent, map[string]interface{}{
		"status": status,
	})
}
