package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/Shyntr/shyntr/pkg/utils"
)

type AuthUseCase interface {
	CreateLoginRequest(ctx context.Context, req *model.LoginRequest) (*model.LoginRequest, error)
	UpdateLoginRequest(ctx context.Context, req *model.LoginRequest) (*model.LoginRequest, error)
	GetLoginRequest(ctx context.Context, challenge string) (*model.LoginRequest, error)
	GetRecentLogins(ctx context.Context, tenantID string, limit int) ([]model.LoginRequest, error)
	GetAuthenticatedLoginRequest(ctx context.Context, challenge string) (*model.LoginRequest, error)
	GetAuthenticatedLoginRequestBySubject(ctx context.Context, subject string) (*model.LoginRequest, error)
	AcceptLoginRequest(ctx context.Context, challenge string, remember bool, rememberFor int, subject string, contextData map[string]interface{}, actorIP, userAgent string) (*model.LoginRequest, error)
	RejectLoginRequest(ctx context.Context, challenge string, errName, errDesc, actorIP, userAgent string) (*model.LoginRequest, error)
	MarkLoginAsProviderStarted(ctx context.Context, challenge, provider, connectionID string, providerContext map[string]interface{}, actorIP, userAgent string) error
	CompleteProviderLogin(ctx context.Context, challenge, subject, connectionName string, contextData map[string]interface{}, actorIP, userAgent string) (*model.LoginRequest, error)

	CreateConsentRequest(ctx context.Context, req *model.ConsentRequest) (*model.ConsentRequest, error)
	GetConsentRequest(ctx context.Context, challenge string) (*model.ConsentRequest, error)
	GetAuthenticatedConsentRequest(ctx context.Context, challenge string) (*model.ConsentRequest, error)
	GetAuthenticatedConsentRequestBySubject(ctx context.Context, subject string) (*model.ConsentRequest, error)
	AcceptConsentRequest(ctx context.Context, challenge string, grantScope, grantAudience []string, remember bool, rememberFor int, contextData map[string]interface{}, actorIP, userAgent string) (*model.ConsentRequest, error)
	RejectConsentRequest(ctx context.Context, challenge string, errName, errDesc, actorIP, userAgent string) (*model.ConsentRequest, error)
}

type authUseCase struct {
	repo  port.AuthRequestRepository
	audit port.AuditLogger
}

func NewAuthUseCase(repo port.AuthRequestRepository, audit port.AuditLogger) AuthUseCase {
	return &authUseCase{
		repo:  repo,
		audit: audit,
	}
}

// --- Login Request Methods ---

func (u *authUseCase) CreateLoginRequest(ctx context.Context, req *model.LoginRequest) (*model.LoginRequest, error) {
	if req.ID == "" {
		req.ID, _ = utils.GenerateRandomHex(16)
	}
	req.Active = true

	if err := u.repo.SaveLoginRequest(ctx, req); err != nil {
		return nil, err
	}
	return req, nil
}

func (u *authUseCase) UpdateLoginRequest(ctx context.Context, req *model.LoginRequest) (*model.LoginRequest, error) {
	req.Active = true
	if err := u.repo.UpdateLoginRequest(ctx, req); err != nil {
		return nil, err
	}
	return req, nil
}

func (u *authUseCase) GetLoginRequest(ctx context.Context, challenge string) (*model.LoginRequest, error) {
	req, err := u.repo.GetLoginRequest(ctx, challenge)
	if err != nil {
		return nil, err
	}
	if !req.Active && !req.Authenticated {
		return nil, errors.New("login request is no longer active (replay attempt detected)")
	}
	return req, nil
}

func (u *authUseCase) GetRecentLogins(ctx context.Context, tenantID string, limit int) ([]model.LoginRequest, error) {
	return u.repo.GetRecentLogins(ctx, tenantID, limit)
}
func (u *authUseCase) GetAuthenticatedLoginRequest(ctx context.Context, challenge string) (*model.LoginRequest, error) {
	return u.repo.GetAuthenticatedLoginRequest(ctx, challenge)
}

func (u *authUseCase) GetAuthenticatedLoginRequestBySubject(ctx context.Context, subject string) (*model.LoginRequest, error) {
	return u.repo.GetAuthenticatedLoginRequestBySubject(ctx, subject)
}

func (u *authUseCase) AcceptLoginRequest(ctx context.Context, challenge string, remember bool, rememberFor int, subject string, contextData map[string]interface{}, actorIP, userAgent string) (*model.LoginRequest, error) {
	req, err := u.repo.GetLoginRequest(ctx, challenge)
	if err != nil {
		return nil, err
	}

	var contextBytes []byte
	if contextData != nil {
		contextBytes, err = json.Marshal(contextData)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal login context data: %w", err)
		}
	}

	req.Subject = subject
	req.Authenticated = true
	req.Remember = remember
	req.RememberFor = rememberFor
	req.Context = contextBytes
	req.Active = false

	if err := u.repo.UpdateLoginRequest(ctx, req); err != nil {
		return nil, err
	}
	u.audit.Log(req.ID, subject, "auth.login.accept", actorIP, userAgent, map[string]interface{}{
		"client_id": req.ClientID,
	})

	return req, nil
}

func (u *authUseCase) RejectLoginRequest(ctx context.Context, challenge string, errName, errDesc, actorIP, userAgent string) (*model.LoginRequest, error) {
	req, err := u.repo.GetLoginRequest(ctx, challenge)
	if err != nil {
		return nil, err
	}

	req.Active = false

	if err := u.repo.UpdateLoginRequest(ctx, req); err != nil {
		return nil, err
	}
	u.audit.Log(req.ID, req.Subject, "auth.login.reject", actorIP, userAgent, map[string]interface{}{
		"client_id":         req.ClientID,
		"error_name":        errName,
		"error_description": errDesc,
	})
	return req, nil
}

func (u *authUseCase) MarkLoginAsProviderStarted(ctx context.Context, challenge, provider, connectionID string, providerContext map[string]interface{}, actorIP, userAgent string) error {
	req, err := u.repo.GetLoginRequest(ctx, challenge)
	if err != nil {
		return err
	}
	if providerContext != nil {
		var existingCtx map[string]interface{}
		if len(req.Context) > 0 {
			_ = json.Unmarshal(req.Context, &existingCtx)
		} else {
			existingCtx = make(map[string]interface{})
		}
		for k, v := range providerContext {
			existingCtx[k] = v
		}
		req.Context, _ = json.Marshal(existingCtx)
		if err := u.repo.UpdateLoginRequest(ctx, req); err != nil {
			return err
		}
	}

	u.audit.Log(req.ID, req.Subject, provider+".login.start", actorIP, userAgent, map[string]interface{}{
		"connection_id":      connectionID,
		"provider":           provider,
		"requested_scopes":   req.RequestedScope,
		"requested_audience": req.RequestedAudience,
		"protocol":           req.Protocol,
	})
	return nil
}

func (u *authUseCase) CompleteProviderLogin(ctx context.Context, challenge, subject, connectionName string, contextData map[string]interface{}, actorIP, userAgent string) (*model.LoginRequest, error) {
	req, err := u.repo.GetLoginRequest(ctx, challenge)
	if err != nil {
		return nil, err
	}

	var contextBytes []byte
	if contextData != nil {
		var err error
		contextBytes, err = json.Marshal(contextData)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal provider context data: %w", err)
		}
	}

	req.Subject = subject
	req.Authenticated = true
	req.Context = contextBytes

	if err := u.repo.UpdateLoginRequest(ctx, req); err != nil {
		return nil, err
	}

	u.audit.Log(req.ID, req.Subject, "provider.login.success", actorIP, userAgent, map[string]interface{}{
		"client_id":          req.ClientID,
		"connection":         connectionName,
		"requested_scopes":   req.RequestedScope,
		"requested_audience": req.RequestedAudience,
		"protocol":           req.Protocol,
	})

	return req, nil
}

// --- Consent Request Methods ---

func (u *authUseCase) CreateConsentRequest(ctx context.Context, req *model.ConsentRequest) (*model.ConsentRequest, error) {
	if req.ID == "" {
		req.ID, _ = utils.GenerateRandomHex(16)
	}
	req.Active = true

	if err := u.repo.SaveConsentRequest(ctx, req); err != nil {
		return nil, err
	}
	return req, nil
}

func (u *authUseCase) GetConsentRequest(ctx context.Context, challenge string) (*model.ConsentRequest, error) {
	return u.repo.GetConsentRequest(ctx, challenge)
}

func (u *authUseCase) GetAuthenticatedConsentRequest(ctx context.Context, challenge string) (*model.ConsentRequest, error) {
	return u.repo.GetAuthenticatedConsentRequest(ctx, challenge)
}

func (u *authUseCase) GetAuthenticatedConsentRequestBySubject(ctx context.Context, subject string) (*model.ConsentRequest, error) {
	return u.repo.GetAuthenticatedConsentRequestBySubject(ctx, subject)
}

func (u *authUseCase) AcceptConsentRequest(ctx context.Context, challenge string, grantScope, grantAudience []string, remember bool, rememberFor int, contextData map[string]interface{}, actorIP, userAgent string) (*model.ConsentRequest, error) {
	req, err := u.repo.GetConsentRequest(ctx, challenge)
	if err != nil {
		return nil, err
	}

	var contextBytes []byte
	if contextData != nil {
		contextBytes, err = json.Marshal(contextData)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal consent session data: %w", err)
		}
	}

	req.GrantedScope = grantScope
	req.GrantedAudience = grantAudience
	req.Remember = remember
	req.RememberFor = rememberFor
	req.Context = contextBytes
	req.Authenticated = true
	req.Active = false

	if err := u.repo.UpdateConsentRequest(ctx, req); err != nil {
		return nil, err
	}

	u.audit.Log(req.ID, req.Subject, "auth.consent.accept", actorIP, userAgent, map[string]interface{}{
		"client_id":          req.ClientID,
		"scopes":             req.GrantedScope,
		"requested_scopes":   req.RequestedScope,
		"audience":           req.GrantedAudience,
		"requested_audience": req.RequestedAudience,
	})

	return req, nil
}

func (u *authUseCase) RejectConsentRequest(ctx context.Context, challenge string, errName, errDesc, actorIP, userAgent string) (*model.ConsentRequest, error) {
	req, err := u.repo.GetConsentRequest(ctx, challenge)
	if err != nil {
		return nil, err
	}
	req.Active = false
	if err := u.repo.UpdateConsentRequest(ctx, req); err != nil {
		return nil, err
	}
	u.audit.Log(req.ID, req.Subject, "auth.consent.reject", actorIP, userAgent, map[string]interface{}{
		"client_id":          req.ClientID,
		"scopes":             req.GrantedScope,
		"requested_scopes":   req.RequestedScope,
		"audience":           req.GrantedAudience,
		"requested_audience": req.RequestedAudience,
		"error":              errName,
		"error_reason":       errDesc,
	})
	return req, nil
}
