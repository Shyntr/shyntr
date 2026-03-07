package usecase

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/nevzatcirak/shyntr/internal/adapters/http/dto"
	"github.com/nevzatcirak/shyntr/internal/application/port"
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
	"github.com/nevzatcirak/shyntr/pkg/utils"
)

type AuthUseCase interface {
	CreateLoginRequest(ctx context.Context, req *entity.LoginRequest) (*entity.LoginRequest, error)
	GetLoginRequest(ctx context.Context, id string) (*entity.LoginRequest, error)
	GetRecentLogins(ctx context.Context, tenantID string, limit int) ([]entity.LoginRequest, error)
	GetAuthenticatedLoginRequest(ctx context.Context, id string) (*entity.LoginRequest, error)
	GetAuthenticatedLoginRequestBySubject(ctx context.Context, userID string) (*entity.LoginRequest, error)
	AcceptLoginRequest(ctx context.Context, id string, request dto.AcceptLoginRequest) (*entity.LoginRequest, error)
	RejectLoginRequest(ctx context.Context, id string) (*entity.LoginRequest, error)

	CreateConsentRequest(ctx context.Context, req *entity.ConsentRequest) (*entity.ConsentRequest, error)
	GetConsentRequest(ctx context.Context, id string) (*entity.ConsentRequest, error)
	GetAuthenticatedConsentRequest(ctx context.Context, id string) (*entity.ConsentRequest, error)
	GetAuthenticatedConsentRequestBySubject(ctx context.Context, userID string) (*entity.ConsentRequest, error)
	AcceptConsentRequest(ctx context.Context, id string, request dto.AcceptConsentRequest) (*entity.ConsentRequest, error)
	RejectConsentRequest(ctx context.Context, id string) (*entity.ConsentRequest, error)
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

// --- LOGIN REQUEST MANAGEMENT ---

func (u *authUseCase) CreateLoginRequest(ctx context.Context, req *entity.LoginRequest) (*entity.LoginRequest, error) {
	if req.ID == "" {
		req.ID, _ = utils.GenerateRandomHex(16)
	}
	req.Active = true

	if err := u.repo.SaveLoginRequest(ctx, req); err != nil {
		return nil, err
	}
	return req, nil
}

func (u *authUseCase) GetLoginRequest(ctx context.Context, id string) (*entity.LoginRequest, error) {
	req, err := u.repo.GetLoginRequest(ctx, id)
	if err != nil {
		return nil, err
	}
	if !req.Active {
		return nil, errors.New("login request is no longer active (replay attempt detected)")
	}
	return req, nil
}

func (u *authUseCase) GetRecentLogins(ctx context.Context, tenantID string, limit int) ([]entity.LoginRequest, error) {
	req, err := u.repo.GetRecentLogins(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func (u *authUseCase) GetAuthenticatedLoginRequest(ctx context.Context, id string) (*entity.LoginRequest, error) {
	req, err := u.repo.GetAuthenticatedLoginRequest(ctx, id)
	if err != nil {
		return nil, err
	}
	if !req.Active {
		return nil, errors.New("login request is no longer active (replay attempt detected)")
	}
	return req, nil
}

func (u *authUseCase) GetAuthenticatedLoginRequestBySubject(ctx context.Context, userID string) (*entity.LoginRequest, error) {
	req, err := u.repo.GetAuthenticatedLoginRequestBySubject(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !req.Active {
		return nil, errors.New("login request is no longer active (replay attempt detected)")
	}
	return req, nil
}

func (u *authUseCase) RejectLoginRequest(ctx context.Context, id string) (*entity.LoginRequest, error) {
	req, err := u.repo.GetLoginRequest(ctx, id)
	if err != nil {
		return nil, err
	}
	req.Active = false
	if err := u.repo.UpdateLoginRequest(ctx, req); err != nil {
		return nil, err
	}
	return req, nil
}

func (u *authUseCase) AcceptLoginRequest(ctx context.Context, id string, request dto.AcceptLoginRequest) (*entity.LoginRequest, error) {
	req, err := u.GetLoginRequest(ctx, id)
	if err != nil {
		return nil, err
	}

	req.Subject = request.Subject
	req.Authenticated = true
	req.Remember = request.Remember
	req.RememberFor = request.RememberFor

	if request.Context != nil {
		var existingCtx map[string]interface{}
		if len(req.Context) > 0 {
			_ = json.Unmarshal(req.Context, &existingCtx)
		} else {
			existingCtx = make(map[string]interface{})
		}
		existingCtx["login_claims"] = request.Context
		mergedBytes, _ := json.Marshal(existingCtx)
		req.Context = mergedBytes
	}

	if err := u.repo.UpdateLoginRequest(ctx, req); err != nil {
		return nil, err
	}
	u.audit.LogWithoutIP(req.TenantID, request.Subject, "auth.login.accept", map[string]interface{}{
		"client_id": req.ClientID,
	})
	return req, nil
}

// --- CONSENT REQUEST MANAGEMENT ---

func (u *authUseCase) CreateConsentRequest(ctx context.Context, req *entity.ConsentRequest) (*entity.ConsentRequest, error) {
	if req.ID == "" {
		req.ID, _ = utils.GenerateRandomHex(16)
	}
	req.Active = true

	if err := u.repo.SaveConsentRequest(ctx, req); err != nil {
		return nil, err
	}
	return req, nil
}

func (u *authUseCase) GetConsentRequest(ctx context.Context, id string) (*entity.ConsentRequest, error) {
	req, err := u.repo.GetConsentRequest(ctx, id)
	if err != nil {
		return nil, err
	}
	if !req.Active {
		return nil, errors.New("consent request is no longer active")
	}
	return req, nil
}

func (u *authUseCase) GetAuthenticatedConsentRequest(ctx context.Context, id string) (*entity.ConsentRequest, error) {
	req, err := u.repo.GetAuthenticatedConsentRequest(ctx, id)
	if err != nil {
		return nil, err
	}
	if !req.Active {
		return nil, errors.New("consent request is no longer active")
	}
	return req, nil
}

func (u *authUseCase) GetAuthenticatedConsentRequestBySubject(ctx context.Context, userID string) (*entity.ConsentRequest, error) {
	req, err := u.repo.GetAuthenticatedConsentRequestBySubject(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !req.Active {
		return nil, errors.New("consent request is no longer active")
	}
	return req, nil
}

func (u *authUseCase) AcceptConsentRequest(ctx context.Context, id string, request dto.AcceptConsentRequest) (*entity.ConsentRequest, error) {
	req, err := u.GetConsentRequest(ctx, id)
	if err != nil {
		return nil, err
	}

	req.GrantedScope = request.GrantScope
	req.GrantedAudience = request.GrantAudience
	req.Authenticated = true
	req.Active = true
	req.Remember = request.Remember
	req.RememberFor = request.RememberFor
	sessionBytes, err := json.Marshal(request.Session)
	if err == nil {
		req.Context = sessionBytes
	}

	if err := u.repo.UpdateConsentRequest(ctx, req); err != nil {
		return nil, err
	}

	u.audit.LogWithoutIP("system", req.Subject, "auth.consent.accept", map[string]interface{}{
		"client_id": req.ClientID,
		"scopes":    request.GrantScope,
	})

	return req, nil
}

func (u *authUseCase) RejectConsentRequest(ctx context.Context, id string) (*entity.ConsentRequest, error) {
	req, err := u.repo.GetConsentRequest(ctx, id)
	if err != nil {
		return nil, err
	}
	req.Active = false
	if err := u.repo.UpdateConsentRequest(ctx, req); err != nil {
		return nil, err
	}
	return req, nil
}
