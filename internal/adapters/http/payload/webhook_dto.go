package payload

import (
	"github.com/Shyntr/shyntr/internal/domain/model"
)

type CreateWebhookRequest struct {
	Name      string   `json:"name" binding:"required" example:"Audit Log Aggregator"`
	URL       string   `json:"url" binding:"required" example:"https://siem.acme.corp/webhooks/shyntr"`
	TenantIDs []string `json:"tenant_ids" example:"tnt_alpha01,tnt_beta02"`
	Events    []string `json:"events" binding:"required" example:"user.login.ext,tenant.created"`
}

type WebhookResponse struct {
	ID        string   `json:"id" example:"wh_9a8b7c6d5e4"`
	Name      string   `json:"name" example:"Audit Log Aggregator"`
	URL       string   `json:"url" example:"https://siem.acme.corp/webhooks/shyntr"`
	TenantIDs []string `json:"tenant_ids" example:"tnt_alpha01,tnt_beta02"`
	Events    []string `json:"events" example:"user.login.ext,tenant.created"`
	IsActive  bool     `json:"is_active" example:"true"`
	CreatedAt string   `json:"created_at" example:"2026-03-14T12:00:00Z"`
}

type WebhookEventResponse struct {
	ID        string `json:"id" example:"evt_123456789"`
	WebhookID string `json:"webhook_id" example:"wh_9a8b7c6d5e4"`
	TenantID  string `json:"tenant_id" example:"tnt_alpha01"`
	EventType string `json:"event_type" example:"user.login.ext"`
	Payload   []byte `json:"payload" swaggertype:"string" example:"{\"sub\":\"usr_123\",\"source\":\"oidc\"}"`
	CreatedAt string `json:"created_at" example:"2026-03-14T12:05:00Z"`
}

func (req *CreateWebhookRequest) ToDomain() *model.Webhook {
	return &model.Webhook{
		Name:      req.Name,
		URL:       req.URL,
		TenantIDs: req.TenantIDs,
		Events:    req.Events,
	}
}

func FromDomain(w *model.Webhook) *WebhookResponse {
	return &WebhookResponse{
		ID:        w.ID,
		Name:      w.Name,
		URL:       w.URL,
		TenantIDs: w.TenantIDs,
		Events:    w.Events,
		IsActive:  w.IsActive,
		CreatedAt: w.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}

func FromDomainEvent(w *model.WebhookEvent) *WebhookEventResponse {
	return &WebhookEventResponse{
		ID:        w.ID,
		WebhookID: w.WebhookID,
		TenantID:  w.TenantID,
		EventType: w.EventType,
		Payload:   w.Payload,
		CreatedAt: w.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}
