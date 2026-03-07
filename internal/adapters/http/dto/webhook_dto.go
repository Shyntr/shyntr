package dto

import (
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
)

type CreateWebhookRequest struct {
	Name      string   `json:"name" binding:"required"`
	URL       string   `json:"url" binding:"required"`
	TenantIDs []string `json:"tenant_ids"`
	Events    []string `json:"events" binding:"required"`
}

type WebhookResponse struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	URL       string   `json:"url"`
	TenantIDs []string `json:"tenant_ids"`
	Events    []string `json:"events"`
	IsActive  bool     `json:"is_active"`
	CreatedAt string   `json:"created_at"`
}

type WebhookEventResponse struct {
	ID        string `json:"id"`
	WebhookID string `json:"webhook_id"`
	TenantID  string `json:"tenant_id"`
	EventType string `json:"event_type"`
	Payload   []byte `json:"payload"`
	CreatedAt string `json:"created_at"`
}

func (req *CreateWebhookRequest) ToDomain() *entity.Webhook {
	return &entity.Webhook{
		Name:      req.Name,
		URL:       req.URL,
		TenantIDs: req.TenantIDs,
		Events:    req.Events,
	}
}

func FromDomain(w *entity.Webhook) *WebhookResponse {
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

func FromDomainEvent(w *entity.WebhookEvent) *WebhookEventResponse {
	return &WebhookEventResponse{
		ID:        w.ID,
		WebhookID: w.WebhookID,
		TenantID:  w.TenantID,
		EventType: w.EventType,
		Payload:   w.Payload,
		CreatedAt: w.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}
