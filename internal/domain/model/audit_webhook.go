package model

import (
	"errors"
	"net/url"
	"time"
)

type AuditLog struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	Details   []byte    `json:"details"`
	CreatedAt time.Time `json:"created_at"`
}

func (a *AuditLog) Validate() error {
	if a.TenantID == "" {
		return errors.New("tenant_id is required for audit logs")
	}
	if a.Action == "" {
		return errors.New("action is required for audit logs")
	}
	return nil
}

type Webhook struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	URL          string    `json:"url"`
	Secret       string    `json:"-"`
	TenantIDs    []string  `json:"tenant_ids"`
	Events       []string  `json:"events"`
	IsActive     bool      `json:"active"`
	FailureCount int       `json:"failure_count"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
}

func (w *Webhook) Validate() error {
	if w.Name == "" {
		return errors.New("webhook name is required")
	}
	if w.URL == "" {
		return errors.New("webhook url is required")
	}
	if _, err := url.ParseRequestURI(w.URL); err != nil {
		return errors.New("invalid webhook url format")
	}
	if len(w.Events) == 0 {
		return errors.New("at least one event must be subscribed to")
	}
	return nil
}

type WebhookEvent struct {
	ID        string
	WebhookID string
	TenantID  string
	EventType string
	Payload   []byte
	CreatedAt time.Time
}
