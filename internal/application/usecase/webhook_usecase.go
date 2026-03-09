package usecase

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"github.com/nevzatcirak/shyntr/internal/application/port"
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"github.com/nevzatcirak/shyntr/pkg/utils"
	"go.uber.org/zap"
)

type WebhookUseCase interface {
	CreateWebhook(ctx context.Context, webhook *entity.Webhook, actorIP, userAgent string) (*entity.Webhook, string, error)
	GetWebhook(ctx context.Context, id string) (*entity.Webhook, error)
	DeleteWebhook(ctx context.Context, id string, actorIP, userAgent string) error
	ListWebhooks(ctx context.Context) ([]*entity.Webhook, error)
	FireEvent(tenantID, eventType string, data map[string]interface{})
	StartDispatcher()
}

type webhookUseCase struct {
	repo      port.WebhookRepository
	eventRepo port.WebhookEventRepository
	audit     port.AuditLogger
	client    *http.Client
}

func NewWebhookUseCase(repo port.WebhookRepository, eventRepo port.WebhookEventRepository, audit port.AuditLogger) WebhookUseCase {
	return &webhookUseCase{
		repo:      repo,
		eventRepo: eventRepo,
		audit:     audit,
		client:    &http.Client{Timeout: 5 * time.Second},
	}
}

func (u *webhookUseCase) CreateWebhook(ctx context.Context, webhook *entity.Webhook, actorIP, userAgent string) (*entity.Webhook, string, error) {
	if webhook.ID == "" {
		webhook.ID, _ = utils.GenerateRandomHex(8)
	}

	secret, _ := utils.GenerateRandomHex(32)
	webhook.Secret = secret
	webhook.IsActive = true

	if err := webhook.Validate(); err != nil {
		return nil, "", err
	}

	if err := u.repo.Create(ctx, webhook); err != nil {
		return nil, "", err
	}

	u.audit.Log("system", "system", "management.webhook.create", actorIP, userAgent, map[string]interface{}{
		"webhook_id": webhook.ID,
		"url":        webhook.URL,
		"ip":         actorIP,
	})

	return webhook, secret, nil
}

func (u *webhookUseCase) GetWebhook(ctx context.Context, id string) (*entity.Webhook, error) {
	return u.repo.GetByID(ctx, id)
}

func (u *webhookUseCase) DeleteWebhook(ctx context.Context, id string, actorIP, userAgent string) error {
	if err := u.repo.Delete(ctx, id); err != nil {
		return err
	}
	u.audit.LogWithoutIP("system", "system", "management.webhook.delete", map[string]interface{}{
		"webhook_id": id,
		"ip":         actorIP,
	})
	return nil
}

func (u *webhookUseCase) ListWebhooks(ctx context.Context) ([]*entity.Webhook, error) {
	return u.repo.List(ctx)
}

func (u *webhookUseCase) FireEvent(tenantID, eventType string, data map[string]interface{}) {
	go func() {
		bgCtx := context.Background()
		webhooks, err := u.repo.List(bgCtx)
		if err != nil {
			return
		}

		eventID, _ := utils.GenerateRandomHex(8)
		payloadBytes, _ := json.Marshal(map[string]interface{}{
			"event_id":   "evt_" + eventID,
			"event_type": eventType,
			"timestamp":  time.Now().Unix(),
			"tenant_id":  tenantID,
			"data":       data,
		})

		for _, wh := range webhooks {
			if matchPattern(tenantID, wh.TenantIDs) && matchPattern(eventType, wh.Events) {
				evtID, _ := utils.GenerateRandomHex(8)
				evt := &entity.WebhookEvent{
					ID:        "we_" + evtID,
					WebhookID: wh.ID,
					TenantID:  tenantID,
					EventType: eventType,
					Payload:   payloadBytes,
					CreatedAt: time.Now(),
				}
				_ = u.eventRepo.SaveEvent(bgCtx, evt)
			}
		}
	}()
}

func (u *webhookUseCase) StartDispatcher() {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		bgCtx := context.Background()

		for range ticker.C {
			webhooks, _ := u.repo.List(bgCtx)
			for _, wh := range webhooks {
				limit := 50
				if !wh.IsActive {
					limit = 1
				}

				events, _ := u.eventRepo.GetPendingEvents(bgCtx, wh.ID, limit)
				for _, evt := range events {
					success := u.sendHTTP(wh, evt.Payload)
					if success {
						_ = u.eventRepo.DeleteEvent(bgCtx, evt.ID)
						if !wh.IsActive {
							_ = u.eventRepo.ResetFailureAndActivate(bgCtx, wh.ID)
							logger.Log.Info("Webhook recovered and active again", zap.String("webhook_id", wh.ID))
						}
					} else {
						failures, _ := u.eventRepo.IncrementFailure(bgCtx, wh.ID)
						if failures >= 5 && wh.IsActive {
							_ = u.eventRepo.DeactivateWebhook(bgCtx, wh.ID)
							logger.Log.Warn("Webhook Circuit Broken: Switching to passive mode", zap.String("webhook_id", wh.ID))
						}
						break
					}
				}
			}
		}
	}()
}

func (u *webhookUseCase) sendHTTP(wh *entity.Webhook, payload []byte) bool {
	req, err := http.NewRequest("POST", wh.URL, bytes.NewBuffer(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	mac := hmac.New(sha256.New, []byte(wh.Secret))
	mac.Write(payload)
	req.Header.Set("X-Shyntr-Signature", hex.EncodeToString(mac.Sum(nil)))

	resp, err := u.client.Do(req)
	if err != nil || resp.StatusCode >= 300 {
		return false
	}
	defer resp.Body.Close()
	return true
}

func matchPattern(value string, patterns []string) bool {
	for _, p := range patterns {
		if p == "*" || p == value {
			return true
		}
		if matched, _ := regexp.MatchString(p, value); matched {
			return true
		}
	}
	return false
}
