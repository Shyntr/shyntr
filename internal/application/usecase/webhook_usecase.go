package usecase

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/Shyntr/shyntr/pkg/utils"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

var (
	ErrWebhookValidation      = errors.New("webhook validation failed")
	ErrWebhookPolicyViolation = errors.New("webhook policy violation")
)

func wrapWebhookValidation(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %v", ErrWebhookValidation, err)
}

type WebhookUseCase interface {
	CreateWebhook(ctx context.Context, webhook *model.Webhook, actorIP, userAgent string) (*model.Webhook, string, error)
	GetWebhook(ctx context.Context, id string) (*model.Webhook, error)
	DeleteWebhook(ctx context.Context, id string, actorIP, userAgent string) error
	ListWebhooks(ctx context.Context) ([]*model.Webhook, error)
	FireEvent(tenantID, eventType string, data map[string]interface{})
	StartDispatcher()
}

type webhookUseCase struct {
	repo      port.WebhookRepository
	eventRepo port.WebhookEventRepository
	audit     port.AuditLogger
	outbound  port.OutboundGuard
}

func NewWebhookUseCase(
	repo port.WebhookRepository,
	eventRepo port.WebhookEventRepository,
	audit port.AuditLogger,
	outbound port.OutboundGuard,
) WebhookUseCase {
	return &webhookUseCase{
		repo:      repo,
		eventRepo: eventRepo,
		audit:     audit,
		outbound:  outbound,
	}
}

func (u *webhookUseCase) CreateWebhook(ctx context.Context, webhook *model.Webhook, actorIP, userAgent string) (*model.Webhook, string, error) {
	if webhook.ID == "" {
		webhook.ID = uuid.New().String()
	}

	secret, _ := utils.GenerateRandomHex(32)
	webhook.Secret = secret
	webhook.IsActive = true

	if err := webhook.Validate(); err != nil {
		return nil, "", wrapWebhookValidation(err)
	}

	effectiveTenantID := resolveWebhookPolicyTenantID(webhook.TenantIDs)
	if _, _, err := u.outbound.ValidateURL(ctx, effectiveTenantID, model.OutboundTargetWebhookDelivery, webhook.URL); err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrWebhookPolicyViolation, err)
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

func (u *webhookUseCase) GetWebhook(ctx context.Context, id string) (*model.Webhook, error) {
	return u.repo.GetByID(ctx, id)
}

func (u *webhookUseCase) DeleteWebhook(ctx context.Context, id string, actorIP, userAgent string) error {
	if err := u.repo.Delete(ctx, id); err != nil {
		return err
	}
	u.audit.Log("system", "system", "management.webhook.delete", actorIP, userAgent, map[string]interface{}{
		"webhook_id": id,
	})
	return nil
}

func (u *webhookUseCase) ListWebhooks(ctx context.Context) ([]*model.Webhook, error) {
	return u.repo.List(ctx)
}

func (u *webhookUseCase) FireEvent(tenantID, eventType string, data map[string]interface{}) {
	go func() {
		bgCtx := context.Background()
		webhooks, err := u.repo.List(bgCtx)
		if err != nil {
			return
		}

		eventID := uuid.New().String()
		payloadBytes, _ := json.Marshal(map[string]interface{}{
			"event_id":   "evt_" + eventID,
			"event_type": eventType,
			"timestamp":  time.Now().Unix(),
			"tenant_id":  tenantID,
			"data":       data,
		})

		for _, wh := range webhooks {
			if matchPattern(tenantID, wh.TenantIDs) && matchPattern(eventType, wh.Events) {
				evtID := uuid.New().String()
				evt := &model.WebhookEvent{
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
					success := u.sendHTTP(bgCtx, wh, evt.Payload)
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

func (u *webhookUseCase) sendHTTP(ctx context.Context, wh *model.Webhook, payload []byte) bool {
	effectiveTenantID := resolveWebhookPolicyTenantID(wh.TenantIDs)

	safeURL, policy, err := u.outbound.ValidateURL(ctx, effectiveTenantID, model.OutboundTargetWebhookDelivery, wh.URL)
	if err != nil {
		logger.Log.Warn("Webhook delivery blocked by outbound policy",
			zap.String("webhook_id", wh.ID),
			zap.String("url", wh.URL),
			zap.String("policy_tenant_id", effectiveTenantID),
			zap.Error(err),
		)
		return false
	}

	client := u.outbound.NewHTTPClient(ctx, effectiveTenantID, model.OutboundTargetWebhookDelivery, policy)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, safeURL.String(), bytes.NewBuffer(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	mac := hmac.New(sha256.New, []byte(wh.Secret))
	mac.Write(payload)
	req.Header.Set("X-Shyntr-Signature", hex.EncodeToString(mac.Sum(nil)))

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return false
	}

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

func resolveWebhookPolicyTenantID(tenantIDs []string) string {
	if len(tenantIDs) == 0 {
		return ""
	}

	candidates := make([]string, 0, len(tenantIDs))
	for _, t := range tenantIDs {
		trimmed := strings.TrimSpace(t)
		if trimmed == "" || trimmed == "*" {
			continue
		}
		if looksLikeRegexPattern(trimmed) {
			continue
		}
		candidates = append(candidates, trimmed)
	}

	if len(candidates) == 1 {
		return candidates[0]
	}

	return ""
}

func looksLikeRegexPattern(value string) bool {
	return strings.ContainsAny(value, `\.+?*()[]{}|^$`)
}
