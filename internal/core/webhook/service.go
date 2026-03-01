package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type Service struct {
	DB     *gorm.DB
	Client *http.Client
}

func NewService(db *gorm.DB) *Service {
	s := &Service{
		DB:     db,
		Client: &http.Client{Timeout: 5 * time.Second},
	}

	go s.startDispatcher()
	return s
}

func (s *Service) FireEvent(tenantID, eventType string, data map[string]interface{}) {
	go func() {
		var webhooks []models.Webhook
		s.DB.Find(&webhooks)

		payloadBytes, _ := json.Marshal(map[string]interface{}{
			"event_id":   "evt_" + strings.ReplaceAll(uuid.New().String(), "-", ""),
			"event_type": eventType,
			"timestamp":  time.Now().Unix(),
			"tenant_id":  tenantID,
			"data":       data,
		})

		for _, wh := range webhooks {
			if matchPattern(tenantID, wh.TenantIDs) && matchPattern(eventType, wh.Events) {
				evt := models.WebhookEvent{
					ID:        "we_" + strings.ReplaceAll(uuid.New().String(), "-", ""),
					WebhookID: wh.ID,
					TenantID:  tenantID,
					EventType: eventType,
					Payload:   payloadBytes,
					CreatedAt: time.Now(),
				}
				s.DB.Create(&evt)
			}
		}
	}()
}

func (s *Service) startDispatcher() {
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		var webhooks []models.Webhook
		s.DB.Find(&webhooks)

		for _, wh := range webhooks {
			var events []models.WebhookEvent

			limit := 50
			if !wh.IsActive {
				limit = 1
			}

			s.DB.Where("webhook_id = ?", wh.ID).Order("created_at asc").Limit(limit).Find(&events)

			for _, evt := range events {
				success := s.sendHTTP(wh, evt.Payload)

				if success {
					s.DB.Delete(&evt)
					if !wh.IsActive || wh.FailureCount > 0 {
						s.DB.Model(&wh).Updates(map[string]interface{}{"is_active": true, "failure_count": 0})
						wh.IsActive = true
						wh.FailureCount = 0
						logger.FromGin(nil).Info("Webhook recovered and active again", zap.String("webhook_id", wh.ID))
					}
				} else {
					wh.FailureCount++
					updates := map[string]interface{}{"failure_count": wh.FailureCount}

					if wh.FailureCount >= 5 && wh.IsActive {
						updates["is_active"] = false
						wh.IsActive = false
						logger.FromGin(nil).Warn("Webhook Circuit Broken: Service unreachable, switching to passive mode", zap.String("webhook_id", wh.ID))
					}
					s.DB.Model(&wh).Updates(updates)
					break
				}
			}
		}
	}
}

func (s *Service) sendHTTP(wh models.Webhook, payload []byte) bool {
	req, err := http.NewRequest("POST", wh.URL, bytes.NewBuffer(payload))
	if err != nil {
		return false
	}

	req.Header.Set("Content-Type", "application/json")

	mac := hmac.New(sha256.New, []byte(wh.Secret))
	mac.Write(payload)
	req.Header.Set("X-Shyntr-Signature", hex.EncodeToString(mac.Sum(nil)))

	resp, err := s.Client.Do(req)
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
