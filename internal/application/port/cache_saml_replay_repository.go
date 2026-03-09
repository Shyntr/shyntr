package port

import (
	"context"
	"time"
)

type SAMLReplayRepository interface {
	CheckAndSaveMessageID(ctx context.Context, messageID, tenantID string, expiration time.Duration) error
}
