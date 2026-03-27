package port

import (
	"context"
	"net/http"
	"net/url"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

type OutboundGuard interface {
	ValidateURL(ctx context.Context, tenantID string, target model.OutboundTargetType, rawURL string) (*url.URL, *model.OutboundPolicy, error)
	NewHTTPClient(ctx context.Context, tenantID string, target model.OutboundTargetType, policy *model.OutboundPolicy) *http.Client
}
