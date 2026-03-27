package tenant

import (
	"context"
	"errors"

	"github.com/Shyntr/shyntr/pkg/consts"
)

var ErrMissingTenant = errors.New("security violation: tenant_id is missing in context")

func FromContext(ctx context.Context) (string, error) {
	val := ctx.Value(consts.ContextKeyTenantID)
	if val == nil {
		return "", ErrMissingTenant
	}

	tenantID, ok := val.(string)
	if !ok || tenantID == "" {
		return "", errors.New("security violation: invalid or empty tenant_id format in context")
	}

	return tenantID, nil
}
