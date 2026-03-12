package utils

import (
	"context"

	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/entity"
	"github.com/Shyntr/shyntr/pkg/utils"
)

func SeedSystemScopesForTenant(ctx context.Context, repo port.ScopeRepository, tenantID string) error {
	systemScopes := []entity.Scope{
		{
			Name:        "openid",
			Description: "Authenticate your identity.",
			Claims:      []string{"sub"},
			IsSystem:    true,
			Active:      true,
		},
		{
			Name:        "offline_access",
			Description: "Maintain access to your data when you are not actively using the application.",
			Claims:      []string{},
			IsSystem:    true,
			Active:      true,
		},
		{
			Name:        "profile",
			Description: "Access your basic profile information.",
			Claims:      []string{"name", "family_name", "given_name", "preferred_username", "picture"},
			IsSystem:    true,
			Active:      true,
		},
		{
			Name:        "email",
			Description: "Access your email address.",
			Claims:      []string{"email", "email_verified"},
			IsSystem:    true,
			Active:      true,
		},
	}

	for _, s := range systemScopes {
		s.TenantID = tenantID

		existing, err := repo.GetByName(ctx, tenantID, s.Name)
		if err == nil && existing != nil {
			continue
		}

		s.ID, _ = utils.GenerateRandomHex(8)
		if err := repo.Create(ctx, &s); err != nil {
			return err
		}
	}
	return nil
}
