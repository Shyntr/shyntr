package utils

import (
	"strings"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

const (
	claimPreferredUsername = "preferred_username"
	claimEmail             = "email"
	claimEmailVerified     = "email_verified"
	claimName              = "name"
	claimGivenName         = "given_name"
	claimFamilyName        = "family_name"
	claimGroups            = "groups"
	claimRoles             = "roles"
	claimAMR               = "amr"
	claimACR               = "acr"
)

var normalizedStringAttributes = []string{
	claimPreferredUsername,
	claimEmail,
	claimName,
	claimGivenName,
	claimFamilyName,
}

func ProjectNormalizedIdentityClaims(loginReq *model.LoginRequest) (map[string]interface{}, bool) {
	if loginReq == nil {
		return nil, false
	}

	normalized, ok, err := loginReq.NormalizedContext()
	if err != nil || !ok {
		return nil, false
	}

	claims := map[string]interface{}{
		"sub": loginReq.Subject,
	}

	if normalized.Identity != nil {
		for _, name := range normalizedStringAttributes {
			if value, ok := stringAttribute(normalized.Identity.Attributes, name); ok {
				claims[name] = value
			}
		}
		if value, ok := normalized.Identity.Attributes[claimEmailVerified].(bool); ok {
			claims[claimEmailVerified] = value
		}
		if len(normalized.Identity.Groups) > 0 {
			claims[claimGroups] = normalized.Identity.Groups
		}
		if len(normalized.Identity.Roles) > 0 {
			claims[claimRoles] = normalized.Identity.Roles
		}
	}

	if normalized.Authentication != nil {
		if len(normalized.Authentication.AMR) > 0 {
			claims[claimAMR] = normalized.Authentication.AMR
		}
		if strings.TrimSpace(normalized.Authentication.ACR) != "" {
			claims[claimACR] = normalized.Authentication.ACR
		}
	}

	return claims, true
}

func stringAttribute(attributes map[string]interface{}, name string) (string, bool) {
	value, ok := attributes[name].(string)
	if !ok || value == "" {
		return "", false
	}
	return value, true
}
