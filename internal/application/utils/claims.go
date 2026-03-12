package utils

import "github.com/Shyntr/shyntr/internal/domain/entity"

// Standard OIDC Claim Mappings
var scopeToClaims = map[string][]string{
	"profile": {"name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at"},
	"email":   {"email", "email_verified"},
	"address": {"address"},
	"phone":   {"phone_number", "phone_number_verified"},
}

// MapClaims filters the raw context map based on requested scopes and tenant context.
func MapClaims(subject string, contextMap map[string]interface{}, grantedScopes []*entity.Scope) map[string]interface{} {
	finalClaims := make(map[string]interface{})
	finalClaims["sub"] = subject

	allowedKeys := make(map[string]bool)

	allowedKeys["tenant_id"] = true
	allowedKeys["idp"] = true
	allowedKeys["amr"] = true

	for _, scope := range grantedScopes {
		for _, claim := range scope.Claims {
			allowedKeys[claim] = true
		}
	}

	for key, value := range contextMap {
		if key == "login_claims" {
			if loginClaims, ok := value.(map[string]interface{}); ok {
				for lcKey, lcVal := range loginClaims {
					if allowedKeys[lcKey] {
						finalClaims[lcKey] = lcVal
					}
				}
			}
			continue
		}

		if allowedKeys[key] {
			finalClaims[key] = value
		}
	}

	return finalClaims
}
