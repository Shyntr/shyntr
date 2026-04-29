package utils

import "github.com/Shyntr/shyntr/internal/domain/model"

// Standard OIDC Claim Mappings
var scopeToClaims = map[string][]string{
	"profile": {"name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at"},
	"email":   {"email", "email_verified"},
	"address": {"address"},
	"phone":   {"phone_number", "phone_number_verified"},
	"groups":  {"groups"},
	"roles":   {"roles"},
}

// MapClaims filters the raw context map based on requested scopes and tenant context.
func MapClaims(subject string, contextMap map[string]interface{}, grantedScopes []*model.Scope) map[string]interface{} {
	finalClaims := make(map[string]interface{})
	finalClaims["sub"] = subject

	allowedKeys := make(map[string]bool)

	allowedKeys["tenant_id"] = true
	allowedKeys["idp"] = true
	allowedKeys["amr"] = true
	allowedKeys["acr"] = true
	//allowedKeys["groups"] = true
	//allowedKeys["roles"] = true

	for _, scope := range grantedScopes {
		for _, claim := range scope.Claims {
			allowedKeys[claim] = true
		}
		// Standard OIDC scopes also allow their well-known claims regardless of
		// whether the database scope record explicitly lists them. This makes
		// granting the "email" scope sufficient to release the "email" claim even
		// when scope.Claims is empty or was not seeded via bindMappingScopes.
		for _, claim := range scopeToClaims[scope.Name] {
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
