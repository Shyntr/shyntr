package utils

import "github.com/Shyntr/shyntr/internal/domain/model"

const SAMLNameIDSubjectAttribute = "__shyntr_saml_nameid_subject"

var normalizedSAMLStringAttributes = []string{
	claimPreferredUsername,
	claimEmail,
	claimName,
	claimGivenName,
	claimFamilyName,
}

// ProjectNormalizedSAMLAttributes returns the conservative SAML projection for a persisted normalized login context.
func ProjectNormalizedSAMLAttributes(loginReq *model.LoginRequest) (map[string]interface{}, bool) {
	if loginReq == nil {
		return nil, false
	}

	normalized, ok, err := loginReq.NormalizedContext()
	if err != nil || !ok {
		return nil, false
	}

	attributes := map[string]interface{}{
		"sub": loginReq.Subject,
	}

	if normalized.Identity == nil {
		return attributes, true
	}

	for _, name := range normalizedSAMLStringAttributes {
		if value, ok := stringAttribute(normalized.Identity.Attributes, name); ok {
			attributes[name] = value
		}
	}
	if len(normalized.Identity.Groups) > 0 {
		attributes[claimGroups] = normalized.Identity.Groups
	}
	if len(normalized.Identity.Roles) > 0 {
		attributes[claimRoles] = normalized.Identity.Roles
	}

	return attributes, true
}
