package model

// SAML 2.0 Subject NameID formats Shyntr can actually issue (SAML Core 2.0,
// section 8.3). These string values are identical to the crewjam/saml
// NameIDFormat constants, but are declared here so the domain layer stays
// framework-free.
//
// persistent is intentionally NOT in this set: it is not satisfiable until real
// opaque pairwise identifiers exist, and the issuance path fails closed on it.
// Advertising a format the IdP cannot produce is worse than not offering it.
const (
	NameIDFormatUnspecified  = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	NameIDFormatEmailAddress = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDFormatTransient    = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
)

// IsValidNameIDFormat reports whether s is a NameID format the issuance path can
// actually produce, and therefore one an operator may pin for advertising in
// metadata. An empty string is not valid: callers treat "unset" (empty)
// separately from "set to an unsupported value". persistent and any other URN
// return false, so a configured format can never advertise something the IdP
// would refuse to issue.
func IsValidNameIDFormat(s string) bool {
	switch s {
	case NameIDFormatUnspecified, NameIDFormatEmailAddress, NameIDFormatTransient:
		return true
	default:
		return false
	}
}
