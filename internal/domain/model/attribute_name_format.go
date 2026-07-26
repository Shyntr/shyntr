package model

import "strings"

// SAML 2.0 attribute name formats (SAML Core 2.0, section 8.2).
const (
	AttrNameFormatURI         = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	AttrNameFormatBasic       = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
	AttrNameFormatUnspecified = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
)

// IsValidAttributeNameFormat reports whether s is one of the three SAML 2.0
// attribute name formats. An empty string is not valid; callers treat "unset"
// (empty) separately from "set to an invalid value".
func IsValidAttributeNameFormat(s string) bool {
	switch s {
	case AttrNameFormatURI, AttrNameFormatBasic, AttrNameFormatUnspecified:
		return true
	default:
		return false
	}
}

// AttributeNameFormatFor returns the SAML attribute NameFormat implied by an
// output attribute name: uri when the name is URI-shaped (it BEGINS with
// "http://", "https://" or "urn:"), otherwise basic. A name that merely contains
// such a scheme elsewhere is basic.
func AttributeNameFormatFor(name string) string {
	if strings.HasPrefix(name, "http://") ||
		strings.HasPrefix(name, "https://") ||
		strings.HasPrefix(name, "urn:") {
		return AttrNameFormatURI
	}
	return AttrNameFormatBasic
}
