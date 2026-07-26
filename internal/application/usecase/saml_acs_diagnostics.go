package usecase

import (
	"errors"
	"strings"

	crewjamsaml "github.com/crewjam/saml"
)

// Inbound ACS validation diagnostics.
//
// crewjam's ParseResponse returns *InvalidResponseError, whose Error() is the
// constant "Authentication failed" and whose real cause lives in PrivateErr. That
// cause cannot be surfaced verbatim: PrivateErr embeds document-derived values on
// some paths (empirically, the destination-mismatch message quotes the inbound
// Response's Destination attribute; crewjam's XML-parse errors can carry
// fragments), and the *InvalidResponseError itself also carries the full raw
// Response XML in its Response field.
//
// So Shyntr maps the cause to a fixed, document-independent CATEGORY and emits
// only that. The category set is a whitelist; anything unrecognised (including a
// future crewjam error string) maps to acsFailOther. Because only these constant
// strings are ever emitted, no attribute value, NameID, XML fragment, or other
// document content can escape through this channel by construction.
const (
	acsFailSignatureInvalid     = "signature_invalid"
	acsFailSignatureAlgRejected = "signature_algorithm_rejected_sha1"
	acsFailExpired              = "assertion_or_response_expired"
	acsFailNotYetValid          = "assertion_not_yet_valid"
	acsFailAudienceMismatch     = "audience_mismatch"
	acsFailDestinationMismatch  = "destination_mismatch"
	acsFailIssuerMismatch       = "issuer_mismatch"
	acsFailInResponseToMismatch = "in_response_to_mismatch"
	acsFailRecipientMismatch    = "recipient_mismatch"
	acsFailStatusNotSuccess     = "status_not_success"
	acsFailMalformedResponse    = "malformed_response"
	acsFailDecryptionFailed     = "decryption_failed"
	acsFailOther                = "validation_failed_other"
)

// classifyACSValidationError maps a crewjam ParseResponse error to a stable
// failure category. It reads InvalidResponseError.PrivateErr ONLY to match
// crewjam's fixed format-string prefixes; it never returns the raw message, so no
// interpolated document value can leak. The signature-algorithm rejection added by
// the SHA-1 policy is distinguished from an ordinary signature-verification failure
// so an operator can tell "we rejected SHA-1" from "the signature did not verify".
func classifyACSValidationError(err error) string {
	msg := privateCauseMessage(err)
	switch {
	// Signature: the SHA-1 policy rejection (our own text, wrapped by crewjam as
	// "cannot validate signature on <tag>: ...") must be distinguishable from a
	// failed cryptographic verification. Checked before the generic signature case.
	case strings.Contains(msg, "SHA-1 is disabled by policy"):
		return acsFailSignatureAlgRejected
	case strings.HasPrefix(msg, "cannot validate signature on "):
		return acsFailSignatureInvalid
	case strings.Contains(msg, "AudienceRestriction does not contain"),
		strings.Contains(msg, "audience restriction validation failed"):
		return acsFailAudienceMismatch
	case strings.HasPrefix(msg, "`Destination` does not match"):
		return acsFailDestinationMismatch
	case strings.HasPrefix(msg, "issuer is not "),
		strings.Contains(msg, "Issuer does not match the IDP metadata"):
		return acsFailIssuerMismatch
	case strings.Contains(msg, "Conditions is not yet valid"):
		return acsFailNotYetValid
	case strings.Contains(msg, "is expired"),
		strings.Contains(msg, "IssueInstant expired"),
		strings.HasPrefix(msg, "expired on "):
		return acsFailExpired
	case strings.Contains(msg, "InResponseTo"),
		strings.Contains(msg, "possible request IDs"):
		return acsFailInResponseToMismatch
	case strings.Contains(msg, "Recipient is not"):
		return acsFailRecipientMismatch
	case strings.Contains(msg, "cannot unmarshal"),
		strings.Contains(msg, "invalid xml"),
		strings.Contains(msg, "invalid XML"),
		strings.Contains(msg, "cannot parse"),
		strings.Contains(msg, "no root"):
		return acsFailMalformedResponse
	case strings.Contains(msg, "failed to decrypt"):
		return acsFailDecryptionFailed
	case strings.Contains(msg, "status code was not"),
		strings.Contains(msg, "StatusCode"):
		return acsFailStatusNotSuccess
	default:
		return acsFailOther
	}
}

// privateCauseMessage returns the message used only for prefix matching. It reads
// InvalidResponseError.PrivateErr when present. The returned string is NEVER
// emitted — only classifyACSValidationError's constant categories are.
func privateCauseMessage(err error) string {
	var ivr *crewjamsaml.InvalidResponseError
	if errors.As(err, &ivr) && ivr.PrivateErr != nil {
		return ivr.PrivateErr.Error()
	}
	if err != nil {
		return err.Error()
	}
	return ""
}
