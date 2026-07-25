package usecase

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/beevik/etree"
	goxmldsig "github.com/russellhaering/goxmldsig"
)

// Inbound SAML signature/digest algorithm policy.
//
// FMN Spiral 4 global parameters mandate SHA-256. Shyntr signs with SHA-256; this
// policy governs what it ACCEPTS on inbound signatures, defaulting to SHA-1
// disabled. One policy value drives both inbound paths:
//   - the redirect binding (VerifyInboundRedirectSignature), and
//   - embedded/POST signatures (verifyPostSignature and the ACS path, the latter
//     via crewjam's ServiceProvider.SignatureVerifier hook).
//
// goxmldsig v1.6.0 exposes no algorithm allow-list and its algorithm maps are
// unexported, so embedded SHA-1 is refused by reading the SignatureMethod and
// every Reference/DigestMethod Algorithm attribute BEFORE cryptographic
// validation. The policy applies to the digest as well as the signature: a
// SHA-256 signature over a SHA-1 digest is rejected, because the digest is where
// collision resistance actually lives.
//
// Error messages name the algorithm category only — never the signature, the
// query, the certificate, or any claim value.

// XML-DSig SHA-1 algorithm identifiers (exact URIs; no suffix matching).
const (
	sigAlgRSASHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	sigAlgDSASHA1   = "http://www.w3.org/2000/09/xmldsig#dsa-sha1"
	sigAlgECDSASHA1 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"
	digestAlgSHA1   = "http://www.w3.org/2000/09/xmldsig#sha1"
)

var (
	errSHA1SignatureDisabled = errors.New("inbound signature algorithm SHA-1 is disabled by policy")
	errSHA1DigestDisabled    = errors.New("inbound digest algorithm SHA-1 is disabled by policy")
)

// signatureAlgorithmPolicy governs which inbound XML-DSig signature and digest
// algorithms are accepted.
type signatureAlgorithmPolicy struct {
	allowSHA1 bool
}

// signaturePolicy derives the policy from configuration, defaulting to SHA-1
// disabled. It tolerates a nil Config so zero-value use-case instances built in
// unit tests behave as the strict default.
func (s *samlBuilderUseCase) signaturePolicy() signatureAlgorithmPolicy {
	allow := false
	if s.Config != nil {
		allow = s.Config.SAMLAllowSHA1Signatures
	}
	return signatureAlgorithmPolicy{allowSHA1: allow}
}

// checkSignatureAlgorithm rejects a SHA-1 signature-method URI unless SHA-1 is
// explicitly enabled.
func (p signatureAlgorithmPolicy) checkSignatureAlgorithm(uri string) error {
	if p.allowSHA1 {
		return nil
	}
	switch uri {
	case sigAlgRSASHA1, sigAlgDSASHA1, sigAlgECDSASHA1:
		return errSHA1SignatureDisabled
	}
	return nil
}

// checkDigestAlgorithm rejects a SHA-1 digest-method URI unless SHA-1 is
// explicitly enabled.
func (p signatureAlgorithmPolicy) checkDigestAlgorithm(uri string) error {
	if p.allowSHA1 {
		return nil
	}
	if uri == digestAlgSHA1 {
		return errSHA1DigestDisabled
	}
	return nil
}

// checkRedirectSignatureAlgorithm reads the (decoded) SigAlg from the raw query of
// an HTTP-Redirect binding message and rejects SHA-1 per policy. A missing or
// malformed SigAlg is left to VerifyInboundRedirectSignature's crypto stage, which
// already fails closed on it; this check only adds the algorithm-policy gate.
func (p signatureAlgorithmPolicy) checkRedirectSignatureAlgorithm(req *http.Request) error {
	if p.allowSHA1 {
		return nil
	}
	raw, ok := rawQueryParam(req.URL.RawQuery, "SigAlg")
	if !ok {
		return nil
	}
	sigAlg, err := url.QueryUnescape(raw)
	if err != nil {
		return nil
	}
	return p.checkSignatureAlgorithm(sigAlg)
}

// checkEmbeddedSignatureAlgorithms pre-inspects an element carrying an enveloped
// XML-DSig Signature and rejects a SHA-1 signature or SHA-1 digest per policy,
// BEFORE the cryptographic validation goxmldsig performs. It reads
// SignedInfo/SignatureMethod and EVERY SignedInfo/Reference/DigestMethod so a
// mixed SHA-256-signature/SHA-1-digest document is caught. Matching is by local
// element name, since the Signature may carry a ds: prefix or a default namespace.
func (p signatureAlgorithmPolicy) checkEmbeddedSignatureAlgorithms(el *etree.Element) error {
	if p.allowSHA1 || el == nil {
		return nil
	}
	sig := childByLocalName(el, "Signature")
	if sig == nil {
		// No enveloped signature to police here; the crypto layer decides whether a
		// signature was required. This check never relaxes that decision.
		return nil
	}
	signedInfo := childByLocalName(sig, "SignedInfo")
	if signedInfo == nil {
		return nil
	}
	if sm := childByLocalName(signedInfo, "SignatureMethod"); sm != nil {
		if err := p.checkSignatureAlgorithm(sm.SelectAttrValue("Algorithm", "")); err != nil {
			return err
		}
	}
	for _, ref := range signedInfo.ChildElements() {
		if ref.Tag != "Reference" {
			continue
		}
		if dm := childByLocalName(ref, "DigestMethod"); dm != nil {
			if err := p.checkDigestAlgorithm(dm.SelectAttrValue("Algorithm", "")); err != nil {
				return err
			}
		}
	}
	return nil
}

// childByLocalName returns the first direct child whose local tag matches, ignoring
// namespace prefix.
func childByLocalName(el *etree.Element, local string) *etree.Element {
	for _, c := range el.ChildElements() {
		if c.Tag == local {
			return c
		}
	}
	return nil
}

// signatureAlgorithmVerifier adapts the embedded-signature policy to crewjam's
// ServiceProvider.SignatureVerifier hook. crewjam calls VerifySignature instead of
// its own default validation, handing us the fully-built goxmldsig
// ValidationContext; we apply the SHA-1 pre-inspection and then delegate the actual
// cryptographic check to that context, so trust decisions are unchanged and only
// the accepted algorithm set is tightened.
type signatureAlgorithmVerifier struct {
	policy signatureAlgorithmPolicy
}

func (v signatureAlgorithmVerifier) VerifySignature(validationContext *goxmldsig.ValidationContext, el *etree.Element) error {
	if err := v.policy.checkEmbeddedSignatureAlgorithms(el); err != nil {
		return err
	}
	_, err := validationContext.Validate(el)
	return err
}
