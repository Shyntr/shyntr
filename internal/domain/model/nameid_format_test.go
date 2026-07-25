package model_test

import (
	"testing"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

func TestIsValidNameIDFormat(t *testing.T) {
	for _, v := range []string{
		model.NameIDFormatUnspecified,
		model.NameIDFormatEmailAddress,
		model.NameIDFormatTransient,
	} {
		if !model.IsValidNameIDFormat(v) {
			t.Fatalf("IsValidNameIDFormat(%q) = false, want true", v)
		}
	}
	for _, v := range []string{
		"",
		"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", // never satisfiable
		"urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
		"emailAddress",
		"arbitrary",
	} {
		if model.IsValidNameIDFormat(v) {
			t.Fatalf("IsValidNameIDFormat(%q) = true, want false", v)
		}
	}
}

// M6 (client): an invalid NameIDFormat is rejected at configuration time, a valid
// one and the unset (empty) case pass.
func TestSAMLClient_Validate_NameIDFormat(t *testing.T) {
	base := func(nf string) *model.SAMLClient {
		return &model.SAMLClient{
			TenantID:     "tenant-a",
			EntityID:     "http://sp.example.test/x",
			ACSURL:       "http://sp.example.test/acs",
			NameIDFormat: nf,
		}
	}
	if err := base("").Validate(); err != nil {
		t.Fatalf("empty NameIDFormat must be accepted (unset), got %v", err)
	}
	if err := base(model.NameIDFormatTransient).Validate(); err != nil {
		t.Fatalf("a supported NameIDFormat must be accepted, got %v", err)
	}
	for _, nf := range []string{
		"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		"not-a-format",
	} {
		if err := base(nf).Validate(); err == nil {
			t.Fatalf("NameIDFormat %q must be rejected at configuration time", nf)
		}
	}
}

// M6 (connection): the same rejection holds on the SP connection side.
func TestSAMLConnection_Validate_NameIDFormat(t *testing.T) {
	base := func(nf string) *model.SAMLConnection {
		return &model.SAMLConnection{
			TenantID:        "tenant-a",
			IdpEntityID:     "https://idp.example.test",
			IdpSingleSignOn: "https://idp.example.test/sso",
			IdpCertificate:  "cert",
			NameIDFormat:    nf,
		}
	}
	if err := base("").Validate(); err != nil {
		t.Fatalf("empty NameIDFormat must be accepted (unset), got %v", err)
	}
	if err := base(model.NameIDFormatEmailAddress).Validate(); err != nil {
		t.Fatalf("a supported NameIDFormat must be accepted, got %v", err)
	}
	for _, nf := range []string{
		"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		"not-a-format",
	} {
		if err := base(nf).Validate(); err == nil {
			t.Fatalf("NameIDFormat %q must be rejected at configuration time", nf)
		}
	}
}
