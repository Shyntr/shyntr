package model_test

import (
	"testing"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

func TestAttributeNameFormatFor(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"http prefix", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", model.AttrNameFormatURI},
		{"https prefix", "https://example.test/claims/role", model.AttrNameFormatURI},
		{"urn prefix", "urn:oid:2.5.4.42", model.AttrNameFormatURI},
		{"plain name", "email", model.AttrNameFormatBasic},
		{"empty name", "", model.AttrNameFormatBasic},
		{"scheme not at start", "claim-http://x", model.AttrNameFormatBasic},
		{"urn not at start", "x-urn:foo", model.AttrNameFormatBasic},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := model.AttributeNameFormatFor(c.in); got != c.want {
				t.Fatalf("AttributeNameFormatFor(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestIsValidAttributeNameFormat(t *testing.T) {
	for _, v := range []string{model.AttrNameFormatURI, model.AttrNameFormatBasic, model.AttrNameFormatUnspecified} {
		if !model.IsValidAttributeNameFormat(v) {
			t.Fatalf("%q should be valid", v)
		}
	}
	for _, v := range []string{"", "basic", "uri", "urn:oasis:names:tc:SAML:2.0:attrname-format:xml", "arbitrary"} {
		if model.IsValidAttributeNameFormat(v) {
			t.Fatalf("%q should be invalid", v)
		}
	}
}

func TestSAMLClient_Validate_NameFormat(t *testing.T) {
	base := func(nf string) *model.SAMLClient {
		return &model.SAMLClient{
			TenantID: "tenant-a", EntityID: "sp", ACSURL: "http://sp.example.test/acs",
			AttributeMapping: map[string]model.AttributeMappingRule{
				"email": {Source: "email", NameFormat: nf},
			},
		}
	}
	if err := base("not-a-format").Validate(); err == nil {
		t.Fatal("expected Validate to reject an invalid name_format")
	}
	if err := base(model.AttrNameFormatURI).Validate(); err != nil {
		t.Fatalf("valid name_format should pass: %v", err)
	}
	// Unset (empty) must keep working so existing stored mappings validate.
	if err := base("").Validate(); err != nil {
		t.Fatalf("empty name_format should pass: %v", err)
	}
}
