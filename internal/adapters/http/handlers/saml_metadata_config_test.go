package handlers_test

// Configurable SAML metadata — the HTTP-boundary layer.
//
// These gates drive the REAL SP and IdP metadata endpoints end to end (routing →
// handler → use case → XML) and assert what the published metadata advertises when
// an operator pins a NameIDFormat per client/connection and configures an
// attribute_mapping. They reuse the fixtures and helpers of the SAML response gate
// (setupOIDCE2EEnvWithClock, metadataNameIDFormats, the fmt* format constants).
//
// The point of the M3 case is the FMN-mandated role claim: a URI-named attribute
// whose rule pins attrname-format:basic must be advertised as basic, not uri — the
// per-rule NameFormat is honoured faithfully, with no claim-URN special-casing.

import (
	"net/http"
	"testing"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/Shyntr/shyntr/internal/testsupport/samlxml"
	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

// createMetadataSAMLClient registers a SAML SP client with an explicit
// NameIDFormat (empty means unconfigured).
func createMetadataSAMLClient(t *testing.T, env *oidcE2EEnv, id, nameIDFormat string) {
	t.Helper()
	require.NoError(t, env.db.Create(&models.SAMLClientGORM{
		ID:           id,
		TenantID:     "tenant-a",
		Name:         "Metadata SP " + id,
		EntityID:     "http://sp.example.test/" + id,
		ACSURL:       "http://sp.example.test/acs",
		NameIDFormat: nameIDFormat,
		Active:       true,
	}).Error)
}

// createMetadataSAMLConnection registers a SAML connection with an attribute
// mapping and an optional pinned NameIDFormat. The IdP fields are placeholders:
// GetConnection is a plain fetch, so metadata rendering never touches them.
func createMetadataSAMLConnection(t *testing.T, env *oidcE2EEnv, id, nameIDFormat string,
	mapping map[string]model.AttributeMappingRule) {
	t.Helper()
	require.NoError(t, env.db.Create(&models.SAMLConnectionGORM{
		ID:               id,
		TenantID:         "tenant-a",
		Name:             "Metadata IdP " + id,
		IdpEntityID:      "https://idp.example.test/" + id,
		IdpSingleSignOn:  "https://idp.example.test/sso",
		IdpCertificate:   "placeholder-not-used-for-metadata",
		NameIDFormat:     nameIDFormat,
		AttributeMapping: mapping,
		Active:           true,
	}).Error)
}

// spMetadataRequestedAttributes fetches an SP metadata endpoint and returns
// whether an AttributeConsumingService is present and, if so, a map of each
// RequestedAttribute Name to its advertised NameFormat.
func spMetadataRequestedAttributes(t *testing.T, env *oidcE2EEnv, path string) (bool, map[string]string) {
	t.Helper()
	resp := serveRequest(t, env.router, http.MethodGet, path, nil, nil)
	require.Equalf(t, http.StatusOK, resp.Code, "metadata endpoint %s must return 200", path)
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(resp.Body.String()))

	acsPresent := false
	formats := make(map[string]string)
	samlxml.WalkElements(doc.Root(), func(el *etree.Element) {
		switch el.Tag {
		case "AttributeConsumingService":
			acsPresent = true
		case "RequestedAttribute":
			formats[el.SelectAttrValue("Name", "")] = el.SelectAttrValue("NameFormat", "")
		}
	})
	return acsPresent, formats
}

// M1: a client with a configured NameIDFormat -> IdP metadata advertises exactly
// that one format and nothing else. MUST have teeth.
func TestSAMLMetadataConfig_M1_IdPAdvertisesSingleConfiguredFormat(t *testing.T) {
	env := setupOIDCE2EEnvWithClock(t, e2eFixedClock)
	createMetadataSAMLClient(t, env, "m1-client", fmtUnspecified)

	formats := metadataNameIDFormats(t, env, "/t/tenant-a/saml/idp/metadata?client_id=m1-client")

	require.Equal(t, []string{fmtUnspecified}, formats,
		"a configured NameIDFormat must be advertised as the one and only IdP format")
}

// M2: a client with no configured NameIDFormat -> IdP metadata advertises the
// current default set, with persistent absent.
func TestSAMLMetadataConfig_M2_IdPDefaultSetWhenUnconfigured(t *testing.T) {
	env := setupOIDCE2EEnvWithClock(t, e2eFixedClock)
	createMetadataSAMLClient(t, env, "m2-client", "")

	formats := metadataNameIDFormats(t, env, "/t/tenant-a/saml/idp/metadata?client_id=m2-client")

	require.ElementsMatch(t, []string{fmtEmail, fmtUnspecified, fmtTransient}, formats,
		"an unconfigured client must fall back to the default set")
	require.NotContains(t, formats, fmtPersistent, "persistent must never be advertised")
}

// M3: a connection whose attribute_mapping includes a rule with an explicit
// NameFormat of basic on a URI-named attribute -> the emitted
// AttributeConsumingService lists that attribute with attrname-format:basic, not
// uri. This is the role-claim case; it is the point of the work order. MUST have
// teeth.
func TestSAMLMetadataConfig_M3_RoleClaimPinnedToBasic(t *testing.T) {
	env := setupOIDCE2EEnvWithClock(t, e2eFixedClock)
	roleURI := "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
	createMetadataSAMLConnection(t, env, "m3-conn", "", map[string]model.AttributeMappingRule{
		roleURI: {Source: "roles", Type: "string", NameFormat: model.AttrNameFormatBasic},
	})

	present, formats := spMetadataRequestedAttributes(t, env, "/t/tenant-a/saml/sp/metadata?connection_id=m3-conn")

	require.True(t, present, "a non-empty mapping must emit an AttributeConsumingService")
	require.Equal(t, model.AttrNameFormatBasic, formats[roleURI],
		"a URI-named claim pinned to basic must be advertised as attrname-format:basic, not uri")
}

// M4: a connection whose attribute_mapping relies on the heuristic -> URI-named
// attributes appear as uri.
func TestSAMLMetadataConfig_M4_HeuristicURIAttributeIsURI(t *testing.T) {
	env := setupOIDCE2EEnvWithClock(t, e2eFixedClock)
	claimURI := "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
	createMetadataSAMLConnection(t, env, "m4-conn", "", map[string]model.AttributeMappingRule{
		claimURI:  {Source: "email", Type: "string"},
		"surname": {Source: "family_name", Type: "string"},
	})

	present, formats := spMetadataRequestedAttributes(t, env, "/t/tenant-a/saml/sp/metadata?connection_id=m4-conn")

	require.True(t, present)
	require.Equal(t, model.AttrNameFormatURI, formats[claimURI],
		"a URI-named attribute with no explicit rule must use the uri heuristic")
	require.Equal(t, model.AttrNameFormatBasic, formats["surname"],
		"a plain-named attribute with no explicit rule must use basic")
}

// M5: an empty attribute_mapping -> no AttributeConsumingService is emitted.
func TestSAMLMetadataConfig_M5_EmptyMappingEmitsNoACS(t *testing.T) {
	env := setupOIDCE2EEnvWithClock(t, e2eFixedClock)
	createMetadataSAMLConnection(t, env, "m5-conn", "", nil)

	present, _ := spMetadataRequestedAttributes(t, env, "/t/tenant-a/saml/sp/metadata?connection_id=m5-conn")

	require.False(t, present, "an empty attribute_mapping must emit no AttributeConsumingService")
}

// M5b: an SP connection with a pinned NameIDFormat -> SP metadata advertises
// exactly that one format (the SP-side counterpart of M1).
func TestSAMLMetadataConfig_M5b_SPAdvertisesSingleConfiguredFormat(t *testing.T) {
	env := setupOIDCE2EEnvWithClock(t, e2eFixedClock)
	createMetadataSAMLConnection(t, env, "m5b-conn", fmtEmail, nil)

	formats := metadataNameIDFormats(t, env, "/t/tenant-a/saml/sp/metadata?connection_id=m5b-conn")

	require.Equal(t, []string{fmtEmail}, formats,
		"a connection's pinned NameIDFormat must be the one and only SP format")
	require.NotContains(t, formats, fmtPersistent)
}
