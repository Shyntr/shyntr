package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mintIDTokenWithScopes drives the full OIDC authorization-code flow for the given
// client, requesting and granting the supplied scopes, and returns the decoded ID
// token claims. It mirrors mintTenantATokenWithLoginPayload but parameterizes the
// client_id and the requested/granted scope set so a client-specific
// attribute_mapping can be exercised end-to-end at the token trust boundary.
func mintIDTokenWithScopes(t *testing.T, env *oidcE2EEnv, clientID string, loginPayload []byte,
	requestScopes []string, grantScopes []string) map[string]interface{} {
	t.Helper()

	codeVerifier := "e2e-code-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"
	codeChallenge := pkceS256Challenge(codeVerifier)
	authURL := "/t/tenant-a/oauth2/auth?client_id=" + url.QueryEscape(clientID) +
		"&response_type=code&redirect_uri=" + url.QueryEscape("http://client.localhost/callback") +
		"&scope=" + url.QueryEscape(strings.Join(requestScopes, " ")) +
		"&state=e2e-map-state&code_challenge=" + url.QueryEscape(codeChallenge) +
		"&code_challenge_method=S256"

	authResp := serveRequest(t, env.router, http.MethodGet, authURL, nil, nil)
	require.Equal(t, http.StatusFound, authResp.Code)

	loginChallenge := parseLocationQuery(t, authResp.Header().Get("Location")).Get("login_challenge")
	require.NotEmpty(t, loginChallenge)

	loginAcceptResp := serveRequest(t, env.router, http.MethodPut,
		"/admin/login/accept?login_challenge="+url.QueryEscape(loginChallenge), bytes.NewReader(loginPayload), nil)
	require.Equal(t, http.StatusOK, loginAcceptResp.Code)

	var loginAcceptBody map[string]string
	require.NoError(t, json.NewDecoder(loginAcceptResp.Body).Decode(&loginAcceptBody))
	loginResumeURLParsed, err := url.Parse(loginAcceptBody["redirect_to"])
	require.NoError(t, err)
	loginVerifier := loginResumeURLParsed.Query().Get("login_verifier")
	require.NotEmpty(t, loginVerifier)

	loginResumeResp := serveRequest(t, env.router, http.MethodGet,
		authURL+"&login_verifier="+url.QueryEscape(loginVerifier), nil, nil)
	require.Equal(t, http.StatusFound, loginResumeResp.Code)

	consentChallenge := parseLocationQuery(t, loginResumeResp.Header().Get("Location")).Get("consent_challenge")
	require.NotEmpty(t, consentChallenge)

	consentBody, err := json.Marshal(map[string]interface{}{
		"grant_scope":    grantScopes,
		"grant_audience": []string{},
		"remember":       true,
		"remember_for":   3600,
		"session":        map[string]interface{}{"tenant_id": "tenant-a"},
	})
	require.NoError(t, err)
	consentAcceptResp := serveRequest(t, env.router, http.MethodPut,
		"/admin/consent/accept?consent_challenge="+url.QueryEscape(consentChallenge), bytes.NewReader(consentBody), nil)
	require.Equal(t, http.StatusOK, consentAcceptResp.Code)

	var consentAcceptBody map[string]string
	require.NoError(t, json.NewDecoder(consentAcceptResp.Body).Decode(&consentAcceptBody))
	authResumeURLParsed, err := url.Parse(consentAcceptBody["redirect_to"])
	require.NoError(t, err)
	consentVerifier := authResumeURLParsed.Query().Get("consent_verifier")
	require.NotEmpty(t, consentVerifier)

	finalAuthResp := serveRequest(t, env.router, http.MethodGet, authURL+
		"&login_verifier="+url.QueryEscape(loginVerifier)+
		"&consent_verifier="+url.QueryEscape(consentVerifier), nil, nil)
	require.Equal(t, http.StatusSeeOther, finalAuthResp.Code)

	code := parseLocationQuery(t, finalAuthResp.Header().Get("Location")).Get("code")
	require.NotEmpty(t, code)

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("client_id", clientID)
	tokenForm.Set("code", code)
	tokenForm.Set("redirect_uri", "http://client.localhost/callback")
	tokenForm.Set("code_verifier", codeVerifier)

	tokenResp := serveRequest(t, env.router, http.MethodPost, "/t/tenant-a/oauth2/token",
		strings.NewReader(tokenForm.Encode()),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	require.Equal(t, http.StatusOK, tokenResp.Code)

	var tokenBody map[string]interface{}
	require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&tokenBody))
	idToken, _ := tokenBody["id_token"].(string)
	require.NotEmpty(t, idToken)

	return decodeIDTokenClaims(t, env, idToken)
}

func createOIDCClientWithMapping(t *testing.T, env *oidcE2EEnv, clientID string,
	scopes []string, mapping map[string]model.AttributeMappingRule) {
	t.Helper()
	require.NoError(t, env.db.Create(&models.OAuth2ClientGORM{
		ID:                      clientID,
		TenantID:                "tenant-a",
		Name:                    clientID,
		Public:                  true,
		EnforcePKCE:             true,
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{"http://client.localhost/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ResponseModes:           []string{"query"},
		Scopes:                  scopes,
		AttributeMapping:        mapping,
	}).Error)
}

func createScope(t *testing.T, env *oidcE2EEnv, name string, claims []string) {
	t.Helper()
	require.NoError(t, env.db.Create(&models.ScopeGORM{
		ID:       "scope-" + name,
		TenantID: "tenant-a",
		Name:     name,
		Claims:   pq.StringArray(claims),
		Active:   true,
	}).Error)
}

// TestOIDCE2E_ClientAttributeMapping_ScopeGated proves the OIDC client's
// attribute_mapping is applied at token generation (the missing APPLICATION step),
// and that a client-mapped target remains subject to scope gating: a target no
// granted scope opens must not reach the token.
func TestOIDCE2E_ClientAttributeMapping_ScopeGated(t *testing.T) {
	// Login context carries internal "roles"; the client mapping renames it to the
	// custom target "nevzat" via a chained source (roles is itself scope-released).
	loginPayload := []byte(`{"subject":"alice","remember":true,"remember_for":3600,"context":{"roles":["admin","dev"],"tenant_id":"tenant-a"}}`)
	mapping := map[string]model.AttributeMappingRule{
		"nevzat": {Source: "roles", Type: "string_array"},
	}

	t.Run("a_target_opened_by_scope_is_present", func(t *testing.T) {
		env := setupOIDCE2EEnv(t)
		// Scope opens BOTH the source ("roles") and the target ("nevzat").
		createScope(t, env, "rolemap", []string{"roles", "nevzat"})
		createOIDCClientWithMapping(t, env, "oidc-map-open",
			[]string{"openid", "profile", "rolemap"}, mapping)

		claims := mintIDTokenWithScopes(t, env, "oidc-map-open", loginPayload,
			[]string{"openid", "profile", "rolemap"}, []string{"openid", "profile", "rolemap"})

		// The mapped target reaches the token with the source's values.
		assert.ElementsMatch(t, []interface{}{"admin", "dev"}, claims["nevzat"])
		// The chained source itself was scope-released too (sanity on the input).
		assert.ElementsMatch(t, []interface{}{"admin", "dev"}, claims["roles"])
	})

	t.Run("b_target_not_opened_by_scope_is_absent", func(t *testing.T) {
		env := setupOIDCE2EEnv(t)
		// Scope opens only the source ("roles"), NOT the target ("nevzat").
		createScope(t, env, "rolesrc", []string{"roles"})
		createOIDCClientWithMapping(t, env, "oidc-map-gated",
			[]string{"openid", "profile", "rolesrc"}, mapping)

		claims := mintIDTokenWithScopes(t, env, "oidc-map-gated", loginPayload,
			[]string{"openid", "profile", "rolesrc"}, []string{"openid", "profile", "rolesrc"})

		// Scope gating holds: the mapped target is dropped (decision 2a).
		assert.NotContains(t, claims, "nevzat")
		// The source claim itself is still released (scope opened it).
		assert.ElementsMatch(t, []interface{}{"admin", "dev"}, claims["roles"])
	})

	t.Run("c_empty_mapping_is_a_noop", func(t *testing.T) {
		env := setupOIDCE2EEnv(t)
		createScope(t, env, "rolesrc", []string{"roles"})
		createOIDCClientWithMapping(t, env, "oidc-map-empty",
			[]string{"openid", "profile", "rolesrc"}, map[string]model.AttributeMappingRule{})

		claims := mintIDTokenWithScopes(t, env, "oidc-map-empty", loginPayload,
			[]string{"openid", "profile", "rolesrc"}, []string{"openid", "profile", "rolesrc"})

		// No mapped target appears; existing scope-released claims are unchanged.
		assert.NotContains(t, claims, "nevzat")
		assert.ElementsMatch(t, []interface{}{"admin", "dev"}, claims["roles"])
		assert.Equal(t, "alice", claims["sub"])
	})
}

func createOIDCClientWithPolicy(t *testing.T, env *oidcE2EEnv, clientID string, scopes []string,
	mapping map[string]model.AttributeMappingRule, passthrough bool, exclude []string) {
	t.Helper()
	require.NoError(t, env.db.Create(&models.OAuth2ClientGORM{
		ID:                      clientID,
		TenantID:                "tenant-a",
		Name:                    clientID,
		Public:                  true,
		EnforcePKCE:             true,
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{"http://client.localhost/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ResponseModes:           []string{"query"},
		Scopes:                  scopes,
		AttributeMapping:        mapping,
		AttributePassthrough:    passthrough,
		AttributeExclude:        exclude,
	}).Error)
}

// TestOIDCE2E_ClientPassthroughAndExclude proves passthrough + exclude at the OIDC
// CLIENT layer, and — critically — that passthrough does NOT bypass the scope-gate.
func TestOIDCE2E_ClientPassthroughAndExclude(t *testing.T) {
	loginPayload := []byte(`{"subject":"alice","remember":true,"remember_for":3600,"context":{"roles":["admin","dev"],"tenant_id":"tenant-a"}}`)
	mapping := map[string]model.AttributeMappingRule{
		"nevzat": {Source: "roles", Type: "string_array"},
	}

	// (e) SCOPE-GATE: passthrough TRUE, but the target "nevzat" is opened by NO
	// granted scope -> it must NOT appear. Passthrough must not bypass the gate.
	t.Run("e_passthrough_does_not_bypass_scope_gate", func(t *testing.T) {
		env := setupOIDCE2EEnv(t)
		createScope(t, env, "rolesrc", []string{"roles"}) // opens source only
		createOIDCClientWithPolicy(t, env, "oidc-pt-gated",
			[]string{"openid", "profile", "rolesrc"}, mapping, true, nil)

		claims := mintIDTokenWithScopes(t, env, "oidc-pt-gated", loginPayload,
			[]string{"openid", "profile", "rolesrc"}, []string{"openid", "profile", "rolesrc"})

		assert.NotContains(t, claims, "nevzat", "passthrough must NOT bypass the scope-gate")
	})

	// (b) MOVE at the client site: passthrough TRUE, target opened by scope -> the
	// mapped target appears AND the source is removed from the token.
	t.Run("b_client_move_removes_source", func(t *testing.T) {
		env := setupOIDCE2EEnv(t)
		createScope(t, env, "rolemap", []string{"roles", "nevzat"}) // opens source + target
		createOIDCClientWithPolicy(t, env, "oidc-pt-move",
			[]string{"openid", "profile", "rolemap"}, mapping, true, nil)

		claims := mintIDTokenWithScopes(t, env, "oidc-pt-move", loginPayload,
			[]string{"openid", "profile", "rolemap"}, []string{"openid", "profile", "rolemap"})

		assert.ElementsMatch(t, []interface{}{"admin", "dev"}, claims["nevzat"], "moved target must be present")
		assert.NotContains(t, claims, "roles", "source must be REMOVED at the client (move)")
	})

	// exclude at the client site (passthrough FALSE): a scope-released base claim
	// listed in exclude is removed from the token.
	t.Run("client_exclude_removes_base_claim", func(t *testing.T) {
		env := setupOIDCE2EEnv(t)
		createScope(t, env, "rolesrc", []string{"roles"})
		createOIDCClientWithPolicy(t, env, "oidc-excl",
			[]string{"openid", "profile", "rolesrc"}, map[string]model.AttributeMappingRule{}, false, []string{"roles"})

		claims := mintIDTokenWithScopes(t, env, "oidc-excl", loginPayload,
			[]string{"openid", "profile", "rolesrc"}, []string{"openid", "profile", "rolesrc"})

		assert.NotContains(t, claims, "roles", "exclude must remove the claim from the token")
	})
}
