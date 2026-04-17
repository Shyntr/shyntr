package model_test

import (
	"testing"

	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// LDAPConnection.Validate()
// ---------------------------------------------------------------------------

func TestLDAPConnection_Validate(t *testing.T) {
	cases := []struct {
		name    string
		conn    model.LDAPConnection
		wantErr string
	}{
		{
			name: "happy path",
			conn: model.LDAPConnection{
				TenantID:  "tnt",
				ServerURL: "ldap://ldap.example.com:389",
				BaseDN:    "dc=example,dc=com",
			},
			wantErr: "",
		},
		{
			name:    "missing tenant_id",
			conn:    model.LDAPConnection{ServerURL: "ldap://ldap.example.com", BaseDN: "dc=example,dc=com"},
			wantErr: "tenant_id is required",
		},
		{
			name:    "missing server_url",
			conn:    model.LDAPConnection{TenantID: "tnt", BaseDN: "dc=example,dc=com"},
			wantErr: "server_url is required",
		},
		{
			name:    "missing base_dn",
			conn:    model.LDAPConnection{TenantID: "tnt", ServerURL: "ldap://ldap.example.com"},
			wantErr: "base_dn is required",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.conn.Validate()
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tc.wantErr, err.Error())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// OIDCConnection.Validate()
// ---------------------------------------------------------------------------

func TestOIDCConnection_Validate(t *testing.T) {
	cases := []struct {
		name    string
		conn    model.OIDCConnection
		wantErr string
	}{
		{
			name: "happy path",
			conn: model.OIDCConnection{
				TenantID:  "tnt",
				IssuerURL: "https://idp.example.com",
				ClientID:  "client-1",
			},
			wantErr: "",
		},
		{
			name:    "missing tenant_id",
			conn:    model.OIDCConnection{IssuerURL: "https://idp.example.com", ClientID: "client-1"},
			wantErr: "tenant_id is required",
		},
		{
			name:    "missing issuer_url",
			conn:    model.OIDCConnection{TenantID: "tnt", ClientID: "client-1"},
			wantErr: "issuer_url is required",
		},
		{
			name:    "missing client_id",
			conn:    model.OIDCConnection{TenantID: "tnt", IssuerURL: "https://idp.example.com"},
			wantErr: "client_id is required for OIDC connections",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.conn.Validate()
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tc.wantErr, err.Error())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SAMLConnection.Validate()
// ---------------------------------------------------------------------------

func TestSAMLConnection_Validate(t *testing.T) {
	cases := []struct {
		name    string
		conn    model.SAMLConnection
		wantErr string
	}{
		{
			name: "happy path",
			conn: model.SAMLConnection{
				TenantID:        "tnt",
				IdpEntityID:     "https://idp.example.com",
				IdpSingleSignOn: "https://idp.example.com/sso",
				IdpCertificate:  "-----BEGIN CERTIFICATE-----",
			},
			wantErr: "",
		},
		{
			name: "missing tenant_id",
			conn: model.SAMLConnection{
				IdpEntityID:     "https://idp.example.com",
				IdpSingleSignOn: "https://idp.example.com/sso",
				IdpCertificate:  "cert",
			},
			wantErr: "tenant_id is required",
		},
		{
			name: "missing idp_entity_id",
			conn: model.SAMLConnection{
				TenantID:        "tnt",
				IdpSingleSignOn: "https://idp.example.com/sso",
				IdpCertificate:  "cert",
			},
			wantErr: "idp_entity_id is required",
		},
		{
			name: "missing idp_sso_url",
			conn: model.SAMLConnection{
				TenantID:       "tnt",
				IdpEntityID:    "https://idp.example.com",
				IdpCertificate: "cert",
			},
			wantErr: "idp_sso_url is required",
		},
		{
			name: "missing idp_certificate",
			conn: model.SAMLConnection{
				TenantID:        "tnt",
				IdpEntityID:     "https://idp.example.com",
				IdpSingleSignOn: "https://idp.example.com/sso",
			},
			wantErr: "idp_certificate is required",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.conn.Validate()
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tc.wantErr, err.Error())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// OAuth2Client.Validate()
// ---------------------------------------------------------------------------

func TestOAuth2Client_Validate(t *testing.T) {
	cases := []struct {
		name    string
		client  model.OAuth2Client
		wantErr string
	}{
		{
			name: "happy path public client",
			client: model.OAuth2Client{
				TenantID:                "tnt",
				Public:                  true,
				Secret:                  "",
				TokenEndpointAuthMethod: "none",
				RedirectURIs:            []string{"http://localhost/cb"},
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
			},
			wantErr: "",
		},
		{
			name: "happy path confidential client",
			client: model.OAuth2Client{
				TenantID:                "tnt",
				Public:                  false,
				Secret:                  "hashed-secret",
				TokenEndpointAuthMethod: "client_secret_basic",
				RedirectURIs:            []string{"http://localhost/cb"},
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
			},
			wantErr: "",
		},
		{
			name: "missing tenant_id",
			client: model.OAuth2Client{
				Public:                  true,
				TokenEndpointAuthMethod: "none",
				RedirectURIs:            []string{"http://localhost/cb"},
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
			},
			wantErr: "tenant_id is required",
		},
		{
			name: "prohibited grant type implicit",
			client: model.OAuth2Client{
				TenantID:                "tnt",
				Public:                  true,
				TokenEndpointAuthMethod: "none",
				RedirectURIs:            []string{"http://localhost/cb"},
				GrantTypes:              []string{"implicit"},
				ResponseTypes:           []string{"code"},
			},
			wantErr: "grant_type 'implicit' is prohibited in OAuth 2.1 standards",
		},
		{
			name: "prohibited response type token",
			client: model.OAuth2Client{
				TenantID:                "tnt",
				Public:                  true,
				TokenEndpointAuthMethod: "none",
				RedirectURIs:            []string{"http://localhost/cb"},
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"token"},
			},
			wantErr: "response_type 'token' is prohibited in OAuth 2.1 standards. Only 'code' is permitted",
		},
		{
			name: "public client with secret",
			client: model.OAuth2Client{
				TenantID:                "tnt",
				Public:                  true,
				Secret:                  "should-not-be-set",
				TokenEndpointAuthMethod: "none",
				RedirectURIs:            []string{"http://localhost/cb"},
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
			},
			wantErr: "public clients cannot have a client_secret",
		},
		{
			name: "confidential client without secret",
			client: model.OAuth2Client{
				TenantID:                "tnt",
				Public:                  false,
				Secret:                  "",
				TokenEndpointAuthMethod: "client_secret_basic",
				RedirectURIs:            []string{"http://localhost/cb"},
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
			},
			wantErr: "confidential clients must have a hashed secret",
		},
		{
			name: "missing redirect_uris",
			client: model.OAuth2Client{
				TenantID:                "tnt",
				Public:                  true,
				TokenEndpointAuthMethod: "none",
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
			},
			wantErr: "at least one redirect_uri is required",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.client.Validate()
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tc.wantErr, err.Error())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tenant.Validate()
// ---------------------------------------------------------------------------

func TestTenant_Validate(t *testing.T) {
	cases := []struct {
		name    string
		tenant  model.Tenant
		wantErr string
	}{
		{
			name:    "happy path",
			tenant:  model.Tenant{Name: "my-tenant"},
			wantErr: "",
		},
		{
			name:    "missing name",
			tenant:  model.Tenant{},
			wantErr: "tenant name cannot be empty",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.tenant.Validate()
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tc.wantErr, err.Error())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Scope.Validate()
// ---------------------------------------------------------------------------

func TestScope_Validate(t *testing.T) {
	cases := []struct {
		name    string
		scope   model.Scope
		wantErr string
	}{
		{
			name:    "happy path",
			scope:   model.Scope{TenantID: "tnt", Name: "openid"},
			wantErr: "",
		},
		{
			name:    "missing tenant_id",
			scope:   model.Scope{Name: "openid"},
			wantErr: "tenant_id is required",
		},
		{
			name:    "missing name",
			scope:   model.Scope{TenantID: "tnt"},
			wantErr: "scope name is required",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.scope.Validate()
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tc.wantErr, err.Error())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Webhook.Validate()
// ---------------------------------------------------------------------------

func TestWebhook_Validate(t *testing.T) {
	cases := []struct {
		name    string
		wh      model.Webhook
		wantErr string
	}{
		{
			name: "happy path",
			wh: model.Webhook{
				Name:   "My Webhook",
				URL:    "https://hooks.example.com/event",
				Events: []string{"user.login"},
			},
			wantErr: "",
		},
		{
			name:    "missing name",
			wh:      model.Webhook{URL: "https://hooks.example.com/event", Events: []string{"user.login"}},
			wantErr: "webhook name is required",
		},
		{
			name:    "missing url",
			wh:      model.Webhook{Name: "hook", Events: []string{"user.login"}},
			wantErr: "webhook url is required",
		},
		{
			name:    "invalid url format",
			wh:      model.Webhook{Name: "hook", URL: "not-a-url", Events: []string{"user.login"}},
			wantErr: "invalid webhook url format",
		},
		{
			name:    "missing events",
			wh:      model.Webhook{Name: "hook", URL: "https://hooks.example.com/event"},
			wantErr: "at least one event must be subscribed to",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.wh.Validate()
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tc.wantErr, err.Error())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AuditLog.Validate()
// ---------------------------------------------------------------------------

func TestAuditLog_Validate(t *testing.T) {
	cases := []struct {
		name    string
		log     model.AuditLog
		wantErr string
	}{
		{
			name:    "happy path",
			log:     model.AuditLog{TenantID: "tnt", Action: "user.login"},
			wantErr: "",
		},
		{
			name:    "missing tenant_id",
			log:     model.AuditLog{Action: "user.login"},
			wantErr: "tenant_id is required for audit logs",
		},
		{
			name:    "missing action",
			log:     model.AuditLog{TenantID: "tnt"},
			wantErr: "action is required for audit logs",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.log.Validate()
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tc.wantErr, err.Error())
			}
		})
	}
}
