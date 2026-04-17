package model_test

import (
	"testing"

	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// LDAPConnection.Validate()
// ---------------------------------------------------------------------------

func TestLDAPConnection_Validate(t *testing.T) {
	cases := []struct {
		name    string
		conn    model.LDAPConnection
		wantErr bool
	}{
		{
			name: "happy path",
			conn: model.LDAPConnection{
				TenantID:  "tnt",
				ServerURL: "ldap://ldap.example.com:389",
				BaseDN:    "dc=example,dc=com",
			},
			wantErr: false,
		},
		{
			name:    "missing tenant_id",
			conn:    model.LDAPConnection{ServerURL: "ldap://ldap.example.com", BaseDN: "dc=example,dc=com"},
			wantErr: true,
		},
		{
			name:    "missing server_url",
			conn:    model.LDAPConnection{TenantID: "tnt", BaseDN: "dc=example,dc=com"},
			wantErr: true,
		},
		{
			name:    "missing base_dn",
			conn:    model.LDAPConnection{TenantID: "tnt", ServerURL: "ldap://ldap.example.com"},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.conn.Validate()
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
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
		wantErr bool
	}{
		{
			name: "happy path",
			conn: model.OIDCConnection{
				TenantID:  "tnt",
				IssuerURL: "https://idp.example.com",
				ClientID:  "client-1",
			},
			wantErr: false,
		},
		{
			name:    "missing tenant_id",
			conn:    model.OIDCConnection{IssuerURL: "https://idp.example.com", ClientID: "client-1"},
			wantErr: true,
		},
		{
			name:    "missing issuer_url",
			conn:    model.OIDCConnection{TenantID: "tnt", ClientID: "client-1"},
			wantErr: true,
		},
		{
			name:    "missing client_id",
			conn:    model.OIDCConnection{TenantID: "tnt", IssuerURL: "https://idp.example.com"},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.conn.Validate()
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
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
		wantErr bool
	}{
		{
			name: "happy path",
			conn: model.SAMLConnection{
				TenantID:        "tnt",
				IdpEntityID:     "https://idp.example.com",
				IdpSingleSignOn: "https://idp.example.com/sso",
				IdpCertificate:  "-----BEGIN CERTIFICATE-----",
			},
			wantErr: false,
		},
		{
			name: "missing tenant_id",
			conn: model.SAMLConnection{
				IdpEntityID:     "https://idp.example.com",
				IdpSingleSignOn: "https://idp.example.com/sso",
				IdpCertificate:  "cert",
			},
			wantErr: true,
		},
		{
			name: "missing idp_entity_id",
			conn: model.SAMLConnection{
				TenantID:        "tnt",
				IdpSingleSignOn: "https://idp.example.com/sso",
				IdpCertificate:  "cert",
			},
			wantErr: true,
		},
		{
			name: "missing idp_sso_url",
			conn: model.SAMLConnection{
				TenantID:       "tnt",
				IdpEntityID:    "https://idp.example.com",
				IdpCertificate: "cert",
			},
			wantErr: true,
		},
		{
			name: "missing idp_certificate",
			conn: model.SAMLConnection{
				TenantID:        "tnt",
				IdpEntityID:     "https://idp.example.com",
				IdpSingleSignOn: "https://idp.example.com/sso",
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.conn.Validate()
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
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
		wantErr bool
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
			wantErr: false,
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
			wantErr: false,
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
			wantErr: true,
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
			wantErr: true,
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
			wantErr: true,
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
			wantErr: true,
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
			wantErr: true,
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
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.client.Validate()
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
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
		wantErr bool
	}{
		{
			name:    "happy path",
			tenant:  model.Tenant{Name: "my-tenant"},
			wantErr: false,
		},
		{
			name:    "missing name",
			tenant:  model.Tenant{},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.tenant.Validate()
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
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
		wantErr bool
	}{
		{
			name:    "happy path",
			scope:   model.Scope{TenantID: "tnt", Name: "openid"},
			wantErr: false,
		},
		{
			name:    "missing tenant_id",
			scope:   model.Scope{Name: "openid"},
			wantErr: true,
		},
		{
			name:    "missing name",
			scope:   model.Scope{TenantID: "tnt"},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.scope.Validate()
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
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
		wantErr bool
	}{
		{
			name: "happy path",
			wh: model.Webhook{
				Name:   "My Webhook",
				URL:    "https://hooks.example.com/event",
				Events: []string{"user.login"},
			},
			wantErr: false,
		},
		{
			name:    "missing name",
			wh:      model.Webhook{URL: "https://hooks.example.com/event", Events: []string{"user.login"}},
			wantErr: true,
		},
		{
			name:    "missing url",
			wh:      model.Webhook{Name: "hook", Events: []string{"user.login"}},
			wantErr: true,
		},
		{
			name:    "invalid url format",
			wh:      model.Webhook{Name: "hook", URL: "not-a-url", Events: []string{"user.login"}},
			wantErr: true,
		},
		{
			name:    "missing events",
			wh:      model.Webhook{Name: "hook", URL: "https://hooks.example.com/event"},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.wh.Validate()
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
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
		wantErr bool
	}{
		{
			name:    "happy path",
			log:     model.AuditLog{TenantID: "tnt", Action: "user.login"},
			wantErr: false,
		},
		{
			name:    "missing tenant_id",
			log:     model.AuditLog{Action: "user.login"},
			wantErr: true,
		},
		{
			name:    "missing action",
			log:     model.AuditLog{TenantID: "tnt"},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.log.Validate()
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
