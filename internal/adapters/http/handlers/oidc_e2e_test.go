package handlers_test

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/audit"
	"github.com/Shyntr/shyntr/internal/adapters/http/handlers"
	"github.com/Shyntr/shyntr/internal/adapters/iam"
	"github.com/Shyntr/shyntr/internal/adapters/persistence"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/repository"
	"github.com/Shyntr/shyntr/internal/application/mapper"
	"github.com/Shyntr/shyntr/internal/application/security"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	utils2 "github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/Shyntr/shyntr/pkg/logger"
	crewjamsaml "github.com/crewjam/saml"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

var testDBCounter atomic.Int64

type oidcE2EEnv struct {
	db      *gorm.DB
	router  *gin.Engine
	baseURL string
	cfg     *config.Config
	state   security.FederationStateProvider
	saml    usecase.SamlBuilderUseCase
}

func setupOIDCE2EEnv(t *testing.T) *oidcE2EEnv {
	t.Helper()

	gin.SetMode(gin.TestMode)
	logger.InitLogger("info")

	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:testdb_%d?mode=memory&cache=shared", testDBCounter.Add(1))), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, persistence.MigrateDB(db))

	cfg := &config.Config{
		CookieSecure:       false,
		AppSecret:          "12345678901234567890123456789012",
		BaseIssuerURL:      "http://example.test",
		DefaultTenantID:    "tenant-a",
		ExternalLoginURL:   "",
		ExternalConsentURL: "",
	}

	require.NoError(t, db.Create(&models.TenantGORM{
		ID:          "tenant-a",
		Name:        "tenant-a",
		DisplayName: "Tenant A",
	}).Error)
	require.NoError(t, db.Create(&models.TenantGORM{
		ID:          "tenant-b",
		Name:        "tenant-b",
		DisplayName: "Tenant B",
	}).Error)

	require.NoError(t, db.Create(&models.OAuth2ClientGORM{
		ID:                      "oidc-client-a",
		TenantID:                "tenant-a",
		Name:                    "OIDC Client A",
		Public:                  true,
		EnforcePKCE:             true,
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{"http://client.localhost/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ResponseModes:           []string{"query"},
		Scopes:                  []string{"openid", "profile"},
		PostLogoutRedirectURIs:  []string{"http://client.localhost/logout"},
	}).Error)
	require.NoError(t, db.Create(&models.OAuth2ClientGORM{
		ID:                      "oidc-client-b",
		TenantID:                "tenant-b",
		Name:                    "OIDC Client B",
		Public:                  true,
		EnforcePKCE:             true,
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{"http://client.localhost/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ResponseModes:           []string{"query"},
		Scopes:                  []string{"openid", "profile"},
		PostLogoutRedirectURIs:  []string{"http://client.localhost/logout"},
	}).Error)

	require.NoError(t, db.Model(&models.OutboundPolicyGORM{}).
		Where("id = ?", "global-outbound-policy-oidc-discovery").
		Updates(map[string]interface{}{
			"allowed_schemes_json":       `["http"]`,
			"allowed_host_patterns_json": `["127.0.0.1"]`,
			"block_private_ips":          false,
			"block_loopback_ips":         false,
			"block_link_local_ips":       false,
			"block_multicast_ips":        false,
			"block_localhost_names":      false,
			"disable_redirects":          true,
			"require_dns_resolve":        false,
		}).Error)

	keyRepo := repository.NewCryptoKeyRepository(db)
	keyMgr := utils2.NewKeyManager(keyRepo, cfg)
	_, _, err = keyMgr.GetActivePrivateKey(context.Background(), "sig")
	require.NoError(t, err)
	_, _, err = keyMgr.GetActivePrivateKey(context.Background(), "enc")
	require.NoError(t, err)

	fositeCfg := &fosite.Config{
		AccessTokenLifespan:            time.Hour,
		AuthorizeCodeLifespan:          10 * time.Minute,
		IDTokenLifespan:                time.Hour,
		RefreshTokenLifespan:           30 * 24 * time.Hour,
		GlobalSecret:                   []byte(cfg.AppSecret),
		IDTokenIssuer:                  cfg.BaseIssuerURL,
		SendDebugMessagesToClients:     true,
		EnforcePKCE:                    true,
		EnforcePKCEForPublicClients:    true,
		EnablePKCEPlainChallengeMethod: false,
	}

	auditLogger := audit.NewAuditLogger(db)
	policyRepo := repository.NewOutboundPolicyRepository(db)
	outboundGuard := security.NewOutboundGuard(policyRepo, cfg.SkipTLSVerify)
	requestRepo := repository.NewAuthRequestRepository(db)
	tenantRepo := repository.NewTenantRepository(db)
	clientRepo := repository.NewOAuth2ClientRepository(db)
	sessionRepo := repository.NewOAuth2SessionRepository(db)
	connRepo := repository.NewOIDCConnectionRepository(db)
	samlConnRepo := repository.NewSAMLConnectionRepository(db)
	scopeRepo := repository.NewScopeRepository(db)
	jtiRepo := repository.NewBlacklistedJTIRepository(db)
	samlReplayRepo := repository.NewSAMLReplayRepository(db)
	webhookRepo := repository.NewWebhookRepository(db)
	webhookEventRepo := repository.NewWebhookEventRepository(db)
	fositeSecretHasher := iam.NewFositeSecretHasher(fositeCfg)
	scopeUseCase := usecase.NewScopeUseCase(scopeRepo, auditLogger)
	authUseCase := usecase.NewAuthUseCase(requestRepo, auditLogger)
	tenantUseCase := usecase.NewTenantUseCase(tenantRepo, auditLogger, scopeRepo)
	clientUseCase := usecase.NewOAuth2ClientUseCase(clientRepo, connRepo, tenantRepo, auditLogger, fositeSecretHasher, keyMgr, outboundGuard, cfg)
	sessionUseCase := usecase.NewOAuth2SessionUseCase(sessionRepo, auditLogger)
	connUseCase := usecase.NewOIDCConnectionUseCase(connRepo, auditLogger, scopeUseCase, outboundGuard)
	samlClientUseCase := usecase.NewSAMLClientUseCase(repository.NewSAMLClientRepository(db), tenantRepo, auditLogger, outboundGuard)
	samlConnUseCase := usecase.NewSAMLConnectionUseCase(samlConnRepo, auditLogger, scopeUseCase, outboundGuard)
	webhookUseCase := usecase.NewWebhookUseCase(webhookRepo, webhookEventRepo, auditLogger, outboundGuard)
	provider := utils2.NewProvider(db, fositeCfg, keyMgr, clientRepo, jtiRepo)
	jwksCache := utils2.NewJWKSCache()
	stateProvider := security.NewFederationStateProvider(cfg)
	samlBuilderUseCase := usecase.NewSamlBuilderUseCase(repository.NewSAMLClientRepository(db), samlConnRepo, samlReplayRepo, keyMgr, cfg, stateProvider)

	oauthHandler := handlers.NewOAuth2Handler(provider, keyMgr, cfg, clientUseCase, authUseCase, sessionUseCase, connUseCase, tenantUseCase, scopeUseCase, jwksCache)
	adminHandler := handlers.NewAdminHandler(tenantUseCase, clientUseCase, authUseCase, cfg)
	oidcHandler := handlers.NewOIDCHandler(cfg, clientUseCase, authUseCase, connUseCase, mapper.New(), webhookUseCase, stateProvider)
	samlHandler := handlers.NewSAMLHandler(cfg, keyMgr, samlBuilderUseCase, clientUseCase, mapper.New(), authUseCase, samlConnUseCase, sessionUseCase, samlClientUseCase, clientUseCase, webhookUseCase, scopeUseCase)

	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/t/:tenant_id/.well-known/openid-configuration", oauthHandler.Discover)
	r.GET("/.well-known/openid-configuration", oauthHandler.Discover)
	r.GET("/t/:tenant_id/oauth2/auth", oauthHandler.Authorize)
	r.GET("/oauth2/auth", oauthHandler.Authorize)
	r.POST("/t/:tenant_id/oauth2/token", oauthHandler.Token)
	r.POST("/oauth2/token", oauthHandler.Token)
	r.GET("/t/:tenant_id/userinfo", oauthHandler.UserInfo)
	r.GET("/userinfo", oauthHandler.UserInfo)
	r.GET("/t/:tenant_id/oauth2/logout", oauthHandler.Logout)
	r.GET("/oauth2/logout", oauthHandler.Logout)
	r.GET("/t/:tenant_id/oidc/login/:connection_id", oidcHandler.Login)
	r.GET("/t/:tenant_id/oidc/callback", oidcHandler.Callback)
	r.GET("/t/:tenant_id/saml/login/:connection_id", samlHandler.Login)
	r.POST("/t/:tenant_id/saml/sp/acs", samlHandler.ACS)
	r.GET("/t/:tenant_id/saml/sp/slo", samlHandler.SPSLO)
	r.POST("/t/:tenant_id/saml/sp/slo", samlHandler.SPSLO)
	r.GET("/t/:tenant_id/saml/idp/slo", samlHandler.IDPSLO)
	r.POST("/t/:tenant_id/saml/idp/slo", samlHandler.IDPSLO)
	r.GET("/t/:tenant_id/saml/resume", samlHandler.ResumeSAML)

	r.GET("/admin/login", adminHandler.GetLoginRequest)
	r.PUT("/admin/login/accept", adminHandler.AcceptLoginRequest)
	r.GET("/admin/consent", adminHandler.GetConsentRequest)
	r.PUT("/admin/consent/accept", adminHandler.AcceptConsentRequest)

	cfg.ExternalLoginURL = cfg.BaseIssuerURL + "/admin/login"
	cfg.ExternalConsentURL = cfg.BaseIssuerURL + "/admin/consent"

	return &oidcE2EEnv{db: db, router: r, baseURL: cfg.BaseIssuerURL, cfg: cfg, state: stateProvider, saml: samlBuilderUseCase}
}

func parseLocationQuery(t *testing.T, loc string) url.Values {
	t.Helper()
	parsed, err := url.Parse(loc)
	require.NoError(t, err)
	return parsed.Query()
}

func serveRequest(t *testing.T, router http.Handler, method, target string, body io.Reader, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, body)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func pkceS256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func createSAMLConnectionFixture(t *testing.T, db *gorm.DB, tenantID, connectionID, entityID, ssoURL, certPEM string) {
	t.Helper()
	require.NoError(t, db.Create(&models.SAMLConnectionGORM{
		ID:              connectionID,
		TenantID:        tenantID,
		Name:            "SAML Federation Connection",
		IdpEntityID:     entityID,
		IdpSingleSignOn: ssoURL,
		IdpCertificate:  certPEM,
		Active:          true,
	}).Error)
}

func createSAMLClientFixture(t *testing.T, db *gorm.DB, tenantID, clientID, entityID, sloURL, certPEM string) {
	t.Helper()
	require.NoError(t, db.Create(&models.SAMLClientGORM{
		ID:            clientID,
		TenantID:      tenantID,
		Name:          "SAML Client " + tenantID,
		EntityID:      entityID,
		ACSURL:        "http://sp.example.test/acs",
		SLOURL:        sloURL,
		SPCertificate: certPEM,
		AllowedScopes: []string{"openid", "profile"},
		Active:        true,
	}).Error)
}

func extractRelayStateAndAuthnRequest(t *testing.T, loginResp *httptest.ResponseRecorder) (string, *crewjamsaml.AuthnRequest) {
	t.Helper()
	if loginResp.Code == http.StatusFound {
		loc := loginResp.Header().Get("Location")
		require.NotEmpty(t, loc)
		query := parseLocationQuery(t, loc)
		relayState := query.Get("RelayState")
		samlReq := strings.ReplaceAll(query.Get("SAMLRequest"), " ", "+")
		require.NotEmpty(t, relayState)
		require.NotEmpty(t, samlReq)
		xmlBytes, err := base64.StdEncoding.DecodeString(samlReq)
		require.NoError(t, err)
		flater := flate.NewReader(bytes.NewReader(xmlBytes))
		inflated, inflateErr := io.ReadAll(flater)
		require.NoError(t, inflateErr)
		require.NoError(t, flater.Close())
		var req crewjamsaml.AuthnRequest
		require.NoError(t, xml.Unmarshal(inflated, &req))
		return relayState, &req
	}
	require.FailNow(t, "unsupported SAML login response", "expected redirect binding")
	return "", nil
}

func extractRelayStateAndLogoutRequest(t *testing.T, logoutResp *httptest.ResponseRecorder) (string, *crewjamsaml.LogoutRequest) {
	t.Helper()
	require.Equal(t, http.StatusFound, logoutResp.Code)
	loc := logoutResp.Header().Get("Location")
	require.NotEmpty(t, loc)
	query := parseLocationQuery(t, loc)
	relayState := query.Get("RelayState")
	samlReq := strings.ReplaceAll(query.Get("SAMLRequest"), " ", "+")
	require.NotEmpty(t, relayState)
	require.NotEmpty(t, samlReq)
	xmlBytes, err := base64.StdEncoding.DecodeString(samlReq)
	require.NoError(t, err)
	flater := flate.NewReader(bytes.NewReader(xmlBytes))
	inflated, inflateErr := io.ReadAll(flater)
	require.NoError(t, inflateErr)
	require.NoError(t, flater.Close())
	var req crewjamsaml.LogoutRequest
	require.NoError(t, xml.Unmarshal(inflated, &req))
	return relayState, &req
}

func buildSAMLResponse(t *testing.T, env *oidcE2EEnv, authReq *crewjamsaml.AuthnRequest, relayState, tenantID string) string {
	t.Helper()
	sp := &model.SAMLClient{
		EntityID:      authReq.Issuer.Value,
		ACSURL:        authReq.AssertionConsumerServiceURL,
		SignResponse:  true,
		SignAssertion: true,
		Active:        true,
		TenantID:      tenantID,
		Name:          "E2E SP",
	}
	userAttrs := map[string]interface{}{
		"sub":       "alice",
		"email":     "alice@example.com",
		"tenant_id": tenantID,
	}
	htmlForm, err := env.saml.GenerateSAMLResponse(context.Background(), tenantID, authReq, sp, userAttrs, relayState)
	require.NoError(t, err)
	require.Contains(t, htmlForm, "SAMLResponse")
	return htmlForm
}

func extractFormField(t *testing.T, htmlBody, field string) string {
	t.Helper()
	start := strings.Index(htmlBody, `name="`+field+`" value="`)
	require.NotEqual(t, -1, start)
	start += len(`name="` + field + `" value="`)
	end := strings.Index(htmlBody[start:], `"`)
	require.NotEqual(t, -1, end)
	return htmlBody[start : start+end]
}

func tamperQueryParamValue(t *testing.T, rawURL, param string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)
	query := parsed.Query()
	value := query.Get(param)
	require.NotEmpty(t, value)
	query.Set(param, value[:len(value)-1]+"A")
	parsed.RawQuery = strings.ReplaceAll(query.Encode(), "+", "%20")
	return parsed.String()
}

func signSAMLRedirectURL(t *testing.T, rawURL string, key *rsa.PrivateKey) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)
	query := parsed.Query()
	sigAlg := "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	query.Set("SigAlg", sigAlg)

	signString := "SAMLRequest=" + url.QueryEscape(query.Get("SAMLRequest"))
	if rs := query.Get("RelayState"); rs != "" {
		signString += "&RelayState=" + url.QueryEscape(rs)
	}
	signString += "&SigAlg=" + url.QueryEscape(sigAlg)

	hasher := crypto.SHA256.New()
	hasher.Write([]byte(signString))
	hashed := hasher.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed)
	require.NoError(t, err)
	query.Set("Signature", base64.StdEncoding.EncodeToString(signature))
	parsed.RawQuery = strings.ReplaceAll(query.Encode(), "+", "%20")
	return parsed.String()
}

type fakeOIDCProvider struct {
	srv      *httptest.Server
	issuer   string
	key      *rsa.PrivateKey
	userInfo map[string]interface{}
	mu       sync.Mutex
	nonce    string
}

func newFakeOIDCProvider(t *testing.T, db *gorm.DB) *fakeOIDCProvider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	f := &fakeOIDCProvider{
		key: key,
		userInfo: map[string]interface{}{
			"sub":       "alice",
			"email":     "alice@example.com",
			"tenant_id": "tenant-a",
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                 f.issuer,
			"authorization_endpoint": f.issuer + "/authorize",
			"token_endpoint":         f.issuer + "/token",
			"userinfo_endpoint":      f.issuer + "/userinfo",
			"jwks_uri":               f.issuer + "/jwks",
			"end_session_endpoint":   f.issuer + "/logout",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		require.NotEmpty(t, r.PostForm.Get("code"))
		require.NotEmpty(t, r.PostForm.Get("code_verifier"))

		f.mu.Lock()
		nonce := f.nonce
		f.mu.Unlock()
		require.NotEmpty(t, nonce)

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, nil)
		require.NoError(t, err)

		idToken, err := jwt.Signed(signer).Claims(jwt.Claims{
			Subject:   "alice",
			Issuer:    f.issuer,
			Audience:  jwt.Audience{"oidc-client-a"},
			Expiry:    jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		}).Claims(map[string]interface{}{
			"nonce": nonce,
		}).Serialize()
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "fake-access-token",
			"token_type":   "Bearer",
			"expires_in":   300,
			"id_token":     idToken,
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		require.NotEmpty(t, auth)
		require.True(t, strings.HasPrefix(auth, "Bearer "))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.userInfo)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{
				Key:       &f.key.PublicKey,
				Use:       "sig",
				Algorithm: string(jose.RS256),
			}},
		})
	})

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	f.srv = httptest.NewUnstartedServer(mux)
	f.srv.Listener = listener
	f.srv.Start()
	f.issuer = f.srv.URL

	issuerURL, err := url.Parse(f.issuer)
	require.NoError(t, err)
	_, portStr, err := net.SplitHostPort(issuerURL.Host)
	require.NoError(t, err)
	require.NoError(t, db.Model(&models.OutboundPolicyGORM{}).
		Where("id = ?", "global-outbound-policy-oidc-discovery").
		Updates(map[string]interface{}{
			"allowed_schemes_json":       `["http"]`,
			"allowed_host_patterns_json": `["127.0.0.1"]`,
			"allowed_ports_json":         fmt.Sprintf(`[%s]`, portStr),
			"block_private_ips":          false,
			"block_loopback_ips":         false,
			"block_link_local_ips":       false,
			"block_multicast_ips":        false,
			"block_localhost_names":      false,
			"disable_redirects":          true,
			"require_dns_resolve":        false,
		}).Error)
	return f
}

func (f *fakeOIDCProvider) Close() {
	if f.srv != nil {
		f.srv.Close()
	}
}

func createOIDCFederationConnection(t *testing.T, db *gorm.DB, tenantID, connectionID, issuerURL string) {
	t.Helper()
	require.NoError(t, db.Create(&models.OIDCConnectionGORM{
		ID:           connectionID,
		TenantID:     tenantID,
		Name:         "OIDC Federation Connection",
		IssuerURL:    issuerURL,
		ClientID:     "oidc-client-a",
		ClientSecret: "",
		Scopes:       []string{"openid", "profile", "email"},
		Active:       true,
	}).Error)
}

func extractLoginVerifier(t *testing.T, redirectURL string) string {
	t.Helper()
	parsed, err := url.Parse(redirectURL)
	require.NoError(t, err)
	return parsed.Query().Get("login_verifier")
}

func mintTenantAToken(t *testing.T, env *oidcE2EEnv) (code string, accessToken string, idToken string) {
	t.Helper()

	codeVerifier := "e2e-code-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"
	codeChallenge := pkceS256Challenge(codeVerifier)
	authURL := "/t/tenant-a/oauth2/auth?client_id=oidc-client-a&response_type=code&redirect_uri=" +
		url.QueryEscape("http://client.localhost/callback") +
		"&scope=openid%20profile&state=e2e-state&code_challenge=" + url.QueryEscape(codeChallenge) +
		"&code_challenge_method=S256"

	authResp := serveRequest(t, env.router, http.MethodGet, authURL, nil, nil)
	require.Equal(t, http.StatusFound, authResp.Code)

	loginLoc := authResp.Header().Get("Location")
	loginQuery := parseLocationQuery(t, loginLoc)
	loginChallenge := loginQuery.Get("login_challenge")
	require.NotEmpty(t, loginChallenge)

	loginPayload := []byte(`{"subject":"alice","remember":true,"remember_for":3600,"context":{"email":"alice@example.com","tenant_id":"tenant-a"}}`)
	loginAcceptResp := serveRequest(t, env.router, http.MethodPut, "/admin/login/accept?login_challenge="+url.QueryEscape(loginChallenge), bytes.NewReader(loginPayload), nil)
	require.Equal(t, http.StatusOK, loginAcceptResp.Code)

	var loginAcceptBody map[string]string
	require.NoError(t, json.NewDecoder(loginAcceptResp.Body).Decode(&loginAcceptBody))
	loginResumeURL := loginAcceptBody["redirect_to"]
	require.NotEmpty(t, loginResumeURL)
	loginResumeURLParsed, err := url.Parse(loginResumeURL)
	require.NoError(t, err)
	loginVerifier := loginResumeURLParsed.Query().Get("login_verifier")
	require.NotEmpty(t, loginVerifier)

	loginResumeResp := serveRequest(t, env.router, http.MethodGet, authURL+"&login_verifier="+url.QueryEscape(loginVerifier), nil, nil)
	require.Equal(t, http.StatusFound, loginResumeResp.Code)

	consentLoc := loginResumeResp.Header().Get("Location")
	consentQuery := parseLocationQuery(t, consentLoc)
	consentChallenge := consentQuery.Get("consent_challenge")
	require.NotEmpty(t, consentChallenge)

	consentPayload := []byte(`{"grant_scope":["openid","profile"],"grant_audience":[],"remember":true,"remember_for":3600,"session":{"tenant_id":"tenant-a"}}`)
	consentAcceptResp := serveRequest(t, env.router, http.MethodPut, "/admin/consent/accept?consent_challenge="+url.QueryEscape(consentChallenge), bytes.NewReader(consentPayload), nil)
	require.Equal(t, http.StatusOK, consentAcceptResp.Code)

	var consentAcceptBody map[string]string
	require.NoError(t, json.NewDecoder(consentAcceptResp.Body).Decode(&consentAcceptBody))
	authResumeURL := consentAcceptBody["redirect_to"]
	require.NotEmpty(t, authResumeURL)
	authResumeURLParsed, err := url.Parse(authResumeURL)
	require.NoError(t, err)
	consentVerifier := authResumeURLParsed.Query().Get("consent_verifier")
	require.NotEmpty(t, consentVerifier)

	finalAuthResp := serveRequest(t, env.router, http.MethodGet, authURL+
		"&login_verifier="+url.QueryEscape(loginVerifier)+
		"&consent_verifier="+url.QueryEscape(consentVerifier), nil, nil)
	require.Equal(t, http.StatusSeeOther, finalAuthResp.Code)

	callbackLoc := finalAuthResp.Header().Get("Location")
	callbackParsed, err := url.Parse(callbackLoc)
	require.NoError(t, err)
	callbackQuery := parseLocationQuery(t, callbackLoc)
	code = callbackQuery.Get("code")
	if code == "" && callbackParsed.Fragment != "" {
		fragmentQuery, fragErr := url.ParseQuery(callbackParsed.Fragment)
		require.NoError(t, fragErr)
		code = fragmentQuery.Get("code")
	}
	require.NotEmpty(t, code)

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("client_id", "oidc-client-a")
	tokenForm.Set("code", code)
	tokenForm.Set("redirect_uri", "http://client.localhost/callback")
	tokenForm.Set("code_verifier", codeVerifier)

	tokenResp := serveRequest(t, env.router, http.MethodPost, "/t/tenant-a/oauth2/token", strings.NewReader(tokenForm.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	require.Equal(t, http.StatusOK, tokenResp.Code)

	var tokenBody map[string]interface{}
	require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&tokenBody))
	accessToken, _ = tokenBody["access_token"].(string)
	idToken, _ = tokenBody["id_token"].(string)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, idToken)

	return code, accessToken, idToken
}

func startOIDCAuthChallenge(t *testing.T, env *oidcE2EEnv, tenantID, clientID string) (authURL string, loginChallenge string, codeVerifier string) {
	t.Helper()
	codeVerifier = "e2e-code-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"
	codeChallenge := pkceS256Challenge(codeVerifier)
	authURL = "/t/" + tenantID + "/oauth2/auth?client_id=" + url.QueryEscape(clientID) +
		"&response_type=code&redirect_uri=" + url.QueryEscape("http://client.localhost/callback") +
		"&scope=openid%20profile&state=e2e-saml-state&code_challenge=" + url.QueryEscape(codeChallenge) +
		"&code_challenge_method=S256"
	authResp := serveRequest(t, env.router, http.MethodGet, authURL, nil, nil)
	require.Equal(t, http.StatusFound, authResp.Code)
	loginChallenge = parseLocationQuery(t, authResp.Header().Get("Location")).Get("login_challenge")
	require.NotEmpty(t, loginChallenge)
	return authURL, loginChallenge, codeVerifier
}

func TestOIDCE2E_CoreFlow(t *testing.T) {
	env := setupOIDCE2EEnv(t)

	discoveryResp := serveRequest(t, env.router, http.MethodGet, "/t/tenant-a/.well-known/openid-configuration", nil, nil)
	require.Equal(t, http.StatusOK, discoveryResp.Code)

	var discovery map[string]interface{}
	require.NoError(t, json.NewDecoder(discoveryResp.Body).Decode(&discovery))
	assert.Equal(t, env.baseURL+"/t/tenant-a", discovery["issuer"])
	assert.Equal(t, env.baseURL+"/t/tenant-a/oauth2/auth", discovery["authorization_endpoint"])
	assert.Equal(t, env.baseURL+"/t/tenant-a/oauth2/token", discovery["token_endpoint"])
	assert.Equal(t, env.baseURL+"/t/tenant-a/userinfo", discovery["userinfo_endpoint"])
	assert.Equal(t, env.baseURL+"/t/tenant-a/oauth2/logout", discovery["end_session_endpoint"])

	_, accessToken, idToken := mintTenantAToken(t, env)

	userInfoResp := serveRequest(t, env.router, http.MethodGet, "/t/tenant-a/userinfo", nil, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	require.Equal(t, http.StatusOK, userInfoResp.Code)

	userInfoBody, err := io.ReadAll(userInfoResp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(userInfoBody), `"sub":"alice"`)
	assert.Contains(t, string(userInfoBody), `"tenant_id":"tenant-a"`)

	logoutURL := "/t/tenant-a/oauth2/logout?id_token_hint=" + url.QueryEscape(idToken) +
		"&post_logout_redirect_uri=" + url.QueryEscape("http://client.localhost/logout") +
		"&state=logout-state"
	logoutResp := serveRequest(t, env.router, http.MethodGet, logoutURL, nil, nil)
	require.Equal(t, http.StatusFound, logoutResp.Code)

	logoutLoc := logoutResp.Header().Get("Location")
	assert.Equal(t, "http://client.localhost/logout?state=logout-state", logoutLoc)
}

func TestOIDCE2E_FederationCallback_ResumesOriginalFlow(t *testing.T) {
	env := setupOIDCE2EEnv(t)
	provider := newFakeOIDCProvider(t, env.db)
	defer provider.Close()

	createOIDCFederationConnection(t, env.db, "tenant-a", "oidc-federation-a", provider.issuer)

	codeVerifier := "e2e-code-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"
	authURL := "/t/tenant-a/oauth2/auth?client_id=oidc-client-a&response_type=code&redirect_uri=" +
		url.QueryEscape("http://client.localhost/callback") +
		"&scope=openid%20profile&state=e2e-fed-state&code_challenge=" + url.QueryEscape(pkceS256Challenge(codeVerifier)) +
		"&code_challenge_method=S256"

	authResp := serveRequest(t, env.router, http.MethodGet, authURL, nil, nil)
	require.Equal(t, http.StatusFound, authResp.Code)

	loginLoc := authResp.Header().Get("Location")
	loginQuery := parseLocationQuery(t, loginLoc)
	loginChallenge := loginQuery.Get("login_challenge")
	require.NotEmpty(t, loginChallenge)

	loginResp := serveRequest(t, env.router, http.MethodGet,
		"/t/tenant-a/oidc/login/oidc-federation-a?login_challenge="+url.QueryEscape(loginChallenge),
		nil, nil)
	require.Equal(t, http.StatusFound, loginResp.Code)

	providerAuthLoc := loginResp.Header().Get("Location")
	providerAuthQuery := parseLocationQuery(t, providerAuthLoc)
	provider.mu.Lock()
	provider.nonce = providerAuthQuery.Get("nonce")
	provider.mu.Unlock()
	require.NotEmpty(t, providerAuthQuery.Get("state"))

	callbackCookie := strings.Split(loginResp.Header().Get("Set-Cookie"), ";")[0]
	callbackResp := serveRequest(t, env.router, http.MethodGet,
		"/t/tenant-a/oidc/callback?code="+url.QueryEscape("external-auth-code")+"&state="+url.QueryEscape(providerAuthQuery.Get("state")),
		nil,
		map[string]string{"Cookie": callbackCookie},
	)
	require.Equal(t, http.StatusFound, callbackResp.Code)

	resumeURL := callbackResp.Header().Get("Location")
	require.NotEmpty(t, resumeURL)
	loginVerifier := extractLoginVerifier(t, resumeURL)
	require.NotEmpty(t, loginVerifier)

	resumeResp := serveRequest(t, env.router, http.MethodGet, authURL+"&login_verifier="+url.QueryEscape(loginVerifier), nil, nil)
	require.Equal(t, http.StatusFound, resumeResp.Code)

	consentLoc := resumeResp.Header().Get("Location")
	consentQuery := parseLocationQuery(t, consentLoc)
	consentChallenge := consentQuery.Get("consent_challenge")
	require.NotEmpty(t, consentChallenge)

	consentPayload := []byte(`{"grant_scope":["openid","profile","email"],"grant_audience":[],"remember":true,"remember_for":3600,"session":{"tenant_id":"tenant-a"}}`)
	consentAcceptResp := serveRequest(t, env.router, http.MethodPut, "/admin/consent/accept?consent_challenge="+url.QueryEscape(consentChallenge), bytes.NewReader(consentPayload), nil)
	require.Equal(t, http.StatusOK, consentAcceptResp.Code)

	var consentAcceptBody map[string]string
	require.NoError(t, json.NewDecoder(consentAcceptResp.Body).Decode(&consentAcceptBody))
	finalAuthURL := consentAcceptBody["redirect_to"]
	require.NotEmpty(t, finalAuthURL)

	finalAuthResp := serveRequest(t, env.router, http.MethodGet, finalAuthURL, nil, nil)
	require.Equal(t, http.StatusSeeOther, finalAuthResp.Code)

	callbackLoc := finalAuthResp.Header().Get("Location")
	callbackQuery := parseLocationQuery(t, callbackLoc)
	code := callbackQuery.Get("code")
	require.NotEmpty(t, code)

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("client_id", "oidc-client-a")
	tokenForm.Set("code", code)
	tokenForm.Set("redirect_uri", "http://client.localhost/callback")
	tokenForm.Set("code_verifier", codeVerifier)

	tokenResp := serveRequest(t, env.router, http.MethodPost, "/t/tenant-a/oauth2/token", strings.NewReader(tokenForm.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	require.Equal(t, http.StatusOK, tokenResp.Code)

	var tokenBody map[string]interface{}
	require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&tokenBody))
	accessToken, _ := tokenBody["access_token"].(string)
	require.NotEmpty(t, accessToken)

	userInfoResp := serveRequest(t, env.router, http.MethodGet, "/t/tenant-a/userinfo", nil, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	require.Equal(t, http.StatusOK, userInfoResp.Code)
	assert.Contains(t, userInfoResp.Body.String(), `"sub":"alice"`)
}

func TestOIDCE2E_FederationCallback_RejectsMissingOrInvalidState(t *testing.T) {
	env := setupOIDCE2EEnv(t)
	provider := newFakeOIDCProvider(t, env.db)
	defer provider.Close()

	createOIDCFederationConnection(t, env.db, "tenant-a", "oidc-federation-a", provider.issuer)

	authResp := serveRequest(t, env.router, http.MethodGet,
		"/t/tenant-a/oauth2/auth?client_id=oidc-client-a&response_type=code&redirect_uri="+
			url.QueryEscape("http://client.localhost/callback")+
			"&scope=openid%20profile&state=e2e-fed-state&code_challenge="+url.QueryEscape(pkceS256Challenge("e2e-code-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"))+
			"&code_challenge_method=S256",
		nil, nil)
	require.Equal(t, http.StatusFound, authResp.Code)

	loginChallenge := parseLocationQuery(t, authResp.Header().Get("Location")).Get("login_challenge")
	require.NotEmpty(t, loginChallenge)

	loginResp := serveRequest(t, env.router, http.MethodGet,
		"/t/tenant-a/oidc/login/oidc-federation-a?login_challenge="+url.QueryEscape(loginChallenge),
		nil, nil)
	require.Equal(t, http.StatusFound, loginResp.Code)

	cases := []struct {
		name  string
		query string
		code  int
	}{
		{name: "missing state", query: "?code=external-auth-code", code: http.StatusBadRequest},
		{name: "invalid state", query: "?code=external-auth-code&state=garbage-state", code: http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := serveRequest(t, env.router, http.MethodGet, "/t/tenant-a/oidc/callback"+tc.query, nil, map[string]string{
				"Cookie": strings.Split(loginResp.Header().Get("Set-Cookie"), ";")[0],
			})
			require.Equal(t, tc.code, resp.Code)
		})
	}
}

func TestOIDCE2E_FederationCallback_RejectsCrossTenantStateReuse(t *testing.T) {
	env := setupOIDCE2EEnv(t)
	provider := newFakeOIDCProvider(t, env.db)
	defer provider.Close()

	createOIDCFederationConnection(t, env.db, "tenant-a", "oidc-federation-a", provider.issuer)

	authResp := serveRequest(t, env.router, http.MethodGet,
		"/t/tenant-a/oauth2/auth?client_id=oidc-client-a&response_type=code&redirect_uri="+
			url.QueryEscape("http://client.localhost/callback")+
			"&scope=openid%20profile&state=e2e-fed-state&code_challenge="+url.QueryEscape(pkceS256Challenge("e2e-code-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"))+
			"&code_challenge_method=S256",
		nil, nil)
	require.Equal(t, http.StatusFound, authResp.Code)

	loginChallenge := parseLocationQuery(t, authResp.Header().Get("Location")).Get("login_challenge")
	require.NotEmpty(t, loginChallenge)

	loginResp := serveRequest(t, env.router, http.MethodGet,
		"/t/tenant-a/oidc/login/oidc-federation-a?login_challenge="+url.QueryEscape(loginChallenge),
		nil, nil)
	require.Equal(t, http.StatusFound, loginResp.Code)

	providerAuthQuery := parseLocationQuery(t, loginResp.Header().Get("Location"))
	provider.mu.Lock()
	provider.nonce = providerAuthQuery.Get("nonce")
	provider.mu.Unlock()

	resp := serveRequest(t, env.router, http.MethodGet,
		"/t/tenant-b/oidc/callback?code="+url.QueryEscape("external-auth-code")+"&state="+url.QueryEscape(providerAuthQuery.Get("state")),
		nil, map[string]string{"Cookie": strings.Split(loginResp.Header().Get("Set-Cookie"), ";")[0]},
	)
	require.Equal(t, http.StatusForbidden, resp.Code)
	assert.Contains(t, resp.Body.String(), "access_denied")
}

func TestOIDCE2E_SAMLACS_ResumesOriginalFlow(t *testing.T) {
	env := setupOIDCE2EEnv(t)
	idp, err := env.saml.GetIdentityProvider(context.Background(), "tenant-a")
	require.NoError(t, err)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idp.Certificate.Raw}))
	createSAMLConnectionFixture(t, env.db, "tenant-a", "saml-conn-a", idp.MetadataURL.String(), "http://saml-idp.local/sso", certPEM)

	authURL, loginChallenge, _ := startOIDCAuthChallenge(t, env, "tenant-a", "oidc-client-a")

	loginResp := serveRequest(t, env.router, http.MethodGet, "/t/tenant-a/saml/login/saml-conn-a?login_challenge="+url.QueryEscape(loginChallenge), nil, nil)
	require.Equal(t, http.StatusFound, loginResp.Code)
	relayState, authReq := extractRelayStateAndAuthnRequest(t, loginResp)
	samlHTML := buildSAMLResponse(t, env, authReq, relayState, "tenant-a")
	samlResponse := extractFormField(t, samlHTML, "SAMLResponse")
	relayStateOut := extractFormField(t, samlHTML, "RelayState")

	acsResp := serveRequest(t, env.router, http.MethodPost, "/t/tenant-a/saml/sp/acs", strings.NewReader(url.Values{
		"SAMLResponse": {samlResponse},
		"RelayState":   {relayStateOut},
	}.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Cookie":       strings.Split(loginResp.Header().Get("Set-Cookie"), ";")[0],
	})
	require.Equal(t, http.StatusFound, acsResp.Code)

	resumeURL := acsResp.Header().Get("Location")
	loginVerifier := extractLoginVerifier(t, resumeURL)
	require.NotEmpty(t, loginVerifier)

	resumeResp := serveRequest(t, env.router, http.MethodGet, authURL+"&login_verifier="+url.QueryEscape(loginVerifier), nil, nil)
	require.Equal(t, http.StatusFound, resumeResp.Code)
	consentChallenge := parseLocationQuery(t, resumeResp.Header().Get("Location")).Get("consent_challenge")
	require.NotEmpty(t, consentChallenge)

	consentPayload := []byte(`{"grant_scope":["openid","profile"],"grant_audience":[],"remember":true,"remember_for":3600,"session":{"tenant_id":"tenant-a"}}`)
	consentAcceptResp := serveRequest(t, env.router, http.MethodPut, "/admin/consent/accept?consent_challenge="+url.QueryEscape(consentChallenge), bytes.NewReader(consentPayload), nil)
	require.Equal(t, http.StatusOK, consentAcceptResp.Code)

	var consentAcceptBody map[string]string
	require.NoError(t, json.NewDecoder(consentAcceptResp.Body).Decode(&consentAcceptBody))
	finalAuthURL := consentAcceptBody["redirect_to"]
	require.NotEmpty(t, finalAuthURL)

	finalAuthResp := serveRequest(t, env.router, http.MethodGet, finalAuthURL, nil, nil)
	require.Equal(t, http.StatusSeeOther, finalAuthResp.Code)
	tokenCode := parseLocationQuery(t, finalAuthResp.Header().Get("Location")).Get("code")
	require.NotEmpty(t, tokenCode)

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("client_id", "oidc-client-a")
	tokenForm.Set("code", tokenCode)
	tokenForm.Set("redirect_uri", "http://client.localhost/callback")
	tokenForm.Set("code_verifier", "e2e-code-verifier-0123456789-abcdefghijklmnopqrstuvwxyz")

	tokenResp := serveRequest(t, env.router, http.MethodPost, "/t/tenant-a/oauth2/token", strings.NewReader(tokenForm.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	require.Equal(t, http.StatusOK, tokenResp.Code)
}

func TestOIDCE2E_SAMLACS_RejectsMissingInvalidRelayStateAndCrossTenant(t *testing.T) {
	env := setupOIDCE2EEnv(t)
	idp, err := env.saml.GetIdentityProvider(context.Background(), "tenant-a")
	require.NoError(t, err)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idp.Certificate.Raw}))
	createSAMLConnectionFixture(t, env.db, "tenant-a", "saml-conn-a", idp.MetadataURL.String(), "http://saml-idp.local/sso", certPEM)

	_, loginChallenge, _ := startOIDCAuthChallenge(t, env, "tenant-a", "oidc-client-a")
	loginResp := serveRequest(t, env.router, http.MethodGet, "/t/tenant-a/saml/login/saml-conn-a?login_challenge="+url.QueryEscape(loginChallenge), nil, nil)
	require.Equal(t, http.StatusFound, loginResp.Code)
	relayState, authReq := extractRelayStateAndAuthnRequest(t, loginResp)
	samlHTML := buildSAMLResponse(t, env, authReq, relayState, "tenant-a")
	samlResponse := extractFormField(t, samlHTML, "SAMLResponse")

	missingRelayResp := serveRequest(t, env.router, http.MethodPost, "/t/tenant-a/saml/sp/acs", strings.NewReader(url.Values{
		"SAMLResponse": {samlResponse},
	}.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Cookie":       strings.Split(loginResp.Header().Get("Set-Cookie"), ";")[0],
	})
	require.Equal(t, http.StatusBadRequest, missingRelayResp.Code)
	assert.Contains(t, missingRelayResp.Body.String(), "RelayState")

	invalidRelayResp := serveRequest(t, env.router, http.MethodPost, "/t/tenant-a/saml/sp/acs", strings.NewReader(url.Values{
		"SAMLResponse": {samlResponse},
		"RelayState":   {"invalid-relay-state"},
	}.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Cookie":       strings.Split(loginResp.Header().Get("Set-Cookie"), ";")[0],
	})
	require.Equal(t, http.StatusForbidden, invalidRelayResp.Code)
	assert.Contains(t, invalidRelayResp.Body.String(), "access_denied")

	crossTenantResp := serveRequest(t, env.router, http.MethodPost, "/t/tenant-b/saml/sp/acs", strings.NewReader(url.Values{
		"SAMLResponse": {samlResponse},
		"RelayState":   {relayState},
	}.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Cookie":       strings.Split(loginResp.Header().Get("Set-Cookie"), ";")[0],
	})
	require.Equal(t, http.StatusForbidden, crossTenantResp.Code)
	assert.Contains(t, crossTenantResp.Body.String(), "access_denied")
}

func TestOIDCE2E_SAMLACS_RejectsReplay(t *testing.T) {
	env := setupOIDCE2EEnv(t)
	idp, err := env.saml.GetIdentityProvider(context.Background(), "tenant-a")
	require.NoError(t, err)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idp.Certificate.Raw}))
	createSAMLConnectionFixture(t, env.db, "tenant-a", "saml-conn-a", idp.MetadataURL.String(), "http://saml-idp.local/sso", certPEM)

	_, loginChallenge, _ := startOIDCAuthChallenge(t, env, "tenant-a", "oidc-client-a")
	loginResp := serveRequest(t, env.router, http.MethodGet, "/t/tenant-a/saml/login/saml-conn-a?login_challenge="+url.QueryEscape(loginChallenge), nil, nil)
	require.Equal(t, http.StatusFound, loginResp.Code)
	relayState, authReq := extractRelayStateAndAuthnRequest(t, loginResp)
	samlHTML := buildSAMLResponse(t, env, authReq, relayState, "tenant-a")
	samlResponse := extractFormField(t, samlHTML, "SAMLResponse")

	postBody := url.Values{
		"SAMLResponse": {samlResponse},
		"RelayState":   {relayState},
	}.Encode()
	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Cookie":       strings.Split(loginResp.Header().Get("Set-Cookie"), ";")[0],
	}

	firstResp := serveRequest(t, env.router, http.MethodPost, "/t/tenant-a/saml/sp/acs", strings.NewReader(postBody), headers)
	require.Equal(t, http.StatusFound, firstResp.Code)

	secondResp := serveRequest(t, env.router, http.MethodPost, "/t/tenant-a/saml/sp/acs", strings.NewReader(postBody), headers)
	require.Equal(t, http.StatusUnauthorized, secondResp.Code)
	assert.Contains(t, secondResp.Body.String(), "invalid_saml_response")
}

func TestOIDCE2E_SAMLSLO_SPInitiated_RequestResponseAndSafeFallback(t *testing.T) {
	env := setupOIDCE2EEnv(t)
	idp, err := env.saml.GetIdentityProvider(context.Background(), "tenant-a")
	require.NoError(t, err)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idp.Certificate.Raw}))
	createSAMLConnectionFixture(t, env.db, "tenant-a", "saml-conn-a", idp.MetadataURL.String(), "http://saml-idp.local/slo", certPEM)
	createSAMLConnectionFixture(t, env.db, "tenant-b", "saml-conn-b", idp.MetadataURL.String(), "http://saml-idp.local/slo", certPEM)

	_, _, idToken := mintTenantAToken(t, env)

	requestResp := serveRequest(t, env.router, http.MethodGet,
		"/t/tenant-a/saml/sp/slo?connection_id=saml-conn-a&id_token_hint="+url.QueryEscape(idToken)+"&RelayState="+url.QueryEscape("http://client.localhost/logout?state=slo-state"),
		nil, nil)
	require.Equal(t, http.StatusFound, requestResp.Code)
	relayState, logoutReq := extractRelayStateAndLogoutRequest(t, requestResp)
	assert.Equal(t, "http://client.localhost/logout?state=slo-state", relayState)
	require.NotNil(t, logoutReq.Issuer)
	assert.Contains(t, logoutReq.Issuer.Value, "/t/tenant-a/saml")
	require.NotNil(t, logoutReq.NameID)
	assert.Equal(t, "alice", logoutReq.NameID.Value)

	responseResp := serveRequest(t, env.router, http.MethodPost, "/t/tenant-a/saml/sp/slo", strings.NewReader(url.Values{
		"SAMLResponse": {"external-logout-response"},
		"RelayState":   {relayState},
	}.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	require.Equal(t, http.StatusFound, responseResp.Code)
	assert.Equal(t, relayState, responseResp.Header().Get("Location"))

	localFallbackResp := serveRequest(t, env.router, http.MethodGet,
		"/t/tenant-a/saml/sp/slo?RelayState="+url.QueryEscape("http://client.localhost/logout?state=local-fallback"),
		nil, nil)
	require.Equal(t, http.StatusFound, localFallbackResp.Code)
	assert.Equal(t, "http://client.localhost/logout?state=local-fallback", localFallbackResp.Header().Get("Location"))
}

func TestOIDCE2E_SAMLSLO_RejectsMalformedAndCrossTenantRequests(t *testing.T) {
	env := setupOIDCE2EEnv(t)
	idp, err := env.saml.GetIdentityProvider(context.Background(), "tenant-a")
	require.NoError(t, err)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idp.Certificate.Raw}))
	createSAMLConnectionFixture(t, env.db, "tenant-a", "saml-conn-a", idp.MetadataURL.String(), "http://saml-idp.local/slo", certPEM)

	malformedResp := serveRequest(t, env.router, http.MethodGet,
		"/t/tenant-a/saml/sp/slo?SAMLRequest="+url.QueryEscape("not-base64"),
		nil, nil)
	require.Equal(t, http.StatusBadRequest, malformedResp.Code)
	assert.Contains(t, malformedResp.Body.String(), "invalid_logout_request")

	safeFallbackResp := serveRequest(t, env.router, http.MethodGet,
		"/t/tenant-a/saml/sp/slo?RelayState="+url.QueryEscape("http://client.localhost/logout?state=trusted-fallback"),
		nil, nil)
	require.Equal(t, http.StatusFound, safeFallbackResp.Code)
	assert.Equal(t, "http://client.localhost/logout?state=trusted-fallback", safeFallbackResp.Header().Get("Location"))

	crossTenantResp := serveRequest(t, env.router, http.MethodGet,
		"/t/tenant-b/saml/sp/slo?connection_id=saml-conn-a&RelayState="+url.QueryEscape("http://client.localhost/logout?state=cross-tenant"),
		nil, nil)
	require.Equal(t, http.StatusFound, crossTenantResp.Code)
	assert.Equal(t, "http://client.localhost/logout?state=cross-tenant", crossTenantResp.Header().Get("Location"))
}

func TestOIDCE2E_SAMLSLO_RejectsTamperedSignedLogoutRequest(t *testing.T) {
	env := setupOIDCE2EEnv(t)
	idp, err := env.saml.GetIdentityProvider(context.Background(), "tenant-a")
	require.NoError(t, err)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idp.Certificate.Raw}))
	sp, err := env.saml.BuildServiceProvider(context.Background(), "tenant-a", &model.SAMLConnection{
		TenantID:        "tenant-a",
		Name:            "SLO SP",
		IdpEntityID:     idp.MetadataURL.String(),
		IdpSingleSignOn: "http://saml-idp.local/sso",
		SignRequest:     true,
	})
	require.NoError(t, err)
	createSAMLClientFixture(t, env.db, "tenant-a", "saml-client-a", sp.EntityID, "http://example.test/t/tenant-a/saml/idp/slo", certPEM)
	createSAMLClientFixture(t, env.db, "tenant-b", "saml-client-b", sp.EntityID, "http://example.test/t/tenant-b/saml/idp/slo", certPEM)

	logoutReq, err := sp.MakeLogoutRequest("http://example.test/t/tenant-a/saml/idp/slo", "alice")
	require.NoError(t, err)
	signedURL := logoutReq.Redirect("http://client.localhost/logout?state=slo-state")
	signedURLStr := signSAMLRedirectURL(t, signedURL.String(), sp.Key.(*rsa.PrivateKey))
	tamperedURL := tamperQueryParamValue(t, signedURLStr, "Signature")

	resp := serveRequest(t, env.router, http.MethodGet, strings.Replace(tamperedURL, "/t/tenant-a/saml/idp/slo", "/t/tenant-b/saml/idp/slo", 1), nil, nil)
	require.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Contains(t, resp.Body.String(), "invalid_signature")
	assert.Empty(t, resp.Header().Get("Location"))
}

func TestOIDCE2E_Logout_PreservesStateOnSuccessfulRedirect(t *testing.T) {
	env := setupOIDCE2EEnv(t)
	_, _, idToken := mintTenantAToken(t, env)

	resp := serveRequest(t, env.router, http.MethodGet,
		"/t/tenant-a/oauth2/logout?id_token_hint="+url.QueryEscape(idToken)+
			"&post_logout_redirect_uri="+url.QueryEscape("http://client.localhost/logout")+
			"&state=logout-state",
		nil, nil)
	require.Equal(t, http.StatusFound, resp.Code)
	assert.Equal(t, "http://client.localhost/logout?state=logout-state", resp.Header().Get("Location"))
}

func TestOIDCE2E_Logout_RejectsUnregisteredPostLogoutRedirectURI(t *testing.T) {
	env := setupOIDCE2EEnv(t)
	_, _, idToken := mintTenantAToken(t, env)

	resp := serveRequest(t, env.router, http.MethodGet,
		"/t/tenant-a/oauth2/logout?id_token_hint="+url.QueryEscape(idToken)+
			"&post_logout_redirect_uri="+url.QueryEscape("http://evil.example/logout")+
			"&state=logout-state",
		nil, nil)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.NotEqual(t, "http://evil.example/logout?state=logout-state", resp.Header().Get("Location"))
	assert.Contains(t, resp.Body.String(), "Redirect blocked")
}

func TestOIDCE2E_Logout_RejectsCrossTenantIdTokenHintContext(t *testing.T) {
	env := setupOIDCE2EEnv(t)
	_, _, idToken := mintTenantAToken(t, env)

	resp := serveRequest(t, env.router, http.MethodGet,
		"/t/tenant-b/oauth2/logout?id_token_hint="+url.QueryEscape(idToken)+
			"&post_logout_redirect_uri="+url.QueryEscape("http://client.localhost/logout")+
			"&state=logout-state",
		nil, nil)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Empty(t, resp.Header().Get("Location"))
	assert.Contains(t, resp.Body.String(), "Successfully logged out")
}

func TestOIDCE2E_Logout_RejectsMalformedIdTokenHintUnsafeRedirect(t *testing.T) {
	env := setupOIDCE2EEnv(t)

	resp := serveRequest(t, env.router, http.MethodGet,
		"/t/tenant-a/oauth2/logout?id_token_hint="+url.QueryEscape("not-a-token")+
			"&post_logout_redirect_uri="+url.QueryEscape("http://client.localhost/logout")+
			"&state=logout-state",
		nil, nil)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Empty(t, resp.Header().Get("Location"))
	assert.Contains(t, resp.Body.String(), "Redirect blocked")
}

func TestOIDCE2E_TenantIsolation_TokenEndpointRejectsForeignCode(t *testing.T) {
	env := setupOIDCE2EEnv(t)
	code, _, _ := mintTenantAToken(t, env)

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("client_id", "oidc-client-b")
	tokenForm.Set("code", code)
	tokenForm.Set("redirect_uri", "http://client.localhost/callback")
	tokenForm.Set("code_verifier", "e2e-code-verifier-0123456789-abcdefghijklmnopqrstuvwxyz")

	resp := serveRequest(t, env.router, http.MethodPost, "/t/tenant-b/oauth2/token", strings.NewReader(tokenForm.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	require.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "invalid_grant")
}

func TestOIDCE2E_TenantIsolation_UserInfoRejectsForeignAccessToken(t *testing.T) {
	env := setupOIDCE2EEnv(t)
	_, accessToken, _ := mintTenantAToken(t, env)

	resp := serveRequest(t, env.router, http.MethodGet, "/t/tenant-b/userinfo", nil, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	require.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Contains(t, resp.Body.String(), "invalid_token")
}

func TestOIDCE2E_TenantIsolation_AuthorizeRejectsForeignClient(t *testing.T) {
	env := setupOIDCE2EEnv(t)

	resp := serveRequest(t, env.router, http.MethodGet, "/t/tenant-b/oauth2/auth?client_id=oidc-client-a&response_type=code&redirect_uri="+
		url.QueryEscape("http://client.localhost/callback")+
		"&scope=openid%20profile&state=tenant-b&code_challenge="+url.QueryEscape(pkceS256Challenge("e2e-code-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"))+
		"&code_challenge_method=S256", nil, nil)
	require.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Contains(t, resp.Body.String(), "invalid_client")
}

func TestOIDCE2E_RedirectURIExactMatching_TokenRejectsTrailingSlashMismatch(t *testing.T) {
	env := setupOIDCE2EEnv(t)
	code, _, _ := mintTenantAToken(t, env)

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("client_id", "oidc-client-a")
	tokenForm.Set("code", code)
	tokenForm.Set("redirect_uri", "http://client.localhost/callback/")
	tokenForm.Set("code_verifier", "e2e-code-verifier-0123456789-abcdefghijklmnopqrstuvwxyz")

	resp := serveRequest(t, env.router, http.MethodPost, "/t/tenant-a/oauth2/token", strings.NewReader(tokenForm.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	require.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "invalid_grant")
}

func TestOIDCE2E_RedirectURIExactMatching_TokenRejectsQueryStringMismatch(t *testing.T) {
	env := setupOIDCE2EEnv(t)
	code, _, _ := mintTenantAToken(t, env)

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("client_id", "oidc-client-a")
	tokenForm.Set("code", code)
	tokenForm.Set("redirect_uri", "http://client.localhost/callback?return=1")
	tokenForm.Set("code_verifier", "e2e-code-verifier-0123456789-abcdefghijklmnopqrstuvwxyz")

	resp := serveRequest(t, env.router, http.MethodPost, "/t/tenant-a/oauth2/token", strings.NewReader(tokenForm.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	require.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "invalid_grant")
}

func TestOIDCE2E_RedirectURIExactMatching_TokenRejectsHostAliasMismatch(t *testing.T) {
	env := setupOIDCE2EEnv(t)
	code, _, _ := mintTenantAToken(t, env)

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("client_id", "oidc-client-a")
	tokenForm.Set("code", code)
	tokenForm.Set("redirect_uri", "http://127.0.0.1/callback")
	tokenForm.Set("code_verifier", "e2e-code-verifier-0123456789-abcdefghijklmnopqrstuvwxyz")

	resp := serveRequest(t, env.router, http.MethodPost, "/t/tenant-a/oauth2/token", strings.NewReader(tokenForm.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	require.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "invalid_grant")
}
