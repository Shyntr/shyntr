package handlers

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/http/payload"
	"github.com/Shyntr/shyntr/internal/application/mapper"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	"github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/Shyntr/shyntr/pkg/consts"
	"github.com/Shyntr/shyntr/pkg/logger"
	utils2 "github.com/Shyntr/shyntr/pkg/utils"
	crewjamsaml "github.com/crewjam/saml"
	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"go.uber.org/zap"
)

type SAMLHandler struct {
	Config             *config.Config
	samlBuilderUseCase usecase.SamlBuilderUseCase
	ClientUseCase      usecase.OAuth2ClientUseCase
	AuthUse            usecase.AuthUseCase
	SAMLUse            usecase.SAMLConnectionUseCase
	SAMLClientUse      usecase.SAMLClientUseCase
	OIDCClientUse      usecase.OAuth2ClientUseCase
	OAuthSessionUse    usecase.OAuth2SessionUseCase
	Mapper             *mapper.Mapper
	KeyMgr             utils.KeyManager
	wh                 usecase.WebhookUseCase
	ScopeUse           usecase.ScopeUseCase
}

func NewSAMLHandler(Config *config.Config, KeyMgr utils.KeyManager, samlBuilderUseCase usecase.SamlBuilderUseCase, ClientUseCase usecase.OAuth2ClientUseCase, m *mapper.Mapper,
	AuthUse usecase.AuthUseCase, SAMLUse usecase.SAMLConnectionUseCase, OAuthSessionUse usecase.OAuth2SessionUseCase,
	SAMLClientUse usecase.SAMLClientUseCase, OIDCClientUse usecase.OAuth2ClientUseCase, wh usecase.WebhookUseCase, ScopeUse usecase.ScopeUseCase) *SAMLHandler {
	return &SAMLHandler{Config: Config, KeyMgr: KeyMgr, samlBuilderUseCase: samlBuilderUseCase, ClientUseCase: ClientUseCase, Mapper: m, AuthUse: AuthUse, SAMLUse: SAMLUse,
		OAuthSessionUse: OAuthSessionUse, SAMLClientUse: SAMLClientUse, OIDCClientUse: OIDCClientUse, wh: wh, ScopeUse: ScopeUse}
}

// SPMetadata godoc
// @Summary Get SAML Service Provider Metadata
// @Description Returns the XML metadata document describing Shyntr's capabilities as a SAML Service Provider (SP) for a specific tenant.
// @Tags SAML Core
// @Produce xml
// @Param tenant_id path string true "Tenant ID"
// @Success 200 {string} string "SAML SP Metadata XML"
// @Failure 500 {object} map[string]string "Internal Server Error"
// @Router /t/{tenant_id}/saml/sp/metadata [get]
func (h *SAMLHandler) SPMetadata(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Config.DefaultTenantID
	}

	// An optional connection_id lets an operator publish SP metadata tailored to a
	// specific SAML connection: its pinned NameIDFormat and an
	// AttributeConsumingService derived from its attribute_mapping. Without it, the
	// endpoint returns the tenant-generic SP metadata unchanged.
	var conn *model.SAMLConnection
	if connectionID := c.Query("connection_id"); connectionID != "" {
		var connErr error
		conn, connErr = h.SAMLUse.GetConnection(c.Request.Context(), tenantID, connectionID)
		if connErr != nil {
			logger.FromGin(c).Warn("SP metadata requested for unknown connection", zap.String("connection_id", connectionID))
			payload.WriteSAMLError(c, http.StatusNotFound, "connection_not_found", "The configured SAML connection could not be found for this tenant.", connErr)
			return
		}
	}

	sp, err := h.samlBuilderUseCase.BuildServiceProvider(c.Request.Context(), tenantID, nil)
	if err != nil {
		logger.FromGin(c).Error("Failed to initialize SP", zap.Error(err), zap.String("protocol", "saml"))
		payload.WriteSAMLError(c, http.StatusInternalServerError, "server_error", "Failed to initialize the SAML federation flow.", err)
		return
	}

	metaDesc := sp.Metadata()

	if len(metaDesc.SPSSODescriptors) > 0 {
		configured := ""
		if conn != nil {
			configured = conn.NameIDFormat
		}
		metaDesc.SPSSODescriptors[0].NameIDFormats = samlMetadataNameIDFormats(configured)

		if conn != nil {
			if acs, ok := buildAttributeConsumingService(conn.Name, conn.AttributeMapping); ok {
				metaDesc.SPSSODescriptors[0].AttributeConsumingServices = []crewjamsaml.AttributeConsumingService{acs}
			}
		}
	}

	c.Header("Content-Type", "application/xml")
	if err := xml.NewEncoder(c.Writer).Encode(metaDesc); err != nil {
		logger.FromGin(c).Error("Failed to write metadata XML", zap.Error(err), zap.String("protocol", "saml"))
	}
}

// Login godoc
// @Summary Initiate SAML SP Login
// @Description Starts the SAML SSO flow as a Service Provider against an external Identity Provider. Generates an AuthnRequest and redirects the user.
// @Tags SAML Federation
// @Produce html
// @Param tenant_id path string true "Tenant ID"
// @Param connection_id path string true "SAML Connection ID (IdP Reference)"
// @Param login_challenge query string true "Active login challenge"
// @Success 302 {string} string "Redirects or posts an HTML form to the external IdP"
// @Failure 400 {object} map[string]string "Missing login challenge"
// @Failure 404 {object} map[string]string "Login request not found"
// @Failure 500 {object} map[string]string "SSO initiation failed"
// @Router /t/{tenant_id}/saml/login/{connection_id} [get]
func (h *SAMLHandler) Login(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Config.DefaultTenantID
	}
	connectionID := c.Param("connection_id")
	loginChallenge := c.Query("login_challenge")

	if loginChallenge == "" {
		payload.WriteSAMLError(c, http.StatusBadRequest, "invalid_request", "The login_challenge query parameter is required.", nil)
		return
	}

	loginReq, err := h.AuthUse.GetLoginRequest(c.Request.Context(), loginChallenge)
	if err != nil {
		payload.WriteSAMLError(c, http.StatusNotFound, "login_request_not_found", "The login request was not found or has expired.", err)
		return
	}
	csrfToken, _ := utils2.GenerateRandomHex(32)
	sameSiteMode := http.SameSiteLaxMode
	if h.Config.CookieSecure {
		sameSiteMode = http.SameSiteNoneMode
	}
	c.SetSameSite(sameSiteMode)
	c.SetCookie("shyntr_fed_csrf", csrfToken, 600, "/", "", h.Config.CookieSecure, true)

	redirectURLOrHTML, requestID, err := h.samlBuilderUseCase.InitiateSSO(c.Request.Context(), tenantID, connectionID, loginChallenge, csrfToken)
	providerCtx := map[string]interface{}{
		"connection_id": connectionID,
	}
	if requestID != "" {
		providerCtx["saml_request_id"] = requestID
	}
	_ = h.AuthUse.MarkLoginAsProviderStarted(c.Request.Context(), loginReq.ID, "saml", connectionID, providerCtx, c.ClientIP(), c.Request.UserAgent())
	redirectURLOrHTML, requestID, err = h.samlBuilderUseCase.InitiateSSO(c.Request.Context(), tenantID, connectionID, loginChallenge, csrfToken)
	if err != nil {
		logger.FromGin(c).Error("Failed to initiate SAML SSO", zap.Error(err), zap.String("protocol", "saml"))
		payload.WriteSAMLError(c, http.StatusInternalServerError, "server_error", "Failed to initiate SAML SSO with the external identity provider.", err)
		return
	}

	var ctxData map[string]interface{}
	if len(loginReq.Context) > 0 {
		_ = json.Unmarshal(loginReq.Context, &ctxData)
	} else {
		ctxData = make(map[string]interface{})
	}
	ctxData["connection_id"] = connectionID
	ctxData["federation_action"] = "saml_login"

	loginReq.Context, _ = json.Marshal(ctxData)
	if requestID != "" {
		loginReq.SAMLRequestID = requestID
	}

	loginReq, err = h.AuthUse.UpdateLoginRequest(c.Request.Context(), loginReq)
	if err != nil {
		logger.FromGin(c).Error("Failed to save Login request", zap.Error(err), zap.String("protocol", "saml"))
		payload.WriteSAMLError(c, http.StatusInternalServerError, "server_error", "Failed to persist the login request for the SAML flow.", err)
		return
	}

	if strings.HasPrefix(strings.TrimSpace(redirectURLOrHTML), "<") {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(redirectURLOrHTML))
	} else {
		c.Redirect(http.StatusFound, redirectURLOrHTML)
	}
}

// ACS godoc
// @Summary SAML Assertion Consumer Service (ACS)
// @Description Receives and validates the SAMLResponse from an external Identity Provider. Prevents XML Signature Wrapping (XSW) and CSRF attacks.
// @Tags SAML Federation
// @Accept application/x-www-form-urlencoded
// @Produce html
// @Param tenant_id path string true "Tenant ID"
// @Param SAMLResponse formData string true "Base64 encoded SAML Response"
// @Param RelayState formData string true "Relay state containing the login challenge"
// @Success 302 {string} string "Redirects back to the originating protocol flow (OIDC or SAML)"
// @Failure 400 {object} map[string]string "Missing relay state"
// @Failure 403 {object} map[string]string "CSRF validation failed or invalid session"
// @Failure 401 {object} map[string]string "Signature or Issuer validation failed (XSW blocked)"
// @Router /t/{tenant_id}/saml/sp/acs [post]
func (h *SAMLHandler) ACS(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Config.DefaultTenantID
	}
	setSAMLDiagnosticContext(c, tenantID, "", "acs_entry")

	relayState := c.PostForm("RelayState")
	if relayState == "" {
		relayState = c.Query("RelayState")
	}
	if relayState == "" {
		setSAMLDiagnosticContext(c, tenantID, "missing_relay_state", "acs_relay_state_missing")
		logger.FromGin(c).Error("SAML ACS failed: RelayState is completely missing")
		payload.AbortWithSAMLError(c, http.StatusBadRequest, "invalid_request", "RelayState is required to resume the SAML login flow.", nil)
		return
	}

	csrfCookie, err := c.Cookie("shyntr_fed_csrf")
	if err != nil || csrfCookie == "" {
		setSAMLDiagnosticContext(c, tenantID, "missing_csrf_cookie", "acs_csrf_cookie_missing")
		logger.FromGin(c).Warn("Missing CSRF Cookie on ACS",
			zap.String("relay_state_sha256", hashForLog(relayState)),
		)
		payload.AbortWithSAMLError(c, http.StatusForbidden, "access_denied", "The SAML login session is missing the CSRF cookie. Restart the login flow.", nil)
		return
	}
	c.SetCookie("shyntr_fed_csrf", "", -1, "/", "", h.Config.CookieSecure, true)

	verifiedState, err := h.samlBuilderUseCase.VerifyRelayState(
		c.Request.Context(),
		tenantID,
		relayState,
		csrfCookie,
	)
	if err != nil {
		setSAMLDiagnosticContext(c, tenantID, "invalid_relay_state", "acs_relay_state_verification")
		logger.FromGin(c).Warn("SAML ACS relay state validation failed",
			zap.Error(err),
			zap.String("relay_state_sha256", hashForLog(relayState)),
			zap.Bool("csrf_cookie_present", true),
		)
		payload.AbortWithSAMLError(c, http.StatusForbidden, "access_denied", "RelayState is invalid, expired, or does not match the current SAML login session.", err)
		return
	}

	loginChallenge := verifiedState.LoginChallenge
	connectionID := verifiedState.ConnectionID
	c.Set("connection_id", connectionID)

	loginReq, err := h.AuthUse.GetLoginRequest(c.Request.Context(), loginChallenge)
	if err != nil {
		setSAMLDiagnosticContext(c, tenantID, "invalid_session", "acs_login_request_lookup")
		logger.FromGin(c).Warn("Invalid RelayState (LoginRequest not found)",
			zap.String("login_challenge_prefix", shortForLog(loginChallenge, 12)),
			zap.String("connection_id", connectionID),
		)
		payload.AbortWithSAMLError(c, http.StatusForbidden, "access_denied", "The SAML login session is invalid or has expired.", err)
		return
	}

	assertion, _, err := h.samlBuilderUseCase.HandleACS(c.Request.Context(), tenantID, c.Request, loginReq.SAMLRequestID)
	if err != nil {
		setSAMLDiagnosticContext(c, tenantID, "invalid_saml_response", "acs_response_validation")
		logger.FromGin(c).Error("Failed to handle SAML ACS",
			zap.Error(err),
			zap.String("connection_id", connectionID),
			zap.String("login_challenge_prefix", shortForLog(loginChallenge, 12)),
		)
		payload.AbortWithSAMLError(c, http.StatusUnauthorized, "invalid_saml_response", "The SAML response is invalid or failed signature/condition validation.", err)
		return
	}

	conn, err := h.SAMLUse.GetConnection(c.Request.Context(), tenantID, connectionID)
	if err != nil {
		setSAMLDiagnosticContext(c, tenantID, "connection_not_found", "acs_connection_lookup")
		logger.FromGin(c).Warn("Connection not found for verified relay state", zap.String("connection_id", connectionID))
		payload.AbortWithSAMLError(c, http.StatusNotFound, "connection_not_found", "The configured SAML connection could not be found for this tenant.", err)
		return
	}

	issuer := assertion.Issuer.Value
	if issuer != conn.IdpEntityID {
		setSAMLDiagnosticContext(c, tenantID, "invalid_issuer", "acs_issuer_validation")
		logger.FromGin(c).Error("SAML Signature Wrapping (XSW) / Issuer Mismatch Detected!",
			zap.String("expected", conn.IdpEntityID),
			zap.String("actual", issuer),
			zap.String("connection_id", connectionID),
		)
		payload.AbortWithSAMLError(c, http.StatusUnauthorized, "invalid_issuer", "The SAML response issuer does not match the configured identity provider.", nil)
		return
	}
	setSAMLDiagnosticContext(c, tenantID, "", "acs_validated")
	logger.FromGin(c).Info("SAML ACS relay state and assertion validated",
		zap.String("login_challenge_prefix", shortForLog(loginChallenge, 12)),
	)
	rawAttributes := make(map[string]interface{})
	tempAttributes := make(map[string][]string)

	for _, statement := range assertion.AttributeStatements {
		for _, attr := range statement.Attributes {
			for _, val := range attr.Values {
				tempAttributes[attr.Name] = append(tempAttributes[attr.Name], val.Value)
			}
		}
	}
	for name, values := range tempAttributes {
		if len(values) == 1 {
			rawAttributes[name] = values[0]
		} else if len(values) > 1 {
			rawAttributes[name] = values
		}
	}

	finalAttributes, err := h.Mapper.Map(rawAttributes, conn.AttributeMapping)
	if err != nil {
		logger.FromGin(c).Warn("Attribute mapping failed, falling back to raw", zap.Error(err), zap.String("protocol", "saml"))
		finalAttributes = rawAttributes
	}

	subject := assertion.Subject.NameID.Value
	if subject == "" {
		if sub, ok := finalAttributes["sub"].(string); ok {
			subject = sub
		}
	}
	if email, ok := finalAttributes["email"].(string); ok && subject == "" {
		subject = email
	}

	finalAttributes["source"] = "saml"
	finalAttributes["connection_id"] = connectionID
	finalAttributes["idp"] = fmt.Sprintf("saml:%s", connectionID)
	finalAttributes["amr"] = []string{"ext"}
	if _, ok := finalAttributes["sub"]; !ok {
		finalAttributes["sub"] = subject
	}

	h.wh.FireEvent(tenantID, "user.login.ext", finalAttributes)

	var existingCtx map[string]interface{}
	if len(loginReq.Context) > 0 {
		_ = json.Unmarshal(loginReq.Context, &existingCtx)
	} else {
		existingCtx = make(map[string]interface{})
	}

	existingCtx["login_claims"] = finalAttributes
	loginReq, err = h.AuthUse.CompleteProviderLogin(
		c.Request.Context(),
		loginChallenge,
		subject,
		conn.Name,
		"saml",
		existingCtx,
		c.ClientIP(),
		c.Request.UserAgent(),
	)
	if err != nil {
		logger.FromGin(c).Error("Failed to complete SAML login", zap.Error(err), zap.String("protocol", "saml"))
		payload.AbortWithSAMLError(c, http.StatusInternalServerError, "server_error", "Failed to complete the SAML login and resume the original authentication flow.", err)
		return
	}

	var redirectTo string

	if loginReq.Protocol == "saml" {
		redirectTo = fmt.Sprintf("%s/t/%s/saml/resume?login_challenge=%s",
			strings.TrimSuffix(h.Config.BaseIssuerURL, "/"),
			tenantID,
			loginReq.ID,
		)
	} else {
		parsedURL, err := url.Parse(loginReq.RequestURL)
		if err != nil {
			payload.AbortWithSAMLError(c, http.StatusInternalServerError, "server_error", "The original redirect URL stored for the login request is invalid.", err)
			return
		}

		safePath := parsedURL.Path
		if safePath == "" {
			safePath = "/"
		} else if !strings.HasPrefix(safePath, "/") {
			safePath = "/" + safePath
		}

		query := parsedURL.Query()
		query.Set("login_verifier", loginReq.ID)
		base := strings.TrimSuffix(h.Config.BaseIssuerURL, "/")
		redirectTo = fmt.Sprintf("%s%s?%s", base, safePath, query.Encode())
	}

	c.Redirect(http.StatusFound, redirectTo)
}

// IDPMetadata godoc
// @Summary Get SAML Identity Provider Metadata
// @Description Returns the XML metadata document describing Shyntr's capabilities as a SAML Identity Provider (IdP) for a specific tenant.
// @Tags SAML Core
// @Produce xml
// @Param tenant_id path string true "Tenant ID"
// @Success 200 {string} string "SAML IdP Metadata XML"
// @Failure 500 {object} map[string]string "Internal Server Error"
// @Router /t/{tenant_id}/saml/idp/metadata [get]
func (h *SAMLHandler) IDPMetadata(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Config.DefaultTenantID
	}

	// An optional client_id lets an operator publish IdP metadata tailored to a
	// specific SP client: the single NameIDFormat that SP has been pinned to.
	// Without it, the endpoint returns the tenant-generic IdP metadata unchanged.
	var spClient *model.SAMLClient
	if clientID := c.Query("client_id"); clientID != "" {
		var clientErr error
		spClient, clientErr = h.SAMLClientUse.GetClient(c.Request.Context(), tenantID, clientID)
		if clientErr != nil {
			logger.FromGin(c).Warn("IdP metadata requested for unknown SP client", zap.String("client_id", clientID))
			payload.WriteSAMLError(c, http.StatusNotFound, "sp_not_found", "The service provider configuration could not be found for this tenant.", clientErr)
			return
		}
	}

	idp, err := h.samlBuilderUseCase.GetIdentityProvider(c.Request.Context(), tenantID)
	if err != nil {
		logger.FromGin(c).Error("Failed to initialize IdP", zap.Error(err), zap.String("protocol", "saml"))
		payload.WriteSAMLError(c, http.StatusInternalServerError, "server_error", "Failed to initialize the SAML identity provider context.", err)
		return
	}

	privKey, cert, _, err := h.KeyMgr.GetActiveKeys(c.Request.Context(), "sig")
	if err != nil {
		logger.FromGin(c).Error("failed to load active SAML crypto keys")
	}
	if privKey != nil && cert != nil {
		idp.Key = privKey
		idp.Certificate = cert
	} else {
		logger.FromGin(c).Warn("No active keys found in KeyMgr. Metadata may contain transient certificates.")
	}
	metaDesc := idp.Metadata()

	if len(metaDesc.IDPSSODescriptors) > 0 {
		configured := ""
		if spClient != nil {
			configured = spClient.NameIDFormat
		}
		metaDesc.IDPSSODescriptors[0].NameIDFormats = samlMetadataNameIDFormats(configured)
	}

	c.Header("Content-Type", "application/xml")
	if err := xml.NewEncoder(c.Writer).Encode(metaDesc); err != nil {
		logger.FromGin(c).Error("Failed to write metadata XML", zap.Error(err), zap.String("protocol", "saml"))
	}
}

// samlMetadataNameIDFormats returns the NameIDFormat list to advertise. When a
// single valid format is configured, it advertises exactly that one; otherwise it
// falls back to the default set.
//
// persistent is never advertised: it is not in the configurable set (config-time
// validation rejects it) and it is absent from the default list, because the
// issuance path fails closed on it. The IsValidNameIDFormat guard is defence in
// depth: a value that somehow bypassed validation (an out-of-band write) can never
// cause metadata to advertise a format the issuance path would refuse to produce;
// such a value falls back to the safe default set instead.
func samlMetadataNameIDFormats(configured string) []crewjamsaml.NameIDFormat {
	if model.IsValidNameIDFormat(configured) {
		return []crewjamsaml.NameIDFormat{crewjamsaml.NameIDFormat(configured)}
	}
	return []crewjamsaml.NameIDFormat{
		crewjamsaml.EmailAddressNameIDFormat, // urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
		crewjamsaml.UnspecifiedNameIDFormat,  // urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified
		crewjamsaml.TransientNameIDFormat,    // urn:oasis:names:tc:SAML:2.0:nameid-format:transient
	}
}

// buildAttributeConsumingService builds the SP AttributeConsumingService that
// declares one RequestedAttribute per attribute_mapping entry, so published
// metadata matches what the SP actually consumes. It returns ok=false for an empty
// mapping, in which case no AttributeConsumingService is emitted (current
// behaviour).
//
// Each RequestedAttribute's Name is the mapping output name (the map key). Its
// NameFormat is the rule's explicit NameFormat when it is a valid attrname-format,
// otherwise the same heuristic the issuance path uses (model.AttributeNameFormatFor
// from T2-4). This is deliberately not a URI-name special case: a URI-named claim
// whose rule pins basic (e.g. the FMN-mandated role claim) is advertised as basic,
// faithfully reflecting the operator's configuration. Keys are sorted so the
// emitted metadata is deterministic.
func buildAttributeConsumingService(serviceName string, mapping map[string]model.AttributeMappingRule) (crewjamsaml.AttributeConsumingService, bool) {
	if len(mapping) == 0 {
		return crewjamsaml.AttributeConsumingService{}, false
	}

	names := make([]string, 0, len(mapping))
	for name := range mapping {
		names = append(names, name)
	}
	sort.Strings(names)

	requested := make([]crewjamsaml.RequestedAttribute, 0, len(names))
	for _, name := range names {
		rule := mapping[name]
		nameFormat := model.AttributeNameFormatFor(name)
		if model.IsValidAttributeNameFormat(rule.NameFormat) {
			nameFormat = rule.NameFormat
		}
		requested = append(requested, crewjamsaml.RequestedAttribute{
			Attribute: crewjamsaml.Attribute{
				Name:       name,
				NameFormat: nameFormat,
			},
		})
	}

	// SAML metadata requires at least one ServiceName in an
	// AttributeConsumingService; fall back to a stable label when the connection
	// has no name.
	if strings.TrimSpace(serviceName) == "" {
		serviceName = "Shyntr Service Provider"
	}

	return crewjamsaml.AttributeConsumingService{
		Index:               1,
		ServiceNames:        []crewjamsaml.LocalizedName{{Lang: "en", Value: serviceName}},
		RequestedAttributes: requested,
	}, true
}

// IDPSSO godoc
// @Summary SAML IdP Single Sign-On
// @Description Receives an AuthnRequest from a Service Provider. Challenges the user for authentication and issues a SAMLResponse containing assertions.
// @Tags SAML Core
// @Accept application/x-www-form-urlencoded
// @Produce html
// @Param tenant_id path string true "Tenant ID"
// @Param SAMLRequest query string false "Deflated and Base64 encoded AuthnRequest (HTTP-Redirect)"
// @Param SAMLRequest formData string false "Base64 encoded AuthnRequest (HTTP-POST)"
// @Param RelayState query string false "Opaque state passed back to the SP"
// @Param login_verifier query string false "Internal verifier after a successful login challenge"
// @Success 200 {string} string "HTML form auto-posting the SAMLResponse to the SP"
// @Success 302 {string} string "Redirects to login UI if unauthenticated"
// @Failure 400 {object} map[string]string "Invalid SAMLRequest or Login Verifier"
// @Failure 403 {object} map[string]string "Unknown Service Provider"
// @Router /t/{tenant_id}/saml/idp/sso [get]
// @Router /t/{tenant_id}/saml/idp/sso [post]
func (h *SAMLHandler) IDPSSO(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Config.DefaultTenantID
	}

	loginVerifier := c.Query("login_verifier")
	if loginVerifier != "" {
		loginReq, err := h.AuthUse.GetAuthenticatedLoginRequest(c.Request.Context(), tenantID, loginVerifier)
		if err != nil {
			logger.FromGin(c).Error("Invalid login verifier for SAML IdP", zap.Error(err))
			payload.AbortWithSAMLError(c, http.StatusBadRequest, "invalid_request", "The login_verifier is invalid or has expired.", nil)
			return
		}

		spClient, err := h.SAMLClientUse.GetClient(c.Request.Context(), tenantID, loginReq.ClientID)
		if err != nil {
			logger.FromGin(c).Error("SP Client not found", zap.Error(err))
			payload.AbortWithSAMLError(c, http.StatusNotFound, "sp_not_found", "The service provider configuration could not be found for this tenant.", err)
			return
		}

		origURL, _ := url.Parse(loginReq.RequestURL)
		samlReqBase64 := origURL.Query().Get("SAMLRequest")
		relayState := origURL.Query().Get("RelayState")

		var authReq *crewjamsaml.AuthnRequest
		if samlReqBase64 != "" {
			parsed, parseErr := parseStoredAuthnRequest(samlReqBase64)
			if parseErr != nil {
				logger.FromGin(c).Error("Failed to parse stored SAML AuthnRequest", zap.Error(parseErr), zap.String("protocol", "saml"))
				payload.AbortWithSAMLError(c, http.StatusBadRequest, "invalid_saml_request", "The stored SAMLRequest could not be parsed.", nil)
				return
			}
			authReq = parsed
		} else {
			// No AuthnRequest was stored (e.g. IdP-initiated); use a minimal one.
			authReq = &crewjamsaml.AuthnRequest{}
		}

		// Preserve fallbacks for values a request may legitimately omit. A parse
		// failure was already turned into an error above, so an empty field here
		// is a genuine absence, not a swallowed parse error.
		if authReq.AssertionConsumerServiceURL == "" {
			authReq.AssertionConsumerServiceURL = spClient.ACSURL
		}
		if authReq.Issuer == nil || authReq.Issuer.Value == "" {
			authReq.Issuer = &crewjamsaml.Issuer{Value: spClient.EntityID}
		}

		var ctxData map[string]interface{}
		if len(loginReq.Context) > 0 {
			_ = json.Unmarshal(loginReq.Context, &ctxData)
		} else {
			ctxData = make(map[string]interface{})
		}

		userAttrs := make(map[string]interface{})
		for k, v := range ctxData {
			if k != "saml_request" && k != "relay_state_raw" && k != "protocol" && k != "sp_entity_id" && k != "request_id" && k != "acs_url" && k != "issuer" {
				userAttrs[k] = v
			}
		}

		userAttrs["sub"] = loginReq.Subject
		if _, ok := userAttrs["email"]; !ok {
			userAttrs["email"] = loginReq.Subject
		}

		allowedScopeEntities, err := h.ScopeUse.GetScopesByNames(c.Request.Context(), tenantID, spClient.AllowedScopes)
		if err != nil {
			logger.FromGin(c).Error("Failed to fetch allowed scopes for mapping", zap.Error(err))
		}

		secureClaims := utils.MapClaims(loginReq.Subject, userAttrs, allowedScopeEntities)
		normalizedClaims, hasNormalizedClaims := utils.ProjectNormalizedSAMLAttributes(loginReq)
		if hasNormalizedClaims {
			secureClaims = normalizedClaims
		}

		finalAttrs, mapOK := h.resolveOutboundAttributes(c, tenantID, authReq, spClient, secureClaims, relayState)
		if !mapOK {
			return
		}
		if hasNormalizedClaims {
			finalAttrs[utils.SAMLNameIDSubjectAttribute] = loginReq.Subject
			delete(finalAttrs, "sub")
		}

		htmlForm, err := h.samlBuilderUseCase.GenerateSAMLResponse(c.Request.Context(), tenantID, authReq, spClient, finalAttrs, relayState)
		if err != nil {
			logger.FromGin(c).Error("Failed to generate SAML Response", zap.Error(err))
			payload.AbortWithSAMLError(c, http.StatusInternalServerError, "server_error", "The SAML response could not be generated.", err)
			return
		}

		if consumeErr := h.AuthUse.MarkLoginRequestConsumed(c.Request.Context(), loginReq.ID); consumeErr != nil {
			logger.FromGin(c).Warn("Failed to consume login request after SAML assertion issuance",
				zap.Error(consumeErr), zap.String("login_request_id", loginReq.ID))
		}

		c.Writer.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';")
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, htmlForm)
		return
	}

	samlReq := c.Query("SAMLRequest")
	if samlReq == "" {
		samlReq = c.PostForm("SAMLRequest")
	}

	if samlReq == "" {
		logger.FromGin(c).Error("Failed to parse SAML AuthnRequest", zap.Error(errors.New("missing SAMLRequest parameter")), zap.String("protocol", "saml"))
		payload.WriteSAMLError(c, http.StatusBadRequest, "invalid_request", "The SAMLRequest parameter is required.", nil)
		return
	}

	authReq, err := h.samlBuilderUseCase.ParseAuthnRequest(c.Request.Context(), tenantID, c.Request)
	if err != nil {
		logger.FromGin(c).Error("Failed to parse SAML AuthnRequest", zap.Error(err), zap.String("protocol", "saml"))
		payload.AbortWithSAMLError(c, http.StatusBadRequest, "invalid_saml_request", "The SAMLRequest could not be parsed or validated.", err)
		return
	}

	spClient, err := h.SAMLClientUse.GetClientByEntityID(c.Request.Context(), tenantID, authReq.Issuer.Value)
	if err != nil {
		logger.FromGin(c).Warn("Unknown SP EntityID", zap.String("entity_id", authReq.Issuer.Value), zap.String("protocol", "saml"))
		payload.AbortWithSAMLError(c, http.StatusForbidden, "unknown_service_provider", "The requesting service provider is not registered for this tenant.", nil)
		return
	}

	rawSAMLRequest := c.Query("SAMLRequest")
	if rawSAMLRequest == "" {
		rawSAMLRequest = c.PostForm("SAMLRequest")
	}

	relayState := c.Query("RelayState")
	if relayState == "" {
		relayState = c.PostForm("RelayState")
	}

	ctxData := map[string]interface{}{
		"saml_request":    rawSAMLRequest,
		"relay_state_raw": relayState,
		"sp_entity_id":    spClient.EntityID,
		"protocol":        "saml",
		"request_id":      authReq.ID,
		"acs_url":         authReq.AssertionConsumerServiceURL,
		"issuer":          authReq.Issuer.Value,
	}
	ctxBytes, _ := json.Marshal(ctxData)

	randomBytes := make([]byte, 32)
	rand.Read(randomBytes)
	loginChallenge := hex.EncodeToString(randomBytes)

	safeReqURL := fmt.Sprintf("%s/t/%s/saml/idp/sso?SAMLRequest=%s&RelayState=%s",
		h.Config.BaseIssuerURL,
		tenantID,
		url.QueryEscape(rawSAMLRequest),
		url.QueryEscape(relayState))

	loginReq := model.LoginRequest{
		ID:         loginChallenge,
		TenantID:   tenantID,
		RequestURL: safeReqURL,
		ClientID:   spClient.ID,
		ClientIP:   c.ClientIP(),
		Protocol:   "saml",
		Context:    ctxBytes,
		Active:     true,
		CreatedAt:  time.Now(),
	}

	savedLoginReq, err := h.AuthUse.CreateLoginRequest(c.Request.Context(), &loginReq)
	if err != nil {
		payload.AbortWithSAMLError(c, http.StatusInternalServerError, "server_error", "The SAML request could not be persisted due to an internal server error.", err)
		return
	}

	redirectURL := fmt.Sprintf("%s?login_challenge=%s", h.Config.ExternalLoginURL, savedLoginReq.ID)
	c.Redirect(http.StatusFound, redirectURL)
}

// IDPSLO godoc
// @Summary SAML IdP Single Logout
// @Description Handles IdP-initiated or SP-initiated Single Logout requests. Clears the local session and potentially notifies other connected applications.
// @Tags SAML Core
// @Accept application/x-www-form-urlencoded
// @Produce html
// @Param tenant_id path string true "Tenant ID"
// @Param SAMLRequest query string false "SAML LogoutRequest (SP-initiated)"
// @Param SAMLResponse query string false "SAML LogoutResponse"
// @Param RelayState query string false "Relay state"
// @Success 200 {string} string "HTML form posting the LogoutResponse"
// @Failure 400 {object} map[string]string "Invalid logout request or missing issuer"
// @Failure 401 {object} map[string]string "Signature verification failed"
// @Router /t/{tenant_id}/saml/idp/slo [get]
// @Router /t/{tenant_id}/saml/idp/slo [post]
func (h *SAMLHandler) IDPSLO(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Config.DefaultTenantID
	}

	logoutReq, err := h.samlBuilderUseCase.ParseLogoutRequest(c.Request)
	if err != nil {
		logger.FromGin(c).Error("Invalid SLO Request", zap.Error(err))
		payload.AbortWithSAMLError(c, http.StatusBadRequest, "invalid_logout_request", "The SAML logout request is invalid or could not be parsed.", nil)
		return
	}

	if logoutReq.Issuer == nil || logoutReq.Issuer.Value == "" {
		logger.FromGin(c).Error("Missing Issuer in SLO Request")
		payload.AbortWithSAMLError(c, http.StatusBadRequest, "invalid_request", "The SAML logout request does not include an issuer.", nil)
		return
	}

	spClient, err := h.SAMLClientUse.GetClientByEntityID(c.Request.Context(), tenantID, logoutReq.Issuer.Value)
	if err != nil {
		logger.FromGin(c).Warn("Unknown SP in SLO", zap.String("entity_id", logoutReq.Issuer.Value))
		payload.AbortWithSAMLError(c, http.StatusForbidden, "unknown_service_provider", "The service provider in the SAML logout request is not registered for this tenant.", nil)
		return
	}

	if spClient.SLOURL == "" {
		logger.FromGin(c).Warn("SP does not have SLO URL configured", zap.String("entity_id", spClient.EntityID))
		payload.AbortWithSAMLError(c, http.StatusBadRequest, "invalid_request", "Single Logout is not configured for the requesting service provider.", nil)
		return
	}

	if spClient.SPCertificate != "" && c.Request.Method == http.MethodGet {
		if err := h.samlBuilderUseCase.VerifyInboundRedirectSignature(c.Request, spClient.SPCertificate); err != nil {
			logger.FromGin(c).Error("SAML SLO Signature Verification Failed! Possible session riding attempt.",
				zap.String("entity_id", spClient.EntityID), zap.Error(err))
			payload.AbortWithSAMLError(c, http.StatusUnauthorized, "invalid_signature", "The SAML logout request signature is invalid.", err)
			return
		}
		logger.FromGin(c).Info("SAML SLO request signature verified successfully", zap.String("sp", spClient.EntityID))
	}

	c.SetCookie(consts.SessionCookieName, "", -1, "/", "", h.Config.CookieSecure, true)

	if logoutReq.NameID != nil && logoutReq.NameID.Value != "" {
		subject := logoutReq.NameID.Value

		activeSession, err := h.OAuthSessionUse.GetBySubject(c.Request.Context(), subject, spClient.ID)
		if err != nil {
			logger.FromGin(c).Warn("Active OAuth session not found. OAuth logout redirection will be skipped.", zap.String("subject_sha256", hashForLog(logoutReq.NameID.Value)),
				zap.String("entity_id", spClient.EntityID))
		} else {
			issuer := fmt.Sprintf("%s/t/%s/oauth2", h.Config.BaseIssuerURL, tenantID)

			oidcClient, clientErr := h.OIDCClientUse.GetClient(c.Request.Context(), tenantID, activeSession.ClientID)
			if clientErr == nil {
				if oidcClient.BackchannelLogoutURI != "" {
					h.ClientUseCase.SendBackchannelLogout(c.Request.Context(), tenantID, oidcClient.ID, oidcClient.BackchannelLogoutURI, subject, issuer)
				}
			}

			err = h.OAuthSessionUse.DeleteByClient(c.Request.Context(), subject, activeSession.ClientID)
			h.OAuthSessionUse.RecordLogout(c.Request.Context(), subject, tenantID, spClient.ID, c.ClientIP(), c.Request.UserAgent(), false)
		}
	}

	relayState := c.Query("RelayState")
	htmlForm, err := h.samlBuilderUseCase.GenerateLogoutResponse(c.Request.Context(), tenantID, logoutReq, spClient, relayState)
	if err != nil {
		logger.FromGin(c).Error("Failed to generate SAML Logout Response", zap.Error(err))
		payload.AbortWithSAMLError(c, http.StatusInternalServerError, "server_error", "The SAML logout response could not be generated.", err)
		return
	}

	c.Writer.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';")
	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, htmlForm)
}

// ResumeSAML godoc
// @Summary Resume SAML Flow
// @Description Resumes the SAML SSO flow after a successful internal authentication event.
// @Tags SAML Core
// @Produce html
// @Param tenant_id path string true "Tenant ID"
// @Param login_challenge query string true "Active login challenge identifier"
// @Success 200 {string} string "HTML form posting the SAMLResponse"
// @Failure 401 {object} map[string]string "Authentication pending"
// @Failure 404 {object} map[string]string "Login request not found"
// @Router /t/{tenant_id}/saml/resume [get]
func (h *SAMLHandler) ResumeSAML(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Config.DefaultTenantID
	}

	loginChallenge := c.Query("login_challenge")
	if loginChallenge == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing_login_challenge"})
		return
	}

	loginReq, loginReqErr := h.AuthUse.GetLoginRequest(c.Request.Context(), loginChallenge)
	if loginReqErr != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "login_request_not_found"})
		return
	}

	if loginReq.TenantID != tenantID {
		payload.AbortWithSAMLError(c, http.StatusForbidden, "access_denied", "The login request does not belong to this tenant.", nil)
		return
	}

	if !loginReq.Authenticated {
		payload.AbortWithSAMLError(c, http.StatusUnauthorized, "authentication_pending", "The user has not completed authentication for this SAML login flow yet.", nil)
		return
	}

	if loginReq.Protocol != "saml" {
		payload.AbortWithSAMLError(c, http.StatusBadRequest, "invalid_request", "The stored login request does not belong to a SAML flow.", nil)
		return
	}

	var ctxData map[string]interface{}
	if err := json.Unmarshal(loginReq.Context, &ctxData); err != nil {
		payload.AbortWithSAMLError(c, http.StatusInternalServerError, "server_error", "The stored SAML session context is invalid or corrupted.", err)
		return
	}

	relayState, _ := ctxData["relay_state_raw"].(string)

	var authReq *crewjamsaml.AuthnRequest
	if samlRequest, ok := ctxData["saml_request"].(string); ok && samlRequest != "" {
		parsed, parseErr := parseStoredAuthnRequest(samlRequest)
		if parseErr != nil {
			logger.FromGin(c).Error("Failed to parse stored SAML AuthnRequest", zap.Error(parseErr), zap.String("protocol", "saml"))
			payload.AbortWithSAMLError(c, http.StatusBadRequest, "invalid_saml_request", "The stored SAMLRequest could not be parsed.", nil)
			return
		}
		authReq = parsed
	} else {
		authReq = &crewjamsaml.AuthnRequest{}
	}

	// Preserve fallbacks for values a request may legitimately omit.
	if authReq.AssertionConsumerServiceURL == "" {
		if acsURL, ok := ctxData["acs_url"].(string); ok {
			authReq.AssertionConsumerServiceURL = acsURL
		}
	}
	if authReq.Issuer == nil || authReq.Issuer.Value == "" {
		fallbackIssuer, _ := ctxData["issuer"].(string)
		authReq.Issuer = &crewjamsaml.Issuer{Value: fallbackIssuer}
	}
	issuer := authReq.Issuer.Value

	spClient, spClientErr := h.SAMLClientUse.GetClientByEntityID(c.Request.Context(), tenantID, issuer)
	if spClientErr != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "sp_not_found"})
		return
	}

	userAttrs := make(map[string]interface{})
	for k, v := range ctxData {
		if k != "saml_request" && k != "relay_state_raw" && k != "protocol" && k != "sp_entity_id" && k != "login_claims" && k != "request_id" && k != "acs_url" && k != "issuer" {
			userAttrs[k] = v
		}
	}

	if claimsRaw, ok := ctxData["login_claims"]; ok {
		if claimsMap, ok := claimsRaw.(map[string]interface{}); ok {
			for k, v := range claimsMap {
				userAttrs[k] = v
			}
		}
	}

	userAttrs["sub"] = loginReq.Subject
	if _, ok := userAttrs["email"]; !ok {
		userAttrs["email"] = loginReq.Subject
	}

	allowedScopeEntities, err := h.ScopeUse.GetScopesByNames(c.Request.Context(), tenantID, spClient.AllowedScopes)
	if err != nil {
		logger.FromGin(c).Error("Failed to resolve SAML allowed scopes", zap.Error(err))
		allowedScopeEntities = []*model.Scope{}
	}

	secureClaims := utils.MapClaims(loginReq.Subject, userAttrs, allowedScopeEntities)
	normalizedClaims, hasNormalizedClaims := utils.ProjectNormalizedSAMLAttributes(loginReq)
	if hasNormalizedClaims {
		secureClaims = normalizedClaims
	}

	finalAttrs, mapOK := h.resolveOutboundAttributes(c, tenantID, authReq, spClient, secureClaims, relayState)
	if !mapOK {
		return
	}
	if hasNormalizedClaims {
		finalAttrs[utils.SAMLNameIDSubjectAttribute] = loginReq.Subject
		delete(finalAttrs, "sub")
	}

	htmlResponse, err := h.samlBuilderUseCase.GenerateSAMLResponse(c.Request.Context(), tenantID, authReq, spClient, finalAttrs, relayState)
	if err != nil {
		logger.FromGin(c).Error("Failed to generate SAML Response", zap.Error(err), zap.String("protocol", "saml"))
		payload.AbortWithSAMLError(c, http.StatusInternalServerError, "server_error", "The SAML response could not be generated.", err)
		return
	}

	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, htmlResponse)
}

// SPSLO godoc
// @Summary SAML SP Single Logout
// @Description Handles logout requests acting as a Service Provider against an external IdP.
// @Tags SAML Federation
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param tenant_id path string true "Tenant ID"
// @Param SAMLRequest query string false "SAML LogoutRequest (HTTP-Redirect)"
// @Param SAMLRequest formData string false "SAML LogoutRequest (HTTP-POST)"
// @Param SAMLResponse query string false "SAML LogoutResponse (HTTP-Redirect)"
// @Param SAMLResponse formData string false "SAML LogoutResponse (HTTP-POST)"
// @Param connection_id query string false "IdP Connection ID for SP-initiated SLO"
// @Param connection_id formData string false "IdP Connection ID for SP-initiated SLO"
// @Param RelayState query string false "Relay state"
// @Param RelayState formData string false "Relay state"
// @Success 302 {string} string "Redirects to external IdP or RelayState"
// @Success 200 {object} map[string]string "Logout successful message"
// @Failure 400 {object} map[string]string "Invalid logout request"
// @Router /t/{tenant_id}/saml/sp/slo [get]
// @Router /t/{tenant_id}/saml/sp/slo [post]
func (h *SAMLHandler) SPSLO(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Config.DefaultTenantID
	}

	samlReqEncoded := firstNonEmpty(
		c.Query("SAMLRequest"),
		c.PostForm("SAMLRequest"),
	)

	samlResEncoded := firstNonEmpty(
		c.Query("SAMLResponse"),
		c.PostForm("SAMLResponse"),
	)

	connectionID := firstNonEmpty(
		c.Query("connection_id"),
		c.PostForm("connection_id"),
	)

	relayState := firstNonEmpty(
		c.Query("RelayState"),
		c.PostForm("RelayState"),
	)

	if samlReqEncoded != "" {
		logoutReq, err := h.samlBuilderUseCase.ParseLogoutRequest(c.Request)
		if err != nil {
			logger.FromGin(c).Error("Invalid IdP SLO Request", zap.Error(err))
			payload.AbortWithSAMLError(c, http.StatusBadRequest, "invalid_logout_request", "The SAML logout request is invalid or could not be parsed.", nil)
			return
		}

		issuer := ""
		if logoutReq.Issuer != nil {
			issuer = logoutReq.Issuer.Value
		}

		c.SetCookie(consts.SessionCookieName, "", -1, "/", "", h.Config.CookieSecure, true)

		conn, err := h.SAMLUse.GetConnectionByIdpEntity(c.Request.Context(), tenantID, issuer)
		if err != nil {
			logger.FromGin(c).Warn("Unknown IdP in SLO", zap.String("entity_id", issuer))
			c.JSON(http.StatusOK, gin.H{"message": "Logged out locally."})
			return
		}
		if logoutReq.NameID != nil && logoutReq.NameID.Value != "" {
			subject := logoutReq.NameID.Value
			_ = h.OAuthSessionUse.Delete(c.Request.Context(), subject)
			logger.FromGin(c).Info("IdP-Initiated SLO successful, local sessions destroyed", zap.String("subject_sha256", hashForLog(subject)))
		}
		sp, err := h.samlBuilderUseCase.BuildServiceProvider(c.Request.Context(), tenantID, conn)
		if err != nil {
			c.Redirect(http.StatusFound, conn.IdpSloUrl)
			return
		}

		randomBytes := make([]byte, 16)
		rand.Read(randomBytes)
		respID := "resp-" + hex.EncodeToString(randomBytes)

		logoutResp := crewjamsaml.LogoutResponse{
			ID:           respID,
			InResponseTo: logoutReq.ID,
			Version:      "2.0",
			IssueInstant: time.Now().UTC(),
			Destination:  conn.IdpSloUrl,
			Issuer: &crewjamsaml.Issuer{
				Value: sp.EntityID,
			},
			Status: crewjamsaml.Status{
				StatusCode: crewjamsaml.StatusCode{
					Value: crewjamsaml.StatusSuccess,
				},
			},
		}

		var xmlBuf bytes.Buffer
		xmlBuf.WriteString(xml.Header)
		encoder := xml.NewEncoder(&xmlBuf)
		_ = encoder.Encode(logoutResp)

		var b bytes.Buffer
		w, _ := flate.NewWriter(&b, flate.DefaultCompression)
		w.Write(xmlBuf.Bytes())
		w.Close()
		samlResponseBase64 := base64.StdEncoding.EncodeToString(b.Bytes())

		redirectURL, _ := url.Parse(conn.IdpSloUrl)
		query := redirectURL.Query()
		query.Set("SAMLResponse", samlResponseBase64)
		if relayState != "" {
			query.Set("RelayState", relayState)
		}
		if conn.SignRequest && sp.Key != nil {
			rsaKey, ok := sp.Key.(*rsa.PrivateKey)
			if ok {
				sigAlg := "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
				if sp.SignatureMethod != "" {
					sigAlg = sp.SignatureMethod
				}
				query.Set("SigAlg", sigAlg)

				signString := "SAMLResponse=" + url.QueryEscape(samlResponseBase64)
				if relayState != "" {
					signString += "&RelayState=" + url.QueryEscape(relayState)
				}
				signString += "&SigAlg=" + url.QueryEscape(sigAlg)

				hasher := crypto.SHA256.New()
				hasher.Write([]byte(signString))
				hashed := hasher.Sum(nil)

				signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hashed)
				if err == nil {
					query.Set("Signature", base64.StdEncoding.EncodeToString(signature))
				}
			}
		}

		rawQuery := query.Encode()
		rawQuery = strings.ReplaceAll(rawQuery, "+", "%20")
		redirectURL.RawQuery = rawQuery

		c.Redirect(http.StatusFound, redirectURL.String())
		return
	}

	if samlResEncoded != "" {
		c.SetCookie(consts.SessionCookieName, "", -1, "/", "", h.Config.CookieSecure, true)

		if relayState != "" {
			c.Redirect(http.StatusFound, relayState)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out from external Identity Provider."})
		return
	}

	if connectionID == "" {
		logger.FromGin(c).Warn("Missing connection_id for SP-initiated SLO.",
			zap.String("method", c.Request.Method),
			zap.Bool("has_saml_request", samlReqEncoded != ""),
			zap.Bool("has_saml_response", samlResEncoded != ""),
		)
		if relayState != "" {
			c.Redirect(http.StatusFound, relayState)
		} else {
			payload.WriteSAMLError(c, http.StatusBadRequest, "invalid_request", "The connection_id query parameter is required for SP-initiated logout.", nil)
		}
		return
	}
	conn, connErr := h.SAMLUse.GetConnection(c.Request.Context(), tenantID, connectionID)
	if connErr != nil {
		logger.FromGin(c).Error("SAML Connection not found for SLO", zap.Error(connErr))
		if relayState != "" {
			c.Redirect(http.StatusFound, relayState)
		} else {
			payload.WriteSAMLError(c, http.StatusBadRequest, "connection_not_found", "The configured SAML connection could not be found for this tenant.", nil)
		}
		return
	}

	sp, err := h.samlBuilderUseCase.BuildServiceProvider(c.Request.Context(), tenantID, conn)
	if err != nil {
		logger.FromGin(c).Error("Failed to build SP for SLO", zap.Error(err))
		if relayState != "" {
			c.Redirect(http.StatusFound, relayState)
		}
		return
	}

	subject := ""

	idTokenHint := c.Query("id_token_hint")
	if idTokenHint != "" {
		allowedAlgs := []jose.SignatureAlgorithm{jose.RS256}
		token, err := jwt.ParseSigned(idTokenHint, allowedAlgs)
		if err == nil {
			_, cert, _, err := h.KeyMgr.GetActiveKeys(c.Request.Context(), "sig")
			if err != nil {
				logger.FromGin(c).Error("failed to load active SAML crypto keys")
			}
			if cert != nil {
				claims := &jwt.Claims{}
				if err := token.Claims(cert.PublicKey, claims); err == nil {
					subject = claims.Subject
				} else {
					logger.FromGin(c).Warn("id_token_hint signature verification failed during SAML SLO")
				}
			}
		}
	}

	if subject == "" {
		sessionCookie, _ := c.Cookie(consts.SessionCookieName)
		if sessionCookie != "" {
			subject = sessionCookie
		}
	}

	if subject == "" {
		logger.FromGin(c).Error("No valid subject found for SLO (stateless token missing/invalid)")
		payload.WriteSAMLError(c, http.StatusBadRequest, "invalid_request", "A subject is required to start SP-initiated logout.", nil)
		return
	}

	sloURL := conn.IdpSloUrl
	if sloURL == "" {
		sloURL = conn.IdpSingleSignOn
	}

	logoutReq, err := sp.MakeLogoutRequest(sloURL, subject)
	if err != nil {
		logger.FromGin(c).Warn("Failed to build SP Logout Request", zap.Error(err))
		if relayState != "" {
			c.Redirect(http.StatusFound, relayState)
		}
		return
	}
	redirectURL := logoutReq.Redirect(relayState)
	query := redirectURL.Query()
	if conn.SignRequest && sp.Key != nil {
		rsaKey, ok := sp.Key.(*rsa.PrivateKey)
		if !ok {
			logger.FromGin(c).Error("SAML SP Key is not an RSA private key, cannot sign")
		} else {
			sigAlg := "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
			if sp.SignatureMethod != "" {
				sigAlg = sp.SignatureMethod
			}

			query.Set("SigAlg", sigAlg)
			signString := "SAMLRequest=" + url.QueryEscape(query.Get("SAMLRequest"))
			if rs := query.Get("RelayState"); rs != "" {
				signString += "&RelayState=" + url.QueryEscape(rs)
			}
			signString += "&SigAlg=" + url.QueryEscape(sigAlg)

			hasher := crypto.SHA256.New()
			hasher.Write([]byte(signString))
			hashed := hasher.Sum(nil)

			signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hashed)
			if err != nil {
				logger.FromGin(c).Error("Failed to sign logout request URL", zap.Error(err))
			} else {
				query.Set("Signature", base64.StdEncoding.EncodeToString(signature))
			}
		}
	}

	rawQuery := query.Encode()
	rawQuery = strings.ReplaceAll(rawQuery, "+", "%20")
	redirectURL.RawQuery = rawQuery

	c.Redirect(http.StatusFound, redirectURL.String())
}

// resolveOutboundAttributes applies the SP's outbound attribute policy and returns
// the attributes to place in the assertion. When it returns ok=false it has
// already written a fail-closed response and the caller must return immediately.
//
//   - empty mapping          -> passthrough: release exactly the scope-gated
//     claims (A1). This holds on BOTH the normalized and non-normalized paths; an
//     earlier guard covered only the normalized one, so a federated
//     (non-normalized) login with an empty mapping had every attribute silently
//     stripped.
//   - non-empty, partial     -> pass: a mapping that resolves some of its sources
//     is legitimate; which claims a user has varies per user.
//   - non-empty, zero output -> fail closed (SAML Core 3.2.2.2): the identity
//     provider could not apply the configured mapping, so emit a Responder error
//     Response with no assertion rather than an attribute-less assertion the SP
//     cannot use.
//
// Map is currently infallible, but a mapping error is handled with the same
// fail-closed path rather than a fallback: were Map ever made fallible, an error
// must never fall through to an emitted assertion.
func (h *SAMLHandler) resolveOutboundAttributes(c *gin.Context, tenantID string, authReq *crewjamsaml.AuthnRequest,
	spClient *model.SAMLClient, secureClaims map[string]interface{}, relayState string) (map[string]interface{}, bool) {

	if len(spClient.AttributeMapping) == 0 {
		return secureClaims, true
	}

	mapped, mapErr := h.Mapper.Map(secureClaims, spClient.AttributeMapping)
	if mapErr != nil || len(mapped) == 0 {
		logger.FromGin(c).Error("SAML outbound attribute mapping could not be applied; failing closed",
			zap.Error(mapErr), zap.String("protocol", "saml"), zap.String("sp_entity_id", spClient.EntityID))
		htmlErr, genErr := h.samlBuilderUseCase.GenerateSAMLErrorResponse(c.Request.Context(), tenantID, authReq, spClient,
			crewjamsaml.StatusResponder, "The identity provider could not produce the required attributes.", relayState)
		if genErr != nil {
			logger.FromGin(c).Error("Failed to generate SAML error response", zap.Error(genErr), zap.String("protocol", "saml"))
			payload.AbortWithSAMLError(c, http.StatusInternalServerError, "server_error", "The SAML response could not be generated.", genErr)
			return nil, false
		}
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, htmlErr)
		return nil, false
	}
	return mapped, true
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// parseStoredAuthnRequest decodes a previously received SAMLRequest string (as it
// arrived on the wire: base64-encoded, and DEFLATE-compressed for the
// HTTP-Redirect binding) and unmarshals it into a full AuthnRequest, preserving
// every field the service provider sent (NameIDPolicy, ForceAuthn, and so on). It
// fails closed: a request that cannot be decoded or unmarshalled returns an error
// instead of an empty request that would silently fall back to service-provider
// defaults. Error values never carry the request body.
func parseStoredAuthnRequest(encoded string) (*crewjamsaml.AuthnRequest, error) {
	encoded = strings.ReplaceAll(encoded, " ", "+")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("SAMLRequest is not valid base64")
	}
	// HTTP-Redirect binding is DEFLATE-compressed; HTTP-POST is not. Inflate when
	// possible, otherwise use the decoded bytes as-is.
	flater := flate.NewReader(bytes.NewReader(decoded))
	if inflated, inflateErr := io.ReadAll(flater); inflateErr == nil {
		decoded = inflated
	}
	flater.Close()

	var authReq crewjamsaml.AuthnRequest
	if err := xml.Unmarshal(decoded, &authReq); err != nil {
		return nil, errors.New("SAMLRequest could not be unmarshalled")
	}
	return &authReq, nil
}

func setSAMLDiagnosticContext(c *gin.Context, tenantID, errorCode, failureStage string) {
	if tenantID != "" {
		c.Set("tenant_id", tenantID)
	}
	c.Set("protocol", "saml")
	if errorCode != "" {
		c.Set("error_code", errorCode)
		c.Header("X-Shyntr-Error-Code", errorCode)
	}
	if failureStage != "" {
		c.Set("failure_stage", failureStage)
	}
	c.Header("Cache-Control", "no-store")
}

func shortForLog(value string, max int) string {
	if value == "" || max <= 0 {
		return ""
	}
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func hashForLog(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
