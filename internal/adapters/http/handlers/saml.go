package handlers

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/application/mapper"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	"github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/Shyntr/shyntr/internal/domain/entity"
	"github.com/Shyntr/shyntr/pkg/consts"
	"github.com/Shyntr/shyntr/pkg/logger"
	utils2 "github.com/Shyntr/shyntr/pkg/utils"
	crewjamsaml "github.com/crewjam/saml"
	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v3/jwt"
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
	KeyMgr             *utils.KeyManager
	wh                 usecase.WebhookUseCase
	ScopeUse           usecase.ScopeUseCase
}

func NewSAMLHandler(Config *config.Config, KeyMgr *utils.KeyManager, samlBuilderUseCase usecase.SamlBuilderUseCase, ClientUseCase usecase.OAuth2ClientUseCase, m *mapper.Mapper,
	AuthUse usecase.AuthUseCase, SAMLUse usecase.SAMLConnectionUseCase, OAuthSessionUse usecase.OAuth2SessionUseCase,
	SAMLClientUse usecase.SAMLClientUseCase, OIDCClientUse usecase.OAuth2ClientUseCase, wh usecase.WebhookUseCase, ScopeUse usecase.ScopeUseCase) *SAMLHandler {
	return &SAMLHandler{Config: Config, KeyMgr: KeyMgr, samlBuilderUseCase: samlBuilderUseCase, ClientUseCase: ClientUseCase, Mapper: m, AuthUse: AuthUse, SAMLUse: SAMLUse,
		OAuthSessionUse: OAuthSessionUse, SAMLClientUse: SAMLClientUse, OIDCClientUse: OIDCClientUse, wh: wh, ScopeUse: ScopeUse}
}

func (h *SAMLHandler) SPMetadata(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Config.DefaultTenantID
	}

	sp, err := h.samlBuilderUseCase.BuildServiceProvider(c.Request.Context(), tenantID, nil)
	if err != nil {
		logger.FromGin(c).Error("Failed to initialize SP", zap.Error(err), zap.String("protocol", "saml"))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "saml_initialization_failed"})
		return
	}

	metaDesc := sp.Metadata()

	c.Header("Content-Type", "application/xml")
	if err := xml.NewEncoder(c.Writer).Encode(metaDesc); err != nil {
		logger.FromGin(c).Error("Failed to write metadata XML", zap.Error(err), zap.String("protocol", "saml"))
	}
}

func (h *SAMLHandler) Login(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Config.DefaultTenantID
	}
	connectionID := c.Param("connection_id")
	loginChallenge := c.Query("login_challenge")

	if loginChallenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_login_challenge"})
		return
	}

	loginReq, err := h.AuthUse.GetLoginRequest(c.Request.Context(), loginChallenge)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "login_request_not_found"})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sso_init_failed", "details": err.Error()})
		return
	}

	var ctxData map[string]interface{}
	if len(loginReq.Context) > 0 {
		_ = json.Unmarshal(loginReq.Context, &ctxData)
	} else {
		ctxData = make(map[string]interface{})
	}
	ctxData["connection_id"] = connectionID
	hash := sha256.Sum256([]byte(csrfToken))
	ctxData["csrf_hash"] = hex.EncodeToString(hash[:])

	loginReq.Context, _ = json.Marshal(ctxData)
	loginReq.Context, _ = json.Marshal(ctxData)
	if requestID != "" {
		loginReq.SAMLRequestID = requestID
	}

	loginReq, err = h.AuthUse.UpdateLoginRequest(c.Request.Context(), loginReq)
	if err != nil {
		logger.FromGin(c).Error("Failed to save Login request", zap.Error(err), zap.String("protocol", "saml"))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "login_request_save_failed", "details": err.Error()})
		return
	}

	if strings.HasPrefix(strings.TrimSpace(redirectURLOrHTML), "<") {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(redirectURLOrHTML))
	} else {
		c.Redirect(http.StatusFound, redirectURLOrHTML)
	}
}

func (h *SAMLHandler) ACS(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Config.DefaultTenantID
	}

	relayState := c.PostForm("RelayState")
	if relayState == "" {
		relayState = c.Query("RelayState")
	}
	if relayState == "" {
		logger.FromGin(c).Error("SAML ACS failed: RelayState is completely missing")
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing_relay_state"})
		return
	}

	csrfCookie, err := c.Cookie("shyntr_fed_csrf")
	if err != nil || csrfCookie == "" {
		logger.FromGin(c).Warn("Missing CSRF Cookie on ACS")
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "missing_csrf_cookie"})
		return
	}
	c.SetCookie("shyntr_fed_csrf", "", -1, "/", "", h.Config.CookieSecure, true)

	loginChallenge := relayState

	loginReq, err := h.AuthUse.GetLoginRequest(c.Request.Context(), loginChallenge)
	if err != nil {
		logger.FromGin(c).Warn("Invalid RelayState (LoginRequest not found)", zap.String("challenge", loginChallenge))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid_session"})
		return
	}

	var ctxData map[string]interface{}
	_ = json.Unmarshal(loginReq.Context, &ctxData)
	expectedCsrfHash, _ := ctxData["csrf_hash"].(string)
	actualHash := sha256.Sum256([]byte(csrfCookie))
	if hex.EncodeToString(actualHash[:]) != expectedCsrfHash {
		logger.FromGin(c).Error("CSRF Flow Hijacking Attempt!")
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid_csrf_token"})
		return
	}
	expectedConnID, ok := ctxData["connection_id"].(string)
	if !ok || expectedConnID == "" {
		logger.FromGin(c).Error("Missing connection_id in session state")
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid_session_state"})
		return
	}
	assertion, _, err := h.samlBuilderUseCase.HandleACS(c.Request.Context(), tenantID, c.Request, loginReq.SAMLRequestID)
	conn, err := h.SAMLUse.GetConnection(c.Request.Context(), tenantID, expectedConnID)
	if err != nil {
		logger.FromGin(c).Warn("Connection not found for stored state", zap.String("connection_id", expectedConnID))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "connection_not_found"})
		return
	}

	issuer := assertion.Issuer.Value
	if issuer != conn.IdpEntityID {
		logger.FromGin(c).Error("SAML Signature Wrapping (XSW) / Issuer Mismatch Detected!",
			zap.String("expected", conn.IdpEntityID), zap.String("actual", issuer))
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_issuer"})
		return
	}
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
		logger.FromGin(c).Warn("Attribute mapping failed", zap.Error(err), zap.String("protocol", "saml"))
		finalAttributes = rawAttributes
	}

	subject := assertion.Subject.NameID.Value
	finalAttributes["sub"] = subject
	finalAttributes["source"] = "saml"
	finalAttributes["issuer"] = issuer

	finalAttributes["idp"] = fmt.Sprintf("saml:%s", conn.ID)
	finalAttributes["amr"] = []string{"ext"}
	h.wh.FireEvent(tenantID, "user.login.ext", finalAttributes)

	var existingCtx map[string]interface{}
	if len(loginReq.Context) > 0 {
		_ = json.Unmarshal(loginReq.Context, &existingCtx)
	} else {
		existingCtx = make(map[string]interface{})
	}

	existingCtx["login_claims"] = finalAttributes
	loginReq, err = h.AuthUse.CompleteProviderLogin(c.Request.Context(), relayState, subject, existingCtx, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		logger.FromGin(c).Error("Failed to update login request", zap.Error(err), zap.String("protocol", "saml"))
		c.AbortWithStatus(http.StatusInternalServerError)
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
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "invalid_redirect_url"})
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

func (h *SAMLHandler) IDPMetadata(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Config.DefaultTenantID
	}

	idp, err := h.samlBuilderUseCase.GetIdentityProvider(c.Request.Context(), tenantID)
	if err != nil {
		logger.FromGin(c).Error("Failed to initialize IdP", zap.Error(err), zap.String("protocol", "saml"))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "idp_init_failed"})
		return
	}

	metaDesc := idp.Metadata()

	if len(metaDesc.IDPSSODescriptors) > 0 {
		metaDesc.IDPSSODescriptors[0].NameIDFormats = []crewjamsaml.NameIDFormat{
			crewjamsaml.PersistentNameIDFormat,
			crewjamsaml.EmailAddressNameIDFormat,
			crewjamsaml.UnspecifiedNameIDFormat,
			crewjamsaml.TransientNameIDFormat,
		}
	}

	c.Header("Content-Type", "application/xml")
	if err := xml.NewEncoder(c.Writer).Encode(metaDesc); err != nil {
		logger.FromGin(c).Error("Failed to write metadata XML", zap.Error(err), zap.String("protocol", "saml"))
	}
}

func (h *SAMLHandler) IDPSSO(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Config.DefaultTenantID
	}

	loginVerifier := c.Query("login_verifier")
	if loginVerifier != "" {
		loginReq, err := h.AuthUse.GetAuthenticatedLoginRequest(c.Request.Context(), loginVerifier)
		if err != nil {
			logger.FromGin(c).Error("Invalid login verifier for SAML IdP", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_login_verifier"})
			return
		}

		spClient, err := h.SAMLClientUse.GetClient(c.Request.Context(), tenantID, loginReq.ClientID)
		if err != nil {
			logger.FromGin(c).Error("SP Client not found", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "sp_not_found"})
			return
		}

		origURL, _ := url.Parse(loginReq.RequestURL)
		samlReqBase64 := origURL.Query().Get("SAMLRequest")
		relayState := origURL.Query().Get("RelayState")

		var requestID, acsURL, issuer string
		if samlReqBase64 != "" {
			samlReqBase64 = strings.ReplaceAll(samlReqBase64, " ", "+")
			decoded, err := base64.StdEncoding.DecodeString(samlReqBase64)
			if err == nil {
				flater := flate.NewReader(bytes.NewReader(decoded))
				inflated, err := io.ReadAll(flater)
				flater.Close()
				if err == nil {
					decoded = inflated
				}

				var tempReq struct {
					ID                          string `xml:"ID,attr"`
					AssertionConsumerServiceURL string `xml:"AssertionConsumerServiceURL,attr"`
					Issuer                      struct {
						Value string `xml:",chardata"`
					} `xml:"Issuer"`
				}
				_ = xml.Unmarshal(decoded, &tempReq)
				requestID = tempReq.ID
				acsURL = tempReq.AssertionConsumerServiceURL
				issuer = tempReq.Issuer.Value
			}
		}

		if acsURL == "" {
			acsURL = spClient.ACSURL
		}
		if issuer == "" {
			issuer = spClient.EntityID
		}

		authReq := &crewjamsaml.AuthnRequest{
			ID:                          requestID,
			AssertionConsumerServiceURL: acsURL,
			Issuer: &crewjamsaml.Issuer{
				Value: issuer,
			},
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

		finalAttrs, err := h.Mapper.Map(secureClaims, spClient.AttributeMapping)
		if err != nil {
			logger.FromGin(c).Warn("Outbound mapping failed", zap.Error(err), zap.String("protocol", "saml"))
			finalAttrs = secureClaims
		}

		htmlForm, err := h.samlBuilderUseCase.GenerateSAMLResponse(c.Request.Context(), tenantID, authReq, spClient, finalAttrs, relayState)
		if err != nil {
			logger.FromGin(c).Error("Failed to generate SAML Response", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "saml_response_generation_failed"})
			return
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing SAMLRequest parameter"})
		return
	}

	authReq, err := h.samlBuilderUseCase.ParseAuthnRequest(c.Request.Context(), tenantID, c.Request)
	if err != nil {
		logger.FromGin(c).Error("Failed to parse SAML AuthnRequest", zap.Error(err), zap.String("protocol", "saml"))
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_saml_request", "details": err.Error()})
		return
	}

	spClient, err := h.SAMLClientUse.GetClientByEntityID(c.Request.Context(), tenantID, authReq.Issuer.Value)
	if err != nil {
		logger.FromGin(c).Warn("Unknown SP EntityID", zap.String("entity_id", authReq.Issuer.Value), zap.String("protocol", "saml"))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "unknown_service_provider"})
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

	loginReq := entity.LoginRequest{
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
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}

	redirectURL := fmt.Sprintf("%s?login_challenge=%s", h.Config.ExternalLoginURL, savedLoginReq.ID)
	c.Redirect(http.StatusFound, redirectURL)
}

func (h *SAMLHandler) IDPSLO(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Config.DefaultTenantID
	}

	logoutReq, err := h.samlBuilderUseCase.ParseLogoutRequest(c.Request)
	if err != nil {
		logger.FromGin(c).Error("Invalid SLO Request", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_logout_request"})
		return
	}

	if logoutReq.Issuer == nil || logoutReq.Issuer.Value == "" {
		logger.FromGin(c).Error("Missing Issuer in SLO Request")
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing_issuer"})
		return
	}

	spClient, err := h.SAMLClientUse.GetClientByEntityID(c.Request.Context(), tenantID, logoutReq.Issuer.Value)
	if err != nil {
		logger.FromGin(c).Warn("Unknown SP in SLO", zap.String("entity_id", logoutReq.Issuer.Value))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "unknown_sp"})
		return
	}

	if spClient.SLOURL == "" {
		logger.FromGin(c).Warn("SP does not have SLO URL configured", zap.String("entity_id", spClient.EntityID))
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "sp_slo_not_configured"})
		return
	}

	if spClient.SPCertificate != "" && c.Request.Method == http.MethodGet {
		if err := verifyRedirectSignature(c.Request, spClient.SPCertificate); err != nil {
			logger.FromGin(c).Error("SAML SLO Signature Verification Failed! Possible session riding attempt.",
				zap.String("entity_id", spClient.EntityID), zap.Error(err))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_signature"})
			return
		}
		logger.FromGin(c).Info("SAML SLO request signature verified successfully", zap.String("sp", spClient.EntityID))
	}

	c.SetCookie(consts.SessionCookieName, "", -1, "/", "", h.Config.CookieSecure, true)

	if logoutReq.NameID != nil && logoutReq.NameID.Value != "" {
		subject := logoutReq.NameID.Value

		activeSession, err := h.OAuthSessionUse.GetBySubject(c.Request.Context(), subject, spClient.ID)
		if err != nil {
			logger.FromGin(c).Error("active session not found", zap.String("entity_id", logoutReq.NameID.Value),
				zap.String("entity_id", spClient.EntityID), zap.Error(err))
		} else {
			issuer := fmt.Sprintf("%s/t/%s/oauth2", h.Config.BaseIssuerURL, tenantID)

			oidcClient, clientErr := h.OIDCClientUse.GetClient(c.Request.Context(), activeSession.ClientID)
			if clientErr == nil {
				if oidcClient.BackchannelLogoutURI != "" {
					h.ClientUseCase.SendBackchannelLogout(oidcClient.ID, oidcClient.BackchannelLogoutURI, subject, issuer)
				}
			}

			err = h.OAuthSessionUse.DeleteBySubject(c.Request.Context(), subject, activeSession.ClientID)
			h.OAuthSessionUse.RecordLogout(c.Request.Context(), spClient.ID, c.ClientIP(), c.Request.UserAgent(), false)
		}
	}

	relayState := c.Query("RelayState")
	htmlForm, err := h.samlBuilderUseCase.GenerateLogoutResponse(c.Request.Context(), tenantID, logoutReq, spClient, relayState)
	if err != nil {
		logger.FromGin(c).Error("Failed to generate SAML Logout Response", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "saml_logout_response_generation_failed"})
		return
	}

	c.Writer.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';")
	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, htmlForm)
}

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

	if !loginReq.Authenticated {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication_pending"})
		return
	}

	if loginReq.Protocol != "saml" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_protocol"})
		return
	}

	var ctxData map[string]interface{}
	if err := json.Unmarshal(loginReq.Context, &ctxData); err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "corrupt_session_context"})
		return
	}

	relayState, _ := ctxData["relay_state_raw"].(string)
	requestID, _ := ctxData["request_id"].(string)
	acsURL, _ := ctxData["acs_url"].(string)
	issuer, _ := ctxData["issuer"].(string)

	authReq := &crewjamsaml.AuthnRequest{
		ID:                          requestID,
		AssertionConsumerServiceURL: acsURL,
		Issuer: &crewjamsaml.Issuer{
			Value: issuer,
		},
	}

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
		allowedScopeEntities = []*entity.Scope{}
	}

	secureClaims := utils.MapClaims(loginReq.Subject, userAttrs, allowedScopeEntities)

	finalAttrs, err := h.Mapper.Map(secureClaims, spClient.AttributeMapping)
	if err != nil {
		logger.FromGin(c).Warn("Outbound mapping failed", zap.Error(err), zap.String("protocol", "saml"))
		finalAttrs = secureClaims
	}

	htmlResponse, err := h.samlBuilderUseCase.GenerateSAMLResponse(c.Request.Context(), tenantID, authReq, spClient, finalAttrs, relayState)
	if err != nil {
		logger.FromGin(c).Error("Failed to generate SAML Response", zap.Error(err), zap.String("protocol", "saml"))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "response_generation_failed"})
		return
	}

	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, htmlResponse)
}

func (h *SAMLHandler) SPSLO(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Config.DefaultTenantID
	}

	samlReqEncoded := c.Query("SAMLRequest")
	samlResEncoded := c.Query("SAMLResponse")
	connectionID := c.Query("connection_id")
	relayState := c.Query("RelayState")

	if samlReqEncoded != "" {
		logoutReq, err := h.samlBuilderUseCase.ParseLogoutRequest(c.Request)
		if err != nil {
			logger.FromGin(c).Error("Invalid IdP SLO Request", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_logout_request"})
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
			_ = h.OAuthSessionUse.DeleteBySubject(c.Request.Context(), subject, "")
			logger.FromGin(c).Info("IdP-Initiated SLO successful, local sessions destroyed", zap.String("subject", subject))
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
		logger.FromGin(c).Warn("SAML Connection is empty for SP-initiated SLO.")
		if relayState != "" {
			c.Redirect(http.StatusFound, relayState)
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "connection_id_required"})
		}
		return
	}
	conn, connErr := h.SAMLUse.GetConnection(c.Request.Context(), tenantID, connectionID)
	if connErr != nil {
		logger.FromGin(c).Error("SAML Connection not found for SLO", zap.Error(connErr))
		if relayState != "" {
			c.Redirect(http.StatusFound, relayState)
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "connection_not_found"})
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
		token, err := jwt.ParseSigned(idTokenHint)
		if err == nil {
			_, cert := h.KeyMgr.GetActiveKeys()
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "subject_required_for_slo"})
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

func verifyRedirectSignature(req *http.Request, certPEM string) error {
	query := req.URL.Query()
	sig := query.Get("Signature")
	sigAlg := query.Get("SigAlg")

	if sig == "" || sigAlg == "" {
		return errors.New("missing Signature or SigAlg in request")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return errors.New("invalid signature base64 format")
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return errors.New("failed to parse SP certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("invalid SP X509 certificate")
	}

	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("SP certificate is not an RSA public key")
	}

	escape := func(s string) string {
		return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
	}

	var parts []string
	if samlReq := query.Get("SAMLRequest"); samlReq != "" {
		parts = append(parts, "SAMLRequest="+escape(samlReq))
	} else if samlRes := query.Get("SAMLResponse"); samlRes != "" {
		parts = append(parts, "SAMLResponse="+escape(samlRes))
	}
	if rs := query.Get("RelayState"); rs != "" {
		parts = append(parts, "RelayState="+escape(rs))
	}
	parts = append(parts, "SigAlg="+escape(sigAlg))
	signString := strings.Join(parts, "&")

	var hash crypto.Hash
	if strings.HasSuffix(sigAlg, "rsa-sha256") {
		hash = crypto.SHA256
	} else if strings.HasSuffix(sigAlg, "rsa-sha1") {
		hash = crypto.SHA1
	} else if strings.HasSuffix(sigAlg, "rsa-sha512") {
		hash = crypto.SHA512
	} else {
		return errors.New("unsupported signature algorithm: " + sigAlg)
	}

	hasher := hash.New()
	hasher.Write([]byte(signString))
	hashed := hasher.Sum(nil)

	return rsa.VerifyPKCS1v15(rsaPub, hash, hashed, sigBytes)
}
