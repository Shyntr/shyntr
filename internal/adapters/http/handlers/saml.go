package handlers

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	crewjamsaml "github.com/crewjam/saml"
	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/application/mapper"
	"github.com/nevzatcirak/shyntr/internal/application/port"
	"github.com/nevzatcirak/shyntr/internal/application/usecase"
	"github.com/nevzatcirak/shyntr/internal/application/utils"
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
	"github.com/nevzatcirak/shyntr/pkg/consts"
	"github.com/nevzatcirak/shyntr/pkg/logger"
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
	Audit              port.AuditLogger
	Mapper             *mapper.Mapper
	KeyMgr             *utils.KeyManager
	wh                 usecase.WebhookUseCase
}

func NewSAMLHandler(Config *config.Config, KeyMgr *utils.KeyManager, samlBuilderUseCase usecase.SamlBuilderUseCase, ClientUseCase usecase.OAuth2ClientUseCase, m *mapper.Mapper,
	AuthUse usecase.AuthUseCase, SAMLUse usecase.SAMLConnectionUseCase, OAuthSessionUse usecase.OAuth2SessionUseCase, Audit port.AuditLogger,
	SAMLClientUse usecase.SAMLClientUseCase, OIDCClientUse usecase.OAuth2ClientUseCase, wh usecase.WebhookUseCase) *SAMLHandler {
	return &SAMLHandler{Config: Config, KeyMgr: KeyMgr, samlBuilderUseCase: samlBuilderUseCase, ClientUseCase: ClientUseCase, Mapper: m, AuthUse: AuthUse, SAMLUse: SAMLUse, Audit: Audit,
		OAuthSessionUse: OAuthSessionUse, SAMLClientUse: SAMLClientUse, OIDCClientUse: OIDCClientUse, wh: wh}
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

	loginReq, err := h.AuthUse.GetLoginRequest(c, loginChallenge)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "login_request_not_found"})
		return
	}

	redirectURLOrHTML, requestID, err := h.samlBuilderUseCase.InitiateSSO(c.Request.Context(), tenantID, connectionID, loginChallenge)
	if err != nil {
		logger.FromGin(c).Error("Failed to initiate SAML SSO", zap.Error(err), zap.String("protocol", "saml"))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sso_init_failed", "details": err.Error()})
		return
	}

	if requestID != "" {
		loginReq.SAMLRequestID = requestID
		loginReq, err = h.AuthUse.CreateLoginRequest(c, loginReq)
		if err != nil {
			logger.FromGin(c).Error("Failed to save Login request", zap.Error(err), zap.String("protocol", "saml"))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "login_request_save_failed", "details": err.Error()})
			return
		}
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
		logger.FromGin(c).Warn("Missing RelayState in SAML Response", zap.String("protocol", "saml"))
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing_relay_state"})
		return
	}

	loginReq, err := h.AuthUse.GetLoginRequest(c, relayState)
	if err != nil {
		logger.FromGin(c).Warn("Invalid RelayState (LoginRequest not found)", zap.String("challenge", relayState), zap.String("protocol", "saml"))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid_session"})
		return
	}

	assertion, _, err := h.samlBuilderUseCase.HandleACS(c.Request.Context(), tenantID, c.Request, loginReq.SAMLRequestID)
	if err != nil {
		logger.FromGin(c).Warn("SAML ACS Validation Failed", zap.Error(err), zap.String("protocol", "saml"))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid_saml_response", "details": err.Error()})
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

	issuer := assertion.Issuer.Value
	conn, err := h.SAMLUse.GetConnectionByIdpEntity(c, tenantID, issuer)
	if err != nil {
		logger.FromGin(c).Warn("Connection not found for mapping, using raw attributes", zap.String("issuer", issuer), zap.String("protocol", "saml"))
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

	if conn.ID != "" {
		finalAttributes["idp"] = fmt.Sprintf("saml:%s", conn.ID)
	} else {
		finalAttributes["idp"] = "saml:unknown"
	}
	finalAttributes["amr"] = []string{"ext"}
	h.wh.FireEvent(tenantID, "user.login.ext", finalAttributes)

	h.Audit.Log(tenantID, subject, "auth.federated.saml.success", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{
		"issuer":        issuer,
		"connection_id": conn.ID,
	})

	loginReq.Authenticated = true
	loginReq.Subject = subject
	loginReq.UpdatedAt = time.Now()

	var existingCtx map[string]interface{}
	if len(loginReq.Context) > 0 {
		_ = json.Unmarshal(loginReq.Context, &existingCtx)
	} else {
		existingCtx = make(map[string]interface{})
	}

	existingCtx["login_claims"] = finalAttributes
	mergedBytes, _ := json.Marshal(existingCtx)
	loginReq.Context = mergedBytes
	loginReq, err = h.AuthUse.CreateLoginRequest(c, loginReq)
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
		redirectPath := loginReq.RequestURL
		if !strings.HasPrefix(redirectPath, "http") {
			base := strings.TrimSuffix(h.Config.BaseIssuerURL, "/")
			if !strings.HasPrefix(redirectPath, "/") {
				redirectPath = "/" + redirectPath
			}
			redirectPath = base + redirectPath
		}
		if strings.Contains(redirectPath, "?") {
			redirectTo = fmt.Sprintf("%s&login_verifier=%s", redirectPath, loginReq.ID)
		} else {
			redirectTo = fmt.Sprintf("%s?login_verifier=%s", redirectPath, loginReq.ID)
		}
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

	authReq, err := h.samlBuilderUseCase.ParseAuthnRequest(c.Request.Context(), tenantID, c.Request)
	if err != nil {
		logger.FromGin(c).Error("Failed to parse SAML AuthnRequest", zap.Error(err), zap.String("protocol", "saml"))
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_saml_request", "details": err.Error()})
		return
	}

	spClient, err := h.SAMLClientUse.GetClientByEntityID(c, tenantID, authReq.Issuer.Value)
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

	loginReq := entity.LoginRequest{
		ID:         fmt.Sprintf("req-%d", time.Now().UnixNano()),
		TenantID:   tenantID,
		RequestURL: fmt.Sprintf("%s/t/%s/saml/idp/sso", h.Config.BaseIssuerURL, tenantID),
		ClientID:   spClient.ID,
		ClientIP:   c.ClientIP(),
		Protocol:   "saml",
		Context:    ctxBytes,
		Active:     true,
		CreatedAt:  time.Now(),
	}

	savedLoginReq, err := h.AuthUse.CreateLoginRequest(c, &loginReq)
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

	spClient, err := h.SAMLClientUse.GetClientByEntityID(c, tenantID, logoutReq.Issuer.Value)
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

		activeSession, err := h.OAuthSessionUse.GetBySubject(c, subject, spClient.ID)
		if err != nil {
			logger.FromGin(c).Error("active session not found", zap.String("entity_id", logoutReq.NameID.Value),
				zap.String("entity_id", spClient.EntityID), zap.Error(err))
			return
		}
		issuer := fmt.Sprintf("%s/t/%s/oauth2", h.Config.BaseIssuerURL, tenantID)

		oidcClient, clientErr := h.OIDCClientUse.GetClient(c, activeSession.ClientID)
		if clientErr == nil {
			if oidcClient.BackchannelLogoutURI != "" {
				h.ClientUseCase.SendBackchannelLogout(oidcClient.ID, oidcClient.BackchannelLogoutURI, subject, issuer)
			}
		}

		err = h.OAuthSessionUse.DeleteBySubject(c, subject, activeSession.ClientID)
		h.Audit.Log(tenantID, subject, "auth.slo.saml.idp_initiated", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{
			"issuer": logoutReq.Issuer.Value,
			"status": err == nil,
		})

		if err != nil {
			logger.FromGin(c).Warn("Failed to delete user Fosite sessions during SLO",
				zap.String("subject", subject),
				zap.Error(err))
		} else {
			logger.FromGin(c).Info("Successfully revoked OAuth2 sessions and dispatched Back-Channel logouts during SAML SLO",
				zap.String("subject", subject))
		}
	}

	relayState := c.Query("RelayState")
	htmlForm, err := h.samlBuilderUseCase.GenerateLogoutResponse(c, tenantID, logoutReq, spClient, relayState)
	if err != nil {
		logger.FromGin(c).Error("Failed to generate SLO response", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed_to_generate_response"})
		return
	}

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

	loginReq, loginReqErr := h.AuthUse.GetLoginRequest(c, loginChallenge)
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

	spClient, spClientErr := h.SAMLClientUse.GetClientByEntityID(c, tenantID, issuer)
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

	finalAttrs, err := h.Mapper.Map(userAttrs, spClient.AttributeMapping)
	if err != nil {
		logger.FromGin(c).Warn("Outbound mapping failed", zap.Error(err), zap.String("protocol", "saml"))
		finalAttrs = userAttrs
	}

	htmlResponse, err := h.samlBuilderUseCase.GenerateSAMLResponse(c.Request.Context(), tenantID, authReq, spClient, finalAttrs, relayState)
	if err != nil {
		logger.FromGin(c).Error("Failed to generate SAML Response", zap.Error(err), zap.String("protocol", "saml"))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "response_generation_failed"})
		return
	}

	h.Audit.Log(tenantID, loginReq.Subject, "auth.saml.assertion.issued", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{
		"sp_entity_id": spClient.EntityID,
		"acs_url":      authReq.AssertionConsumerServiceURL,
	})
	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, htmlResponse)
}

func (h *SAMLHandler) SPSLOInitiate(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	connectionID := c.Query("connection_id")
	relayState := c.Query("RelayState")

	conn, connErr := h.SAMLUse.GetConnectionByIdpEntity(c, tenantID, connectionID)
	if connectionID == "" {
		logger.FromGin(c).Warn("SAML Connection is empty.")
		if relayState != "" {
			c.Redirect(http.StatusFound, relayState)
		}
		return
	}
	if connErr != nil {
		logger.FromGin(c).Error("SAML Connection not found for SLO", zap.Error(connErr))
		if relayState != "" {
			c.Redirect(http.StatusFound, relayState)
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

		rawQuery := query.Encode()
		rawQuery = strings.ReplaceAll(rawQuery, "+", "%20")
		redirectURL.RawQuery = rawQuery

		h.Audit.Log(tenantID, subject, "auth.slo.saml.sp_initiated", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{
			"connection_id": connectionID,
			"slo_url":       sloURL,
		})
		c.Redirect(http.StatusFound, redirectURL.String())
	}
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
