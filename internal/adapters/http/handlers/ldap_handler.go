package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/http/payload"
	"github.com/Shyntr/shyntr/internal/application/mapper"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// LDAPHandler handles the user-facing LDAP username/password login flow.
type LDAPHandler struct {
	cfg    *config.Config
	auth   usecase.AuthUseCase
	ldap   usecase.LDAPConnectionUseCase
	wh     usecase.WebhookUseCase
	mapper *mapper.Mapper
}

func NewLDAPHandler(
	cfg *config.Config,
	auth usecase.AuthUseCase,
	ldap usecase.LDAPConnectionUseCase,
	wh usecase.WebhookUseCase,
	m *mapper.Mapper,
) *LDAPHandler {
	return &LDAPHandler{cfg: cfg, auth: auth, ldap: ldap, wh: wh, mapper: m}
}

// ldapLoginRequest is the JSON body accepted by the LDAP login endpoint.
type ldapLoginRequest struct {
	LoginChallenge string `json:"login_challenge" binding:"required"`
	Username       string `json:"username" binding:"required"`
	Password       string `json:"password" binding:"required"`
}

// Login godoc
// @Summary LDAP Username/Password Login
// @Description Authenticates a user against an LDAP/Active-Directory Identity Provider and completes the login challenge.
// @Tags LDAP Federation
// @Accept json
// @Produce html
// @Param tenant_id path string true "Tenant ID"
// @Param connection_id path string true "LDAP Connection ID"
// @Param request body ldapLoginRequest true "Login credentials and challenge"
// @Success 302 {string} string "Redirects back to the relying party with a login_verifier"
// @Failure 400 {object} map[string]string "Bad Request"
// @Failure 401 {object} map[string]string "Unauthorized (invalid credentials or user not found)"
// @Failure 404 {object} map[string]string "Login request not found"
// @Failure 500 {object} map[string]string "Internal Server Error"
// @Router /t/{tenant_id}/ldap/login/{connection_id} [post]
func (h *LDAPHandler) Login(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	connectionID := c.Param("connection_id")

	var req ldapLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		payload.WriteOIDCError(c, http.StatusBadRequest, "invalid_request", "Missing required fields: login_challenge, username, password.", err)
		return
	}

	// Validate the login challenge is still active.
	loginReq, err := h.auth.GetLoginRequest(c.Request.Context(), req.LoginChallenge)
	if err != nil {
		payload.WriteOIDCError(c, http.StatusNotFound, "login_request_not_found", "The login request was not found or has expired.", err)
		return
	}

	// Authenticate against LDAP; audit events are emitted inside AuthenticateUser.
	entry, err := h.ldap.AuthenticateUser(c.Request.Context(), tenantID, connectionID, req.Username, req.Password)
	if err != nil {
		logger.FromGin(c).Warn("LDAP authentication failed",
			zap.String("tenant_id", tenantID),
			zap.String("connection_id", connectionID),
			zap.String("protocol", "ldap"),
		)
		// Never expose internal LDAP error details to the client.
		payload.WriteOIDCError(c, http.StatusUnauthorized, "invalid_credentials", "Authentication failed. Check your username and password.", nil)
		return
	}

	// Fetch the connection to access its AttributeMapping.
	conn, err := h.ldap.GetConnection(c.Request.Context(), tenantID, connectionID)
	if err != nil {
		payload.WriteOIDCError(c, http.StatusInternalServerError, "server_error", "The configured LDAP connection could not be found for this tenant.", err)
		return
	}

	// Convert the LDAP entry attributes to a flat map suitable for attribute mapping.
	rawAttrs := make(map[string]interface{}, len(entry.Attributes)+1)
	for k, vs := range entry.Attributes {
		if len(vs) == 1 {
			rawAttrs[k] = vs[0]
		} else {
			rawAttrs[k] = vs
		}
	}
	rawAttrs["dn"] = entry.DN

	finalAttributes, err := h.mapper.Map(rawAttrs, conn.AttributeMapping)
	if err != nil {
		logger.FromGin(c).Warn("LDAP attribute mapping failed, using raw attributes",
			zap.Error(err), zap.String("protocol", "ldap"))
		finalAttributes = rawAttrs
	}

	// Determine the subject — prefer the mapped DN, fall back to username.
	subject := req.Username
	if dn, ok := finalAttributes["dn"].(string); ok && dn != "" {
		subject = dn
	}

	finalAttributes["source"] = "ldap"
	finalAttributes["connection_id"] = connectionID
	finalAttributes["idp"] = fmt.Sprintf("ldap:%s", connectionID)
	finalAttributes["amr"] = []string{"pwd"}
	if _, ok := finalAttributes["sub"]; !ok {
		finalAttributes["sub"] = subject
	}

	h.wh.FireEvent(tenantID, "user.login.ext", finalAttributes)

	// Merge login_claims into the existing login request context.
	existingCtx := make(map[string]interface{})
	if len(loginReq.Context) > 0 {
		_ = json.Unmarshal(loginReq.Context, &existingCtx)
	}
	existingCtx["login_claims"] = finalAttributes

	loginReq, err = h.auth.CompleteProviderLogin(
		c.Request.Context(),
		req.LoginChallenge,
		subject,
		conn.Name,
		existingCtx,
		c.ClientIP(),
		c.Request.UserAgent(),
	)
	if err != nil {
		logger.FromGin(c).Error("Failed to complete LDAP login", zap.Error(err), zap.String("protocol", "ldap"))
		payload.WriteOIDCError(c, http.StatusInternalServerError, "server_error", "Failed to complete the LDAP login and resume the authentication flow.", err)
		return
	}

	// Redirect back to the relying party — same logic as OIDCHandler.Callback.
	var redirectTo string
	if loginReq.Protocol == "saml" {
		redirectTo = fmt.Sprintf("%s/t/%s/saml/resume?login_challenge=%s",
			strings.TrimSuffix(h.cfg.BaseIssuerURL, "/"),
			tenantID,
			loginReq.ID,
		)
	} else {
		parsedURL, err := url.Parse(loginReq.RequestURL)
		if err != nil {
			payload.WriteOIDCError(c, http.StatusInternalServerError, "server_error", "The original redirect URL stored for the login request is invalid.", err)
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
		base := strings.TrimSuffix(h.cfg.BaseIssuerURL, "/")
		redirectTo = fmt.Sprintf("%s%s?%s", base, safePath, query.Encode())
	}
	c.Redirect(http.StatusFound, redirectTo)
}
