package usecase

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/http/payload"
	"github.com/Shyntr/shyntr/internal/application/port"
	utils2 "github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/Shyntr/shyntr/pkg/crypto"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/Shyntr/shyntr/pkg/utils"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type OAuth2ClientUseCase interface {
	InitiateAuth(ctx context.Context, tenantID, connectionID, loginChallenge, csrfToken string) (string, map[string]interface{}, error)
	VerifyState(encryptedState, csrfToken string) (loginChallenge, connectionID string, err error)
	ExchangeAndUserInfo(ctx context.Context, tenantID, code, connectionID, codeVerifier, expectedNonce string) (map[string]interface{}, error)
	SendBackchannelLogout(ctx context.Context, clientID, logoutURI, subject, issuer string)
	CreateClient(ctx context.Context, client *model.OAuth2Client, unhashedSecret string, actorIP, userAgent string) (*model.OAuth2Client, string, error)
	UpdateClient(ctx context.Context, client *model.OAuth2Client, unhashedSecret string, actorIP, userAgent string) (*model.OAuth2Client, string, error)
	GetClient(ctx context.Context, clientID string) (*model.OAuth2Client, error)
	GetClientCount(ctx context.Context, tenantID string) (int64, error)
	GetPublicClientCount(ctx context.Context, tenantID string) (int64, error)
	GetConfidentialClientCount(ctx context.Context, tenantID string) (int64, error)
	GetClientByTenant(ctx context.Context, tenantID, clientID string) (*model.OAuth2Client, error)
	DeleteClient(ctx context.Context, tenantID, clientID string, actorIP, userAgent string) error
	ListClients(ctx context.Context, tenantID string) ([]*payload.OAuth2ClientResponse, error)
}

type oauth2ClientUseCase struct {
	repo     port.OAuth2ClientRepository
	connRepo port.OIDCConnectionRepository
	tenant   port.TenantRepository
	audit    port.AuditLogger
	hasher   port.SecretHasher
	keyMgr   utils2.KeyManager
	Config   *config.Config
}

type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	Issuer                string `json:"issuer"`
}

func NewOAuth2ClientUseCase(repo port.OAuth2ClientRepository, connRepo port.OIDCConnectionRepository, tenant port.TenantRepository,
	audit port.AuditLogger, hasher port.SecretHasher, keyMgr utils2.KeyManager, cfg *config.Config) OAuth2ClientUseCase {
	return &oauth2ClientUseCase{
		repo:     repo,
		connRepo: connRepo,
		tenant:   tenant,
		audit:    audit,
		hasher:   hasher,
		keyMgr:   keyMgr,
		Config:   cfg,
	}
}

func (u *oauth2ClientUseCase) InitiateAuth(ctx context.Context, tenantID, connectionID, loginChallenge, csrfToken string) (string, map[string]interface{}, error) {
	conn, err := u.connRepo.GetByTenantAndID(ctx, tenantID, connectionID)
	if err != nil {
		return "", nil, fmt.Errorf("connection not found: %w", err)
	}

	if conn.AuthorizationEndpoint == "" || conn.TokenEndpoint == "" {
		if conn.IssuerURL == "" {
			return "", nil, errors.New("neither endpoints nor issuer_url provided")
		}
		discovered, err := u.discoverEndpoints(ctx, conn.IssuerURL)
		if err != nil {
			return "", nil, fmt.Errorf("oidc discovery failed: %w", err)
		}
		conn.AuthorizationEndpoint = discovered.AuthorizationEndpoint
		conn.TokenEndpoint = discovered.TokenEndpoint
		conn.UserInfoEndpoint = discovered.UserInfoEndpoint
		conn.JWKSURI = discovered.JWKSURI
		conn.EndSessionEndpoint = discovered.EndSessionEndpoint
	}

	redirectURL := fmt.Sprintf("%s/t/%s/oidc/callback", u.Config.BaseIssuerURL, tenantID)

	oauth2Config := &oauth2.Config{
		ClientID:     conn.ClientID,
		ClientSecret: conn.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  conn.AuthorizationEndpoint,
			TokenURL: conn.TokenEndpoint,
		},
		RedirectURL: redirectURL,
		Scopes:      conn.Scopes,
	}

	nonce, _ := utils.GenerateRandomHex(16)
	codeVerifier, _ := utils.GenerateRandomHex(32)

	hashPkce := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hashPkce[:])

	hashCsrf := sha256.Sum256([]byte(csrfToken))
	csrfHash := hex.EncodeToString(hashCsrf[:])

	plainState := fmt.Sprintf("%s|%s|%s", loginChallenge, connectionID, csrfHash)
	encryptedState, err := crypto.EncryptAES([]byte(plainState), []byte(u.Config.AppSecret))
	if err != nil {
		return "", nil, fmt.Errorf("failed to encrypt state: %w", err)
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}

	providerContext := map[string]interface{}{
		"nonce":         nonce,
		"code_verifier": codeVerifier,
	}

	return oauth2Config.AuthCodeURL(encryptedState, opts...), providerContext, nil
}

func (u *oauth2ClientUseCase) VerifyState(encryptedState, csrfToken string) (loginChallenge, connectionID string, err error) {
	decryptedBytes, err := crypto.DecryptAES(encryptedState, []byte(u.Config.AppSecret))
	if err != nil {
		return "", "", fmt.Errorf("invalid state signature: %w", err)
	}

	parts := strings.Split(string(decryptedBytes), "|")
	if len(parts) != 3 {
		return "", "", errors.New("malformed state payload")
	}

	expectedHash := parts[2]
	hashCsrf := sha256.Sum256([]byte(csrfToken))
	actualHash := hex.EncodeToString(hashCsrf[:])

	if expectedHash != actualHash {
		return "", "", errors.New("csrf token mismatch: potential login csrf attack blocked")
	}
	return parts[0], parts[1], nil
}

func (u *oauth2ClientUseCase) ExchangeAndUserInfo(ctx context.Context, tenantID, code, connectionID, codeVerifier, expectedNonce string) (map[string]interface{}, error) {
	conn, err := u.connRepo.GetByTenantAndID(ctx, tenantID, connectionID)
	if err != nil {
		return nil, fmt.Errorf("connection not found: %w", err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: u.Config.SkipTLSVerify},
	}
	httpClient := &http.Client{Timeout: 30 * time.Second, Transport: otelhttp.NewTransport(tr)}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	if conn.TokenEndpoint == "" || conn.UserInfoEndpoint == "" {
		if conn.IssuerURL == "" {
			return nil, errors.New("missing issuer url for discovery")
		}
		discovered, err := u.discoverEndpoints(ctx, conn.IssuerURL)
		if err != nil {
			return nil, fmt.Errorf("oidc discovery failed: %w", err)
		}
		conn.TokenEndpoint = discovered.TokenEndpoint
		conn.UserInfoEndpoint = discovered.UserInfoEndpoint
	}

	redirectURL := fmt.Sprintf("%s/t/%s/oidc/callback", u.Config.BaseIssuerURL, tenantID)

	oauth2Config := &oauth2.Config{
		ClientID:     conn.ClientID,
		ClientSecret: conn.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  conn.AuthorizationEndpoint,
			TokenURL: conn.TokenEndpoint,
		},
		RedirectURL: redirectURL,
	}

	opts := []oauth2.AuthCodeOption{}
	if codeVerifier != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	}
	token, err := oauth2Config.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	if conn.UserInfoEndpoint == "" {
		return nil, errors.New("userinfo endpoint is missing")
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if ok && expectedNonce != "" {

		tokenParts := strings.Split(rawIDToken, ".")
		if len(tokenParts) == 5 {
			privKey, _, err := u.keyMgr.GetActivePrivateKey(ctx, "enc")
			if err != nil {
				return nil, errors.New("no active private key available to decrypt ID token")
			}

			decryptedToken, err := ParseAndDecryptJWE(rawIDToken, privKey)
			if err != nil {
				return nil, fmt.Errorf("failed to parse encrypted ID token: %w", err)
			}
			rawIDToken = decryptedToken
		}

		provider, err := oidc.NewProvider(ctx, conn.IssuerURL)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize oidc provider for verification: %w", err)
		}

		oidcConfig := &oidc.Config{ClientID: conn.ClientID}
		verifier := provider.Verifier(oidcConfig)

		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			return nil, fmt.Errorf("id_token verification failed: %w", err)
		}

		if idToken.Nonce != expectedNonce {
			return nil, errors.New("nonce mismatch in ID Token: potential replay attack")
		}
	}

	// UserInfo Fetch
	client := oauth2Config.Client(ctx, token)
	resp, err := client.Get(conn.UserInfoEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo endpoint returned status: %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	var userInfo map[string]interface{}

	if strings.Contains(contentType, "application/jwt") {
		// Yanıt bir JWT (veya JWE). Body'yi okuyup yukarıdaki gibi deşifre/doğrulama yapmalıyız
		bodyBytes, _ := io.ReadAll(resp.Body)
		jwtStr := string(bodyBytes)

		if len(strings.Split(jwtStr, ".")) == 5 {
			//TODO
		}

		return nil, errors.New("encrypted/signed jwt userinfo is currently unsupported, expecting application/json")

	} else {
		if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
			return nil, fmt.Errorf("failed to decode userinfo: %w", err)
		}
	}

	return userInfo, nil
}

func (u *oauth2ClientUseCase) SendBackchannelLogout(ctx context.Context, clientID, logoutURI, subject, issuer string) {
	if logoutURI == "" {
		return
	}

	privKey, _, _, err := u.keyMgr.GetActiveKeys(ctx, "sig")
	if privKey == nil {
		logger.Log.Error("No active private key for backchannel logout")
		return
	}

	claims := map[string]interface{}{
		"iss": issuer,
		"sub": subject,
		"aud": clientID,
		"iat": time.Now().Unix(),
		"jti": uuid.New().String(),
		"events": map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
		},
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, nil)
	if err != nil {
		logger.Log.Error("Failed to create signer for backchannel logout", zap.Error(err))
		return
	}

	builder := jwt.Signed(signer).Claims(claims)
	logoutToken, err := builder.Serialize()
	if err != nil {
		logger.Log.Error("Failed to serialize logout token", zap.Error(err))
		return
	}

	data := url.Values{}
	data.Set("logout_token", logoutToken)

	go func() {
		req, _ := http.NewRequest("POST", logoutURI, bytes.NewBufferString(data.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			logger.Log.Warn("Backchannel logout failed", zap.String("client", clientID), zap.Error(err))
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
			logger.Log.Info("Backchannel logout successful", zap.String("client", clientID))
		} else {
			logger.Log.Warn("Backchannel logout returned non-OK status", zap.String("client", clientID), zap.Int("status", resp.StatusCode))
		}
	}()
}

func (u *oauth2ClientUseCase) discoverEndpoints(ctx context.Context, issuer string) (*oidcDiscovery, error) {
	issuer = strings.TrimRight(issuer, "/")
	configURL := fmt.Sprintf("%s/.well-known/openid-configuration", issuer)

	logger.Log.Info("Discovering OIDC endpoints", zap.String("url", configURL))

	req, err := http.NewRequestWithContext(ctx, "GET", configURL, nil)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: u.Config.SkipTLSVerify},
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: otelhttp.NewTransport(tr),
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery returned status %d", resp.StatusCode)
	}

	var disc oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		return nil, err
	}

	return &disc, nil
}

func (u *oauth2ClientUseCase) CreateClient(ctx context.Context, client *model.OAuth2Client, unhashedSecret string, actorIP, userAgent string) (*model.OAuth2Client, string, error) {
	if client.TenantID == "" {
		client.TenantID = "default"
	}
	if _, err := u.tenant.GetByID(ctx, client.TenantID); err != nil {
		return nil, "", errors.New("the specified tenant does not exist")
	}

	if client.ID == "" {
		client.ID, _ = utils.GenerateRandomHex(8)
	}

	if client.Name == "" {
		client.Name = "New Client " + client.ID
	}

	// Handle Secret Generation and Hashing
	returnedSecret := ""
	if !client.Public {
		if unhashedSecret == "" {
			unhashedSecret, _ = utils.GenerateRandomHex(16)
		}
		returnedSecret = unhashedSecret

		hashed, err := u.hasher.Hash(ctx, unhashedSecret)
		if err != nil {
			return nil, "", errors.New("failed to hash client secret securely")
		}
		client.Secret = hashed
	} else {
		client.Secret = ""
		client.TokenEndpointAuthMethod = "none"
		client.EnforcePKCE = true
	}

	if len(client.ResponseModes) == 0 {
		client.ResponseModes = []string{"query", "fragment", "form_post"}
	}
	if len(client.GrantTypes) == 0 {
		client.GrantTypes = []string{"authorization_code", "refresh_token"}
	}

	if err := client.Validate(); err != nil {
		return nil, "", err
	}

	if err := u.repo.Create(ctx, client); err != nil {
		return nil, "", err
	}

	u.audit.Log(client.TenantID, "system", "management.client.oidc.create", actorIP, userAgent, map[string]interface{}{
		"client_id":                 client.ID,
		"public":                    client.Public,
		"scopes":                    client.Scopes,
		"redirect_uris":             client.RedirectURIs,
		"post_logout_redirect_uris": client.PostLogoutRedirectURIs,
	})

	return client, returnedSecret, nil
}

func (u *oauth2ClientUseCase) UpdateClient(ctx context.Context, client *model.OAuth2Client, unhashedSecret string, actorIP, userAgent string) (*model.OAuth2Client, string, error) {
	if client.TenantID == "" {
		client.TenantID = "default"
	}
	if _, err := u.tenant.GetByID(ctx, client.TenantID); err != nil {
		return nil, "", errors.New("the specified tenant does not exist")
	}

	_, err := u.GetClient(ctx, client.ID)
	if err != nil {
		return nil, "", errors.New("the specified client does not exist")
	}

	// Handle Secret Generation and Hashing
	returnedSecret := ""
	if !client.Public {
		if unhashedSecret == "" {
			unhashedSecret, _ = utils.GenerateRandomHex(16)
		}
		returnedSecret = unhashedSecret

		hashed, err := u.hasher.Hash(ctx, unhashedSecret)
		if err != nil {
			return nil, "", errors.New("failed to hash client secret securely")
		}
		client.Secret = hashed
	} else {
		client.Secret = ""
		client.TokenEndpointAuthMethod = "none"
		client.EnforcePKCE = true
	}

	if len(client.ResponseModes) == 0 {
		client.ResponseModes = []string{"query", "fragment", "form_post"}
	}
	if len(client.GrantTypes) == 0 {
		client.GrantTypes = []string{"authorization_code", "refresh_token"}
	}

	if err := client.Validate(); err != nil {
		return nil, "", err
	}

	if err := u.repo.Update(ctx, client); err != nil {
		return nil, "", err
	}

	u.audit.Log(client.TenantID, "system", "management.client.oidc.create", actorIP, userAgent, map[string]interface{}{
		"client_id":                 client.ID,
		"public":                    client.Public,
		"scopes":                    client.Scopes,
		"redirect_uris":             client.RedirectURIs,
		"post_logout_redirect_uris": client.PostLogoutRedirectURIs,
	})

	return client, returnedSecret, nil
}

func (u *oauth2ClientUseCase) GetClient(ctx context.Context, clientID string) (*model.OAuth2Client, error) {
	return u.repo.GetByID(ctx, clientID)
}

func (u *oauth2ClientUseCase) GetClientCount(ctx context.Context, tenantID string) (int64, error) {
	return u.repo.GetClientCount(ctx, tenantID)
}

func (u *oauth2ClientUseCase) GetPublicClientCount(ctx context.Context, tenantID string) (int64, error) {
	return u.repo.GetPublicClientCount(ctx, tenantID)
}

func (u *oauth2ClientUseCase) GetConfidentialClientCount(ctx context.Context, tenantID string) (int64, error) {
	return u.repo.GetConfidentialClientCount(ctx, tenantID)
}

func (u *oauth2ClientUseCase) GetClientByTenant(ctx context.Context, tenantID, clientID string) (*model.OAuth2Client, error) {
	return u.repo.GetByTenantAndID(ctx, tenantID, clientID)
}

func (u *oauth2ClientUseCase) DeleteClient(ctx context.Context, tenantID, clientID string, actorIP, userAgent string) error {
	if err := u.repo.Delete(ctx, tenantID, clientID); err != nil {
		return err
	}
	u.audit.Log(tenantID, "system", "management.client.oidc.delete", actorIP, userAgent, map[string]interface{}{
		"client_id": clientID,
	})
	return nil
}

func (u *oauth2ClientUseCase) ListClients(ctx context.Context, tenantID string) ([]*payload.OAuth2ClientResponse, error) {
	clients, err := u.repo.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return payload.FromDomainOAuth2Clients(clients), nil
}

func ParseAndDecryptJWE(rawToken string, privateKey interface{}) (string, error) {
	jweToken, err := jose.ParseEncrypted(rawToken, model.AllowedJWEAlgs, model.AllowedJWEEncs)
	if err != nil {
		return "", errors.New("jwe parse failed or weak cryptography detected: " + err.Error())
	}

	decryptedBytes, err := jweToken.Decrypt(privateKey)
	if err != nil {
		return "", err
	}

	return string(decryptedBytes), nil
}
