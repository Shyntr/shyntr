package auth

import (
	"time"

	"github.com/nevzatcirak/shyntr/internal/data/repository"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"gorm.io/gorm"
)

type Provider struct {
	Fosite fosite.OAuth2Provider
	Store  *repository.SQLStore
	Config *fosite.Config
}

func NewProvider(db *gorm.DB, secret []byte, issuerURL string) *Provider {
	store := repository.NewSQLStore(db)

	// Load or Generate RSA Key for OIDC Signing
	// This ensures we can issue valid ID Tokens.
	privateKey := GetOrGenerateRSAPrivateKey("shyntr-signing-key.pem")

	config := &fosite.Config{
		AccessTokenLifespan: time.Hour,
		GlobalSecret:        secret,
		// OIDC Specific Config
		IDTokenIssuer:   issuerURL,
		IDTokenLifespan: time.Hour,
	}

	// Compose the strategy with all features enabled (OIDC, PKCE, OAuth2)
	oauth2Provider := compose.ComposeAllEnabled(
		config,
		store,
		privateKey,
	)

	return &Provider{
		Fosite: oauth2Provider,
		Store:  store,
		Config: config,
	}
}
