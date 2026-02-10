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

func NewProvider(db *gorm.DB, secret []byte, issuerURL string, km *KeyManager) *Provider {
	store := repository.NewSQLStore(db)
	privateKey := km.GetActivePrivateKey()

	config := &fosite.Config{
		AccessTokenLifespan:   1 * time.Hour,
		AuthorizeCodeLifespan: 10 * time.Minute,
		IDTokenLifespan:       1 * time.Hour,

		RefreshTokenLifespan: 30 * 24 * time.Hour, // 30 Gün

		GlobalSecret:  secret,
		IDTokenIssuer: issuerURL,

		SendDebugMessagesToClients: true,
	}

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
