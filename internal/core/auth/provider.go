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

	// Retrieve key from DB/Env via KeyManager
	privateKey := km.GetActivePrivateKey()

	config := &fosite.Config{
		AccessTokenLifespan: time.Hour,
		GlobalSecret:        secret,
		IDTokenIssuer:       issuerURL,
		IDTokenLifespan:     time.Hour,
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
