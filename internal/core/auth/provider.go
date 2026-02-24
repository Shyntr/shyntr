package auth

import (
	"context"
	"time"

	"github.com/nevzatcirak/shyntr/internal/data/repository"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	fositejwt "github.com/ory/fosite/token/jwt"
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

	keyGetter := func(ctx context.Context) (interface{}, error) {
		return privateKey, nil
	}
	hmacStrategy := compose.NewOAuth2HMACStrategy(config)
	jwtStrategy := compose.NewOAuth2JWTStrategy(
		keyGetter,
		hmacStrategy,
		config,
	)

	oauth2Provider := compose.Compose(
		config,
		store,
		&compose.CommonStrategy{
			CoreStrategy:               jwtStrategy,
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, config),
			Signer:                     &fositejwt.DefaultSigner{GetPrivateKey: keyGetter},
		},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2AuthorizeImplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2PKCEFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectImplicitFactory,
		compose.OpenIDConnectHybridFactory,
		compose.OpenIDConnectRefreshFactory,
	)

	return &Provider{
		Fosite: oauth2Provider,
		Store:  store,
		Config: config,
	}
}
