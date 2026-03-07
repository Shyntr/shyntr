package utils

import (
	"context"

	"github.com/nevzatcirak/shyntr/internal/adapters/iam"
	"github.com/nevzatcirak/shyntr/internal/application/port"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	fositejwt "github.com/ory/fosite/token/jwt"
	"gorm.io/gorm"
)

type Provider struct {
	Fosite     fosite.OAuth2Provider
	Store      *iam.FositeStore
	Config     *fosite.Config
	clientRepo port.OAuth2ClientRepository
	jtiRepo    port.BlacklistedJTIRepository
}

func NewProvider(db *gorm.DB, config *fosite.Config, km *KeyManager, clientRepo port.OAuth2ClientRepository, jtiRepo port.BlacklistedJTIRepository) *Provider {
	store := iam.NewFositeStore(db, clientRepo, jtiRepo)
	privateKey := km.GetActivePrivateKey()

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
