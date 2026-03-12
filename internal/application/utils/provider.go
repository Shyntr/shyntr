package utils

import (
	"context"
	"strings"
	"sync"

	"github.com/nevzatcirak/shyntr/internal/adapters/iam"
	"github.com/nevzatcirak/shyntr/internal/application/port"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	fositejwt "github.com/ory/fosite/token/jwt"
	"gorm.io/gorm"
)

type Provider struct {
	db           *gorm.DB
	baseConfig   *fosite.Config
	keyMgr       *KeyManager
	clientRepo   port.OAuth2ClientRepository
	jtiRepo      port.BlacklistedJTIRepository
	tenantFosite sync.Map
}

func NewProvider(db *gorm.DB, baseConfig *fosite.Config, km *KeyManager, clientRepo port.OAuth2ClientRepository, jtiRepo port.BlacklistedJTIRepository) *Provider {
	return &Provider{
		db:         db,
		baseConfig: baseConfig,
		keyMgr:     km,
		clientRepo: clientRepo,
		jtiRepo:    jtiRepo,
	}
}

func (p *Provider) GetFosite(tenantID string) fosite.OAuth2Provider {
	if cached, ok := p.tenantFosite.Load(tenantID); ok {
		return cached.(fosite.OAuth2Provider)
	}

	tConfig := *p.baseConfig
	tenantConfig := &tConfig

	baseURL := strings.TrimSuffix(p.baseConfig.IDTokenIssuer, "/")
	tenantConfig.TokenURL = baseURL + "/t/" + tenantID + "/oauth2/token"

	store := iam.NewFositeStore(p.db, p.clientRepo, p.jtiRepo)
	privateKey := p.keyMgr.GetActivePrivateKey()
	keyGetter := func(ctx context.Context) (interface{}, error) {
		return privateKey, nil
	}
	hmacStrategy := compose.NewOAuth2HMACStrategy(tenantConfig)
	jwtStrategy := compose.NewOAuth2JWTStrategy(keyGetter, hmacStrategy, tenantConfig)
	oauth2Provider := compose.Compose(
		tenantConfig,
		store,
		&compose.CommonStrategy{
			CoreStrategy:               jwtStrategy,
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, tenantConfig),
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

	p.tenantFosite.Store(tenantID, oauth2Provider)
	return oauth2Provider
}
