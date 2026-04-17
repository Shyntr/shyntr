package persistence

import (
	"path/filepath"
	"testing"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestMigrateDB_SeedsLDAPOutboundPolicyDefaults(t *testing.T) {
	t.Parallel()

	logger.InitLogger("info")

	dbPath := filepath.Join(t.TempDir(), "persistence.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	require.NoError(t, err)

	require.NoError(t, MigrateDB(db))

	var row models.OutboundPolicyGORM
	require.NoError(t, db.Where("id = ?", "global-outbound-policy-ldap-auth").First(&row).Error)

	require.False(t, row.BlockPrivateIPs)
	require.True(t, row.BlockLoopbackIPs)
	require.True(t, row.BlockLinkLocalIPs)
	require.True(t, row.BlockLocalhostNames)
	require.True(t, row.RequireDNSResolve)
	require.Equal(t, "[]", row.AllowedPathPatternsJSON)
}

func TestMigrateDB_NormalizesExistingLDAPOutboundPolicy(t *testing.T) {
	t.Parallel()

	logger.InitLogger("info")

	dbPath := filepath.Join(t.TempDir(), "persistence.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	require.NoError(t, err)

	require.NoError(t, db.AutoMigrate(
		&models.TenantGORM{},
		&models.OAuth2ClientGORM{},
		&models.SAMLConnectionGORM{},
		&models.SAMLClientGORM{},
		&models.SAMLReplayCache{},
		&models.OIDCConnectionGORM{},
		&models.LDAPConnectionGORM{},
		&models.OAuth2SessionGORM{},
		&models.CryptoKeyGORM{},
		&models.LoginRequestGORM{},
		&models.ConsentRequestGORM{},
		&models.BlacklistedJTIGORM{},
		&models.WebhookGORM{},
		&models.WebhookEventGORM{},
		&models.ScopeGORM{},
		&models.AuditLogGORM{},
		&models.OutboundPolicyGORM{},
	))

	require.NoError(t, db.Create(&models.OutboundPolicyGORM{
		ID:                      "global-outbound-policy-ldap-auth",
		TenantID:                "",
		Name:                    "Global Outbound Policy - LDAP Auth",
		Target:                  "ldap_auth",
		Enabled:                 true,
		AllowedSchemesJSON:      `["ldap","ldaps"]`,
		AllowedHostPatternsJSON: `["*"]`,
		AllowedPathPatternsJSON: `["/*"]`,
		AllowedPortsJSON:        `[]`,
		BlockPrivateIPs:         true,
		BlockLoopbackIPs:        false,
		BlockLinkLocalIPs:       false,
		BlockMulticastIPs:       true,
		BlockLocalhostNames:     false,
		DisableRedirects:        true,
		RequireDNSResolve:       false,
		RequestTimeoutSeconds:   10,
		MaxResponseBytes:        2 << 20,
	}).Error)

	require.NoError(t, seedGlobalOutboundPolicies(db))

	var row models.OutboundPolicyGORM
	require.NoError(t, db.Where("id = ?", "global-outbound-policy-ldap-auth").First(&row).Error)

	require.False(t, row.BlockPrivateIPs)
	require.True(t, row.BlockLoopbackIPs)
	require.True(t, row.BlockLinkLocalIPs)
	require.True(t, row.BlockLocalhostNames)
	require.True(t, row.RequireDNSResolve)
	require.Equal(t, "[]", row.AllowedPathPatternsJSON)
}
