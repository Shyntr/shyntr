package data

import (
	"log"
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/pkg/logger"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func ConnectDB(cfg *config.Config) (*gorm.DB, error) {
	if cfg.DSN == "" {
		log.Fatal("DSN (Database Source Name) is empty.")
	}

	db, err := gorm.Open(postgres.Open(cfg.DSN), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	db.Exec("CREATE EXTENSION IF NOT EXISTS pgcrypto")

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxIdleConns(cfg.DBMaxIdleConns)
	sqlDB.SetMaxOpenConns(cfg.DBMaxOpenConns)
	sqlDB.SetConnMaxLifetime(time.Hour)

	return db, nil
}

// MigrateDB runs the schema migration.
func MigrateDB(db *gorm.DB) error {
	if err := db.AutoMigrate(
		&models.TenantGORM{},
		&models.OAuth2ClientGORM{},
		&models.SAMLConnectionGORM{},
		&models.SAMLClientGORM{},
		&models.SAMLReplayCache{},
		&models.OIDCConnectionGORM{},
		&models.OAuth2SessionGORM{},
		&models.SigningKeyGORM{},
		&models.LoginRequestGORM{},
		&models.ConsentRequestGORM{},
		&models.BlacklistedJTIGORM{},
		&models.WebhookGORM{},
		&models.WebhookEventGORM{},
		&models.ScopeGORM{},
		&models.AuditLogGORM{},
	); err != nil {
		return err
	}

	if db.Migrator().HasTable("o_auth2_sessions") {
		if db.Dialector.Name() == "postgres" {
			fixPrimaryKeySQL := `
          DO $$
          DECLARE
             pk_columns integer;
          BEGIN
             -- Safely count the number of columns in the current primary key
             SELECT count(a.attname) INTO pk_columns
             FROM pg_index i
             JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
             WHERE i.indrelid = 'o_auth2_sessions'::regclass AND i.indisprimary;

             -- If the primary key has only 1 column (the old schema), migrate to composite key
             IF pk_columns = 1 THEN
                ALTER TABLE o_auth2_sessions DROP CONSTRAINT o_auth2_sessions_pkey;
                ALTER TABLE o_auth2_sessions ADD PRIMARY KEY (signature, token_type);
             END IF;
          END $$;
          `
			if err := db.Exec(fixPrimaryKeySQL).Error; err != nil {
				return err
			}
		}

		if err := db.Exec(`
          DROP INDEX IF EXISTS oauth2_sessions_one_active_refresh_per_request;
       `).Error; err != nil {
		}

		if err := db.Exec(`
          CREATE INDEX IF NOT EXISTS oauth2_sessions_family_lookup 
          ON o_auth2_sessions (token_family_id, token_type);
       `).Error; err != nil {
			return err
		}

		if err := db.Exec(`
          CREATE INDEX IF NOT EXISTS oauth2_sessions_refresh_grace_lookup 
          ON o_auth2_sessions (request_id, signature, grace_expires_at, grace_used_at) 
          WHERE token_type = 'refresh_token';
       `).Error; err != nil {
			return err
		}
	}
	return nil
}

func SeedDefaultTenant(db *gorm.DB, cfg *config.Config) {
	var count int64
	if err := db.Model(&models.TenantGORM{}).Where("id = ?", "default").Count(&count).Error; err != nil {
		logger.Log.Error("Failed to check default tenant", zap.Error(err))
		return
	}

	if count == 0 {
		defaultTenant := models.TenantGORM{
			ID:          cfg.DefaultTenantID,
			Name:        "default",
			DisplayName: "Default Tenant",
			Description: "This is the default (root) isolation area of the system. All applications (clients) and identity providers (connections) operate in this space unless a specific tenant (customer/domain) is designated. This tenant cannot be deleted to ensure system integrity.",
		}

		if err := db.Create(&defaultTenant).Error; err != nil {
			logger.Log.Fatal("Failed to create default tenant on startup", zap.Error(err))
			return
		}
		logger.Log.Info("Default tenant successfully seeded.")
	} else {
		logger.Log.Info("Default tenant already exists.")
	}
}
