package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
	shcrypto "github.com/Shyntr/shyntr/pkg/crypto"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type ldapConnectionRepository struct {
	db        *gorm.DB
	appSecret []byte
}

var ErrLDAPConnectionNotFound = errors.New("ldap connection not found")
var ErrLDAPConnectionTenantRequired = errors.New("tenant_id is required")

// NewLDAPConnectionRepository creates a repository that transparently encrypts
// and decrypts BindPassword using AES-256-GCM (same key as CryptoKey.KeyData).
// appSecret must be exactly 32 bytes (enforced by config.LoadConfig).
func NewLDAPConnectionRepository(db *gorm.DB, appSecret []byte) port.LDAPConnectionRepository {
	return &ldapConnectionRepository{db: db, appSecret: appSecret}
}

// encryptBindPassword encrypts the plain-text bind password before storage.
// Returns an empty slice when password is empty (anonymous bind).
func (r *ldapConnectionRepository) encryptBindPassword(plaintext string) ([]byte, error) {
	if plaintext == "" {
		return nil, nil
	}
	encrypted, err := shcrypto.EncryptAES([]byte(plaintext), r.appSecret)
	if err != nil {
		return nil, fmt.Errorf("ldap: failed to encrypt bind_password: %w", err)
	}
	return []byte(encrypted), nil
}

// decryptBindPassword decrypts the stored ciphertext back to plaintext.
// Returns an empty string when no ciphertext is stored (anonymous bind).
func (r *ldapConnectionRepository) decryptBindPassword(ciphertext []byte) (string, error) {
	if len(ciphertext) == 0 {
		return "", nil
	}
	plaintext, err := shcrypto.DecryptAES(string(ciphertext), r.appSecret)
	if err != nil {
		return "", fmt.Errorf("ldap: failed to decrypt bind_password: %w", err)
	}
	return string(plaintext), nil
}

// toDomain converts a GORM model to domain, decrypting BindPassword in the process.
func (r *ldapConnectionRepository) toDomain(m *models.LDAPConnectionGORM) (*model.LDAPConnection, error) {
	d := m.ToDomain()
	pw, err := r.decryptBindPassword(m.BindPasswordEncrypted)
	if err != nil {
		return nil, err
	}
	d.BindPassword = pw
	return d, nil
}

func (r *ldapConnectionRepository) Create(ctx context.Context, conn *model.LDAPConnection) error {
	dbModel := models.FromDomainLDAPConnection(conn)
	encrypted, err := r.encryptBindPassword(conn.BindPassword)
	if err != nil {
		return err
	}
	dbModel.BindPasswordEncrypted = encrypted
	if err := r.db.WithContext(ctx).Create(dbModel).Error; err != nil {
		return err
	}
	conn.ID = dbModel.ID // write back BeforeCreate-generated ID
	return nil
}

func (r *ldapConnectionRepository) GetByID(ctx context.Context, id string) (*model.LDAPConnection, error) {
	var dbModel models.LDAPConnectionGORM
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&dbModel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrLDAPConnectionNotFound
		}
		return nil, err
	}
	return r.toDomain(&dbModel)
}

func (r *ldapConnectionRepository) GetByTenantAndID(ctx context.Context, tenantID, id string) (*model.LDAPConnection, error) {
	var dbModel models.LDAPConnectionGORM
	if err := r.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).First(&dbModel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrLDAPConnectionNotFound
		}
		return nil, err
	}
	return r.toDomain(&dbModel)
}

func (r *ldapConnectionRepository) GetConnectionCount(ctx context.Context, tenantID string) (int64, error) {
	if tenantID == "" {
		return 0, ErrLDAPConnectionTenantRequired
	}
	var count int64
	if err := r.db.WithContext(ctx).Model(&models.LDAPConnectionGORM{}).
		Where("tenant_id = ?", tenantID).
		Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *ldapConnectionRepository) Update(ctx context.Context, conn *model.LDAPConnection) error {
	if conn == nil || conn.TenantID == "" || conn.ID == "" {
		return ErrLDAPConnectionNotFound
	}
	encrypted, err := r.encryptBindPassword(conn.BindPassword)
	if err != nil {
		return err
	}
	// AttributeMapping uses a GORM JSON serializer; when passed in a raw map
	// the serializer is bypassed, so we pre-encode it ourselves.
	attrMappingJSON, err := json.Marshal(conn.AttributeMapping)
	if err != nil {
		return fmt.Errorf("ldap: failed to marshal attribute_mapping: %w", err)
	}
	updates := map[string]interface{}{
		"name":                     conn.Name,
		"server_url":               conn.ServerURL,
		"bind_dn":                  conn.BindDN,
		"bind_password_encrypted":  encrypted,
		"base_dn":                  conn.BaseDN,
		"user_search_filter":       conn.UserSearchFilter,
		"user_search_attributes":   pq.StringArray(conn.UserSearchAttributes),
		"group_search_filter":      conn.GroupSearchFilter,
		"group_search_base_dn":     conn.GroupSearchBaseDN,
		"attribute_mapping":        string(attrMappingJSON),
		"start_tls":                conn.StartTLS,
		"tls_insecure_skip_verify": conn.TLSInsecureSkipVerify,
		"active":                   conn.Active,
	}
	result := r.db.WithContext(ctx).Model(&models.LDAPConnectionGORM{}).
		Where("id = ? AND tenant_id = ?", conn.ID, conn.TenantID).
		Updates(updates)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrLDAPConnectionNotFound
	}
	return nil
}

func (r *ldapConnectionRepository) Delete(ctx context.Context, tenantID, id string) error {
	result := r.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).Delete(&models.LDAPConnectionGORM{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrLDAPConnectionNotFound
	}
	return nil
}

func (r *ldapConnectionRepository) ListByTenant(ctx context.Context, tenantID string) ([]*model.LDAPConnection, error) {
	if tenantID == "" {
		return nil, ErrLDAPConnectionTenantRequired
	}
	var dbModels []models.LDAPConnectionGORM
	if err := r.db.WithContext(ctx).Model(&models.LDAPConnectionGORM{}).
		Where("tenant_id = ?", tenantID).
		Find(&dbModels).Error; err != nil {
		return nil, err
	}
	entities := make([]*model.LDAPConnection, 0, len(dbModels))
	for i := range dbModels {
		d, err := r.toDomain(&dbModels[i])
		if err != nil {
			return nil, err
		}
		entities = append(entities, d)
	}
	return entities, nil
}

func (r *ldapConnectionRepository) ListActiveByTenant(ctx context.Context, tenantID string) ([]*model.LDAPConnection, error) {
	if tenantID == "" {
		return nil, ErrLDAPConnectionTenantRequired
	}
	var dbModels []models.LDAPConnectionGORM
	if err := r.db.WithContext(ctx).Where("tenant_id = ? AND active = ?", tenantID, true).Find(&dbModels).Error; err != nil {
		return nil, err
	}
	entities := make([]*model.LDAPConnection, 0, len(dbModels))
	for i := range dbModels {
		d, err := r.toDomain(&dbModels[i])
		if err != nil {
			return nil, err
		}
		entities = append(entities, d)
	}
	return entities, nil
}

func (r *ldapConnectionRepository) List(ctx context.Context) ([]*model.LDAPConnection, error) {
	var dbModels []models.LDAPConnectionGORM
	if err := r.db.WithContext(ctx).Find(&dbModels).Error; err != nil {
		return nil, err
	}
	entities := make([]*model.LDAPConnection, 0, len(dbModels))
	for i := range dbModels {
		d, err := r.toDomain(&dbModels[i])
		if err != nil {
			return nil, err
		}
		entities = append(entities, d)
	}
	return entities, nil
}
