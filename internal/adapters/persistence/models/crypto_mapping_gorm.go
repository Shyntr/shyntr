package models

import (
	"time"

	"github.com/Shyntr/shyntr/internal/domain/model"
	"gorm.io/gorm"
)

type CryptoKeyGORM struct {
	ID        string         `gorm:"primaryKey;type:varchar(255)"` // kid (Key ID)
	Use       string         `gorm:"type:varchar(10);index"`       // 'sig' or 'enc'
	State     model.KeyState `gorm:"type:varchar(20);index"`
	KeyData   []byte         `gorm:"type:bytea"` // AES-256-GCM encrypted private key
	CertData  string         `gorm:"type:text"`  // X.509 PEM
	Algorithm string         `gorm:"type:varchar(50)"`
	CreatedAt time.Time      `gorm:"autoCreateTime"`
	ExpiresAt *time.Time     `gorm:"index"`
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

func (CryptoKeyGORM) TableName() string { return "crypto_keys" }

func (m *CryptoKeyGORM) ToDomain() *model.CryptoKey {
	return &model.CryptoKey{
		ID:        m.ID,
		Use:       m.Use,
		State:     m.State,
		Algorithm: m.Algorithm,
		KeyData:   m.KeyData,
		CertData:  m.CertData,
		CreatedAt: m.CreatedAt,
		ExpiresAt: m.ExpiresAt,
	}
}

func FromDomainCryptoKey(e *model.CryptoKey) *CryptoKeyGORM {
	return &CryptoKeyGORM{
		ID:        e.ID,
		Use:       e.Use,
		State:     e.State,
		Algorithm: e.Algorithm,
		KeyData:   e.KeyData,
		CertData:  e.CertData,
		ExpiresAt: e.ExpiresAt,
	}
}

type BlacklistedJTIGORM struct {
	JTI       string    `gorm:"primaryKey;type:varchar(255)"`
	ExpiresAt time.Time `gorm:"index"`
}

func (BlacklistedJTIGORM) TableName() string { return "blacklisted_jtis" }

func (m *BlacklistedJTIGORM) ToDomain() *model.BlacklistedJTI {
	return &model.BlacklistedJTI{
		JTI:       m.JTI,
		ExpiresAt: m.ExpiresAt,
	}
}

func FromDomainBlacklistedJTI(e *model.BlacklistedJTI) *BlacklistedJTIGORM {
	return &BlacklistedJTIGORM{
		JTI:       e.JTI,
		ExpiresAt: e.ExpiresAt,
	}

}
