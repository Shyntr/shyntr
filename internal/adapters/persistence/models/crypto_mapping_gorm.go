package models

import (
	"time"

	"github.com/nevzatcirak/shyntr/internal/domain/entity"
)

type SigningKeyGORM struct {
	ID        string    `gorm:"primaryKey;type:varchar(255)"`
	Algorithm string    `gorm:"type:varchar(50);not null"`
	KeyData   string    `gorm:"type:text;not null"`
	CertData  string    `gorm:"type:text"`
	IsActive  bool      `gorm:"default:true"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
	ExpiresAt time.Time `gorm:"index"`
}

func (SigningKeyGORM) TableName() string { return "signing_keys" }

func (m *SigningKeyGORM) ToDomain() *entity.SigningKey {
	return &entity.SigningKey{
		ID:        m.ID,
		Algorithm: m.Algorithm,
		KeyData:   m.KeyData,
		CertData:  m.CertData,
		IsActive:  m.IsActive,
		CreatedAt: m.CreatedAt,
		UpdatedAt: m.UpdatedAt,
		ExpiresAt: m.ExpiresAt,
	}
}

func FromDomainSigningKey(e *entity.SigningKey) *SigningKeyGORM {
	return &SigningKeyGORM{
		ID:        e.ID,
		Algorithm: e.Algorithm,
		KeyData:   e.KeyData,
		CertData:  e.CertData,
		IsActive:  e.IsActive,
		ExpiresAt: e.ExpiresAt,
	}
}

type BlacklistedJTIGORM struct {
	JTI       string    `gorm:"primaryKey;type:varchar(255)"`
	ExpiresAt time.Time `gorm:"index"`
}

func (BlacklistedJTIGORM) TableName() string { return "blacklisted_jtis" }

func (m *BlacklistedJTIGORM) ToDomain() *entity.BlacklistedJTI {
	return &entity.BlacklistedJTI{
		JTI:       m.JTI,
		ExpiresAt: m.ExpiresAt,
	}
}

func FromDomainBlacklistedJTI(e *entity.BlacklistedJTI) *BlacklistedJTIGORM {
	return &BlacklistedJTIGORM{
		JTI:       e.JTI,
		ExpiresAt: e.ExpiresAt,
	}

}
