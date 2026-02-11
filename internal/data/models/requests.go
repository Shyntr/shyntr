package models

import (
	"time"

	"github.com/lib/pq"
	"gorm.io/gorm"
)

type LoginRequest struct {
	ID                string         `gorm:"primaryKey"`
	RequestedScope    pq.StringArray `gorm:"type:text[]"`
	RequestedAudience pq.StringArray `gorm:"type:text[]"`
	Skip              bool           `gorm:"default:false"`
	Subject           string         `gorm:"index"`
	Context           []byte         `gorm:"type:jsonb"`
	ClientID          string         `gorm:"index;not null"`
	RequestURL        string         `gorm:"not null"`
	Authenticated     bool           `gorm:"default:false"`
	Active            bool           `gorm:"default:true"`
	SessionID         string
	ClientIP          string

	SAMLRequestID string `gorm:"index"`

	Remember    bool `gorm:"default:false"`
	RememberFor int  `gorm:"default:0"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

type ConsentRequest struct {
	ID                string         `gorm:"primaryKey"`
	LoginChallenge    string         `gorm:"index"`
	ClientID          string         `gorm:"index;not null"`
	Subject           string         `gorm:"index;not null"`
	RequestedScope    pq.StringArray `gorm:"type:text[]"`
	RequestedAudience pq.StringArray `gorm:"type:text[]"`
	GrantedScope      pq.StringArray `gorm:"type:text[]"`
	GrantedAudience   pq.StringArray `gorm:"type:text[]"`
	Skip              bool           `gorm:"default:false"`
	Active            bool           `gorm:"default:true"`
	Authenticated     bool           `gorm:"default:false"`
	RequestURL        string

	Remember    bool `gorm:"default:false"`
	RememberFor int  `gorm:"default:0"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}
