package models

import (
	"time"

	"github.com/lib/pq"
	"gorm.io/gorm"
)

type LoginRequest struct {
	ID                string         `gorm:"primaryKey"` // Challenge ID
	RequestedScope    pq.StringArray `gorm:"type:text[]"`
	RequestedAudience pq.StringArray `gorm:"type:text[]"`
	Skip              bool           `gorm:"default:false"`
	Subject           string         `gorm:"index"` // User ID
	ClientID          string         `gorm:"index;not null"`
	RequestURL        string         `gorm:"not null"`
	Authenticated     bool           `gorm:"default:false"`
	Active            bool           `gorm:"default:true"`
	SessionID         string
	ClientIP          string
	Remember          bool `gorm:"default:false"`
	CreatedAt         time.Time
	UpdatedAt         time.Time
	DeletedAt         gorm.DeletedAt `gorm:"index"`
}

type ConsentRequest struct {
	ID                string         `gorm:"primaryKey"` // Challenge ID
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
	CreatedAt         time.Time
	UpdatedAt         time.Time
	DeletedAt         gorm.DeletedAt `gorm:"index"`
}
