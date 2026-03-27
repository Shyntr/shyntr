package models

import "time"

type OutboundPolicyGORM struct {
	ID       string `gorm:"primaryKey;size:64"`
	TenantID string `gorm:"index;size:64"`
	Name     string `gorm:"size:255;not null"`
	Target   string `gorm:"index;size:64;not null"`
	Enabled  bool   `gorm:"not null;default:true"`

	AllowedSchemesJSON      string `gorm:"type:text"`
	AllowedHostPatternsJSON string `gorm:"type:text"`
	AllowedPathPatternsJSON string `gorm:"type:text"`
	AllowedPortsJSON        string `gorm:"type:text"`

	BlockPrivateIPs     bool `gorm:"not null;default:true"`
	BlockLoopbackIPs    bool `gorm:"not null;default:true"`
	BlockLinkLocalIPs   bool `gorm:"not null;default:true"`
	BlockMulticastIPs   bool `gorm:"not null;default:true"`
	BlockLocalhostNames bool `gorm:"not null;default:true"`
	DisableRedirects    bool `gorm:"not null;default:true"`
	RequireDNSResolve   bool `gorm:"not null;default:true"`

	RequestTimeoutSeconds int64 `gorm:"not null;default:10"`
	MaxResponseBytes      int64 `gorm:"not null;default:2097152"`

	CreatedAt time.Time
	UpdatedAt time.Time
}
