package saml

import (
	"gorm.io/gorm"
	"net/http"
)

type Service struct {
	DB *gorm.DB
}

func NewService(db *gorm.DB) *Service {
	return &Service{DB: db}
}

func (s *Service) InitiateLogin(w http.ResponseWriter, r *http.Request) {
	// Logic to find IDP connection and start SAML flow
	w.Write([]byte("Shyntr: SAML Login Initiated"))
}
