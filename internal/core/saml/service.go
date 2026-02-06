package saml

import (
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"net/http"
)

type Service struct {
	DB *gorm.DB
}

// NewService is unused for now, but ready for future SAML features
func NewService(db *gorm.DB) *Service {
	return &Service{DB: db}
}

func (s *Service) InitiateLogin(w http.ResponseWriter, _ *http.Request) {
	// Logic to find IDP connection and start SAML flow
	if _, err := w.Write([]byte("Shyntr: SAML Login Initiated")); err != nil {
		logger.Log.Error("Failed to write SAML response", zap.Error(err))
	}
}
