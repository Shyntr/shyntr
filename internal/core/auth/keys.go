package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"

	"github.com/go-jose/go-jose/v3"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/pkg/consts"
	"github.com/nevzatcirak/shyntr/pkg/crypto"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// KeyManager handles RSA key lifecycle (Load -> Decrypt -> Use).
type KeyManager struct {
	DB     *gorm.DB
	Config *config.Config
}

func NewKeyManager(db *gorm.DB, cfg *config.Config) *KeyManager {
	return &KeyManager{DB: db, Config: cfg}
}

// GetActivePrivateKey retrieves the signing key in this order:
// 1. Check ENV (Base64 encoded PEM)
// 2. Check DB (Encrypted)
// 3. Generate New -> Save to DB (Encrypted)
func (km *KeyManager) GetActivePrivateKey() *rsa.PrivateKey {
	// 1. Try Environment Variable (Stateless / K8s Secrets)
	if km.Config.RSAPrivateKeyBase64 != "" {
		key, err := parseBase64PEM(km.Config.RSAPrivateKeyBase64)
		if err == nil {
			logger.Log.Info("Loaded signing key from Environment Variable")
			return key
		}
		logger.Log.Error("Failed to parse key from ENV", zap.Error(err))
	}

	// 2. Try Database
	var keyModel models.SigningKey
	if err := km.DB.First(&keyModel, "id = ?", consts.SigningKeyID).Error; err == nil {
		// Decrypt
		decryptedBytes, err := crypto.DecryptAES(keyModel.KeyData, []byte(km.Config.AppSecret))
		if err != nil {
			logger.Log.Fatal("Failed to decrypt signing key from DB. Check APP_SECRET.", zap.Error(err))
		}

		key, err := x509.ParsePKCS1PrivateKey(decryptedBytes)
		if err != nil {
			logger.Log.Fatal("Failed to parse decrypted key", zap.Error(err))
		}
		logger.Log.Info("Loaded signing key from Database")
		return key
	}

	// 3. Generate New & Save to DB
	logger.Log.Info("No signing key found. Generating new one...")
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		logger.Log.Fatal("Failed to generate RSA key", zap.Error(err))
	}

	// Encrypt before saving
	keyBytes := x509.MarshalPKCS1PrivateKey(newKey)
	encryptedData, err := crypto.EncryptAES(keyBytes, []byte(km.Config.AppSecret))
	if err != nil {
		logger.Log.Fatal("Failed to encrypt new key", zap.Error(err))
	}

	newModel := models.SigningKey{
		ID:        consts.SigningKeyID,
		Algorithm: "RS256",
		KeyData:   encryptedData,
		Active:    true,
	}

	if err := km.DB.Create(&newModel).Error; err != nil {
		logger.Log.Fatal("Failed to save new key to DB", zap.Error(err))
	}

	return newKey
}

func parseBase64PEM(b64 string) (*rsa.PrivateKey, error) {
	pemBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func GeneratePublicJWKS(privateKey *rsa.PrivateKey) *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       &privateKey.PublicKey,
				KeyID:     consts.SigningKeyID,
				Algorithm: "RS256",
				Use:       "sig",
			},
		},
	}
}
