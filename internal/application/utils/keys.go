package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/pkg/consts"
	"github.com/Shyntr/shyntr/pkg/crypto"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/go-jose/go-jose/v3"
	"gorm.io/gorm"
)

type KeyManager struct {
	DB     *gorm.DB
	Config *config.Config

	mu         sync.RWMutex
	cachedKey  *rsa.PrivateKey
	cachedCert *x509.Certificate
}

func NewKeyManager(db *gorm.DB, cfg *config.Config) *KeyManager {
	return &KeyManager{DB: db, Config: cfg}
}

func (km *KeyManager) GetActivePrivateKey() *rsa.PrivateKey {
	key, _ := km.GetActiveKeys()
	return key
}

func (km *KeyManager) GetActiveKeys() (*rsa.PrivateKey, *x509.Certificate) {
	km.mu.RLock()
	if km.cachedKey != nil && km.cachedCert != nil {
		km.mu.RUnlock()
		return km.cachedKey, km.cachedCert
	}
	km.mu.RUnlock()

	km.mu.Lock()
	defer km.mu.Unlock()

	if km.cachedKey != nil {
		return km.cachedKey, km.cachedCert
	}

	var keyModel models.SigningKeyGORM
	if err := km.DB.First(&keyModel, "id = ?", consts.SigningKeyID).Error; err == nil {
		decryptedBytes, _ := crypto.DecryptAES(keyModel.KeyData, []byte(km.Config.AppSecret))
		key, _ := x509.ParsePKCS1PrivateKey(decryptedBytes)

		var cert *x509.Certificate
		if keyModel.CertData != "" {
			block, _ := pem.Decode([]byte(keyModel.CertData))
			if block != nil {
				cert, _ = x509.ParseCertificate(block.Bytes)
			}
		}

		if cert == nil && key != nil {
			logger.Log.Info("Found existing private key but no certificate. Generating missing certificate...")

			template := x509.Certificate{
				SerialNumber:          big.NewInt(time.Now().Unix()),
				Subject:               pkix.Name{CommonName: "Shyntr Global Identity"},
				NotBefore:             time.Now().Add(-1 * time.Minute),
				NotAfter:              time.Now().Add(365 * 24 * time.Hour * 10),
				KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
			}

			certBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
			cert, _ = x509.ParseCertificate(certBytes)
			pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
			km.DB.Model(&keyModel).Update("cert_data", string(pemCert))
		}
		logger.Log.Info("Loaded signing key and certificate from Database into Memory")
		km.cachedKey = key
		km.cachedCert = cert
		return key, cert
	}

	logger.Log.Info("No signing key found. Generating and caching a new stable key pair...")
	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Shyntr Global Identity"},
		NotBefore: time.Now().Add(-1 * time.Minute), NotAfter: time.Now().Add(365 * 24 * time.Hour * 10),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &newKey.PublicKey, newKey)
	newCert, _ := x509.ParseCertificate(certBytes)
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	encryptedData, _ := crypto.EncryptAES(x509.MarshalPKCS1PrivateKey(newKey), []byte(km.Config.AppSecret))
	newModel := models.SigningKeyGORM{
		ID:        consts.SigningKeyID,
		Algorithm: "RS256",
		KeyData:   encryptedData,
		CertData:  string(pemCert),
		IsActive:  true,
	}
	km.DB.Create(&newModel)

	km.cachedKey = newKey
	km.cachedCert = newCert
	return newKey, newCert
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

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return privKey, nil
	}

	parsedKey, errPKCS8 := x509.ParsePKCS8PrivateKey(block.Bytes)
	if errPKCS8 != nil {
		return nil, fmt.Errorf("failed to parse private key. PKCS#1 error: %v, PKCS#8 error: %v", err, errPKCS8)
	}

	rsaPrivKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("parsed PKCS#8 key is not a valid RSA private key")
	}

	return rsaPrivKey, nil
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
