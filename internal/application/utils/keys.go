package utils

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/Shyntr/shyntr/pkg/crypto"
	"github.com/Shyntr/shyntr/pkg/logger"
	jose "github.com/go-jose/go-jose/v4"
	"go.uber.org/zap"
)

type KeyManager interface {
	GetActivePrivateKey(ctx context.Context, use string) (*rsa.PrivateKey, string, error)
	GetDecryptionKeys(ctx context.Context) (map[string]*rsa.PrivateKey, error)
	GetPublicJWKS(ctx context.Context) (*jose.JSONWebKeySet, error)
	GetActiveKeys(ctx context.Context, use string) (*rsa.PrivateKey, *x509.Certificate, string, error)
	RotateKeys(ctx context.Context) error
	ImportKey(ctx context.Context, use string, privKey *rsa.PrivateKey, certPEM []byte) (*model.CryptoKey, error)
}

type DefaultKeyManager struct {
	repo   port.CryptoKeyRepository
	config *config.Config

	mu          sync.RWMutex
	cachedKeys  map[string]*rsa.PrivateKey
	cachedKIDs  map[string]string
	cachedCerts map[string]*x509.Certificate

	cacheRefreshTime map[string]time.Time
	cachedDecRing    map[string]*rsa.PrivateKey
	decRingRefresh   time.Time
}

const (
	RotationActiveTTL  = 30 * 24 * time.Hour
	RotationPendingTTL = 1 * time.Hour
	RotationPassiveTTL = 24 * time.Hour
)

func NewKeyManager(repo port.CryptoKeyRepository, cfg *config.Config) KeyManager {
	return &DefaultKeyManager{
		repo:             repo,
		config:           cfg,
		cachedKeys:       make(map[string]*rsa.PrivateKey),
		cachedKIDs:       make(map[string]string),
		cachedCerts:      make(map[string]*x509.Certificate),
		cacheRefreshTime: make(map[string]time.Time),
		cachedDecRing:    make(map[string]*rsa.PrivateKey),
	}
}

func (km *DefaultKeyManager) loadOrGenerateActiveKey(ctx context.Context, use string) (*model.CryptoKey, error) {
	dbKey, err := km.repo.GetActiveKey(ctx, use)
	if err == nil && dbKey != nil {
		return dbKey, nil
	}

	logger.Log.Info("No active key found for use '" + use + "' in DB. Initializing...")

	var newKey *rsa.PrivateKey
	var keySource string

	if km.config.RSAPrivateKeyBase64 != "" {
		parsedKey, err := parseBase64PEM(km.config.RSAPrivateKeyBase64)
		if err == nil {
			logger.Log.Info("Successfully loaded Seed Key from environment variable for use " + use)
			newKey = parsedKey
			keySource = "seeded"
		} else {
			logger.Log.Warn("Failed to parse provided APP_PRIVATE_KEY_BASE64, falling back to random generation", zap.Error(err))
		}
	}

	if newKey == nil {
		logger.Log.Info("Generating and caching a new High-Assurance (4096-bit) random stable key pair for use '" + use + "'...")
		generatedKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random 4096-bit RSA key: %w", err)
		}
		newKey = generatedKey
		keySource = "random_4096"
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "Shyntr Global Identity - " + use},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour * 10),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &newKey.PublicKey, newKey)
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	encryptedData, err := crypto.EncryptAES(x509.MarshalPKCS1PrivateKey(newKey), []byte(km.config.AppSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt new private key: %w", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&newKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key for KID generation: %w", err)
	}
	hash := sha256.Sum256(pubKeyBytes)
	kidHash := fmt.Sprintf("%x", hash)
	kid := fmt.Sprintf("%s-%s", use, kidHash[:8])

	newCryptoKey := &model.CryptoKey{
		ID:        kid,
		Use:       use,
		State:     model.KeyStateActive,
		Algorithm: "RS256",
		KeyData:   []byte(encryptedData),
		CertData:  string(pemCert),
	}

	if err := km.repo.Save(ctx, newCryptoKey); err != nil {
		return nil, fmt.Errorf("failed to save %s key to repository: %w", keySource, err)
	}

	logger.Log.Info("Saved newly initialized key to database", zap.String("source", keySource), zap.String("use", use), zap.String("kid", kid))
	return newCryptoKey, nil
}

func (km *DefaultKeyManager) GetActivePrivateKey(ctx context.Context, use string) (*rsa.PrivateKey, string, error) {
	km.mu.RLock()
	cachedKey, keyExists := km.cachedKeys[use]
	cachedKID, kidExists := km.cachedKIDs[use]
	lastRefresh := km.cacheRefreshTime[use]
	km.mu.RUnlock()

	if keyExists && kidExists && time.Since(lastRefresh) < 5*time.Minute {
		return cachedKey, cachedKID, nil
	}

	km.mu.Lock()
	defer km.mu.Unlock()

	if time.Since(km.cacheRefreshTime[use]) < 5*time.Minute {
		return km.cachedKeys[use], km.cachedKIDs[use], nil
	}

	dbKey, err := km.loadOrGenerateActiveKey(ctx, use)
	if err != nil {
		if keyExists {
			logger.Log.Warn("Failed to fetch active key from DB, falling back to stale cache for use " + use)
			return cachedKey, cachedKID, nil
		}
		return nil, "", err
	}

	decryptedBytes, err := crypto.DecryptAES(string(dbKey.KeyData), []byte(km.config.AppSecret))
	if err != nil {
		return nil, "", fmt.Errorf("failed to decrypt AES key data: %w", err)
	}

	privKey, err := x509.ParsePKCS1PrivateKey(decryptedBytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	km.cachedKeys[use] = privKey
	km.cachedKIDs[use] = dbKey.ID
	km.cacheRefreshTime[use] = time.Now()

	logger.Log.Info("Refreshed active " + use + " key in memory cache from database")
	return privKey, dbKey.ID, nil
}

func (km *DefaultKeyManager) GetDecryptionKeys(ctx context.Context) (map[string]*rsa.PrivateKey, error) {
	km.mu.RLock()
	lastRefresh := km.decRingRefresh
	ringCount := len(km.cachedDecRing)
	km.mu.RUnlock()

	if ringCount > 0 && time.Since(lastRefresh) < 5*time.Minute {
		km.mu.RLock()
		defer km.mu.RUnlock()
		return km.cachedDecRing, nil
	}

	states := []model.KeyState{model.KeyStateActive, model.KeyStatePassive}
	dbKeys, err := km.repo.GetKeysByStates(ctx, "enc", states)
	if err != nil {
		return nil, err
	}

	if len(dbKeys) == 0 {
		return nil, errors.New("no active or passive decryption keys available in the ring")
	}

	decryptionRing := make(map[string]*rsa.PrivateKey)
	for _, key := range dbKeys {
		decryptedBytes, err := crypto.DecryptAES(string(key.KeyData), []byte(km.config.AppSecret))
		if err != nil {
			logger.Log.Warn("Failed to decrypt key data for kid " + key.ID + ", skipping...")
			continue
		}
		privKey, err := x509.ParsePKCS1PrivateKey(decryptedBytes)
		if err == nil {
			decryptionRing[key.ID] = privKey
		}
	}

	km.mu.Lock()
	km.cachedDecRing = decryptionRing
	km.decRingRefresh = time.Now()
	km.mu.Unlock()

	return decryptionRing, nil
}

func (km *DefaultKeyManager) GetPublicJWKS(ctx context.Context) (*jose.JSONWebKeySet, error) {
	jwks := &jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0)}
	states := []model.KeyState{model.KeyStatePending, model.KeyStateActive, model.KeyStatePassive}

	sigKeys, _ := km.repo.GetKeysByStates(ctx, "sig", states)
	encKeys, _ := km.repo.GetKeysByStates(ctx, "enc", states)

	allKeys := append(sigKeys, encKeys...)

	for _, dbKey := range allKeys {
		decryptedBytes, err := crypto.DecryptAES(string(dbKey.KeyData), []byte(km.config.AppSecret))
		if err != nil {
			continue
		}
		privKey, err := x509.ParsePKCS1PrivateKey(decryptedBytes)
		if err != nil {
			continue
		}

		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:       &privKey.PublicKey,
			KeyID:     dbKey.ID,
			Algorithm: dbKey.Algorithm,
			Use:       dbKey.Use,
		})
	}

	return jwks, nil
}

func parseBase64PEM(b64 string) (*rsa.PrivateKey, error) {
	pemBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block from decoded base64 string")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return privKey, nil
	}

	parsedKey, errPKCS8 := x509.ParsePKCS8PrivateKey(block.Bytes)
	if errPKCS8 != nil {
		return nil, fmt.Errorf("failed parsing as PKCS#1 (%v) and PKCS#8 (%v)", err, errPKCS8)
	}

	rsaPrivKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("parsed PKCS#8 key is not a valid RSA private key")
	}

	return rsaPrivKey, nil
}

func (km *DefaultKeyManager) GetActiveKeys(ctx context.Context, use string) (*rsa.PrivateKey, *x509.Certificate, string, error) {
	privKey, kid, err := km.GetActivePrivateKey(ctx, use)
	if err != nil {
		return nil, nil, "", err
	}

	km.mu.RLock()
	cachedCert, certExists := km.cachedCerts[use]
	km.mu.RUnlock()

	if certExists && cachedCert != nil {
		return privKey, cachedCert, kid, nil
	}

	dbKey, err := km.repo.GetActiveKey(ctx, use)
	if err != nil {
		return privKey, nil, kid, nil
	}

	var cert *x509.Certificate
	if dbKey.CertData != "" {
		block, _ := pem.Decode([]byte(dbKey.CertData))
		if block != nil {
			cert, _ = x509.ParseCertificate(block.Bytes)
		}
	}

	if cert != nil {
		km.mu.Lock()
		km.cachedCerts[use] = cert
		km.mu.Unlock()
	}

	return privKey, cert, kid, nil
}

func (km *DefaultKeyManager) RotateKeys(ctx context.Context) error {
	if !km.config.AutoKeyRotationEnabled {
		logger.Log.Info("AutoKeyRotation is DISABLED by policy. Skipping automatic key rotation. Administrators must inject CA-signed keys manually.")
		return nil
	}

	uses := []string{"sig", "enc"}

	for _, use := range uses {
		if err := km.processRotationForUse(ctx, use); err != nil {
			logger.Log.Error("Failed to rotate keys", zap.String("use", use), zap.Error(err))
			continue
		}
	}
	return nil
}

func (km *DefaultKeyManager) ImportKey(ctx context.Context, use string, privKey *rsa.PrivateKey, certPEM []byte) (*model.CryptoKey, error) {
	logger.Log.Info("Starting manual key import for use '" + use + "'...")

	activeKey, err := km.repo.GetActiveKey(ctx, use)
	if err == nil && activeKey != nil {
		activeKey.State = model.KeyStatePassive
		km.repo.Save(ctx, activeKey)
		logger.Log.Info("Demoted existing ACTIVE key (" + activeKey.ID + ") to PASSIVE during manual import.")
	}

	encryptedData, err := crypto.EncryptAES(x509.MarshalPKCS1PrivateKey(privKey), []byte(km.config.AppSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt imported private key: %w", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	hash := sha256.Sum256(pubKeyBytes)
	kidHash := fmt.Sprintf("%x", hash)
	kid := fmt.Sprintf("%s-%s", use, kidHash[:8])

	newCryptoKey := &model.CryptoKey{
		ID:        kid,
		Use:       use,
		State:     model.KeyStateActive,
		Algorithm: "RS256",
		KeyData:   []byte(encryptedData),
		CertData:  string(certPEM),
	}

	if err := km.repo.Save(ctx, newCryptoKey); err != nil {
		return nil, fmt.Errorf("failed to save imported key: %w", err)
	}

	km.mu.Lock()
	km.cacheRefreshTime[use] = time.Time{}
	km.mu.Unlock()

	logger.Log.Info("Successfully imported and activated CA-signed key for use '" + use + "' (KID: " + kid + ")")
	return newCryptoKey, nil
}

func (km *DefaultKeyManager) processRotationForUse(ctx context.Context, use string) error {
	now := time.Now()
	allStates := []model.KeyState{model.KeyStatePending, model.KeyStateActive, model.KeyStatePassive}
	keys, err := km.repo.GetKeysByStates(ctx, use, allStates)
	if err != nil {
		return err
	}

	var activeKey *model.CryptoKey
	var pendingKey *model.CryptoKey
	var passiveKeys []*model.CryptoKey

	for _, k := range keys {
		switch k.State {
		case model.KeyStateActive:
			activeKey = k
		case model.KeyStatePending:
			pendingKey = k
		case model.KeyStatePassive:
			passiveKeys = append(passiveKeys, k)
		}
	}

	for _, pk := range passiveKeys {
		age := now.Sub(pk.CreatedAt)
		if age > (RotationActiveTTL + RotationPassiveTTL) {
			logger.Log.Info("Destroying expired PASSIVE key: " + pk.ID + " (use: " + use + ")")
			km.repo.DeleteKey(ctx, pk.ID)
		}
	}

	if pendingKey != nil {
		if now.Sub(pendingKey.CreatedAt) > RotationPendingTTL {
			logger.Log.Info("Promoting PENDING key to ACTIVE: " + pendingKey.ID)

			if activeKey != nil {
				activeKey.State = model.KeyStatePassive
				km.repo.Save(ctx, activeKey)
				logger.Log.Info("Demoted old ACTIVE key to PASSIVE: " + activeKey.ID)
			}

			pendingKey.State = model.KeyStateActive
			km.repo.Save(ctx, pendingKey)

			km.mu.Lock()
			km.cacheRefreshTime[use] = time.Time{}
			km.mu.Unlock()

			return nil
		}
	}

	if activeKey != nil && pendingKey == nil {
		if now.Sub(activeKey.CreatedAt) > RotationActiveTTL {
			logger.Log.Info("ACTIVE key " + activeKey.ID + " is nearing expiration. Generating new PENDING key...")
			_, err := km.generateKeyInternal(ctx, use, model.KeyStatePending)
			if err != nil {
				return fmt.Errorf("failed to generate pending key: %w", err)
			}
		}
	}

	return nil
}

func (km *DefaultKeyManager) generateKeyInternal(ctx context.Context, use string, state model.KeyState) (*model.CryptoKey, error) {
	newKey, _ := rsa.GenerateKey(rand.Reader, 4096)

	template := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "Shyntr Global Identity - " + use},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour * 10),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &newKey.PublicKey, newKey)
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	encryptedData, err := crypto.EncryptAES(x509.MarshalPKCS1PrivateKey(newKey), []byte(km.config.AppSecret))
	if err != nil {
		return nil, err
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&newKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key for KID generation: %w", err)
	}
	hash := sha256.Sum256(pubKeyBytes)
	kidHash := fmt.Sprintf("%x", hash)
	kid := fmt.Sprintf("%s-%s", use, kidHash[:8])

	newCryptoKey := &model.CryptoKey{
		ID:        kid,
		Use:       use,
		State:     state,
		Algorithm: "RS256",
		KeyData:   []byte(encryptedData),
		CertData:  string(pemCert),
	}

	if err := km.repo.Save(ctx, newCryptoKey); err != nil {
		return nil, err
	}

	return newCryptoKey, nil
}
