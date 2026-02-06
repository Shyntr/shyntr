package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/go-jose/go-jose/v3"
)

// GetOrGenerateRSAPrivateKey loads a private key from a file or generates a new one.
// In a real production environment, this should retrieve keys from a Vault or Encrypted DB.
func GetOrGenerateRSAPrivateKey(path string) *rsa.PrivateKey {
	keyBytes, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(keyBytes)
		if block != nil {
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err == nil {
				return key
			}
		}
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	_ = os.WriteFile(path, pemBytes, 0600)

	return key
}

// GeneratePublicJWKS converts the private key to a JSON Web Key Set (public part only).
func GeneratePublicJWKS(privateKey *rsa.PrivateKey) *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       &privateKey.PublicKey,
				KeyID:     "shyntr-key-1", // Must match the kid in the ID Token header
				Algorithm: "RS256",
				Use:       "sig",
			},
		},
	}
}
