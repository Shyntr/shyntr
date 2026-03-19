package iam

import (
	"context"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
)

type KeyFetcher interface {
	GetEncryptionKey(ctx context.Context, uri string, alg string) (interface{}, error)
}

type JWEIDTokenStrategy struct {
	openid.OpenIDConnectTokenStrategy
	KeyFetcher KeyFetcher
}

var _ openid.OpenIDConnectTokenStrategy = (*JWEIDTokenStrategy)(nil)

func (s *JWEIDTokenStrategy) GenerateIDToken(ctx context.Context, lifespan time.Duration, requester fosite.Requester) (string, error) {
	jwsToken, err := s.OpenIDConnectTokenStrategy.GenerateIDToken(ctx, lifespan, requester)
	if err != nil {
		return "", err
	}

	client, ok := requester.GetClient().(*ExtendedClient)
	if !ok {
		return jwsToken, nil
	}

	alg := client.IDTokenEncryptedResponseAlg
	enc := client.IDTokenEncryptedResponseEnc

	if alg == "" {
		return jwsToken, nil
	}
	if enc == "" {
		enc = "A256GCM"
	}

	var pubKey interface{}

	if client.JwksURI != "" {
		pubKey, err = s.KeyFetcher.GetEncryptionKey(ctx, client.JwksURI, alg)
		if err != nil {
			return "", fmt.Errorf("failed to retrieve remote encryption key: %w", err)
		}
	} else if client.JSONWebKeys != nil {
		for _, key := range client.JSONWebKeys.Keys {
			if key.Use == "enc" || key.Use == "" {
				pubKey = key.Key
				break
			}
		}
	}

	if pubKey == nil {
		return "", fmt.Errorf("client requested JWE but no suitable encryption key found")
	}

	recipient := jose.Recipient{
		Algorithm: jose.KeyAlgorithm(alg),
		Key:       pubKey,
	}

	encrypter, err := jose.NewEncrypter(
		jose.ContentEncryption(enc),
		recipient,
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to initialize JWE encrypter: %w", err)
	}

	object, err := encrypter.Encrypt([]byte(jwsToken))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt ID token: %w", err)
	}

	serializedJWE, err := object.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize JWE token: %w", err)
	}

	return serializedJWE, nil
}
