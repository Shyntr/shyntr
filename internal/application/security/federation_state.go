package security

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/pkg/utils"
)

const (
	FederationActionOIDCLogin   = "oidc_login"
	FederationActionSAMLLogin   = "saml_login"
	FederationActionAccountLink = "account_link"
)

var (
	ErrInvalidFederationState = errors.New("invalid federation state")
	ErrExpiredFederationState = errors.New("expired federation state")
	ErrCSRFMismatch           = errors.New("csrf binding mismatch")
	ErrTenantMismatch         = errors.New("tenant mismatch")
	ErrUserMismatch           = errors.New("user mismatch")
	ErrActionMismatch         = errors.New("action mismatch")
	ErrMissingRequiredField   = errors.New("missing required field in federation state")
)

type FederationStateProvider interface {
	Issue(ctx context.Context, input IssueFederationStateInput) (string, error)
	Verify(ctx context.Context, token string, input VerifyFederationStateInput) (*FederationStatePayload, error)
}

type IssueFederationStateInput struct {
	Action         string
	TenantID       string
	LoginChallenge string
	ConnectionID   string
	UserID         string
	CSRFToken      string
	TTL            time.Duration
}

type VerifyFederationStateInput struct {
	ExpectedAction string
	ExpectedTenant string
	ExpectedUserID string
	CSRFToken      string
	Now            time.Time
}

type FederationStatePayload struct {
	Action         string `json:"action"`
	TenantID       string `json:"tenant_id"`
	LoginChallenge string `json:"login_challenge"`
	ConnectionID   string `json:"connection_id"`
	UserID         string `json:"user_id,omitempty"`
	CSRFHash       string `json:"csrf_hash,omitempty"`
	ExpiresAt      int64  `json:"exp"`
	IssuedAt       int64  `json:"iat"`
	Version        int    `json:"v"`
}

type federationStateManager struct {
	secret []byte
	clock  func() time.Time
}

func deriveFederationStateKey(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

func NewFederationStateProvider(cfg *config.Config) FederationStateProvider {
	return &federationStateManager{
		secret: deriveFederationStateKey(cfg.AppSecret),
		clock:  func() time.Time { return time.Now().UTC() },
	}
}

func NewFederationStateProviderWithClock(cfg *config.Config, clock func() time.Time) FederationStateProvider {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &federationStateManager{
		secret: deriveFederationStateKey(cfg.AppSecret),
		clock:  clock,
	}
}

func (m *federationStateManager) Issue(ctx context.Context, input IssueFederationStateInput) (string, error) {
	_ = ctx

	if err := validateIssueInput(input); err != nil {
		return "", err
	}

	now := m.clock()
	payload := FederationStatePayload{
		Action:         input.Action,
		TenantID:       input.TenantID,
		LoginChallenge: input.LoginChallenge,
		ConnectionID:   input.ConnectionID,
		UserID:         input.UserID,
		ExpiresAt:      now.Add(input.TTL).Unix(),
		IssuedAt:       now.Unix(),
		Version:        1,
	}

	if input.CSRFToken != "" {
		payload.CSRFHash = sha256Hex(input.CSRFToken)
	}

	plain, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal federation state: %w", err)
	}

	token, err := encryptOpaque(plain, m.secret)
	if err != nil {
		return "", fmt.Errorf("encrypt federation state: %w", err)
	}

	return token, nil
}

func (m *federationStateManager) Verify(ctx context.Context, token string, input VerifyFederationStateInput) (*FederationStatePayload, error) {
	_ = ctx

	if token == "" {
		return nil, ErrInvalidFederationState
	}

	now := input.Now.UTC()
	if now.IsZero() {
		now = m.clock()
	}

	plain, err := decryptOpaque(token, m.secret)
	if err != nil {
		return nil, ErrInvalidFederationState
	}

	var payload FederationStatePayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, ErrInvalidFederationState
	}

	if payload.Version != 1 {
		return nil, ErrInvalidFederationState
	}
	if payload.Action == "" || payload.TenantID == "" || payload.ConnectionID == "" {
		return nil, ErrMissingRequiredField
	}

	switch payload.Action {
	case FederationActionOIDCLogin, FederationActionSAMLLogin:
		if payload.LoginChallenge == "" {
			return nil, ErrMissingRequiredField
		}
	case FederationActionAccountLink:
		if payload.UserID == "" {
			return nil, ErrMissingRequiredField
		}
	default:
		return nil, ErrInvalidFederationState
	}

	if payload.ExpiresAt <= now.Unix() {
		return nil, ErrExpiredFederationState
	}
	if input.ExpectedAction != "" && payload.Action != input.ExpectedAction {
		return nil, ErrActionMismatch
	}
	if input.ExpectedTenant != "" && payload.TenantID != input.ExpectedTenant {
		return nil, ErrTenantMismatch
	}
	if input.ExpectedUserID != "" && payload.UserID != input.ExpectedUserID {
		return nil, ErrUserMismatch
	}

	if payload.CSRFHash != "" {
		if input.CSRFToken == "" {
			return nil, ErrCSRFMismatch
		}
		expectedHash := sha256Hex(input.CSRFToken)
		if subtle.ConstantTimeCompare([]byte(payload.CSRFHash), []byte(expectedHash)) != 1 {
			return nil, ErrCSRFMismatch
		}
	} else if input.CSRFToken != "" {
		return nil, ErrCSRFMismatch
	}

	return &payload, nil
}

func validateIssueInput(input IssueFederationStateInput) error {
	if input.Action == "" {
		return fmt.Errorf("%w: action", ErrMissingRequiredField)
	}
	if input.TenantID == "" {
		return fmt.Errorf("%w: tenant_id", ErrMissingRequiredField)
	}
	if input.ConnectionID == "" {
		return fmt.Errorf("%w: connection_id", ErrMissingRequiredField)
	}
	if input.TTL <= 0 {
		return errors.New("invalid federation state ttl")
	}

	switch input.Action {
	case FederationActionOIDCLogin, FederationActionSAMLLogin:
		if input.LoginChallenge == "" {
			return fmt.Errorf("%w: login_challenge", ErrMissingRequiredField)
		}

	case FederationActionAccountLink:
		if input.UserID == "" {
			return fmt.Errorf("%w: user_id", ErrMissingRequiredField)
		}

	default:
		return fmt.Errorf("unsupported federation action: %s", input.Action)
	}

	return nil
}

func encryptOpaque(plain []byte, secret []byte) (string, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce, err := utils.GenerateRandomBytes(gcm.NonceSize())
	if err != nil {
		return "", err
	}
	if len(nonce) != gcm.NonceSize() {
		return "", fmt.Errorf("invalid nonce size: got=%d want=%d", len(nonce), gcm.NonceSize())
	}

	ciphertext := gcm.Seal(nil, nonce, plain, nil)
	raw := append(nonce, ciphertext...)

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decryptOpaque(token string, secret []byte) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return nil, ErrInvalidFederationState
	}

	nonce := raw[:nonceSize]
	ciphertext := raw[nonceSize:]

	return gcm.Open(nil, nonce, ciphertext, nil)
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
