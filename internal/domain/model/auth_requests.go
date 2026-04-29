package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type LoginRequest struct {
	ID                string
	TenantID          string
	ClientID          string
	Subject           string
	RequestedScope    []string
	RequestedAudience []string
	RequestURL        string
	Protocol          string
	SAMLRequestID     string
	ClientIP          string
	Context           []byte // JSON encoded state
	Authenticated     bool
	Remember          bool
	RememberFor       int
	Active            bool
	Skip              bool
	SessionID         string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type LoginContext struct {
	Identity       *LoginIdentityContext       `json:"identity,omitempty"`
	Authentication *LoginAuthenticationContext `json:"authentication,omitempty"`
}

type LoginIdentityContext struct {
	Attributes map[string]interface{} `json:"attributes,omitempty"`
	Groups     []string               `json:"groups,omitempty"`
	Roles      []string               `json:"roles,omitempty"`
}

type LoginAuthenticationContext struct {
	AMR             []string   `json:"amr,omitempty"`
	ACR             string     `json:"acr,omitempty"`
	AuthenticatedAt *time.Time `json:"authenticated_at,omitempty"`
}

func (r *LoginRequest) NormalizedContext() (*LoginContext, bool, error) {
	if r == nil || len(r.Context) == 0 {
		return nil, false, nil
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(r.Context, &raw); err != nil {
		return nil, false, fmt.Errorf("invalid login context: %w", err)
	}
	if identityRaw, hasIdentity := raw["identity"]; hasIdentity {
		if string(identityRaw) == "null" {
			return nil, false, errors.New("identity context must be an object")
		}
	} else {
		if authenticationRaw, hasAuthentication := raw["authentication"]; hasAuthentication {
			if string(authenticationRaw) == "null" {
				return nil, false, errors.New("authentication context must be an object")
			}
		} else {
			return nil, false, nil
		}
	}
	if authenticationRaw, hasAuthentication := raw["authentication"]; hasAuthentication && string(authenticationRaw) == "null" {
		return nil, false, errors.New("authentication context must be an object")
	}

	var ctx LoginContext
	if err := json.Unmarshal(r.Context, &ctx); err != nil {
		return nil, false, fmt.Errorf("invalid normalized login context: %w", err)
	}
	if err := ctx.Validate(); err != nil {
		return nil, false, err
	}
	return &ctx, true, nil
}

func ValidateNormalizedLoginContextData(contextData map[string]interface{}) error {
	if contextData == nil {
		return nil
	}
	if identity, hasIdentity := contextData["identity"]; hasIdentity {
		if identity == nil {
			return errors.New("identity context must be an object")
		}
	} else {
		if authentication, hasAuthentication := contextData["authentication"]; hasAuthentication {
			if authentication == nil {
				return errors.New("authentication context must be an object")
			}
		} else {
			return nil
		}
	}
	if authentication, hasAuthentication := contextData["authentication"]; hasAuthentication && authentication == nil {
		return errors.New("authentication context must be an object")
	}

	contextBytes, err := json.Marshal(contextData)
	if err != nil {
		return fmt.Errorf("failed to marshal login context data: %w", err)
	}

	var ctx LoginContext
	if err := json.Unmarshal(contextBytes, &ctx); err != nil {
		return fmt.Errorf("invalid normalized login context: %w", err)
	}
	return ctx.Validate()
}

func (c *LoginContext) Validate() error {
	if c == nil {
		return nil
	}
	if c.Identity != nil {
		if err := c.Identity.Validate(); err != nil {
			return err
		}
	}
	if c.Authentication != nil {
		if err := c.Authentication.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (c *LoginIdentityContext) Validate() error {
	if c == nil {
		return nil
	}
	for key, value := range c.Attributes {
		if strings.TrimSpace(key) == "" {
			return errors.New("identity attribute name must not be empty")
		}
		if !isSupportedIdentityAttributeValue(value) {
			return fmt.Errorf("identity attribute %q has unsupported value type", key)
		}
	}
	if err := validateStringSlice("identity groups", c.Groups); err != nil {
		return err
	}
	if err := validateStringSlice("identity roles", c.Roles); err != nil {
		return err
	}
	return nil
}

func (c *LoginAuthenticationContext) Validate() error {
	if c == nil {
		return nil
	}
	if err := validateStringSlice("authentication amr", c.AMR); err != nil {
		return err
	}
	if strings.TrimSpace(c.ACR) != c.ACR {
		return errors.New("authentication acr must not include leading or trailing whitespace")
	}
	if c.AuthenticatedAt != nil && c.AuthenticatedAt.IsZero() {
		return errors.New("authentication authenticated_at must be a valid timestamp")
	}
	return nil
}

func validateStringSlice(field string, values []string) error {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s must not contain empty values", field)
		}
		if strings.TrimSpace(value) != value {
			return fmt.Errorf("%s values must not include leading or trailing whitespace", field)
		}
	}
	return nil
}

func isSupportedIdentityAttributeValue(value interface{}) bool {
	switch value.(type) {
	case nil, string, bool, float32, float64, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, json.Number:
		return true
	default:
		return false
	}
}

type ConsentRequest struct {
	ID                string
	LoginChallenge    string
	ClientID          string
	Subject           string
	RequestedScope    []string
	RequestedAudience []string
	GrantedScope      []string
	GrantedAudience   []string
	RequestURL        string
	Context           []byte // JSON encoded session
	Skip              bool
	Authenticated     bool
	Remember          bool
	RememberFor       int
	Active            bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
}
