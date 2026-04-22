package model

import "time"

type OutboundTargetType string

const (
	OutboundTargetWebhookDelivery   OutboundTargetType = "webhook_delivery"
	OutboundTargetSAMLMetadataFetch OutboundTargetType = "saml_metadata_fetch"
	OutboundTargetOIDCDiscovery     OutboundTargetType = "oidc_discovery"
	OutboundTargetOIDCBackchannel   OutboundTargetType = "oidc_backchannel_logout"
	OutboundTargetLDAPAuth          OutboundTargetType = "ldap_auth"
)

type OutboundPolicy struct {
	ID       string
	TenantID string // empty => global
	Name     string
	Target   OutboundTargetType
	Enabled  bool

	AllowedSchemes      []string
	AllowedHostPatterns []string
	AllowedPathPatterns []string
	AllowedPorts        []int

	BlockPrivateIPs     bool
	BlockLoopbackIPs    bool
	BlockLinkLocalIPs   bool
	BlockMulticastIPs   bool
	BlockLocalhostNames bool
	DisableRedirects    bool
	RequireDNSResolve   bool

	RequestTimeoutSeconds int
	MaxResponseBytes      int64

	CreatedAt time.Time
	UpdatedAt time.Time
}
