package payload

import (
	"time"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

type CreateOutboundPolicyRequest struct {
	ID       string `json:"id" example:"policy-123"`
	TenantID string `json:"tenant_id" example:"tenant-abc"`
	Name     string `json:"name" binding:"required" example:"Default Webhook Policy"`
	Target   string `json:"target" binding:"required,oneof=webhook_delivery saml_metadata_fetch oidc_discovery oidc_backchannel_logout" example:"webhook_delivery"`
	Enabled  bool   `json:"enabled" example:"true"`

	AllowedSchemes      []string `json:"allowed_schemes" example:"https"`
	AllowedHostPatterns []string `json:"allowed_host_patterns" example:"*.example.com"`
	AllowedPathPatterns []string `json:"allowed_path_patterns" example:"/api/*"`
	AllowedPorts        []int    `json:"allowed_ports" example:"443"`

	BlockPrivateIPs     bool `json:"block_private_ips" example:"true"`
	BlockLoopbackIPs    bool `json:"block_loopback_ips" example:"true"`
	BlockLinkLocalIPs   bool `json:"block_link_local_ips" example:"true"`
	BlockMulticastIPs   bool `json:"block_multicast_ips" example:"true"`
	BlockLocalhostNames bool `json:"block_localhost_names" example:"true"`

	DisableRedirects  bool `json:"disable_redirects" example:"true"`
	RequireDNSResolve bool `json:"require_dns_resolve" example:"true"`

	RequestTimeoutSeconds int   `json:"request_timeout_seconds" binding:"gte=1,lte=30" example:"5"`
	MaxResponseBytes      int64 `json:"max_response_bytes" binding:"gte=1024,lte=10485760" example:"2097152"`
}

type UpdateOutboundPolicyRequest struct {
	Name    string `json:"name" binding:"required" example:"Updated Policy Name"`
	Enabled bool   `json:"enabled" example:"true"`

	AllowedSchemes      []string `json:"allowed_schemes" example:"https"`
	AllowedHostPatterns []string `json:"allowed_host_patterns" example:"api.example.com"`
	AllowedPathPatterns []string `json:"allowed_path_patterns" example:"/v1/*"`
	AllowedPorts        []int    `json:"allowed_ports" example:"443"`

	BlockPrivateIPs     bool `json:"block_private_ips" example:"true"`
	BlockLoopbackIPs    bool `json:"block_loopback_ips" example:"true"`
	BlockLinkLocalIPs   bool `json:"block_link_local_ips" example:"true"`
	BlockMulticastIPs   bool `json:"block_multicast_ips" example:"true"`
	BlockLocalhostNames bool `json:"block_localhost_names" example:"true"`

	DisableRedirects  bool `json:"disable_redirects" example:"true"`
	RequireDNSResolve bool `json:"require_dns_resolve" example:"true"`

	RequestTimeoutSeconds int   `json:"request_timeout_seconds" binding:"gte=1,lte=30" example:"5"`
	MaxResponseBytes      int64 `json:"max_response_bytes" binding:"gte=1024,lte=10485760" example:"2097152"`
}

type OutboundPolicyResponse struct {
	ID       string `json:"id" example:"policy-123"`
	TenantID string `json:"tenant_id" example:"tenant-abc"`
	Name     string `json:"name" example:"Default Webhook Policy"`
	Target   string `json:"target" example:"webhook_delivery"`
	Enabled  bool   `json:"enabled" example:"true"`

	AllowedSchemes      []string `json:"allowed_schemes" example:"https"`
	AllowedHostPatterns []string `json:"allowed_host_patterns" example:"*.example.com"`
	AllowedPathPatterns []string `json:"allowed_path_patterns" example:"/api/*"`
	AllowedPorts        []int    `json:"allowed_ports" example:"443"`

	BlockPrivateIPs     bool `json:"block_private_ips" example:"true"`
	BlockLoopbackIPs    bool `json:"block_loopback_ips" example:"true"`
	BlockLinkLocalIPs   bool `json:"block_link_local_ips" example:"true"`
	BlockMulticastIPs   bool `json:"block_multicast_ips" example:"true"`
	BlockLocalhostNames bool `json:"block_localhost_names" example:"true"`

	DisableRedirects  bool `json:"disable_redirects" example:"true"`
	RequireDNSResolve bool `json:"require_dns_resolve" example:"true"`

	RequestTimeoutSeconds int   `json:"request_timeout_seconds" example:"5"`
	MaxResponseBytes      int64 `json:"max_response_bytes" example:"2097152"`

	CreatedAt time.Time `json:"created_at" example:"2026-01-01T12:00:00Z"`
	UpdatedAt time.Time `json:"updated_at" example:"2026-01-01T12:00:00Z"`
}

func (r *CreateOutboundPolicyRequest) ToDomain() *model.OutboundPolicy {
	return &model.OutboundPolicy{
		ID:                    r.ID,
		TenantID:              r.TenantID,
		Name:                  r.Name,
		Target:                model.OutboundTargetType(r.Target),
		Enabled:               r.Enabled,
		AllowedSchemes:        r.AllowedSchemes,
		AllowedHostPatterns:   r.AllowedHostPatterns,
		AllowedPathPatterns:   r.AllowedPathPatterns,
		AllowedPorts:          r.AllowedPorts,
		BlockPrivateIPs:       r.BlockPrivateIPs,
		BlockLoopbackIPs:      r.BlockLoopbackIPs,
		BlockLinkLocalIPs:     r.BlockLinkLocalIPs,
		BlockMulticastIPs:     r.BlockMulticastIPs,
		BlockLocalhostNames:   r.BlockLocalhostNames,
		DisableRedirects:      r.DisableRedirects,
		RequireDNSResolve:     r.RequireDNSResolve,
		RequestTimeoutSeconds: r.RequestTimeoutSeconds,
		MaxResponseBytes:      r.MaxResponseBytes,
	}
}

func ApplyOutboundPolicyUpdate(dst *model.OutboundPolicy, req *UpdateOutboundPolicyRequest) {
	dst.Name = req.Name
	dst.Enabled = req.Enabled
	dst.AllowedSchemes = req.AllowedSchemes
	dst.AllowedHostPatterns = req.AllowedHostPatterns
	dst.AllowedPathPatterns = req.AllowedPathPatterns
	dst.AllowedPorts = req.AllowedPorts
	dst.BlockPrivateIPs = req.BlockPrivateIPs
	dst.BlockLoopbackIPs = req.BlockLoopbackIPs
	dst.BlockLinkLocalIPs = req.BlockLinkLocalIPs
	dst.BlockMulticastIPs = req.BlockMulticastIPs
	dst.BlockLocalhostNames = req.BlockLocalhostNames
	dst.DisableRedirects = req.DisableRedirects
	dst.RequireDNSResolve = req.RequireDNSResolve
	dst.RequestTimeoutSeconds = req.RequestTimeoutSeconds
	dst.MaxResponseBytes = req.MaxResponseBytes
}

func FromDomainOutboundPolicy(p *model.OutboundPolicy) *OutboundPolicyResponse {
	return &OutboundPolicyResponse{
		ID:                    p.ID,
		TenantID:              p.TenantID,
		Name:                  p.Name,
		Target:                string(p.Target),
		Enabled:               p.Enabled,
		AllowedSchemes:        p.AllowedSchemes,
		AllowedHostPatterns:   p.AllowedHostPatterns,
		AllowedPathPatterns:   p.AllowedPathPatterns,
		AllowedPorts:          p.AllowedPorts,
		BlockPrivateIPs:       p.BlockPrivateIPs,
		BlockLoopbackIPs:      p.BlockLoopbackIPs,
		BlockLinkLocalIPs:     p.BlockLinkLocalIPs,
		BlockMulticastIPs:     p.BlockMulticastIPs,
		BlockLocalhostNames:   p.BlockLocalhostNames,
		DisableRedirects:      p.DisableRedirects,
		RequireDNSResolve:     p.RequireDNSResolve,
		RequestTimeoutSeconds: p.RequestTimeoutSeconds,
		MaxResponseBytes:      p.MaxResponseBytes,
		CreatedAt:             p.CreatedAt,
		UpdatedAt:             p.UpdatedAt,
	}
}

func FromDomainOutboundPolicies(items []*model.OutboundPolicy) []*OutboundPolicyResponse {
	out := make([]*OutboundPolicyResponse, 0, len(items))
	for _, item := range items {
		out = append(out, FromDomainOutboundPolicy(item))
	}
	return out
}
