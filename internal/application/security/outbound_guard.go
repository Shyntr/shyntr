package security

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
)

var (
	ErrOutboundPolicyNotFound = errors.New("no outbound policy configured")
	ErrURLNotAllowed          = errors.New("url not allowed by outbound policy")
)

type outboundGuard struct {
	repo          port.OutboundPolicyRepository
	skipTLSVerify bool
}

func NewOutboundGuard(repo port.OutboundPolicyRepository, skipTLSVerify bool) port.OutboundGuard {
	return &outboundGuard{
		repo:          repo,
		skipTLSVerify: skipTLSVerify,
	}
}

func validatePolicyIP(policy *model.OutboundPolicy, addr netip.Addr) error {
	if policy == nil {
		return nil
	}
	if policy.BlockPrivateIPs && addr.IsPrivate() {
		return fmt.Errorf("%w: private ip %q is blocked", ErrURLNotAllowed, addr.String())
	}
	if policy.BlockLoopbackIPs && addr.IsLoopback() {
		return fmt.Errorf("%w: loopback ip %q is blocked", ErrURLNotAllowed, addr.String())
	}
	if policy.BlockLinkLocalIPs && (addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast()) {
		return fmt.Errorf("%w: link-local ip %q is blocked", ErrURLNotAllowed, addr.String())
	}
	if policy.BlockMulticastIPs && addr.IsMulticast() {
		return fmt.Errorf("%w: multicast ip %q is blocked", ErrURLNotAllowed, addr.String())
	}
	if addr.IsUnspecified() {
		return fmt.Errorf("%w: unspecified ip %q is blocked", ErrURLNotAllowed, addr.String())
	}
	return nil
}

func parseNetIP(ip net.IP) (netip.Addr, error) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, errors.New("failed to parse resolved ip")
	}
	return addr, nil
}

func (g *outboundGuard) ValidateURL(ctx context.Context, tenantID string, target model.OutboundTargetType, rawURL string) (*url.URL, *model.OutboundPolicy, error) {
	policy, err := g.repo.GetEffectivePolicy(ctx, tenantID, target)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrOutboundPolicyNotFound, err)
	}
	if policy == nil || !policy.Enabled {
		return nil, nil, ErrOutboundPolicyNotFound
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid url: %w", err)
	}

	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, nil, fmt.Errorf("%w: missing scheme or host", ErrURLNotAllowed)
	}

	if !containsStringCI(policy.AllowedSchemes, parsed.Scheme) {
		return nil, nil, fmt.Errorf("%w: scheme %q is not allowed", ErrURLNotAllowed, parsed.Scheme)
	}

	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return nil, nil, fmt.Errorf("%w: empty hostname", ErrURLNotAllowed)
	}

	if policy.BlockLocalhostNames && isLocalHostname(host) {
		return nil, nil, fmt.Errorf("%w: localhost-style hostname is blocked", ErrURLNotAllowed)
	}

	if literalIP, err := netip.ParseAddr(host); err == nil {
		if err := validatePolicyIP(policy, literalIP); err != nil {
			return nil, nil, err
		}
	}

	if len(policy.AllowedHostPatterns) > 0 && !matchHostPatternList(host, policy.AllowedHostPatterns) {
		return nil, nil, fmt.Errorf("%w: host %q is not allowed", ErrURLNotAllowed, host)
	}

	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if len(policy.AllowedPathPatterns) > 0 && !matchPathPatternList(path, policy.AllowedPathPatterns) {
		return nil, nil, fmt.Errorf("%w: path %q is not allowed", ErrURLNotAllowed, path)
	}

	if len(policy.AllowedPorts) > 0 {
		port := effectivePort(parsed)
		if !containsInt(policy.AllowedPorts, port) {
			return nil, nil, fmt.Errorf("%w: port %d is not allowed", ErrURLNotAllowed, port)
		}
	}

	if policy.RequireDNSResolve {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, nil, fmt.Errorf("dns resolution failed: %w", err)
		}
		if len(ips) == 0 {
			return nil, nil, fmt.Errorf("dns resolution returned no ip for %q", host)
		}
		for _, ip := range ips {
			addr, err := parseNetIP(ip)
			if err != nil {
				return nil, nil, fmt.Errorf("%s for host %q", err.Error(), host)
			}
			if err := validatePolicyIP(policy, addr); err != nil {
				return nil, nil, err
			}
		}
	}

	return parsed, policy, nil
}

func (g *outboundGuard) NewHTTPClient(ctx context.Context, tenantID string, target model.OutboundTargetType, policy *model.OutboundPolicy) *http.Client {
	timeout := 10 * time.Second
	if policy != nil && policy.RequestTimeoutSeconds > 0 {
		timeout = time.Duration(policy.RequestTimeoutSeconds) * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: g.skipTLSVerify,
		},
	}

	dialer := &net.Dialer{Timeout: timeout}
	transport.DialContext = func(dialCtx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		if host == "" {
			return nil, fmt.Errorf("%w: empty hostname", ErrURLNotAllowed)
		}

		if policy != nil {
			if policy.BlockLocalhostNames && isLocalHostname(host) {
				return nil, fmt.Errorf("%w: localhost-style hostname is blocked", ErrURLNotAllowed)
			}

			if literalIP, err := netip.ParseAddr(host); err == nil {
				if err := validatePolicyIP(policy, literalIP); err != nil {
					return nil, err
				}
				return dialer.DialContext(dialCtx, network, net.JoinHostPort(literalIP.String(), port))
			}

			ips, err := net.DefaultResolver.LookupIP(dialCtx, "ip", host)
			if err != nil {
				return nil, fmt.Errorf("dns resolution failed: %w", err)
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("dns resolution returned no ip for %q", host)
			}

			var lastErr error
			for _, ip := range ips {
				ipAddr, err := parseNetIP(ip)
				if err != nil {
					lastErr = err
					continue
				}
				if err := validatePolicyIP(policy, ipAddr); err != nil {
					lastErr = err
					continue
				}

				conn, err := dialer.DialContext(dialCtx, network, net.JoinHostPort(ipAddr.String(), port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, fmt.Errorf("no allowed ip address available for host %q", host)
		}

		return dialer.DialContext(dialCtx, network, addr)
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	if policy != nil && policy.DisableRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
		return client
	}

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if _, _, err := g.ValidateURL(ctx, tenantID, target, req.URL.String()); err != nil {
			return err
		}
		return nil
	}

	return client
}

func containsStringCI(values []string, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, v := range values {
		if strings.ToLower(strings.TrimSpace(v)) == target {
			return true
		}
	}
	return false
}

func containsInt(values []int, target int) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}

func isLocalHostname(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	return host == "localhost" ||
		host == "localhost.localdomain" ||
		strings.HasSuffix(host, ".local")
}

func matchHostPatternList(host string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchHostPattern(host, pattern) {
			return true
		}
	}
	return false
}

func matchHostPattern(host, pattern string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	pattern = strings.ToLower(strings.TrimSpace(pattern))

	if pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(host, suffix)
	}
	return host == pattern
}

func matchPathPatternList(path string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchPathPattern(path, pattern) {
			return true
		}
	}
	return false
}

func matchPathPattern(path, pattern string) bool {
	path = strings.TrimSpace(path)
	pattern = strings.TrimSpace(pattern)

	if pattern == "" {
		return false
	}
	if pattern == "*" || pattern == "/*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		base := strings.TrimSuffix(strings.TrimSuffix(pattern, "*"), "/")
		return path == base || strings.HasPrefix(path, base+"/")
	}
	return path == pattern
}

func effectivePort(u *url.URL) int {
	if p := u.Port(); p != "" {
		port, err := strconv.Atoi(p)
		if err == nil {
			return port
		}
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return 443
	case "http":
		return 80
	default:
		return 0
	}
}
