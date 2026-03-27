package utils

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/crewjam/saml"
)

func FetchAndParseMetadata(
	ctx context.Context,
	tenantID string,
	metadataURL string,
	outbound port.OutboundGuard,
) (*saml.EntityDescriptor, string, error) {
	safeURL, policy, err := outbound.ValidateURL(ctx, tenantID, model.OutboundTargetSAMLMetadataFetch, metadataURL)
	if err != nil {
		return nil, "", fmt.Errorf("metadata url violates outbound policy: %w", err)
	}

	client := outbound.NewHTTPClient(ctx, tenantID, model.OutboundTargetSAMLMetadataFetch, policy)

	req, err := httpNewRequestWithContext(ctx, safeURL.String())
	if err != nil {
		return nil, "", fmt.Errorf("failed to build metadata request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch metadata url: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("metadata url returned status %d", resp.StatusCode)
	}

	maxBytes := int64(2 << 20)
	if policy != nil && policy.MaxResponseBytes > 0 {
		maxBytes = policy.MaxResponseBytes
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return nil, "", fmt.Errorf("failed to read metadata body: %w", err)
	}

	var descriptor saml.EntityDescriptor
	if err := xml.Unmarshal(bodyBytes, &descriptor); err != nil {
		return nil, "", fmt.Errorf("failed to parse metadata xml: %w", err)
	}

	return &descriptor, string(bodyBytes), nil
}

func FormatCertificate(rawCert string) string {
	rawCert = strings.TrimSpace(rawCert)
	if !strings.HasPrefix(rawCert, "-----BEGIN CERTIFICATE-----") {
		return fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", rawCert)
	}
	return rawCert
}
