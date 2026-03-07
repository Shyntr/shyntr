package utils

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/crewjam/saml"
)

func FetchAndParseMetadata(metadataURL string) (*saml.EntityDescriptor, string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(metadataURL)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch metadata url: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, "", fmt.Errorf("metadata url returned status %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
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
