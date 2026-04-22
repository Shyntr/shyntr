package model

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"time"
)

// hexColorRe matches #RGB, #RGBA, #RRGGBB, and #RRGGBBAA hex color formats.
var hexColorRe = regexp.MustCompile(`^#([0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$`)

// maxBrandingTextLen caps display-string fields that are rendered in the login UI.
const maxBrandingTextLen = 255

// BrandingColors holds the color palette for the login UI.
type BrandingColors struct {
	Primary       string `json:"primary"`
	Secondary     string `json:"secondary"`
	Background    string `json:"background"`
	Surface       string `json:"surface"`
	Text          string `json:"text"`
	TextSecondary string `json:"textSecondary"`
	Border        string `json:"border"`
	Error         string `json:"error"`
	Success       string `json:"success"`
	Warning       string `json:"warning"`
}

// BrandingFonts holds the typography settings.
type BrandingFonts struct {
	Family       string `json:"family"`
	SizeBase     int    `json:"sizeBase"`
	WeightNormal int    `json:"weightNormal"`
	WeightBold   int    `json:"weightBold"`
}

// BrandingBorders holds border style settings.
type BrandingBorders struct {
	Radius int `json:"radius"`
	Width  int `json:"width"`
}

// BrandingWidget holds the widget-level branding assets.
type BrandingWidget struct {
	LogoURL       string `json:"logoUrl"`
	FaviconURL    string `json:"faviconUrl"`
	LoginTitle    string `json:"loginTitle"`
	LoginSubtitle string `json:"loginSubtitle"`
}

// BrandingPageBackground holds the page background configuration.
type BrandingPageBackground struct {
	Type  string `json:"type"`  // "color" | "image"
	Value string `json:"value"` // hex color or absolute https URL
}

// BrandingConfig is the canonical Branding Spec v1 shape stored per lifecycle state.
type BrandingConfig struct {
	DisplayName    string                 `json:"displayName"`
	ThemeID        string                 `json:"themeId"`
	Version        int                    `json:"version"`
	Colors         BrandingColors         `json:"colors"`
	Fonts          BrandingFonts          `json:"fonts"`
	Borders        BrandingBorders        `json:"borders"`
	Widget         BrandingWidget         `json:"widget"`
	PageBackground BrandingPageBackground `json:"page_background"`
}

// TenantBranding is the domain aggregate for tenant-scoped branding state.
// Published is nil when no publish has ever occurred.
type TenantBranding struct {
	TenantID    string
	Draft       BrandingConfig
	Published   *BrandingConfig
	UpdatedAt   time.Time
	PublishedAt *time.Time
}

// DefaultBrandingConfig returns the static hardcoded default branding configuration.
func DefaultBrandingConfig() BrandingConfig {
	return BrandingConfig{
		DisplayName: "",
		ThemeID:     "default",
		Version:     1,
		Colors: BrandingColors{
			Primary:       "#6366f1",
			Secondary:     "#8b5cf6",
			Background:    "#ffffff",
			Surface:       "#f8fafc",
			Text:          "#0f172a",
			TextSecondary: "#64748b",
			Border:        "#e2e8f0",
			Error:         "#ef4444",
			Success:       "#22c55e",
			Warning:       "#f59e0b",
		},
		Fonts: BrandingFonts{
			Family:       "Inter, system-ui, sans-serif",
			SizeBase:     16,
			WeightNormal: 400,
			WeightBold:   700,
		},
		Borders: BrandingBorders{
			Radius: 8,
			Width:  1,
		},
		Widget: BrandingWidget{
			LogoURL:       "",
			FaviconURL:    "",
			LoginTitle:    "",
			LoginSubtitle: "",
		},
		PageBackground: BrandingPageBackground{
			Type:  "color",
			Value: "#f8fafc",
		},
	}
}

// Validate enforces domain-level constraints on a BrandingConfig.
func (c *BrandingConfig) Validate() error {
	if c.ThemeID == "" {
		return errors.New("themeId cannot be empty")
	}
	if c.Version < 1 {
		return errors.New("version must be at least 1")
	}
	if len(c.DisplayName) > maxBrandingTextLen {
		return fmt.Errorf("displayName must not exceed %d characters", maxBrandingTextLen)
	}
	if err := validateBrandingColors(c.Colors); err != nil {
		return err
	}
	if err := validateBrandingFonts(c.Fonts); err != nil {
		return err
	}
	if err := validateBrandingBorders(c.Borders); err != nil {
		return err
	}
	if err := validateBrandingURL("widget.logoUrl", c.Widget.LogoURL); err != nil {
		return err
	}
	if err := validateBrandingURL("widget.faviconUrl", c.Widget.FaviconURL); err != nil {
		return err
	}
	if len(c.Widget.LoginTitle) > maxBrandingTextLen {
		return fmt.Errorf("widget.loginTitle must not exceed %d characters", maxBrandingTextLen)
	}
	if len(c.Widget.LoginSubtitle) > maxBrandingTextLen {
		return fmt.Errorf("widget.loginSubtitle must not exceed %d characters", maxBrandingTextLen)
	}
	if c.PageBackground.Type != "color" && c.PageBackground.Type != "image" {
		return fmt.Errorf("page_background.type must be 'color' or 'image', got '%s'", c.PageBackground.Type)
	}
	if c.PageBackground.Type == "color" {
		if c.PageBackground.Value == "" {
			return errors.New("page_background.value cannot be empty when type is 'color'")
		}
		if !hexColorRe.MatchString(c.PageBackground.Value) {
			return fmt.Errorf("page_background.value must be a valid hex color when type is 'color', got '%s'", c.PageBackground.Value)
		}
	}
	if c.PageBackground.Type == "image" {
		if c.PageBackground.Value == "" {
			return errors.New("page_background.value cannot be empty when type is 'image'")
		}
		if err := validateBrandingURL("page_background.value", c.PageBackground.Value); err != nil {
			return err
		}
	}
	return nil
}

func validateBrandingColors(c BrandingColors) error {
	fields := map[string]string{
		"colors.primary":       c.Primary,
		"colors.secondary":     c.Secondary,
		"colors.background":    c.Background,
		"colors.surface":       c.Surface,
		"colors.text":          c.Text,
		"colors.textSecondary": c.TextSecondary,
		"colors.border":        c.Border,
		"colors.error":         c.Error,
		"colors.success":       c.Success,
		"colors.warning":       c.Warning,
	}
	// Iterate in a deterministic order for stable error messages in tests.
	order := []string{
		"colors.primary", "colors.secondary", "colors.background", "colors.surface",
		"colors.text", "colors.textSecondary", "colors.border",
		"colors.error", "colors.success", "colors.warning",
	}
	for _, field := range order {
		value := fields[field]
		if value == "" {
			return fmt.Errorf("%s cannot be empty", field)
		}
		if !hexColorRe.MatchString(value) {
			return fmt.Errorf("%s must be a valid hex color (e.g. #rrggbb), got '%s'", field, value)
		}
	}
	return nil
}

func validateBrandingFonts(f BrandingFonts) error {
	if f.Family == "" {
		return errors.New("fonts.family cannot be empty")
	}
	if f.SizeBase < 8 || f.SizeBase > 72 {
		return fmt.Errorf("fonts.sizeBase must be between 8 and 72, got %d", f.SizeBase)
	}
	if f.WeightNormal < 100 || f.WeightNormal > 900 {
		return fmt.Errorf("fonts.weightNormal must be between 100 and 900, got %d", f.WeightNormal)
	}
	if f.WeightBold < 100 || f.WeightBold > 900 {
		return fmt.Errorf("fonts.weightBold must be between 100 and 900, got %d", f.WeightBold)
	}
	return nil
}

func validateBrandingBorders(b BrandingBorders) error {
	if b.Radius < 0 || b.Radius > 100 {
		return fmt.Errorf("borders.radius must be between 0 and 100, got %d", b.Radius)
	}
	if b.Width < 0 || b.Width > 10 {
		return fmt.Errorf("borders.width must be between 0 and 10, got %d", b.Width)
	}
	return nil
}

// validateBrandingURL rejects http://, javascript:, data:, and relative URLs.
// An empty string is allowed (field is optional).
func validateBrandingURL(field, rawURL string) error {
	if rawURL == "" {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", field, err)
	}
	if !u.IsAbs() {
		return fmt.Errorf("%s must be an absolute URL", field)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%s must use the https scheme, got '%s'", field, u.Scheme)
	}
	return nil
}
