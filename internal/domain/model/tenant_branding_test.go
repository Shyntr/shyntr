package model_test

import (
	"strings"
	"testing"

	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func validConfig() model.BrandingConfig { return model.DefaultBrandingConfig() }

// ─── smoke test ──────────────────────────────────────────────────────────────

func TestBrandingConfig_DefaultIsValid(t *testing.T) {
	cfg := model.DefaultBrandingConfig()
	require.NoError(t, cfg.Validate(), "DefaultBrandingConfig must pass its own validation")
}

// ─── themeId ─────────────────────────────────────────────────────────────────

func TestBrandingConfig_EmptyThemeID_Rejected(t *testing.T) {
	cfg := validConfig()
	cfg.ThemeID = ""
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "themeId")
}

// ─── version ─────────────────────────────────────────────────────────────────

func TestBrandingConfig_Version_TableDriven(t *testing.T) {
	cases := []struct {
		version int
		wantErr bool
	}{
		{1, false},
		{2, false},
		{0, true},
		{-1, true},
	}
	for _, tc := range cases {
		cfg := validConfig()
		cfg.Version = tc.version
		err := cfg.Validate()
		if tc.wantErr {
			require.Error(t, err, "version %d should be rejected", tc.version)
			assert.Contains(t, err.Error(), "version")
		} else {
			require.NoError(t, err, "version %d should be accepted", tc.version)
		}
	}
}

// ─── displayName ─────────────────────────────────────────────────────────────

func TestBrandingConfig_DisplayName_TableDriven(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"empty", "", false},
		{"short", "Acme Corp", false},
		{"exactly255", strings.Repeat("x", 255), false},
		{"256chars", strings.Repeat("x", 256), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.DisplayName = tc.value
			err := cfg.Validate()
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "displayName")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// ─── colors ──────────────────────────────────────────────────────────────────

func TestBrandingConfig_Colors_HexFormats_Accepted(t *testing.T) {
	formats := []string{"#abc", "#abcd", "#aabbcc", "#aabbccdd"}
	for _, hex := range formats {
		cfg := validConfig()
		cfg.Colors.Primary = hex
		require.NoError(t, cfg.Validate(), "hex %q should be accepted", hex)
	}
}

func TestBrandingConfig_Colors_InvalidHex_Rejected(t *testing.T) {
	invalid := []string{"", "abc", "#xyz", "#12345", "rgb(0,0,0)", "red"}
	for _, val := range invalid {
		cfg := validConfig()
		cfg.Colors.Primary = val
		err := cfg.Validate()
		require.Error(t, err, "%q should be rejected", val)
		assert.Contains(t, err.Error(), "colors.primary")
	}
}

func TestBrandingConfig_Colors_AllFieldsValidated(t *testing.T) {
	type colorSetter func(c *model.BrandingConfig, v string)
	fields := []struct {
		name   string
		set    colorSetter
		errKey string
	}{
		{"primary", func(c *model.BrandingConfig, v string) { c.Colors.Primary = v }, "colors.primary"},
		{"secondary", func(c *model.BrandingConfig, v string) { c.Colors.Secondary = v }, "colors.secondary"},
		{"background", func(c *model.BrandingConfig, v string) { c.Colors.Background = v }, "colors.background"},
		{"surface", func(c *model.BrandingConfig, v string) { c.Colors.Surface = v }, "colors.surface"},
		{"text", func(c *model.BrandingConfig, v string) { c.Colors.Text = v }, "colors.text"},
		{"textSecondary", func(c *model.BrandingConfig, v string) { c.Colors.TextSecondary = v }, "colors.textSecondary"},
		{"border", func(c *model.BrandingConfig, v string) { c.Colors.Border = v }, "colors.border"},
		{"error", func(c *model.BrandingConfig, v string) { c.Colors.Error = v }, "colors.error"},
		{"success", func(c *model.BrandingConfig, v string) { c.Colors.Success = v }, "colors.success"},
		{"warning", func(c *model.BrandingConfig, v string) { c.Colors.Warning = v }, "colors.warning"},
	}
	for _, f := range fields {
		t.Run(f.name+"_empty", func(t *testing.T) {
			cfg := validConfig()
			f.set(&cfg, "")
			err := cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), f.errKey)
		})
		t.Run(f.name+"_invalid", func(t *testing.T) {
			cfg := validConfig()
			f.set(&cfg, "notacolor")
			err := cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), f.errKey)
		})
	}
}

// ─── fonts ───────────────────────────────────────────────────────────────────

func TestBrandingConfig_Fonts_TableDriven(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(c *model.BrandingConfig)
		errFrag string
		wantErr bool
	}{
		{"family_empty", func(c *model.BrandingConfig) { c.Fonts.Family = "" }, "fonts.family", true},
		{"sizeBase_low", func(c *model.BrandingConfig) { c.Fonts.SizeBase = 7 }, "fonts.sizeBase", true},
		{"sizeBase_high", func(c *model.BrandingConfig) { c.Fonts.SizeBase = 73 }, "fonts.sizeBase", true},
		{"sizeBase_min", func(c *model.BrandingConfig) { c.Fonts.SizeBase = 8 }, "", false},
		{"sizeBase_max", func(c *model.BrandingConfig) { c.Fonts.SizeBase = 72 }, "", false},
		{"weightNormal_low", func(c *model.BrandingConfig) { c.Fonts.WeightNormal = 99 }, "fonts.weightNormal", true},
		{"weightNormal_high", func(c *model.BrandingConfig) { c.Fonts.WeightNormal = 901 }, "fonts.weightNormal", true},
		{"weightNormal_min", func(c *model.BrandingConfig) { c.Fonts.WeightNormal = 100 }, "", false},
		{"weightNormal_max", func(c *model.BrandingConfig) { c.Fonts.WeightNormal = 900 }, "", false},
		{"weightBold_low", func(c *model.BrandingConfig) { c.Fonts.WeightBold = 99 }, "fonts.weightBold", true},
		{"weightBold_high", func(c *model.BrandingConfig) { c.Fonts.WeightBold = 901 }, "fonts.weightBold", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errFrag)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// ─── borders ─────────────────────────────────────────────────────────────────

func TestBrandingConfig_Borders_TableDriven(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(c *model.BrandingConfig)
		errFrag string
		wantErr bool
	}{
		{"radius_zero", func(c *model.BrandingConfig) { c.Borders.Radius = 0 }, "", false},
		{"radius_max", func(c *model.BrandingConfig) { c.Borders.Radius = 100 }, "", false},
		{"radius_negative", func(c *model.BrandingConfig) { c.Borders.Radius = -1 }, "borders.radius", true},
		{"radius_over", func(c *model.BrandingConfig) { c.Borders.Radius = 101 }, "borders.radius", true},
		{"width_zero", func(c *model.BrandingConfig) { c.Borders.Width = 0 }, "", false},
		{"width_max", func(c *model.BrandingConfig) { c.Borders.Width = 10 }, "", false},
		{"width_negative", func(c *model.BrandingConfig) { c.Borders.Width = -1 }, "borders.width", true},
		{"width_over", func(c *model.BrandingConfig) { c.Borders.Width = 11 }, "borders.width", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errFrag)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// ─── widget URLs ─────────────────────────────────────────────────────────────

func TestBrandingConfig_Widget_URLs_TableDriven(t *testing.T) {
	type urlSetter func(c *model.BrandingConfig, v string)
	fields := []struct {
		fieldName string
		set       urlSetter
		errKey    string
	}{
		{"logoUrl", func(c *model.BrandingConfig, v string) { c.Widget.LogoURL = v }, "widget.logoUrl"},
		{"faviconUrl", func(c *model.BrandingConfig, v string) { c.Widget.FaviconURL = v }, "widget.faviconUrl"},
	}
	urlCases := []struct {
		label   string
		value   string
		wantErr bool
	}{
		{"empty_allowed", "", false},
		{"valid_https", "https://cdn.example.com/logo.png", false},
		{"http_rejected", "http://cdn.example.com/logo.png", true},
		{"relative_rejected", "/logo.png", true},
		{"javascript_rejected", "javascript:alert(1)", true},
		{"data_rejected", "data:image/png;base64,abc", true},
		{"ftp_rejected", "ftp://cdn.example.com/logo.png", true},
	}
	for _, f := range fields {
		for _, u := range urlCases {
			t.Run(f.fieldName+"/"+u.label, func(t *testing.T) {
				cfg := validConfig()
				f.set(&cfg, u.value)
				err := cfg.Validate()
				if u.wantErr {
					require.Error(t, err)
					assert.Contains(t, err.Error(), f.errKey)
				} else {
					require.NoError(t, err)
				}
			})
		}
	}
}

// ─── widget display strings ───────────────────────────────────────────────────

func TestBrandingConfig_Widget_DisplayStrings_TableDriven(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(c *model.BrandingConfig)
		errFrag string
		wantErr bool
	}{
		{"loginTitle_empty", func(c *model.BrandingConfig) { c.Widget.LoginTitle = "" }, "", false},
		{"loginTitle_255", func(c *model.BrandingConfig) { c.Widget.LoginTitle = strings.Repeat("a", 255) }, "", false},
		{"loginTitle_256", func(c *model.BrandingConfig) { c.Widget.LoginTitle = strings.Repeat("a", 256) }, "widget.loginTitle", true},
		{"loginSubtitle_empty", func(c *model.BrandingConfig) { c.Widget.LoginSubtitle = "" }, "", false},
		{"loginSubtitle_255", func(c *model.BrandingConfig) { c.Widget.LoginSubtitle = strings.Repeat("b", 255) }, "", false},
		{"loginSubtitle_256", func(c *model.BrandingConfig) { c.Widget.LoginSubtitle = strings.Repeat("b", 256) }, "widget.loginSubtitle", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errFrag)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// ─── page_background ─────────────────────────────────────────────────────────

func TestBrandingConfig_PageBackground_TableDriven(t *testing.T) {
	cases := []struct {
		name    string
		bgType  string
		bgValue string
		errFrag string
		wantErr bool
	}{
		// type validation
		// Regression: dashboard editor previously sent 'solid' and 'gradient'; backend must reject both
		{"invalid_type_solid", "solid", "#ffffff", "page_background.type", true},
		{"invalid_type_gradient", "gradient", "linear-gradient(135deg, #0f172a, #1e293b)", "page_background.type", true},
		{"empty_type", "", "#ffffff", "page_background.type", true},

		// type=color
		{"color_valid_6digit", "color", "#f8fafc", "", false},
		{"color_valid_3digit", "color", "#fff", "", false},
		{"color_valid_8digit", "color", "#aabbccdd", "", false},
		{"color_empty_value", "color", "", "page_background.value", true},
		{"color_invalid_hex", "color", "notacolor", "page_background.value", true},
		{"color_http_url", "color", "http://example.com/bg.jpg", "page_background.value", true},
		{"color_https_url_rejected_as_color", "color", "https://example.com/bg.jpg", "page_background.value", true},

		// type=image
		{"image_valid_https", "image", "https://cdn.example.com/bg.jpg", "", false},
		{"image_http_rejected", "image", "http://cdn.example.com/bg.jpg", "page_background.value", true},
		{"image_relative_rejected", "image", "/bg.jpg", "page_background.value", true},
		{"image_empty_rejected", "image", "", "page_background.value", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.PageBackground.Type = tc.bgType
			cfg.PageBackground.Value = tc.bgValue
			err := cfg.Validate()
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errFrag)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
