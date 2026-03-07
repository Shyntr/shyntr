package entity

type AuthMethod struct {
	ID       string `json:"id"`
	Type     string `json:"type"` // "saml", "oidc", "password"
	Name     string `json:"name"`
	LogoURL  string `json:"logo_url,omitempty"`
	LoginURL string `json:"login_url"`
}
