package dto

type AcceptConsentRequest struct {
	GrantScope    []string `json:"grant_scope"`
	GrantAudience []string `json:"grant_audience"`
	Remember      bool     `json:"remember"`
	RememberFor   int      `json:"remember_for"`
	Session       *struct {
		AccessToken map[string]any `json:"access_token"`
		IDToken     map[string]any `json:"id_token"`
	} `json:"session,omitempty"`
}

type AcceptLoginRequest struct {
	Subject     string                 `json:"subject" binding:"required"`
	Remember    bool                   `json:"remember"`
	RememberFor int                    `json:"remember_for"`
	Context     map[string]interface{} `json:"context"`
}
