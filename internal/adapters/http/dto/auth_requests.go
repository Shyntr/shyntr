package dto

type RejectRequestPayload struct {
	Error            string `json:"error" binding:"required"`
	ErrorDescription string `json:"error_description"`
}

type AcceptConsentRequest struct {
	GrantScope    []string               `json:"grant_scope"`
	GrantAudience []string               `json:"grant_audience"`
	Remember      bool                   `json:"remember"`
	RememberFor   int                    `json:"remember_for"`
	Session       map[string]interface{} `json:"session,omitempty"`
}

type AcceptLoginRequest struct {
	Subject     string                 `json:"subject" binding:"required"`
	Remember    bool                   `json:"remember"`
	RememberFor int                    `json:"remember_for"`
	Context     map[string]interface{} `json:"context"`
}
