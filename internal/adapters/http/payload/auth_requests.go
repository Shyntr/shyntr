package payload

type RejectRequestPayload struct {
	Error            string `json:"error" binding:"required" example:"access_denied"`
	ErrorDescription string `json:"error_description" example:"The resource owner or authorization server denied the request."`
}

type AcceptConsentRequest struct {
	GrantScope    []string               `json:"grant_scope" example:"openid,profile,email"`
	GrantAudience []string               `json:"grant_audience" example:"api.shyntr.internal"`
	Remember      bool                   `json:"remember" example:"true"`
	RememberFor   int                    `json:"remember_for" example:"3600"`
	Session       map[string]interface{} `json:"session,omitempty" swaggertype:"object"`
}

type AcceptLoginRequest struct {
	Subject     string                 `json:"subject" binding:"required" example:"usr_9f8b7c6d5e4a3b2c1"`
	Remember    bool                   `json:"remember" example:"false"`
	RememberFor int                    `json:"remember_for" example:"0"`
	Context     map[string]interface{} `json:"context" swaggertype:"object"`
}
