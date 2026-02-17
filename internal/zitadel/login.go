package zitadel

// LoginResult represents the result of a login attempt
type LoginResult struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}
