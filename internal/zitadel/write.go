package zitadel

// UserCreateRequest contains required data to create a human user.
type UserCreateRequest struct {
	Username          string            `json:"username,omitempty"`
	Email             string            `json:"email,omitempty"`
	GivenName         string            `json:"givenName,omitempty"`
	FamilyName        string            `json:"familyName,omitempty"`
	NickName          string            `json:"nickName,omitempty"`
	DisplayName       string            `json:"displayName,omitempty"`
	PreferredLanguage string            `json:"preferredLanguage,omitempty"`
	Gender            string            `json:"gender,omitempty"`
	Phone             string            `json:"phone,omitempty"`
	Avatar            string            `json:"avatar,omitempty"`
	Password          string            `json:"password,omitempty"`
	Metadata          map[string][]byte `json:"metadata,omitempty"`
}

// UserUpdateRequest contains optional data to update a human user.
type UserUpdateRequest struct {
	Username          *string           `json:"username,omitempty"`
	Email             *string           `json:"email,omitempty"`
	GivenName         *string           `json:"givenName,omitempty"`
	FamilyName        *string           `json:"familyName,omitempty"`
	NickName          *string           `json:"nickName,omitempty"`
	DisplayName       *string           `json:"displayName,omitempty"`
	PreferredLanguage *string           `json:"preferredLanguage,omitempty"`
	Gender            *string           `json:"gender,omitempty"`
	Phone             *string           `json:"phone,omitempty"`
	Avatar            *string           `json:"avatar,omitempty"`
	Password          *string           `json:"password,omitempty"`
	Metadata          map[string][]byte `json:"metadata,omitempty"`
}
