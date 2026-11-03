package zitadel

import (
	"time"
)

// UserResults contains paginated user query results
type UserResults struct {
	Details Details `json:"details"`
	Result  []User  `json:"result,omitempty"`
}

// Details contains pagination and timing information
type Details struct {
	TotalResult string    `json:"totalResult,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// Profile represents a user's profile information
type Profile struct {
	GivenName         string `json:"givenName,omitempty"`
	FamilyName        string `json:"familyName,omitempty"`
	NickName          string `json:"nickName,omitempty"`
	DisplayName       string `json:"displayName,omitempty"`
	PreferredLanguage string `json:"preferredLanguage,omitempty"`
	Gender            string `json:"gender,omitempty"`
}

// Email represents a user's email information
type Email struct {
	Email      string `json:"email,omitempty"`
	IsVerified bool   `json:"isVerified,omitempty"`
}

// Human represents a human user account
type Human struct {
	Profile         Profile   `json:"profile"`
	Email           Email     `json:"email"`
	PasswordChanged time.Time `json:"passwordChanged"`
	Groups          []string  `json:"groups,omitempty"`
}

// Machine represents a service account
type Machine struct {
	Name            string `json:"name,omitempty"`
	Description     string `json:"description,omitempty"`
	HasSecret       bool   `json:"hasSecret,omitempty"`
	AccessTokenType string `json:"accessTokenType,omitempty"`
}

// User represents a Zitadel user (human or machine)
type User struct {
	UserID             string   `json:"userId,omitempty"`
	State              string   `json:"state,omitempty"`
	Username           string   `json:"username,omitempty"`
	LoginNames         []string `json:"loginNames,omitempty"`
	PreferredLoginName string   `json:"preferredLoginName,omitempty"`
	Human              *Human   `json:"human,omitempty"`
	Machine            *Machine `json:"machine,omitempty"`
}
