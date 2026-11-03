package zitadel

import (
	"time"
)

// ProjectResults contains paginated project query results
type ProjectResults struct {
	Details Details         `json:"details"`
	Result  []ProjectResult `json:"result,omitempty"`
}

// ProjectDetails contains project metadata
type ProjectDetails struct {
	Sequence      string    `json:"sequence,omitempty"`
	CreationDate  time.Time `json:"creationDate"`
	ChangeDate    time.Time `json:"changeDate"`
	ResourceOwner string    `json:"resourceOwner,omitempty"`
}

// ProjectResult represents a Zitadel project
type ProjectResult struct {
	ID                   string         `json:"id,omitempty"`
	Details              ProjectDetails `json:"details"`
	Name                 string         `json:"name,omitempty"`
	State                string         `json:"state,omitempty"`
	ProjectRoleCheck     bool           `json:"projectRoleCheck,omitempty"`
	ProjectRoleAssertion bool           `json:"projectRoleAssertion,omitempty"`
}

// RoleResults contains paginated role query results
type RoleResults struct {
	Details Details      `json:"details"`
	Result  []RoleResult `json:"result,omitempty"`
}

// RoleDetails contains role metadata
type RoleDetails struct {
	Sequence      string    `json:"sequence,omitempty"`
	CreationDate  time.Time `json:"creationDate"`
	ChangeDate    time.Time `json:"changeDate"`
	ResourceOwner string    `json:"resourceOwner,omitempty"`
}

// RoleResult represents a project role
type RoleResult struct {
	Key         string      `json:"key,omitempty"`
	Details     RoleDetails `json:"details"`
	DisplayName string      `json:"displayName,omitempty"`
	Group       string      `json:"group,omitempty"`
}
