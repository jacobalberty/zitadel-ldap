package zitadel

// GrantResults contains paginated grant query results
type GrantResults struct {
	Details Details `json:"details,omitempty"`
	Result  []Grant `json:"result,omitempty"`
}

// Grant represents a user's role grant in a project
type Grant struct {
	ID                 string   `json:"id,omitempty"`
	RoleKeys           []string `json:"roleKeys,omitempty"`
	State              string   `json:"state,omitempty"`
	UserID             string   `json:"userId,omitempty"`
	UserName           string   `json:"userName,omitempty"`
	FirstName          string   `json:"firstName,omitempty"`
	LastName           string   `json:"lastName,omitempty"`
	Email              string   `json:"email,omitempty"`
	DisplayName        string   `json:"displayName,omitempty"`
	OrgID              string   `json:"orgId,omitempty"`
	OrgName            string   `json:"orgName,omitempty"`
	OrgDomain          string   `json:"orgDomain,omitempty"`
	ProjectID          string   `json:"projectId,omitempty"`
	ProjectName        string   `json:"projectName,omitempty"`
	PreferredLoginName string   `json:"preferredLoginName,omitempty"`
	UserType           string   `json:"userType,omitempty"`
	GrantedOrgID       string   `json:"grantedOrgId,omitempty"`
	GrantedOrgName     string   `json:"grantedOrgName,omitempty"`
	GrantedOrgDomain   string   `json:"grantedOrgDomain,omitempty"`
}
