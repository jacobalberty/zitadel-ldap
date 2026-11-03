package handler

import (
	"strings"

	ldaputil "github.com/jacobalberty/zitadel-ldap/internal/ldap"
)

// BuildGroupMembershipFilter builds a filter for group membership lookups.
// If useDN is true, the filter targets DN-based membership (uniqueMember).
// If false, the filter targets UID-based membership (memberUid).
func BuildGroupMembershipFilter(userIDOrDN string, useDN bool) string {
	return ldaputil.BuildUserMembershipFilter(userIDOrDN, useDN)
}

// BuildMetadataFilter builds a validated filter for metadata lookups.
// Metadata attributes are prefixed with "gl_" if not already present.
func BuildMetadataFilter(key, value string) (string, error) {
	return ldaputil.CompileFilterForMetadata(key, value)
}

// BuildUserIdentityFilter builds a filter that matches by username or email.
// The resulting filter is useful for flexible user lookups.
func BuildUserIdentityFilter(username, email string) string {
	filters := []string{}
	if strings.TrimSpace(username) != "" {
		filters = append(filters, ldaputil.BuildEqualityFilter("cn", username))
	}
	if strings.TrimSpace(email) != "" {
		filters = append(filters, ldaputil.BuildEqualityFilter("mail", email))
	}

	return ldaputil.BuildOrFilter(filters...)
}
