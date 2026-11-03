package ldap

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// EscapeFilterValue escapes a string for use in an LDAP filter.
// Handles special characters according to RFC 4515.
// Examples:
//
//	"John Doe" -> "John Doe"
//	"John,Doe" -> "John,Doe"
//	"test*value" -> "test\\2avalue"
func EscapeFilterValue(val string) string {
	return ldap.EscapeFilter(val)
}

// ValidateFilter validates LDAP filter syntax by attempting to compile it.
// Returns nil if the filter is valid, error otherwise.
// Example valid filters: "(&(cn=john)(mail=*@example.com))"
func ValidateFilter(filter string) error {
	if strings.TrimSpace(filter) == "" {
		return fmt.Errorf("filter cannot be empty")
	}

	_, err := ldap.CompileFilter(filter)
	if err != nil {
		return fmt.Errorf("invalid filter syntax: %w", err)
	}

	return nil
}

// BuildEqualityFilter constructs a simple equality filter for an attribute.
// Automatically escapes the value for RFC 4515 compliance.
// Example: BuildEqualityFilter("mail", "john@example.com") -> "(mail=john@example.com)"
func BuildEqualityFilter(attribute, value string) string {
	escapedValue := EscapeFilterValue(value)
	return fmt.Sprintf("(%s=%s)", attribute, escapedValue)
}

// BuildSubstringFilter constructs a substring filter for attribute matching.
// Supports wildcard patterns within the substring filter format.
// Example: BuildSubstringFilter("cn", "*john*") -> "(cn=*john*)"
func BuildSubstringFilter(attribute, pattern string) string {
	return fmt.Sprintf("(%s=%s)", attribute, pattern)
}

// BuildSubstringFilterEscaped constructs a substring filter from a literal value.
// The value is escaped, then optional wildcards are added.
// Example: BuildSubstringFilterEscaped("cn", "john", true, true) -> "(cn=*john*)"
func BuildSubstringFilterEscaped(attribute, value string, prefixWildcard, suffixWildcard bool) string {
	escaped := EscapeFilterValue(value)
	if prefixWildcard {
		escaped = "*" + escaped
	}
	if suffixWildcard {
		escaped = escaped + "*"
	}
	return fmt.Sprintf("(%s=%s)", attribute, escaped)
}

// BuildAndFilter combines multiple filters with AND logic.
// Example: BuildAndFilter(["(cn=john)", "(mail=*)"]) -> "(&(cn=john)(mail=*))"
func BuildAndFilter(filters ...string) string {
	if len(filters) == 0 {
		return ""
	}
	if len(filters) == 1 {
		return filters[0]
	}
	return fmt.Sprintf("(&%s)", strings.Join(filters, ""))
}

// BuildOrFilter combines multiple filters with OR logic.
// Example: BuildOrFilter(["(cn=john)", "(cn=jane)"]) -> "(|(cn=john)(cn=jane))"
func BuildOrFilter(filters ...string) string {
	if len(filters) == 0 {
		return ""
	}
	if len(filters) == 1 {
		return filters[0]
	}
	return fmt.Sprintf("(|%s)", strings.Join(filters, ""))
}

// BuildNotFilter negates a filter.
// Example: BuildNotFilter("(accountStatus=inactive)") -> "(!(accountStatus=inactive))"
func BuildNotFilter(filter string) string {
	return fmt.Sprintf("(!%s)", filter)
}

// CompileFilterForMetadata constructs and validates a filter for matching metadata attributes.
// Metadata attributes are typically stored with prefixes like "gl_" in LDAP.
// Example: CompileFilterForMetadata("gl_department", "engineering") -> "(gl_department=engineering)"
func CompileFilterForMetadata(key, value string) (string, error) {
	// Ensure metadata key has proper prefix if not already present
	attrName := key
	if !strings.HasPrefix(key, "gl_") {
		attrName = "gl_" + key
	}

	filter := BuildEqualityFilter(attrName, value)

	// Validate the constructed filter
	if err := ValidateFilter(filter); err != nil {
		return "", fmt.Errorf("failed to compile metadata filter: %w", err)
	}

	return filter, nil
}

// BuildUserMembershipFilter constructs a filter to find all groups a user belongs to.
// Example: "(memberUid=john)" or "(uniqueMember=cn=john,ou=users,dc=example,dc=com)"
func BuildUserMembershipFilter(userIDOrDN string, useDN bool) string {
	if useDN {
		return BuildEqualityFilter("uniqueMember", userIDOrDN)
	}
	return BuildEqualityFilter("memberUid", userIDOrDN)
}

// MatchFilter evaluates a limited subset of LDAP filters against attributes.
// Supported operators: AND (&), OR (|), NOT (!), equality, presence, and substring.
// Attribute names are matched case-insensitively.
func MatchFilter(filter string, attributes map[string][]string) (bool, error) {
	if err := ValidateFilter(filter); err != nil {
		return false, err
	}

	normalized := normalizeAttributes(attributes)
	return matchFilter(strings.TrimSpace(filter), normalized)
}

// MatchAnyFilter returns true if any filter matches the attributes.
func MatchAnyFilter(filters []string, attributes map[string][]string) (bool, error) {
	for _, filter := range filters {
		matched, err := MatchFilter(filter, attributes)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}

	return false, nil
}

func normalizeAttributes(attributes map[string][]string) map[string][]string {
	normalized := make(map[string][]string, len(attributes))
	for key, values := range attributes {
		lowerKey := strings.ToLower(strings.TrimSpace(key))
		if lowerKey == "" {
			continue
		}
		normalized[lowerKey] = append([]string{}, values...)
	}
	return normalized
}

func matchFilter(filter string, attributes map[string][]string) (bool, error) {
	if len(filter) < 2 || filter[0] != '(' || filter[len(filter)-1] != ')' {
		return false, fmt.Errorf("invalid filter format: %s", filter)
	}

	inner := strings.TrimSpace(filter[1 : len(filter)-1])
	if inner == "" {
		return false, fmt.Errorf("empty filter")
	}

	switch inner[0] {
	case '&':
		subfilters, err := splitSubfilters(inner[1:])
		if err != nil {
			return false, err
		}
		for _, sub := range subfilters {
			matched, err := matchFilter(sub, attributes)
			if err != nil {
				return false, err
			}
			if !matched {
				return false, nil
			}
		}
		return true, nil
	case '|':
		subfilters, err := splitSubfilters(inner[1:])
		if err != nil {
			return false, err
		}
		for _, sub := range subfilters {
			matched, err := matchFilter(sub, attributes)
			if err != nil {
				return false, err
			}
			if matched {
				return true, nil
			}
		}
		return false, nil
	case '!':
		sub := strings.TrimSpace(inner[1:])
		matched, err := matchFilter(sub, attributes)
		if err != nil {
			return false, err
		}
		return !matched, nil
	default:
		return matchSimpleFilter(inner, attributes)
	}
}

func splitSubfilters(filters string) ([]string, error) {
	var subfilters []string
	depth := 0
	start := -1

	for i, r := range filters {
		switch r {
		case '(':
			if depth == 0 {
				start = i
			}
			depth++
		case ')':
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("unbalanced filter: %s", filters)
			}
			if depth == 0 && start >= 0 {
				subfilters = append(subfilters, filters[start:i+1])
				start = -1
			}
		}
	}

	if depth != 0 {
		return nil, fmt.Errorf("unbalanced filter: %s", filters)
	}

	return subfilters, nil
}

func matchSimpleFilter(filter string, attributes map[string][]string) (bool, error) {
	parts := strings.SplitN(filter, "=", 2)
	if len(parts) != 2 {
		return false, fmt.Errorf("unsupported filter: %s", filter)
	}

	attr := strings.ToLower(strings.TrimSpace(parts[0]))
	value := parts[1]
	if attr == "" {
		return false, fmt.Errorf("empty attribute in filter: %s", filter)
	}
	// Ordering/approximate matches are valid LDAP but not implemented here.
	// Fail loudly rather than silently evaluating to "no match".
	if last := attr[len(attr)-1]; last == '>' || last == '<' || last == '~' || last == ':' {
		return false, fmt.Errorf("unsupported filter operator in %q (only =, presence and substring are supported)", filter)
	}

	values := attributes[attr]
	if len(values) == 0 {
		return false, nil
	}

	// Presence filter
	if value == "*" {
		return true, nil
	}

	// Substring filter
	if strings.Contains(value, "*") {
		for _, v := range values {
			if wildcardMatch(strings.ToLower(v), strings.ToLower(value)) {
				return true, nil
			}
		}
		return false, nil
	}

	// Equality filter (case-insensitive, like most LDAP string attributes)
	value = unescapeFilterValue(value)
	for _, v := range values {
		if strings.EqualFold(v, value) {
			return true, nil
		}
	}

	return false, nil
}

func wildcardMatch(value, pattern string) bool {
	if pattern == "*" {
		return true
	}

	parts := strings.Split(pattern, "*")
	index := 0

	if !strings.HasPrefix(pattern, "*") {
		if !strings.HasPrefix(value, parts[0]) {
			return false
		}
		index = len(parts[0])
		parts = parts[1:]
	}

	for i, part := range parts {
		if part == "" {
			continue
		}

		pos := strings.Index(value[index:], part)
		if pos < 0 {
			return false
		}
		index += pos + len(part)

		if i == len(parts)-1 && !strings.HasSuffix(pattern, "*") {
			return strings.HasSuffix(value, part)
		}
	}

	return true
}

// unescapeFilterValue decodes RFC 4515 \XX hex escapes. Escapes other than
// a literal '*' (\2a) are decoded here; callers handle unescaped '*' before
// calling this, so values reaching it contain no wildcards.
func unescapeFilterValue(v string) string {
	if !strings.Contains(v, `\`) {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' && i+2 < len(v) {
			if n, err := strconv.ParseUint(v[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 2
				continue
			}
		}
		b.WriteByte(v[i])
	}
	return b.String()
}
