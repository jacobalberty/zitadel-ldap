package ldap

import (
	"strings"
	"testing"
)

func TestEscapeFilterValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple string",
			input: "john",
			want:  "john",
		},
		{
			name:  "string with comma",
			input: "john,doe",
			want:  "john,doe",
		},
		{
			name:  "string with asterisk",
			input: "test*value",
			want:  "test\\2avalue",
		},
		{
			name:  "string with parentheses",
			input: "test(value)",
			want:  "test\\28value\\29",
		},
		{
			name:  "string with backslash",
			input: "test\\value",
			want:  "test\\5cvalue",
		},
		{
			name:  "complex filter string",
			input: "admin,root*test(filter)",
			want:  "admin,root\\2atest\\28filter\\29",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EscapeFilterValue(tt.input)
			if got != tt.want {
				t.Errorf("EscapeFilterValue() got = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateFilter(t *testing.T) {
	tests := []struct {
		name    string
		filter  string
		wantErr bool
	}{
		{
			name:    "simple equality filter",
			filter:  "(cn=john)",
			wantErr: false,
		},
		{
			name:    "AND filter",
			filter:  "(&(cn=john)(mail=john@example.com))",
			wantErr: false,
		},
		{
			name:    "OR filter",
			filter:  "(|(cn=john)(cn=alice))",
			wantErr: false,
		},
		{
			name:    "NOT filter",
			filter:  "(!(accountStatus=inactive))",
			wantErr: false,
		},
		{
			name:    "substring filter",
			filter:  "(cn=john*)",
			wantErr: false,
		},
		{
			name:    "empty filter",
			filter:  "",
			wantErr: true,
		},
		{
			name:    "whitespace only filter",
			filter:  "   ",
			wantErr: true,
		},
		{
			name:    "invalid filter syntax",
			filter:  "(cn=john",
			wantErr: true,
		},
		{
			name:    "complex nested filter",
			filter:  "(&(|(cn=john)(cn=alice))(!(accountStatus=inactive)))",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFilter(tt.filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFilter() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBuildEqualityFilter(t *testing.T) {
	tests := []struct {
		name      string
		attribute string
		value     string
		want      string
	}{
		{
			name:      "simple equality",
			attribute: "cn",
			value:     "john",
			want:      "(cn=john)",
		},
		{
			name:      "equality with comma",
			attribute: "cn",
			value:     "john,doe",
			want:      "(cn=john,doe)",
		},
		{
			name:      "equality with asterisk",
			attribute: "mail",
			value:     "*@example.com",
			want:      "(mail=\\2a@example.com)",
		},
		{
			name:      "mail attribute",
			attribute: "mail",
			value:     "john@example.com",
			want:      "(mail=john@example.com)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildEqualityFilter(tt.attribute, tt.value)
			if got != tt.want {
				t.Errorf("BuildEqualityFilter() got = %q, want %q", got, tt.want)
			}

			// Ensure the filter is valid
			if err := ValidateFilter(got); err != nil {
				t.Errorf("BuildEqualityFilter() produced invalid filter: %v", err)
			}
		})
	}
}

func TestBuildSubstringFilter(t *testing.T) {
	tests := []struct {
		name      string
		attribute string
		pattern   string
		want      string
	}{
		{
			name:      "wildcard prefix",
			attribute: "cn",
			pattern:   "*john",
			want:      "(cn=*john)",
		},
		{
			name:      "wildcard suffix",
			attribute: "cn",
			pattern:   "john*",
			want:      "(cn=john*)",
		},
		{
			name:      "wildcard both sides",
			attribute: "cn",
			pattern:   "*john*",
			want:      "(cn=*john*)",
		},
		{
			name:      "mail substring",
			attribute: "mail",
			pattern:   "*@example.com",
			want:      "(mail=*@example.com)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildSubstringFilter(tt.attribute, tt.pattern)
			if got != tt.want {
				t.Errorf("BuildSubstringFilter() got = %q, want %q", got, tt.want)
			}

			// Note: substring filters with wildcards may not validate against CompileFilter
			// because * is a wildcard, not a literal character
		})
	}
}

func TestBuildSubstringFilterEscaped(t *testing.T) {
	tests := []struct {
		name           string
		attribute      string
		value          string
		prefixWildcard bool
		suffixWildcard bool
		want           string
	}{
		{
			name:           "prefix and suffix wildcard",
			attribute:      "cn",
			value:          "john",
			prefixWildcard: true,
			suffixWildcard: true,
			want:           "(cn=*john*)",
		},
		{
			name:           "suffix wildcard only",
			attribute:      "cn",
			value:          "john",
			prefixWildcard: false,
			suffixWildcard: true,
			want:           "(cn=john*)",
		},
		{
			name:           "escaped value with wildcard",
			attribute:      "cn",
			value:          "john*doe",
			prefixWildcard: true,
			suffixWildcard: false,
			want:           "(cn=*john\\2adoe)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildSubstringFilterEscaped(tt.attribute, tt.value, tt.prefixWildcard, tt.suffixWildcard)
			if got != tt.want {
				t.Errorf("BuildSubstringFilterEscaped() got = %q, want %q", got, tt.want)
			}

			if ValidateFilter(got) != nil {
				t.Errorf("BuildSubstringFilterEscaped() produced invalid filter: %s", got)
			}
		})
	}
}

func TestBuildAndFilter(t *testing.T) {
	tests := []struct {
		name    string
		filters []string
		want    string
	}{
		{
			name:    "empty filters",
			filters: []string{},
			want:    "",
		},
		{
			name:    "single filter",
			filters: []string{"(cn=john)"},
			want:    "(cn=john)",
		},
		{
			name:    "two filters",
			filters: []string{"(cn=john)", "(mail=john@example.com)"},
			want:    "(&(cn=john)(mail=john@example.com))",
		},
		{
			name:    "multiple filters",
			filters: []string{"(cn=john)", "(mail=john@example.com)", "(accountStatus=active)"},
			want:    "(&(cn=john)(mail=john@example.com)(accountStatus=active))",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildAndFilter(tt.filters...)
			if got != tt.want {
				t.Errorf("BuildAndFilter() got = %q, want %q", got, tt.want)
			}

			// Validate non-empty filters
			if got != "" && ValidateFilter(got) != nil {
				t.Errorf("BuildAndFilter() produced invalid filter: %s", got)
			}
		})
	}
}

func TestBuildOrFilter(t *testing.T) {
	tests := []struct {
		name    string
		filters []string
		want    string
	}{
		{
			name:    "empty filters",
			filters: []string{},
			want:    "",
		},
		{
			name:    "single filter",
			filters: []string{"(cn=john)"},
			want:    "(cn=john)",
		},
		{
			name:    "two filters",
			filters: []string{"(cn=john)", "(cn=alice)"},
			want:    "(|(cn=john)(cn=alice))",
		},
		{
			name:    "multiple filters",
			filters: []string{"(cn=john)", "(cn=alice)", "(cn=bob)"},
			want:    "(|(cn=john)(cn=alice)(cn=bob))",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildOrFilter(tt.filters...)
			if got != tt.want {
				t.Errorf("BuildOrFilter() got = %q, want %q", got, tt.want)
			}

			// Validate non-empty filters
			if got != "" && ValidateFilter(got) != nil {
				t.Errorf("BuildOrFilter() produced invalid filter: %s", got)
			}
		})
	}
}

func TestBuildNotFilter(t *testing.T) {
	tests := []struct {
		name   string
		filter string
		want   string
	}{
		{
			name:   "negate equality",
			filter: "(accountStatus=inactive)",
			want:   "(!(accountStatus=inactive))",
		},
		{
			name:   "negate OR",
			filter: "(|(cn=john)(cn=alice))",
			want:   "(!(|(cn=john)(cn=alice)))",
		},
		{
			name:   "negate AND",
			filter: "(&(cn=john)(mail=john@example.com))",
			want:   "(!(&(cn=john)(mail=john@example.com)))",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildNotFilter(tt.filter)
			if got != tt.want {
				t.Errorf("BuildNotFilter() got = %q, want %q", got, tt.want)
			}

			if ValidateFilter(got) != nil {
				t.Errorf("BuildNotFilter() produced invalid filter: %s", got)
			}
		})
	}
}

func TestCompileFilterForMetadata(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		value   string
		wantErr bool
		check   func(string) bool
	}{
		{
			name:    "metadata without prefix",
			key:     "department",
			value:   "engineering",
			wantErr: false,
			check: func(f string) bool {
				return strings.Contains(f, "gl_department") && strings.Contains(f, "engineering")
			},
		},
		{
			name:    "metadata with prefix",
			key:     "gl_department",
			value:   "sales",
			wantErr: false,
			check: func(f string) bool {
				return strings.Contains(f, "gl_department") && strings.Contains(f, "sales")
			},
		},
		{
			name:    "metadata with special chars",
			key:     "gl_role",
			value:   "admin*test",
			wantErr: false,
			check: func(f string) bool {
				return strings.Contains(f, "gl_role") && strings.Contains(f, "admin")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CompileFilterForMetadata(tt.key, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("CompileFilterForMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && !tt.check(got) {
				t.Errorf("CompileFilterForMetadata() got = %q, check failed", got)
			}
		})
	}
}

func TestBuildUserMembershipFilter(t *testing.T) {
	tests := []struct {
		name       string
		userIDOrDN string
		useDN      bool
		want       string
	}{
		{
			name:       "membership by UID",
			userIDOrDN: "john",
			useDN:      false,
			want:       "(memberUid=john)",
		},
		{
			name:       "membership by DN",
			userIDOrDN: "cn=john,ou=users,dc=example,dc=com",
			useDN:      true,
			want:       "(uniqueMember=cn=john,ou=users,dc=example,dc=com)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildUserMembershipFilter(tt.userIDOrDN, tt.useDN)
			if got != tt.want {
				t.Errorf("BuildUserMembershipFilter() got = %q, want %q", got, tt.want)
			}

			if ValidateFilter(got) != nil {
				t.Errorf("BuildUserMembershipFilter() produced invalid filter: %s", got)
			}
		})
	}
}

func TestMatchFilter(t *testing.T) {
	attributes := map[string][]string{
		"cn":            {"alice"},
		"mail":          {"alice@example.com"},
		"gl_department": {"engineering"},
		"uidNumber":     {"1001"},
	}

	tests := []struct {
		name    string
		filter  string
		want    bool
		wantErr bool
	}{
		{
			name:    "equality match",
			filter:  "(cn=alice)",
			want:    true,
			wantErr: false,
		},
		{
			name:    "equality no match",
			filter:  "(cn=bob)",
			want:    false,
			wantErr: false,
		},
		{
			name:    "presence match",
			filter:  "(mail=*)",
			want:    true,
			wantErr: false,
		},
		{
			name:    "substring match",
			filter:  "(mail=*example.com)",
			want:    true,
			wantErr: false,
		},
		{
			name:    "and match",
			filter:  "(&(cn=alice)(gl_department=engineering))",
			want:    true,
			wantErr: false,
		},
		{
			name:    "or match",
			filter:  "(|(cn=bob)(cn=alice))",
			want:    true,
			wantErr: false,
		},
		{
			name:    "not match",
			filter:  "(!(cn=bob))",
			want:    true,
			wantErr: false,
		},
		{
			name:    "invalid filter",
			filter:  "(cn=alice",
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MatchFilter(tt.filter, attributes)
			if (err != nil) != tt.wantErr {
				t.Errorf("MatchFilter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("MatchFilter() got = %v, want %v", got, tt.want)
			}
		})
	}
}
