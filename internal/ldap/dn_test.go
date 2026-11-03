package ldap

import (
	"testing"
)

func TestParseAndValidateDN(t *testing.T) {
	tests := []struct {
		name    string
		dn      string
		wantErr bool
	}{
		{
			name:    "valid simple DN",
			dn:      "cn=john,ou=users,dc=example,dc=com",
			wantErr: false,
		},
		{
			name:    "valid DN with escaped comma",
			dn:      "cn=john\\,doe,ou=users,dc=example,dc=com",
			wantErr: false,
		},
		{
			name:    "valid DN with escaped equals",
			dn:      "cn=john\\=admin,ou=users,dc=example,dc=com",
			wantErr: false,
		},
		{
			name:    "valid DN with escaped backslash",
			dn:      "cn=john\\\\smith,ou=users,dc=example,dc=com",
			wantErr: false,
		},
		{
			name:    "empty DN",
			dn:      "",
			wantErr: true,
		},
		{
			name:    "invalid DN no RDN",
			dn:      "    ",
			wantErr: true,
		},
		{
			name:    "DN with multiple RDNs",
			dn:      "cn=alice+sn=smith,ou=users,dc=example,dc=com",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dn, err := ParseAndValidateDN(tt.dn)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAndValidateDN() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && dn == nil {
				t.Error("ParseAndValidateDN() returned nil DN for valid input")
			}
		})
	}
}

func TestExtractCNFromDN(t *testing.T) {
	tests := []struct {
		name    string
		dn      string
		want    string
		wantErr bool
	}{
		{
			name:    "simple CN extraction",
			dn:      "cn=john,ou=users,dc=example,dc=com",
			want:    "john",
			wantErr: false,
		},
		{
			name:    "CN with escaped comma",
			dn:      "cn=john\\,doe,ou=users,dc=example,dc=com",
			want:    "john,doe",
			wantErr: false,
		},
		{
			name:    "CN with escaped equals",
			dn:      "cn=john\\=admin,ou=users,dc=example,dc=com",
			want:    "john=admin",
			wantErr: false,
		},
		{
			name:    "CN with escaped backslash",
			dn:      "cn=john\\\\smith,ou=users,dc=example,dc=com",
			want:    "john\\smith",
			wantErr: false,
		},
		{
			name:    "uppercase CN",
			dn:      "CN=alice,ou=users,dc=example,dc=com",
			want:    "alice",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedDN, err := ParseAndValidateDN(tt.dn)
			if err != nil {
				t.Fatalf("Failed to parse DN: %v", err)
			}

			got, err := ExtractCNFromDN(parsedDN)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractCNFromDN() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ExtractCNFromDN() got = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSafeConstructDN(t *testing.T) {
	tests := []struct {
		name   string
		rdn    string
		ou     string
		baseDN string
		want   string
	}{
		{
			name:   "simple DN construction",
			rdn:    "john",
			ou:     "ou=users",
			baseDN: "dc=example,dc=com",
			want:   "cn=john,ou=users,dc=example,dc=com",
		},
		{
			name:   "DN with comma in RDN",
			rdn:    "john,doe",
			ou:     "ou=users",
			baseDN: "dc=example,dc=com",
			want:   "cn=john\\,doe,ou=users,dc=example,dc=com",
		},
		{
			name:   "DN with equals in RDN",
			rdn:    "john=admin",
			ou:     "ou=users",
			baseDN: "dc=example,dc=com",
			want:   "cn=john\\=admin,ou=users,dc=example,dc=com",
		},
		{
			name:   "DN without OU",
			rdn:    "alice",
			ou:     "",
			baseDN: "dc=example,dc=com",
			want:   "cn=alice,dc=example,dc=com",
		},
		{
			name:   "DN with asterisk in RDN",
			rdn:    "test*user",
			ou:     "ou=users",
			baseDN: "dc=example,dc=com",
			want:   "cn=test*user,ou=users,dc=example,dc=com",
		},
		{
			name:   "DN with leading space in RDN",
			rdn:    " alice",
			ou:     "ou=users",
			baseDN: "dc=example,dc=com",
			want:   "cn=\\ alice,ou=users,dc=example,dc=com",
		},
		{
			name:   "DN with trailing space in RDN",
			rdn:    "alice ",
			ou:     "ou=users",
			baseDN: "dc=example,dc=com",
			want:   "cn=alice\\ ,ou=users,dc=example,dc=com",
		},
		{
			name:   "DN with leading hash in RDN",
			rdn:    "#admin",
			ou:     "ou=users",
			baseDN: "dc=example,dc=com",
			want:   "cn=\\#admin,ou=users,dc=example,dc=com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SafeConstructDN(tt.rdn, tt.ou, tt.baseDN)
			if got != tt.want {
				t.Errorf("SafeConstructDN() got = %q, want %q", got, tt.want)
			}

			// Verify the constructed DN is valid
			if err := ValidateDN(got); err != nil {
				t.Errorf("SafeConstructDN() produced invalid DN: %v", err)
			}
		})
	}
}

func TestValidateDN(t *testing.T) {
	tests := []struct {
		name    string
		dn      string
		wantErr bool
	}{
		{
			name:    "valid DN",
			dn:      "cn=john,ou=users,dc=example,dc=com",
			wantErr: false,
		},
		{
			name:    "empty DN",
			dn:      "",
			wantErr: true,
		},
		{
			name:    "whitespace DN",
			dn:      "   ",
			wantErr: true,
		},
		{
			name:    "DN with special escaped chars",
			dn:      "cn=john\\,doe\\=test,ou=users,dc=example,dc=com",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDN(tt.dn)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDN() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDNEqual(t *testing.T) {
	tests := []struct {
		name    string
		dn1     string
		dn2     string
		want    bool
		wantErr bool
	}{
		{
			name:    "identical DNs",
			dn1:     "cn=john,ou=users,dc=example,dc=com",
			dn2:     "cn=john,ou=users,dc=example,dc=com",
			want:    true,
			wantErr: false,
		},
		{
			name:    "semantically equal DNs with whitespace",
			dn1:     "cn=john, ou=users, dc=example, dc=com",
			dn2:     "cn=john,ou=users,dc=example,dc=com",
			want:    true,
			wantErr: false,
		},
		{
			name:    "different DNs",
			dn1:     "cn=john,ou=users,dc=example,dc=com",
			dn2:     "cn=alice,ou=users,dc=example,dc=com",
			want:    false,
			wantErr: false,
		},
		{
			name:    "escaped vs different CN",
			dn1:     "cn=john\\,doe,ou=users,dc=example,dc=com",
			dn2:     "cn=john,ou=users,dc=example,dc=com",
			want:    false,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DNEqual(tt.dn1, tt.dn2)
			if (err != nil) != tt.wantErr {
				t.Errorf("DNEqual() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("DNEqual() got = %v, want %v", got, tt.want)
			}
		})
	}
}
