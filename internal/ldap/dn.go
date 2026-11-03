package ldap

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// ParseAndValidateDN parses an LDAP DN string using RFC 4514-compliant parsing.
// Returns the parsed DN object or an error if the DN is invalid.
func ParseAndValidateDN(dn string) (*ldap.DN, error) {
	if strings.TrimSpace(dn) == "" {
		return nil, fmt.Errorf("DN cannot be empty")
	}

	parsedDN, err := ldap.ParseDN(dn)
	if err != nil {
		return nil, fmt.Errorf("invalid DN syntax: %w", err)
	}

	if parsedDN == nil || len(parsedDN.RDNs) == 0 {
		return nil, fmt.Errorf("DN has no RDN sequence")
	}

	return parsedDN, nil
}

// ExtractCNFromDN extracts the CN (Common Name) value from a parsed DN.
// Handles escaped characters properly (e.g., \, in usernames).
// Returns the CN value or an error if CN is not found or DN is invalid.
func ExtractCNFromDN(d *ldap.DN) (string, error) {
	if d == nil {
		return "", fmt.Errorf("DN is nil")
	}

	if len(d.RDNs) == 0 {
		return "", fmt.Errorf("DN has no RDN sequence")
	}

	// The first RDN typically contains the CN attribute
	firstRDN := d.RDNs[0]

	for _, attrTypeAndValue := range firstRDN.Attributes {
		if strings.ToLower(attrTypeAndValue.Type) == "cn" {
			return attrTypeAndValue.Value, nil
		}
	}

	return "", fmt.Errorf("CN attribute not found in DN")
}

// SafeConstructDN builds an RFC 4514-compliant DN using the default "cn" attribute.
// Properly escapes special characters in the RDN value.
// Components: rdn (e.g., username), ou (organizational unit), baseDN (e.g., dc=example,dc=com)
func SafeConstructDN(rdn, ou, baseDN string) string {
	return SafeConstructDNWithAttr("cn", rdn, ou, baseDN)
}

// SafeConstructDNWithAttr builds an RFC 4514-compliant DN using the provided attribute name.
// Properly escapes special characters in the RDN value.
// Components: attr (e.g., cn, uid), rdn (e.g., username), ou (organizational unit), baseDN (e.g., dc=example,dc=com)
func SafeConstructDNWithAttr(attr, rdn, ou, baseDN string) string {
	// Escape the RDN value for RFC 4514 compliance
	escapedRDN := escapeDNComponent(rdn)

	// Build the DN from components
	if ou != "" {
		return fmt.Sprintf("%s=%s,%s,%s", attr, escapedRDN, ou, baseDN)
	}
	return fmt.Sprintf("%s=%s,%s", attr, escapedRDN, baseDN)
}

// escapeDNComponent escapes a single DN component value according to RFC 4514.
// Special characters that need escaping: , = + < > # ; " \ and control characters
func escapeDNComponent(value string) string {
	if value == "" {
		return ""
	}

	var result strings.Builder
	runes := []rune(value)
	specialChars := map[rune]bool{
		',':  true,
		'=':  true,
		'+':  true,
		'<':  true,
		'>':  true,
		';':  true,
		'"':  true,
		'\\': true,
	}

	for i, r := range runes {
		isLeading := i == 0
		isTrailing := i == len(runes)-1

		switch {
		case r == ' ' && (isLeading || isTrailing):
			// Escape leading or trailing space
			result.WriteString(`\ `)
		case r == '#' && isLeading:
			// Escape leading '#'
			result.WriteString(`\#`)
		case specialChars[r]:
			// Escape special characters
			fmt.Fprintf(&result, "\\%c", r)
		case r < 0x20 || r > 0x7E:
			// Escape non-ASCII and control characters by UTF-8 bytes
			for _, b := range []byte(string(r)) {
				fmt.Fprintf(&result, "\\%02x", b)
			}
		default:
			result.WriteRune(r)
		}
	}

	return result.String()
}

// ValidateDN validates DN syntax without constructing a full parse tree.
// Returns nil if valid, error otherwise.
func ValidateDN(dn string) error {
	if strings.TrimSpace(dn) == "" {
		return fmt.Errorf("DN cannot be empty")
	}

	_, err := ldap.ParseDN(dn)
	if err != nil {
		return fmt.Errorf("invalid DN syntax: %w", err)
	}

	return nil
}

// DNEqual compares two DN strings for semantic equality (ignoring whitespace differences).
// Returns true if DNs represent the same distinguished name.
func DNEqual(dn1, dn2 string) (bool, error) {
	parsed1, err := ParseAndValidateDN(dn1)
	if err != nil {
		return false, err
	}

	parsed2, err := ParseAndValidateDN(dn2)
	if err != nil {
		return false, err
	}

	return parsed1.Equal(parsed2), nil
}
