package handler

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/glauth/ldap"
	goldap "github.com/go-ldap/ldap/v3"

	ldaputil "github.com/jacobalberty/zitadel-ldap/internal/ldap"
)

const (
	// envEnableWrites enables Add/Modify/Delete when set to "true".
	envEnableWrites = "ZITADEL_LDAP_ENABLE_WRITES"
	// envAllowAnonymousBind controls whether anonymous binds are accepted
	// (default true to preserve existing behavior). Set to "false" to reject.
	envAllowAnonymousBind = "ZITADEL_LDAP_ALLOW_ANONYMOUS_BIND"

	// writeCapability is the cap_* metadata action a bound user needs in
	// order to perform write operations.
	writeCapability = "write"

	usersOU = "users"
)

func envBool(name string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	switch v {
	case "":
		return def
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

// recoverOp converts a panic in an LDAP operation into an OperationsError so a
// single malformed request cannot take down the whole glauth process.
func (z *zitadelHandler) recoverOp(op string, code *ldap.LDAPResultCode, err *error) {
	if r := recover(); r != nil {
		z.log.Error().Str("op", op).Interface("panic", r).Bytes("stack", debug.Stack()).Msg("Recovered from panic")
		*code = ldap.LDAPResultOperationsError
		*err = fmt.Errorf("internal error in %s", op)
	}
}

// authorizeWrite decides whether boundDN may perform write operations.
// It returns LDAPResultSuccess when allowed.
func (z *zitadelHandler) authorizeWrite(ctx context.Context, boundDN string) (ldap.LDAPResultCode, error) {
	if !z.writesEnabled {
		z.log.Warn().Msg("Write rejected: writes are disabled")
		return ldap.LDAPResultInsufficientAccessRights, fmt.Errorf("write operations are disabled")
	}
	if strings.TrimSpace(boundDN) == "" {
		z.log.Warn().Msg("Write rejected: anonymous bind")
		return ldap.LDAPResultInsufficientAccessRights, fmt.Errorf("authentication required")
	}

	name, err := z.usernameFromDN(boundDN)
	if err != nil {
		z.log.Warn().Err(err).Msg("Write rejected: bound DN not a user DN")
		return ldap.LDAPResultInsufficientAccessRights, fmt.Errorf("insufficient access")
	}

	found, user, err := z.FindUser(ctx, name, false)
	if err != nil {
		z.log.Error().Err(err).Str("user", name).Msg("Write authorization lookup failed")
		return ldap.LDAPResultOperationsError, fmt.Errorf("authorization lookup failed")
	}
	if !found || user.Disabled {
		z.log.Warn().Str("user", name).Msg("Write rejected: user unknown or disabled")
		return ldap.LDAPResultInsufficientAccessRights, fmt.Errorf("insufficient access")
	}
	for _, c := range user.Capabilities {
		if strings.EqualFold(c.Action, writeCapability) {
			return ldap.LDAPResultSuccess, nil
		}
	}

	z.log.Warn().Str("user", name).Msg("Write rejected: missing cap_write capability")
	return ldap.LDAPResultInsufficientAccessRights, fmt.Errorf("insufficient access")
}

// usernameFromDN returns the user name from a DN of the exact form
// <nameformat>=<user>,ou=users,<baseDN>. Any other DN (groups, other OUs,
// deeper subtrees, other base DNs) is rejected.
func (z *zitadelHandler) usernameFromDN(dn string) (string, error) {
	parsed, err := ldaputil.ParseAndValidateDN(dn)
	if err != nil {
		return "", err
	}
	base, err := goldap.ParseDN(z.baseDN)
	if err != nil {
		return "", fmt.Errorf("invalid base DN: %w", err)
	}
	if len(parsed.RDNs) != len(base.RDNs)+2 {
		return "", fmt.Errorf("DN is not directly under ou=%s,%s", usersOU, z.baseDN)
	}

	nameAttr := z.options.Backend.NameFormat
	if nameAttr == "" {
		nameAttr = "cn"
	}
	first := parsed.RDNs[0]
	if len(first.Attributes) != 1 || !strings.EqualFold(first.Attributes[0].Type, nameAttr) {
		return "", fmt.Errorf("DN must start with a single %s attribute", nameAttr)
	}
	ou := parsed.RDNs[1]
	if len(ou.Attributes) != 1 || !strings.EqualFold(ou.Attributes[0].Type, "ou") ||
		!strings.EqualFold(ou.Attributes[0].Value, usersOU) {
		return "", fmt.Errorf("DN must be under ou=%s", usersOU)
	}
	rest := &goldap.DN{RDNs: parsed.RDNs[2:]}
	if !rest.EqualFold(base) {
		return "", fmt.Errorf("DN is outside base DN")
	}

	name := first.Attributes[0].Value
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("empty user name in DN")
	}
	return name, nil
}
