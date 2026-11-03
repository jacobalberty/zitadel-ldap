package handler

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/glauth/glauth/v2/pkg/config"

	ldaputil "github.com/jacobalberty/zitadel-ldap/internal/ldap"
	zclient "github.com/jacobalberty/zitadel-ldap/internal/zitadel"
)

type dynamicGroupDefinition struct {
	name      string
	gidNumber int
	filters   []string
}

// dynamicGroupDefinitions returns the validated dynamic group definitions.
// The result is computed once: filters come from static config, and doing it
// per user would re-validate and re-log on every entry.
func (z *zitadelHandler) dynamicGroupDefinitions() []dynamicGroupDefinition {
	z.dynOnce.Do(func() { z.dynDefs = z.buildDynamicGroupDefinitions() })
	return z.dynDefs
}

func (z *zitadelHandler) buildDynamicGroupDefinitions() []dynamicGroupDefinition {
	if z.options.Config == nil {
		return nil
	}

	defs := []dynamicGroupDefinition{}
	for _, group := range z.options.Config.Groups {
		filters := dynamicGroupFiltersFromCapabilities(group.Capabilities)
		if len(filters) == 0 {
			continue
		}
		// Evaluate against an empty entry to surface syntax errors and
		// unsupported operators once, instead of failing every search.
		if _, err := ldaputil.MatchAnyFilter(filters, nil); err != nil {
			z.log.Warn().Err(err).Str("group", group.Name).Msg("Ignoring dynamic group with invalid filter")
			continue
		}

		gid := group.GIDNumber
		if gid == 0 {
			gid = z.hash("dyn:" + group.Name)
		}

		defs = append(defs, dynamicGroupDefinition{
			name:      group.Name,
			gidNumber: gid,
			filters:   filters,
		})
	}

	return defs
}

func dynamicGroupFiltersFromCapabilities(caps []config.Capability) []string {
	filters := []string{}
	for _, cap := range caps {
		if !strings.EqualFold(cap.Action, "dynamicFilter") {
			continue
		}
		filter := strings.TrimSpace(cap.Object)
		if filter == "" {
			continue
		}
		filters = append(filters, filter)
	}
	return filters
}

func (z *zitadelHandler) resolveDynamicGroupMembers(users []zclient.User, metadata map[string]*zclient.MetadataResults, hierarchy string, defs []dynamicGroupDefinition) (map[string][]string, error) {
	members := map[string][]string{}
	if len(defs) == 0 || len(users) == 0 {
		return members, nil
	}

	for _, u := range users {
		if u.Human == nil {
			continue
		}

		attrs, err := z.userAttributesForFilter(u, metadata[u.UserID])
		if err != nil {
			return nil, err
		}

		for _, def := range defs {
			matched, err := ldaputil.MatchAnyFilter(def.filters, attrs)
			if err != nil {
				return nil, err
			}
			if matched {
				members[def.name] = append(members[def.name], z.addUserHierarchy(u.Username, hierarchy))
			}
		}
	}

	return members, nil
}

func (z *zitadelHandler) dynamicMemberOf(u zclient.User, metadata *zclient.MetadataResults) ([]string, error) {
	defs := z.dynamicGroupDefinitions()
	if len(defs) == 0 {
		return nil, nil
	}

	attrs, err := z.userAttributesForFilter(u, metadata)
	if err != nil {
		return nil, err
	}

	groups := []string{}
	for _, def := range defs {
		matched, err := ldaputil.MatchAnyFilter(def.filters, attrs)
		if err != nil {
			return nil, err
		}
		if matched {
			groups = append(groups, z.buildDN(z.options.Backend.GroupFormat, def.name, "ou=groups"))
		}
	}

	return groups, nil
}

func (z *zitadelHandler) userAttributesForFilter(u zclient.User, metadata *zclient.MetadataResults) (map[string][]string, error) {
	attrs := map[string][]string{}

	username := strings.TrimSpace(u.Username)
	if username != "" {
		attrs["cn"] = append(attrs["cn"], username)
		attrs["uid"] = append(attrs["uid"], username)
		attrs["username"] = append(attrs["username"], username)
		attrs["uidnumber"] = append(attrs["uidnumber"], fmt.Sprintf("%d", z.hash(username)))
	}

	if u.State != "" {
		status := "inactive"
		if u.State == "USER_STATE_ACTIVE" {
			status = "active"
		}
		attrs["accountstatus"] = append(attrs["accountstatus"], status)
	}

	if u.Human != nil {
		if u.Human.Profile.GivenName != "" {
			attrs["givenname"] = append(attrs["givenname"], u.Human.Profile.GivenName)
		}
		if u.Human.Profile.FamilyName != "" {
			attrs["sn"] = append(attrs["sn"], u.Human.Profile.FamilyName)
		}
		if u.Human.Email.Email != "" {
			attrs["mail"] = append(attrs["mail"], u.Human.Email.Email)
			attrs["userprincipalname"] = append(attrs["userprincipalname"], u.Human.Email.Email)
		}
	}

	if metadata == nil {
		return attrs, nil
	}

	for _, m := range metadata.Result {
		value, err := base64.StdEncoding.DecodeString(string(m.Value))
		if err != nil {
			// One malformed metadata row must not break the whole lookup.
			z.log.Warn().Str("user", u.Username).Str("key", m.Key).Msg("Skipping metadata with invalid base64 value")
			continue
		}

		key := strings.ToLower(m.Key)
		attrs[key] = append(attrs[key], string(value))
		if strings.HasPrefix(key, "gl_") {
			trimmed := strings.TrimPrefix(key, "gl_")
			if trimmed != "" {
				attrs[trimmed] = append(attrs[trimmed], string(value))
			}
		}
	}

	return attrs, nil
}
