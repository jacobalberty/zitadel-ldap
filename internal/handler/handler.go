package handler

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/url"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GeertJohan/yubigo"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/handler"
	"github.com/glauth/ldap"
	goldap "github.com/go-ldap/ldap/v3"
	"github.com/rs/zerolog"
	"github.com/zitadel/zitadel-go/v3/pkg/client"
	zit "github.com/zitadel/zitadel-go/v3/pkg/zitadel"
	"google.golang.org/grpc"

	apperrors "github.com/jacobalberty/zitadel-ldap/internal/errors"
	ldaputil "github.com/jacobalberty/zitadel-ldap/internal/ldap"
	"github.com/jacobalberty/zitadel-ldap/internal/repository"
	"github.com/jacobalberty/zitadel-ldap/internal/stores/zitadel"
	zclient "github.com/jacobalberty/zitadel-ldap/internal/zitadel"
)

// splitDN splits a DN on unescaped commas (RFC 4514: "\," is a literal comma).
func splitDN(dn string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(dn); i++ {
		switch dn[i] {
		case '\\':
			i++ // skip the escaped character
		case ',':
			parts = append(parts, dn[start:i])
			start = i + 1
		}
	}
	return append(parts, dn[start:])
}

func upperDNAttributeTypes(dn string) string {
	if dn == "" {
		return dn
	}

	parts := splitDN(dn)
	for i, part := range parts {
		p := strings.TrimSpace(part)
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			parts[i] = p
			continue
		}

		parts[i] = strings.ToUpper(strings.TrimSpace(kv[0])) + "=" + kv[1]
	}

	return strings.Join(parts, ",")
}

// buildDN assembles "<attr>=<escaped value>[,<hierarchy>],<baseDN>". The value
// is escaped so user/group names containing commas, '+', quotes etc. cannot
// inject extra RDNs or break the DN.
func (z *zitadelHandler) buildDN(attr, value, hierarchy string) string {
	dn := attr + "=" + goldap.EscapeDN(value)
	if hierarchy != "" {
		dn += "," + hierarchy
	}
	if z.baseDN != "" {
		dn += "," + z.baseDN
	}
	return dn
}

const (
	// defaultTimeout is the default timeout for Zitadel API calls
	defaultTimeout = 30 * time.Second
)

type zitadelHandler struct {
	options     handler.Options
	ldohelper   handler.LDAPOpsHelper
	repository  repository.Repository
	log         *zerolog.Logger
	yubikeyAuth *yubigo.YubiAuth
	baseDN      string

	dynOnce sync.Once
	dynDefs []dynamicGroupDefinition

	// writesEnabled gates Add/Modify/Delete (ZITADEL_LDAP_ENABLE_WRITES).
	writesEnabled bool
	// denyAnonymousBind rejects anonymous binds (ZITADEL_LDAP_ALLOW_ANONYMOUS_BIND=false).
	denyAnonymousBind bool
}

// NewZitadelHandler creates a new instance of the zitadel backend
func NewZitadelHandler(opts ...handler.Option) handler.Handler {
	options := handler.NewOptions(opts...)

	// Initialize Zitadel SDK client
	repo, err := initializeRepository(options.Logger)
	if err != nil {
		options.Logger.Fatal().Err(err).Msg("Failed to initialize Zitadel repository")
	}

	return &zitadelHandler{
		options:     options,
		ldohelper:   options.LDAPHelper,
		repository:  repo,
		log:         options.Logger,
		yubikeyAuth: options.YubiAuth,
		baseDN:      options.Backend.BaseDN,

		writesEnabled:     envBool(envEnableWrites, false),
		denyAnonymousBind: !envBool(envAllowAnonymousBind, true),
	}
}

// initializeRepository creates a new Zitadel repository using the SDK
func initializeRepository(logger *zerolog.Logger) (repository.Repository, error) {
	zitadelURL := os.Getenv("ZITADEL_URL")
	if zitadelURL == "" {
		return nil, fmt.Errorf("ZITADEL_URL environment variable is required")
	}

	zitadelPAT := os.Getenv("ZITADEL_PAT")
	if zitadelPAT == "" {
		return nil, fmt.Errorf("ZITADEL_PAT environment variable is required")
	}

	authority := strings.TrimSpace(os.Getenv("ZITADEL_AUTHORITY"))

	// Parse Zitadel URL
	u, err := url.Parse(zitadelURL)
	if err != nil {
		return nil, fmt.Errorf("invalid ZITADEL_URL format: %w", err)
	}

	// Configure Zitadel options
	zitOpts := []zit.Option{}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil {
			return nil, fmt.Errorf("invalid port in ZITADEL_URL: %w", err)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port out of range in ZITADEL_URL: %d", port)
		}
		if u.Scheme == "http" {
			zitOpts = append(zitOpts, zit.WithInsecure(u.Port()))
		} else {
			zitOpts = append(zitOpts, zit.WithPort(uint16(port)))
		}
	} else if u.Scheme == "http" {
		zitOpts = append(zitOpts, zit.WithInsecure("80"))
	}

	// Create Zitadel instance
	zitInstance := zit.New(u.Hostname(), zitOpts...)

	dialOpts := []grpc.DialOption{}
	if authority != "" {
		dialOpts = append(dialOpts, grpc.WithAuthority(authority))
	}

	// Create SDK client
	zitClient, err := client.New(context.Background(), zitInstance,
		client.WithAuth(client.PAT(zitadelPAT)),
		client.WithGRPCDialOptions(dialOpts...))
	if err != nil {
		return nil, fmt.Errorf("failed to create Zitadel client: %w", err)
	}

	// Create store and repository
	store := zitadel.NewZitadelStore(zitClient)
	repo := repository.NewZitadelRepository(store.GetQuerier())

	logger.Info().Str("url", zitadelURL).Msg("Initialized Zitadel SDK client")

	return repo, nil
}

func (z *zitadelHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (code ldap.LDAPResultCode, err error) {
	defer z.recoverOp("Bind", &code, &err)

	z.log.Debug().Str("bindDN", bindDN).Msg("trying to login")

	if strings.TrimSpace(bindDN) == "" {
		if z.denyAnonymousBind {
			z.log.Info().Msg("Anonymous bind rejected")
			return ldap.LDAPResultInappropriateAuthentication, nil
		}
		z.log.Info().Msg("Anonymous bind accepted")
		return ldap.LDAPResultSuccess, nil
	}

	// RFC 4513 5.1.2: a DN with an empty password is an "unauthenticated
	// bind" and must not be treated as a successful authentication.
	if bindSimplePw == "" {
		z.log.Info().Msg("Bind rejected: empty password")
		return ldap.LDAPResultUnwillingToPerform, fmt.Errorf("empty password not allowed")
	}

	parsedDN, err := ldaputil.ParseAndValidateDN(bindDN)
	if err != nil {
		z.log.Warn().Err(err).Msg("Invalid bind DN")
		return ldap.LDAPResultInvalidDNSyntax, fmt.Errorf("invalid DN")
	}
	first := parsedDN.RDNs[0]
	if len(first.Attributes) == 0 || first.Attributes[0].Value == "" {
		z.log.Warn().Msg("Invalid bind DN: empty leading RDN")
		return ldap.LDAPResultInvalidDNSyntax, fmt.Errorf("invalid DN")
	}
	user := first.Attributes[0].Value

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	success, err := z.repository.Login(ctx, user, bindSimplePw)
	if err != nil {
		// Check error type for better logging
		if apperrors.IsUnauthorized(err) {
			z.log.Info().Str("user", user).Msg("Invalid credentials")
			return ldap.LDAPResultInvalidCredentials, nil
		}
		if apperrors.IsTimeout(err) || errors.Is(err, context.DeadlineExceeded) {
			z.log.Error().Err(err).Str("user", user).Msg("Login timeout")
			return ldap.LDAPResultBusy, fmt.Errorf("authentication timeout: %w", err)
		}
		z.log.Error().Err(err).Str("user", user).Msg("Login error")
		return ldap.LDAPResultOperationsError, fmt.Errorf("authentication failed: %w", err)
	}

	if success {
		z.log.Info().Str("user", user).Msg("Login successful")
		return ldap.LDAPResultSuccess, nil
	}

	z.log.Info().Str("user", user).Msg("Invalid credentials")
	return ldap.LDAPResultInvalidCredentials, nil
}

func (z *zitadelHandler) Search(boundDN string, req ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			z.log.Error().Interface("panic", r).Bytes("stack", debug.Stack()).Msg("Recovered from panic in Search")
			result = ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}
			err = fmt.Errorf("internal error in Search")
		}
	}()

	z.log.Info().Str("backend", "zitadel").Str("user", boundDN).Msg("Doing a search")

	// Create context with timeout for search operations
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	return z.ldohelper.Search(ctx, z, boundDN, req, conn)
}

func (z *zitadelHandler) Close(boundDN string, conn net.Conn) error {
	return nil
}

func (z *zitadelHandler) FindUser(ctx context.Context, userName string, searchByUPN bool) (bool, config.User, error) {
	z.log.Info().Str("backend", "zitadel").Str("username", userName).Msg("Finding user")

	// Ensure context has a timeout
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}

	var users *zclient.UserResults
	var err error
	if searchByUPN {
		users, err = z.repository.FindUserByMail(ctx, userName)
		if err != nil {
			z.log.Error().Err(err).Str("username", userName).Msg("Failed to find user by mail")
			return false, config.User{}, fmt.Errorf("failed to find user by mail: %w", err)
		}
	} else {
		users, err = z.repository.FindUserByName(ctx, userName)
		if err != nil {
			z.log.Error().Err(err).Str("username", userName).Msg("Failed to find user by name")
			return false, config.User{}, fmt.Errorf("failed to find user by name: %w", err)
		}
	}

	if users == nil || len(users.Result) == 0 || len(users.Result) > 1 {
		return false, config.User{}, nil
	}

	zUser := users.Result[0]

	metadata, err := z.repository.ListMetadata(ctx, zUser.UserID)
	if err != nil {
		return false, config.User{}, fmt.Errorf("failed to list metadata: %w", err)
	}

	caps := []config.Capability{}

	z.log.Debug().Str("user", zUser.Username).Int("metadata", len(metadata.Result)).Msg("Found metadata")

	for _, m := range metadata.Result {
		z.log.Debug().Str("user", zUser.Username).Str("metadata key", m.Key).Msg("Checking metadata key")
		if strings.HasPrefix(m.Key, "cap_") {
			z.log.Debug().Str("user", zUser.Username).Str("metadata key", m.Key).Msg("Valid cap key")
			key := strings.TrimPrefix(m.Key, "cap_")
			val, err := base64.StdEncoding.DecodeString(string(m.Value))
			if err != nil {
				z.log.Warn().Str("user", zUser.Username).Str("key", m.Key).Msg("Skipping capability with invalid base64 value")
				continue
			}

			z.log.Debug().Str("user", zUser.Username).Str("metadata key", m.Key).Msg("Appending to existing caps")

			caps = append(caps, config.Capability{
				Action: key,
				Object: string(val),
			})
		}
	}

	z.log.Debug().Str("user", zUser.Username).Int("caps", len(caps)).Msg("Found capabilities")

	groups, err := z.getUserGroupIDs(ctx, zUser.UserID)
	if err != nil {
		return false, config.User{}, fmt.Errorf("failed to get user groups: %w", err)
	}

	user := config.User{
		Name:         zUser.Username,
		Disabled:     zUser.State != "USER_STATE_ACTIVE",
		Mail:         zUser.Human.Email.Email,
		UnixID:       z.hash(zUser.Username),
		UIDNumber:    z.hash(zUser.Username),
		Capabilities: caps,
		OtherGroups:  groups,
	}

	return true, user, nil
}

func (z *zitadelHandler) FindGroup(ctx context.Context, groupName string) (bool, config.Group, error) {
	z.log.Info().Str("backend", "zitadel").Str("group", groupName).Msg("Finding groups")

	// Ensure context has a timeout
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}

	projects, err := z.repository.ListProjects(ctx)
	if err != nil {
		z.log.Error().Err(err).Msg("Failed to list projects")
		return false, config.Group{}, fmt.Errorf("failed to list projects: %w", err)
	}

	for _, p := range projects.Result {
		roles, err := z.repository.ListRoles(ctx, p.ID)
		if err != nil {
			return false, config.Group{}, fmt.Errorf("failed to list roles for project %s: %w", p.ID, err)
		}

		for _, r := range roles.Result {
			if r.Group == groupName {
				return true, config.Group{
					Name:      groupName,
					UnixID:    z.hash(p.ID + groupName),
					GIDNumber: z.hash(p.ID + groupName),
				}, nil
			}
		}
	}

	return false, config.Group{}, nil
}

func (z *zitadelHandler) GetBackend() config.Backend       { return z.options.Backend }
func (z *zitadelHandler) GetLog() *zerolog.Logger          { return z.log }
func (z *zitadelHandler) GetCfg() *config.Config           { return z.options.Config }
func (z *zitadelHandler) GetYubikeyAuth() *yubigo.YubiAuth { return z.yubikeyAuth }

func (z *zitadelHandler) FindPosixAccounts(ctx context.Context, hierarchy string) (entrylist []*ldap.Entry, err error) {
	z.log.Info().Str("backend", "zitadel").Str("posixAccount", hierarchy).Msg("Finding posixAccount")

	// Ensure context has a timeout
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}

	entries := []*ldap.Entry{}

	users, err := z.repository.ListUsers(ctx)
	if err != nil {
		z.log.Error().Err(err).Msg("Failed to list users for posix accounts")
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	for _, u := range users.Result {

		if u.Human == nil {
			continue
		}

		attrs := []*ldap.EntryAttribute{}
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uid", Values: []string{u.Username}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{u.Username}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "givenName", Values: []string{u.Human.Profile.GivenName}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "sn", Values: []string{u.Human.Profile.FamilyName}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "ou", Values: []string{"users"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uidNumber", Values: []string{fmt.Sprintf("%d", z.hash(u.Username))}})
		if u.State != "USER_STATE_ACTIVE" {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "accountStatus", Values: []string{"inactive"}})
		} else {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "accountStatus", Values: []string{"active"}})
		}
		attrs = append(attrs, &ldap.EntryAttribute{Name: "mail", Values: []string{u.Human.Email.Email}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "userPrincipalName", Values: []string{u.Human.Email.Email}})

		attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixAccount", "shadowAccount"}})

		attrs = append(attrs, &ldap.EntryAttribute{Name: "loginShell", Values: []string{"/bin/bash"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "homeDirectory", Values: []string{"/home/" + u.Username}})

		attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{u.Username}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "gecos", Values: []string{u.Username}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", z.hash("zitadel"))}})

		groups, err := z.memberOf(ctx, u.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed to get memberOf for user %s: %w", u.UserID, err)
		}

		memberAttr := &ldap.EntryAttribute{Name: "memberOf", Values: groups}
		attrs = append(attrs, memberAttr)

		attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowExpire", Values: []string{"-1"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowFlag", Values: []string{"134538308"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowInactive", Values: []string{"-1"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowLastChange", Values: []string{"11000"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowMax", Values: []string{"99999"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowMin", Values: []string{"-1"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowWarning", Values: []string{"7"}})

		metadata, err := z.repository.ListMetadata(ctx, u.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed to list metadata for user %s: %w", u.UserID, err)
		}

		for _, m := range metadata.Result {
			if after, ok := strings.CutPrefix(m.Key, "gl_"); ok {
				key := after
				val, err := base64.StdEncoding.DecodeString(string(m.Value))
				if err != nil {
					z.log.Warn().Str("user", u.Username).Str("key", m.Key).Msg("Skipping metadata with invalid base64 value")
					continue
				}
				attrs = append(attrs, &ldap.EntryAttribute{Name: key, Values: []string{string(val)}})
			}
		}

		dynGroups, err := z.dynamicMemberOf(u, metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate dynamic groups for user %s: %w", u.UserID, err)
		}
		memberAttr.Values = append(memberAttr.Values, dynGroups...)

		dn := upperDNAttributeTypes(z.buildDN(z.options.Backend.NameFormat, u.Username, hierarchy))

		entries = append(entries, &ldap.Entry{DN: dn, Attributes: nonEmptyAttrs(attrs)})
	}

	return entries, nil

}

// nonEmptyAttrs sanitizes entry attributes so they don't break strict LDAP
// clients. jellyfin-plugin-ldapauth's admin-filter search requests all
// attributes, and the Novell.Directory.Ldap client mishandles entries that
// carry an attribute with empty/blank values (NullReferenceException) or with
// duplicate values (a malformed value set, which makes it hang while decoding).
// For each attribute we drop blank values and collapse duplicates, and we omit
// the attribute entirely when nothing usable remains.
func nonEmptyAttrs(in []*ldap.EntryAttribute) []*ldap.EntryAttribute {
	out := make([]*ldap.EntryAttribute, 0, len(in))
	for _, a := range in {
		vals := make([]string, 0, len(a.Values))
		seen := make(map[string]struct{}, len(a.Values))
		for _, v := range a.Values {
			if strings.TrimSpace(v) == "" {
				continue
			}
			if _, dup := seen[v]; dup {
				continue
			}
			seen[v] = struct{}{}
			vals = append(vals, v)
		}
		if len(vals) == 0 {
			continue
		}
		out = append(out, &ldap.EntryAttribute{Name: a.Name, Values: vals})
	}
	return out
}
func (z *zitadelHandler) FindPosixGroups(ctx context.Context, hierarchy string) (entrylist []*ldap.Entry, err error) {
	z.log.Info().Str("backend", "zitadel").Str("hieararchy", hierarchy).Msg("Finding posixGroup")

	// Ensure context has a timeout
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}

	asGroupOfUniqueNames := strings.EqualFold(hierarchy, "ou=groups")

	projects, err := z.repository.ListProjects(ctx)
	if err != nil {
		z.log.Error().Err(err).Msg("Failed to list projects for posix groups")
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}

	grants, err := z.repository.ListGrants(ctx)
	if err != nil {
		z.log.Error().Err(err).Msg("Failed to list grants for posix groups")
		return nil, fmt.Errorf("failed to list grants: %w", err)
	}

	// Grants reference roles by Key, so members are indexed by (project, role key).
	// A NUL delimiter keeps ("ab","c") and ("a","bc") distinct.
	grantMap := map[string][]string{}

	for _, g := range grants.Result {
		for _, rk := range g.RoleKeys {
			k := g.ProjectName + "\x00" + rk
			grantMap[k] = append(grantMap[k], z.addUserHierarchy(g.UserName, "ou=users"))
		}
	}

	entries := []*ldap.Entry{}

	for _, p := range projects.Result {
		roles, err := z.repository.ListRoles(ctx, p.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to list roles for project %s: %w", p.ID, err)
		}

		for _, r := range roles.Result {

			// The GID hash input is intentionally unchanged to keep emitted numbers stable.
			groupKey := p.Name + r.Group
			members := grantMap[p.Name+"\x00"+r.Key]

			attrs := []*ldap.EntryAttribute{}
			attrs = append(attrs, &ldap.EntryAttribute{Name: "CN", Values: []string{r.Group}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{fmt.Sprintf("%s via Zitadel", r.Group)}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", z.hash(groupKey))}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "uniqueMember", Values: members})

			if asGroupOfUniqueNames {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"groupOfUniqueNames", "top"}})
			} else {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "memberUid", Values: members})
				attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixGroup", "top"}})
			}

			dn := upperDNAttributeTypes(z.buildDN(z.options.Backend.GroupFormat, r.Group, hierarchy))

			entries = append(entries, &ldap.Entry{DN: dn, Attributes: nonEmptyAttrs(attrs)})
		}

	}

	dynEntries, err := z.dynamicGroupEntries(ctx, hierarchy, asGroupOfUniqueNames, entries)
	if err != nil {
		return nil, err
	}
	entries = append(entries, dynEntries...)

	return entries, nil

}

// dynamicGroupEntries builds LDAP entries for filter-based groups defined in
// the glauth config. It is a no-op when no dynamic groups are configured.
func (z *zitadelHandler) dynamicGroupEntries(ctx context.Context, hierarchy string, asGroupOfUniqueNames bool, existing []*ldap.Entry) ([]*ldap.Entry, error) {
	defs := z.dynamicGroupDefinitions()
	if len(defs) == 0 {
		return nil, nil
	}

	users, err := z.repository.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users for dynamic groups: %w", err)
	}
	md := make(map[string]*zclient.MetadataResults, len(users.Result))
	for _, u := range users.Result {
		if u.Human == nil {
			continue
		}
		m, err := z.repository.ListMetadata(ctx, u.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed to list metadata for user %s: %w", u.UserID, err)
		}
		md[u.UserID] = m
	}

	members, err := z.resolveDynamicGroupMembers(users.Result, md, "ou=users", defs)
	if err != nil {
		return nil, err
	}

	taken := map[string]bool{}
	for _, e := range existing {
		taken[strings.ToLower(e.DN)] = true
	}

	var out []*ldap.Entry
	for _, def := range defs {
		dn := upperDNAttributeTypes(z.buildDN(z.options.Backend.GroupFormat, def.name, hierarchy))
		if taken[strings.ToLower(dn)] {
			z.log.Warn().Str("group", def.name).Msg("Dynamic group name collides with an existing group; skipping")
			continue
		}
		attrs := []*ldap.EntryAttribute{
			{Name: "CN", Values: []string{def.name}},
			{Name: "description", Values: []string{fmt.Sprintf("%s (dynamic)", def.name)}},
			{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", def.gidNumber)}},
			{Name: "uniqueMember", Values: members[def.name]},
		}
		if asGroupOfUniqueNames {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"groupOfUniqueNames", "top"}})
		} else {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "memberUid", Values: members[def.name]})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixGroup", "top"}})
		}
		out = append(out, &ldap.Entry{DN: dn, Attributes: nonEmptyAttrs(attrs)})
	}

	return out, nil
}

func (z *zitadelHandler) hash(s string) int {
	h := fnv.New32a()
	h.Write([]byte(s))
	return int(h.Sum32())
}

func (z *zitadelHandler) addUserHierarchy(user string, hierarchy string) string {
	if hierarchy == "" {
		hierarchy = "OU=users"
	}
	return upperDNAttributeTypes(z.buildDN(z.options.Backend.NameFormat, user, hierarchy))
}

func (z *zitadelHandler) memberOf(ctx context.Context, userID string) ([]string, error) {
	grants, err := z.repository.ListGrants(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list grants: %w", err)
	}

	groups := []string{}
	roleGroups := map[string]map[string]string{} // projectID -> role key -> group

	for _, g := range grants.Result {
		if g.UserID != userID {
			continue
		}
		for _, rk := range g.RoleKeys {
			name := rk
			// Group entries are named after the role's Group, not its Key.
			if _, ok := roleGroups[g.ProjectID]; !ok {
				m := map[string]string{}
				if roles, err := z.repository.ListRoles(ctx, g.ProjectID); err == nil && roles != nil {
					for _, r := range roles.Result {
						if r.Group != "" {
							m[r.Key] = r.Group
						}
					}
				}
				roleGroups[g.ProjectID] = m
			}
			if gn, ok := roleGroups[g.ProjectID][rk]; ok {
				name = gn
			}
			groups = append(groups, z.buildDN(z.options.Backend.GroupFormat, name, "ou=groups"))
		}
	}

	return groups, nil
}

func (z *zitadelHandler) getUserGroupIDs(ctx context.Context, userID string) ([]int, error) {
	groups := []int{}

	grants, err := z.repository.ListGrants(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list grants: %w", err)
	}

	for _, g := range grants.Result {
		if g.UserID == userID {
			for _, r := range g.RoleKeys {
				groups = append(groups, z.hash(g.ProjectID+r))
			}
		}
	}

	return groups, nil
}
