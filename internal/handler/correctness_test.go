package handler

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/ldap"

	ldaputil "github.com/jacobalberty/zitadel-ldap/internal/ldap"
	zclient "github.com/jacobalberty/zitadel-ldap/internal/zitadel"
)

func entryAttr(e *ldap.Entry, name string) []string {
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, name) {
			return a.Values
		}
	}
	return nil
}

func TestUpperDNAttributeTypesRespectsEscapedComma(t *testing.T) {
	got := upperDNAttributeTypes(`cn=smith\, bob,ou=users,dc=example,dc=com`)
	want := `CN=smith\, bob,OU=users,DC=example,DC=com`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestBuildDNEscapesInjection(t *testing.T) {
	h := newTestHandler(&mockRepository{})
	dn := h.buildDN("cn", "evil,ou=admins", "ou=users")
	parsed, err := ldaputil.ParseAndValidateDN(dn)
	if err != nil {
		t.Fatal(err)
	}
	// cn + ou=users + dc + dc: the injected ",ou=admins" must not add an RDN.
	if len(parsed.RDNs) != 4 {
		t.Fatalf("injection produced %d RDNs: %s", len(parsed.RDNs), dn)
	}
}

func groupsRepo() *mockRepository {
	return &mockRepository{
		listProjectsFn: func(ctx context.Context) (*zclient.ProjectResults, error) {
			return &zclient.ProjectResults{Result: []zclient.ProjectResult{{ID: "p1", Name: "proj"}}}, nil
		},
		listRolesFn: func(ctx context.Context, id string) (*zclient.RoleResults, error) {
			return &zclient.RoleResults{Result: []zclient.RoleResult{{Key: "adm", Group: "admins"}}}, nil
		},
		listGrantsFn: func(ctx context.Context) (*zclient.GrantResults, error) {
			return &zclient.GrantResults{Result: []zclient.Grant{
				{UserID: "u1", UserName: "alice", ProjectID: "p1", ProjectName: "proj", RoleKeys: []string{"adm"}},
			}}, nil
		},
	}
}

// Regression: members were looked up by role Group but indexed by role Key, so
// they were empty unless group == key.
func TestPosixGroupMembersResolvedByRoleKey(t *testing.T) {
	h := newTestHandler(groupsRepo())
	entries, err := h.FindPosixGroups(context.Background(), "ou=groups")
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries=%d err=%v", len(entries), err)
	}
	members := entryAttr(entries[0], "uniqueMember")
	if len(members) != 1 || !strings.EqualFold(members[0], "CN=alice,OU=users,DC=example,DC=com") {
		t.Fatalf("members = %v", members)
	}
}

// memberOf must name the group the way the group entry's CN does.
func TestMemberOfUsesRoleGroupName(t *testing.T) {
	h := newTestHandler(groupsRepo())
	groups, err := h.memberOf(context.Background(), "u1")
	if err != nil || len(groups) != 1 {
		t.Fatalf("groups=%v err=%v", groups, err)
	}
	if !strings.HasPrefix(groups[0], "cn=admins,") {
		t.Fatalf("memberOf = %q, want cn=admins,...", groups[0])
	}
}

func dynHandler(filter string) (*zitadelHandler, *mockRepository) {
	repo := &mockRepository{
		listUsersFn: func(ctx context.Context) (*zclient.UserResults, error) {
			return &zclient.UserResults{Result: []zclient.User{
				{UserID: "u1", Username: "alice", State: "USER_STATE_ACTIVE", Human: &zclient.Human{Email: zclient.Email{Email: "a@x.com"}}},
				{UserID: "u2", Username: "bob", State: "USER_STATE_ACTIVE", Human: &zclient.Human{Email: zclient.Email{Email: "b@x.com"}}},
			}}, nil
		},
		listMetadataFn: func(ctx context.Context, id string) (*zclient.MetadataResults, error) {
			dept := "sales"
			if id == "u1" {
				dept = "Engineering" // case differs from the filter on purpose
			}
			return &zclient.MetadataResults{Result: []zclient.MetadataResult{
				{Key: "gl_department", Value: base64.StdEncoding.EncodeToString([]byte(dept))},
				{Key: "gl_broken", Value: "!!not-base64!!"},
			}}, nil
		},
	}
	h := newTestHandler(repo)
	h.options.Config = &config.Config{Groups: []config.Group{{
		Name: "eng", GIDNumber: 9001,
		Capabilities: []config.Capability{{Action: "dynamicFilter", Object: filter}},
	}}}
	return h, repo
}

func TestDynamicGroupsAreWired(t *testing.T) {
	h, _ := dynHandler("(gl_department=engineering)")

	groups, err := h.FindPosixGroups(context.Background(), "ou=groups")
	if err != nil {
		t.Fatal(err)
	}
	var eng *ldap.Entry
	for _, e := range groups {
		if strings.Contains(strings.ToLower(e.DN), "cn=eng,") {
			eng = e
		}
	}
	if eng == nil {
		t.Fatal("dynamic group entry missing from FindPosixGroups")
	}
	m := entryAttr(eng, "uniqueMember")
	if len(m) != 1 || !strings.Contains(strings.ToLower(m[0]), "cn=alice") {
		t.Fatalf("members = %v (case-insensitive match should include only alice)", m)
	}
	if gid := entryAttr(eng, "gidNumber"); len(gid) != 1 || gid[0] != "9001" {
		t.Fatalf("gid = %v", gid)
	}

	accts, err := h.FindPosixAccounts(context.Background(), "ou=users")
	if err != nil {
		t.Fatalf("bad base64 metadata must not fail the search: %v", err)
	}
	for _, e := range accts {
		has := false
		for _, g := range entryAttr(e, "memberOf") {
			if strings.Contains(strings.ToLower(g), "cn=eng,") {
				has = true
			}
		}
		if strings.Contains(e.DN, "alice") != has {
			t.Fatalf("%s memberOf dynamic group = %v", e.DN, has)
		}
	}
}

func TestDynamicGroupWithUnsupportedFilterIsIgnored(t *testing.T) {
	h, _ := dynHandler("(gl_level>=5)")
	if defs := h.dynamicGroupDefinitions(); len(defs) != 0 {
		t.Fatalf("unsupported operator must disable the group, got %d defs", len(defs))
	}
	if _, err := h.FindPosixGroups(context.Background(), "ou=groups"); err != nil {
		t.Fatal(err)
	}
}

func TestMatchFilterOperatorsAndEscapes(t *testing.T) {
	attrs := map[string][]string{"cn": {"Bob*Smith"}}
	for _, f := range []string{"(age>=5)", "(age<=5)", "(cn~=bob)"} {
		if _, err := ldaputil.MatchFilter(f, attrs); err == nil {
			t.Errorf("%s: expected unsupported-operator error", f)
		}
	}
	if ok, err := ldaputil.MatchFilter(`(cn=bob\2asmith)`, attrs); err != nil || !ok {
		t.Errorf(`escaped \2a should match literal '*': ok=%v err=%v`, ok, err)
	}
	if ok, _ := ldaputil.MatchFilter("(cn=BOB*)", attrs); !ok {
		t.Error("substring match should be case-insensitive")
	}
}

func modifyHandler() (*zitadelHandler, *int32) {
	var c, d, u int32
	h := newTestHandler(writerRepo(true, &c, &d, &u))
	h.writesEnabled = true
	return h, &u
}

func TestModifyDeleteAttributesRejected(t *testing.T) {
	h, u := modifyHandler()
	req := ldap.ModifyRequest{Dn: bobDN, DeleteAttributes: []ldap.PartialAttribute{{AttrType: "mail"}}}
	code, err := h.Modify(adminDN, req, nil)
	if code != ldap.LDAPResultUnwillingToPerform || err == nil || *u != 0 {
		t.Fatalf("code=%d err=%v updates=%d", code, err, *u)
	}
}

func TestModifyRejectsHashedPasswordAndReservedAttrs(t *testing.T) {
	h, u := modifyHandler()
	cases := []ldap.PartialAttribute{
		{AttrType: "userPassword", AttrVals: []string{"{SSHA}abcdef=="}},
		{AttrType: "uidNumber", AttrVals: []string{"0"}},
		{AttrType: "memberOf", AttrVals: []string{"cn=admins,ou=groups,dc=example,dc=com"}},
		{AttrType: "objectClass", AttrVals: []string{"top"}},
	}
	for _, a := range cases {
		code, err := h.Modify(adminDN, ldap.ModifyRequest{Dn: bobDN, ReplaceAttributes: []ldap.PartialAttribute{a}}, nil)
		if code != ldap.LDAPResultConstraintViolation || err == nil {
			t.Errorf("%s: code=%d err=%v", a.AttrType, code, err)
		}
	}
	if *u != 0 {
		t.Fatalf("no update may reach the repository, got %d", *u)
	}
}

func TestModifyCustomAttrBecomesMetadata(t *testing.T) {
	var c, d, u int32
	repo := writerRepo(true, &c, &d, &u)
	var got *zclient.UserUpdateRequest
	repo.updateUserFn = func(ctx context.Context, id string, r *zclient.UserUpdateRequest) error { got = r; return nil }
	h := newTestHandler(repo)
	h.writesEnabled = true
	req := ldap.ModifyRequest{Dn: bobDN, ReplaceAttributes: []ldap.PartialAttribute{
		{AttrType: "department", AttrVals: []string{"eng"}},
		{AttrType: "gl_team", AttrVals: []string{"core"}},
	}}
	if code, err := h.Modify(adminDN, req, nil); code != ldap.LDAPResultSuccess || err != nil {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if string(got.Metadata["gl_department"]) != "eng" || string(got.Metadata["gl_team"]) != "core" || len(got.Metadata) != 2 {
		t.Fatalf("metadata = %v (gl_ prefix must not be doubled)", got.Metadata)
	}
}
