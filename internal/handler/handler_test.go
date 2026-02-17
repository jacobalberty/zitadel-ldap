package handler

import (
	"context"
	"encoding/base64"
	"io"
	"testing"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/handler"
	"github.com/glauth/ldap"
	"github.com/rs/zerolog"

	apperrors "github.com/jacobalberty/zitadel-ldap/internal/errors"
	"github.com/jacobalberty/zitadel-ldap/internal/repository"
	zclient "github.com/jacobalberty/zitadel-ldap/internal/zitadel"
)

type mockRepository struct {
	loginFn          func(ctx context.Context, username, password string) (bool, error)
	findUserByNameFn func(ctx context.Context, name string) (*zclient.UserResults, error)
	findUserByMailFn func(ctx context.Context, mail string) (*zclient.UserResults, error)
	listMetadataFn   func(ctx context.Context, userID string) (*zclient.MetadataResults, error)
	listProjectsFn   func(ctx context.Context) (*zclient.ProjectResults, error)
	listRolesFn      func(ctx context.Context, projectID string) (*zclient.RoleResults, error)
	listUsersFn      func(ctx context.Context) (*zclient.UserResults, error)
	listGrantsFn     func(ctx context.Context) (*zclient.GrantResults, error)
}

func (m *mockRepository) ListUsers(ctx context.Context) (*zclient.UserResults, error) {
	if m.listUsersFn == nil {
		return &zclient.UserResults{}, nil
	}
	return m.listUsersFn(ctx)
}

func (m *mockRepository) FindUserByName(ctx context.Context, name string) (*zclient.UserResults, error) {
	if m.findUserByNameFn == nil {
		return &zclient.UserResults{}, nil
	}
	return m.findUserByNameFn(ctx, name)
}

func (m *mockRepository) FindUserByMail(ctx context.Context, mail string) (*zclient.UserResults, error) {
	if m.findUserByMailFn == nil {
		return &zclient.UserResults{}, nil
	}
	return m.findUserByMailFn(ctx, mail)
}

func (m *mockRepository) ListGrants(ctx context.Context) (*zclient.GrantResults, error) {
	if m.listGrantsFn == nil {
		return &zclient.GrantResults{}, nil
	}
	return m.listGrantsFn(ctx)
}

func (m *mockRepository) ListProjects(ctx context.Context) (*zclient.ProjectResults, error) {
	if m.listProjectsFn == nil {
		return &zclient.ProjectResults{}, nil
	}
	return m.listProjectsFn(ctx)
}

func (m *mockRepository) ListRoles(ctx context.Context, projectID string) (*zclient.RoleResults, error) {
	if m.listRolesFn == nil {
		return &zclient.RoleResults{}, nil
	}
	return m.listRolesFn(ctx, projectID)
}

func (m *mockRepository) ListMetadata(ctx context.Context, userID string) (*zclient.MetadataResults, error) {
	if m.listMetadataFn == nil {
		return &zclient.MetadataResults{}, nil
	}
	return m.listMetadataFn(ctx, userID)
}

func (m *mockRepository) Login(ctx context.Context, username, password string) (bool, error) {
	if m.loginFn == nil {
		return false, nil
	}
	return m.loginFn(ctx, username, password)
}

var _ repository.Repository = (*mockRepository)(nil)

func newTestHandler(repo repository.Repository) *zitadelHandler {
	logger := zerolog.New(io.Discard)
	return &zitadelHandler{
		repository: repo,
		log:        &logger,
		baseDN:     "dc=example,dc=com",
		options: handler.Options{
			Backend: config.Backend{
				NameFormat:  "cn",
				GroupFormat: "cn",
				BaseDN:      "dc=example,dc=com",
			},
		},
	}
}

func TestBindInvalidDN(t *testing.T) {
	h := newTestHandler(&mockRepository{})
	code, err := h.Bind("invalid", "pass", nil)
	if err == nil {
		// invalid CN returns an error
		if code != ldap.LDAPResultInvalidDNSyntax {
			t.Fatalf("expected invalid DN syntax, got %d", code)
		}
	}
}

func TestBindUnauthorized(t *testing.T) {
	repo := &mockRepository{
		loginFn: func(ctx context.Context, username, password string) (bool, error) {
			return false, apperrors.NewZitadelError("CreateSession", apperrors.ErrUnauthorized, false)
		},
	}
	h := newTestHandler(repo)
	code, err := h.Bind("cn=alice,dc=example,dc=com", "pass", nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if code != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("expected invalid credentials, got %d", code)
	}
}

func TestBindTimeout(t *testing.T) {
	repo := &mockRepository{
		loginFn: func(ctx context.Context, username, password string) (bool, error) {
			return false, apperrors.NewZitadelError("CreateSession", apperrors.ErrTimeout, true)
		},
	}
	h := newTestHandler(repo)
	code, err := h.Bind("cn=alice,dc=example,dc=com", "pass", nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if code != ldap.LDAPResultBusy {
		t.Fatalf("expected busy, got %d", code)
	}
}

func TestBindSuccess(t *testing.T) {
	repo := &mockRepository{
		loginFn: func(ctx context.Context, username, password string) (bool, error) {
			return true, nil
		},
	}
	h := newTestHandler(repo)
	code, err := h.Bind("cn=alice,dc=example,dc=com", "pass", nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if code != ldap.LDAPResultSuccess {
		t.Fatalf("expected success, got %d", code)
	}
}

func TestFindUserHappyPath(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("servers"))
	repo := &mockRepository{
		findUserByNameFn: func(ctx context.Context, name string) (*zclient.UserResults, error) {
			return &zclient.UserResults{Result: []zclient.User{
				{
					UserID:   "u1",
					Username: "alice",
					State:    "USER_STATE_ACTIVE",
					Human: &zclient.Human{
						Profile: zclient.Profile{GivenName: "Alice", FamilyName: "Doe"},
						Email:   zclient.Email{Email: "alice@example.com"},
					},
				},
			}}, nil
		},
		listMetadataFn: func(ctx context.Context, userID string) (*zclient.MetadataResults, error) {
			return &zclient.MetadataResults{Result: []zclient.MetadataResult{
				{Key: "cap_admin", Value: encoded},
			}}, nil
		},
		listGrantsFn: func(ctx context.Context) (*zclient.GrantResults, error) {
			return &zclient.GrantResults{Result: []zclient.Grant{
				{UserID: "u1", RoleKeys: []string{"role1"}, ProjectID: "p1"},
			}}, nil
		},
	}

	h := newTestHandler(repo)
	ok, user, err := h.FindUser(context.Background(), "alice", false)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !ok {
		t.Fatalf("expected user to be found")
	}
	if user.Name != "alice" || user.Mail != "alice@example.com" {
		t.Fatalf("unexpected user fields: %#v", user)
	}
	if len(user.Capabilities) != 1 {
		t.Fatalf("expected 1 capability, got %d", len(user.Capabilities))
	}
	if len(user.OtherGroups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(user.OtherGroups))
	}
}

func TestFindGroupFound(t *testing.T) {
	repo := &mockRepository{
		listProjectsFn: func(ctx context.Context) (*zclient.ProjectResults, error) {
			return &zclient.ProjectResults{Result: []zclient.ProjectResult{
				{ID: "p1", Name: "proj1"},
			}}, nil
		},
		listRolesFn: func(ctx context.Context, projectID string) (*zclient.RoleResults, error) {
			return &zclient.RoleResults{Result: []zclient.RoleResult{
				{Group: "admins"},
			}}, nil
		},
	}

	h := newTestHandler(repo)
	ok, group, err := h.FindGroup(context.Background(), "admins")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !ok {
		t.Fatalf("expected group to be found")
	}
	if group.Name != "admins" {
		t.Fatalf("unexpected group name: %s", group.Name)
	}
}

func TestAddUserHierarchy(t *testing.T) {
	h := newTestHandler(&mockRepository{})

	withHierarchy := h.addUserHierarchy("alice", "ou=staff")
	if withHierarchy != "cn=alice,ou=staff,dc=example,dc=com" {
		t.Fatalf("unexpected hierarchy DN: %s", withHierarchy)
	}

	withoutHierarchy := h.addUserHierarchy("alice", "")
	if withoutHierarchy != "cn=alice,ou=users,dc=example,dc=com" {
		t.Fatalf("unexpected default DN: %s", withoutHierarchy)
	}
}

func TestMemberOfAndGroupIDs(t *testing.T) {
	repo := &mockRepository{
		listGrantsFn: func(ctx context.Context) (*zclient.GrantResults, error) {
			return &zclient.GrantResults{Result: []zclient.Grant{
				{UserID: "u1", RoleKeys: []string{"roleA", "roleB"}, ProjectID: "p1"},
				{UserID: "u2", RoleKeys: []string{"roleC"}, ProjectID: "p2"},
			}}, nil
		},
	}
	h := newTestHandler(repo)

	groups, err := h.memberOf(context.Background(), "u1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}

	ids, err := h.getUserGroupIDs(context.Background(), "u1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 group IDs, got %d", len(ids))
	}
}

func TestFindPosixAccounts(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("/data"))
	repo := &mockRepository{
		listUsersFn: func(ctx context.Context) (*zclient.UserResults, error) {
			return &zclient.UserResults{Result: []zclient.User{
				{UserID: "u1", Username: "alice", State: "USER_STATE_ACTIVE", Human: &zclient.Human{
					Profile: zclient.Profile{GivenName: "Alice", FamilyName: "Doe"},
					Email:   zclient.Email{Email: "alice@example.com"},
				}},
			}}, nil
		},
		listGrantsFn: func(ctx context.Context) (*zclient.GrantResults, error) {
			return &zclient.GrantResults{Result: []zclient.Grant{
				{UserID: "u1", RoleKeys: []string{"roleA"}, ProjectID: "p1"},
			}}, nil
		},
		listMetadataFn: func(ctx context.Context, userID string) (*zclient.MetadataResults, error) {
			return &zclient.MetadataResults{Result: []zclient.MetadataResult{
				{Key: "gl_homeDirectory", Value: encoded},
			}}, nil
		},
	}
	h := newTestHandler(repo)

	entries, err := h.FindPosixAccounts(context.Background(), "ou=users")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].DN == "" {
		t.Fatalf("expected DN to be set")
	}
	if !entryHasAttr(entries[0], "homeDirectory", "/data") {
		t.Fatalf("expected metadata attribute to be present")
	}
}

func TestFindPosixGroups(t *testing.T) {
	repo := &mockRepository{
		listProjectsFn: func(ctx context.Context) (*zclient.ProjectResults, error) {
			return &zclient.ProjectResults{Result: []zclient.ProjectResult{
				{ID: "p1", Name: "proj1"},
			}}, nil
		},
		listRolesFn: func(ctx context.Context, projectID string) (*zclient.RoleResults, error) {
			return &zclient.RoleResults{Result: []zclient.RoleResult{
				{Group: "admins"},
			}}, nil
		},
		listGrantsFn: func(ctx context.Context) (*zclient.GrantResults, error) {
			return &zclient.GrantResults{Result: []zclient.Grant{
				{UserName: "alice", ProjectName: "proj1", RoleKeys: []string{"admins"}},
			}}, nil
		},
	}
	h := newTestHandler(repo)

	entries, err := h.FindPosixGroups(context.Background(), "ou=groups")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if !entryHasAttr(entries[0], "objectClass", "groupOfUniqueNames") {
		t.Fatalf("expected groupOfUniqueNames objectClass")
	}
}

func entryHasAttr(entry *ldap.Entry, name, value string) bool {
	for _, attr := range entry.Attributes {
		if attr.Name != name {
			continue
		}
		for _, v := range attr.Values {
			if v == value {
				return true
			}
		}
	}
	return false
}
