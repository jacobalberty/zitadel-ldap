package repository

import (
	"context"
	"testing"

	"github.com/jacobalberty/zitadel-ldap/internal/stores/zitadel"
	zclient "github.com/jacobalberty/zitadel-ldap/internal/zitadel"
)

type mockQuerier struct {
	listUsersResult      *zclient.UserResults
	listUsersErr         error
	listUsersCalled      bool
	findUserByNameArg    string
	findUserByNameRes    *zclient.UserResults
	findUserByNameErr    error
	findUserByNameCalled bool
	findUserByMailArg    string
	findUserByMailRes    *zclient.UserResults
	findUserByMailErr    error
	findUserByMailCalled bool
	listGrantsRes        *zclient.GrantResults
	listGrantsErr        error
	listGrantsCalled     bool
	listProjectsRes      *zclient.ProjectResults
	listProjectsErr      error
	listProjectsCalled   bool
	listRolesArg         string
	listRolesRes         *zclient.RoleResults
	listRolesErr         error
	listRolesCalled      bool
	listMetadataArg      string
	listMetadataRes      *zclient.MetadataResults
	listMetadataErr      error
	listMetadataCalled   bool
	loginUserArg         string
	loginPassArg         string
	loginRes             bool
	loginErr             error
	loginCalled          bool
	createUserArg        *zclient.UserCreateRequest
	createUserRes        *zclient.User
	createUserErr        error
	createUserCalled     bool
	updateUserIDArg      string
	updateUserArg        *zclient.UserUpdateRequest
	updateUserErr        error
	updateUserCalled     bool
	deleteUserArg        string
	deleteUserErr        error
	deleteUserCalled     bool
	setPasswordIDArg     string
	setPasswordArg       string
	setPasswordErr       error
	setPasswordCalled    bool
	updateMetadataIDArg  string
	updateMetadataKeyArg string
	updateMetadataValArg []byte
	updateMetadataErr    error
	updateMetadataCalled bool
}

func (m *mockQuerier) Login(ctx context.Context, username, password string) (bool, error) {
	m.loginCalled = true
	m.loginUserArg = username
	m.loginPassArg = password
	return m.loginRes, m.loginErr
}

func (m *mockQuerier) ListGrants(ctx context.Context) (*zclient.GrantResults, error) {
	m.listGrantsCalled = true
	return m.listGrantsRes, m.listGrantsErr
}

func (m *mockQuerier) ListMetadata(ctx context.Context, id string) (*zclient.MetadataResults, error) {
	m.listMetadataCalled = true
	m.listMetadataArg = id
	return m.listMetadataRes, m.listMetadataErr
}

func (m *mockQuerier) ListProjects(ctx context.Context) (*zclient.ProjectResults, error) {
	m.listProjectsCalled = true
	return m.listProjectsRes, m.listProjectsErr
}

func (m *mockQuerier) ListRoles(ctx context.Context, projectID string) (*zclient.RoleResults, error) {
	m.listRolesCalled = true
	m.listRolesArg = projectID
	return m.listRolesRes, m.listRolesErr
}

func (m *mockQuerier) ListUsers(ctx context.Context) (*zclient.UserResults, error) {
	m.listUsersCalled = true
	return m.listUsersResult, m.listUsersErr
}

func (m *mockQuerier) FindUserByName(ctx context.Context, name string) (*zclient.UserResults, error) {
	m.findUserByNameCalled = true
	m.findUserByNameArg = name
	return m.findUserByNameRes, m.findUserByNameErr
}

func (m *mockQuerier) FindUserByMail(ctx context.Context, mail string) (*zclient.UserResults, error) {
	m.findUserByMailCalled = true
	m.findUserByMailArg = mail
	return m.findUserByMailRes, m.findUserByMailErr
}

func (m *mockQuerier) CreateUser(ctx context.Context, req *zclient.UserCreateRequest) (*zclient.User, error) {
	m.createUserCalled = true
	m.createUserArg = req
	return m.createUserRes, m.createUserErr
}

func (m *mockQuerier) UpdateUser(ctx context.Context, userID string, req *zclient.UserUpdateRequest) error {
	m.updateUserCalled = true
	m.updateUserIDArg = userID
	m.updateUserArg = req
	return m.updateUserErr
}

func (m *mockQuerier) DeleteUser(ctx context.Context, userID string) error {
	m.deleteUserCalled = true
	m.deleteUserArg = userID
	return m.deleteUserErr
}

func (m *mockQuerier) SetUserPassword(ctx context.Context, userID, password string) error {
	m.setPasswordCalled = true
	m.setPasswordIDArg = userID
	m.setPasswordArg = password
	return m.setPasswordErr
}

func (m *mockQuerier) UpdateMetadata(ctx context.Context, userID, key string, value []byte) error {
	m.updateMetadataCalled = true
	m.updateMetadataIDArg = userID
	m.updateMetadataKeyArg = key
	m.updateMetadataValArg = value
	return m.updateMetadataErr
}

var _ zitadel.Querier = (*mockQuerier)(nil)

func TestZitadelRepositoryDelegates(t *testing.T) {
	mq := &mockQuerier{
		listUsersResult:   &zclient.UserResults{Result: []zclient.User{}},
		findUserByNameRes: &zclient.UserResults{Result: []zclient.User{}},
		findUserByMailRes: &zclient.UserResults{Result: []zclient.User{}},
		listGrantsRes:     &zclient.GrantResults{Result: []zclient.Grant{}},
		listProjectsRes:   &zclient.ProjectResults{Result: []zclient.ProjectResult{}},
		listRolesRes:      &zclient.RoleResults{Result: []zclient.RoleResult{}},
		listMetadataRes:   &zclient.MetadataResults{Result: []zclient.MetadataResult{}},
		loginRes:          true,
	}

	repo := NewZitadelRepository(mq)
	ctx := context.Background()

	_, _ = repo.ListUsers(ctx)
	if !mq.listUsersCalled {
		t.Fatalf("expected ListUsers to be called")
	}

	_, _ = repo.FindUserByName(ctx, "alice")
	if !mq.findUserByNameCalled || mq.findUserByNameArg != "alice" {
		t.Fatalf("expected FindUserByName to be called with alice")
	}

	_, _ = repo.FindUserByMail(ctx, "alice@example.com")
	if !mq.findUserByMailCalled || mq.findUserByMailArg != "alice@example.com" {
		t.Fatalf("expected FindUserByMail to be called with alice@example.com")
	}

	_, _ = repo.ListGrants(ctx)
	if !mq.listGrantsCalled {
		t.Fatalf("expected ListGrants to be called")
	}

	_, _ = repo.ListProjects(ctx)
	if !mq.listProjectsCalled {
		t.Fatalf("expected ListProjects to be called")
	}

	_, _ = repo.ListRoles(ctx, "proj1")
	if !mq.listRolesCalled || mq.listRolesArg != "proj1" {
		t.Fatalf("expected ListRoles to be called with proj1")
	}

	_, _ = repo.ListMetadata(ctx, "user1")
	if !mq.listMetadataCalled || mq.listMetadataArg != "user1" {
		t.Fatalf("expected ListMetadata to be called with user1")
	}

	_, _ = repo.Login(ctx, "user", "pass")
	if !mq.loginCalled || mq.loginUserArg != "user" || mq.loginPassArg != "pass" {
		t.Fatalf("expected Login to be called with user/pass")
	}

	_, _ = repo.CreateUser(ctx, &zclient.UserCreateRequest{Username: "alice"})
	if !mq.createUserCalled || mq.createUserArg == nil || mq.createUserArg.Username != "alice" {
		t.Fatalf("expected CreateUser to be called with alice")
	}

	_ = repo.UpdateUser(ctx, "u1", &zclient.UserUpdateRequest{Email: stringPtr("alice@example.com")})
	if !mq.updateUserCalled || mq.updateUserIDArg != "u1" {
		t.Fatalf("expected UpdateUser to be called with u1")
	}

	_ = repo.DeleteUser(ctx, "u2")
	if !mq.deleteUserCalled || mq.deleteUserArg != "u2" {
		t.Fatalf("expected DeleteUser to be called with u2")
	}

	_ = repo.SetUserPassword(ctx, "u3", "secret")
	if !mq.setPasswordCalled || mq.setPasswordIDArg != "u3" || mq.setPasswordArg != "secret" {
		t.Fatalf("expected SetUserPassword to be called with u3/secret")
	}

	_ = repo.UpdateMetadata(ctx, "u4", "gl_team", []byte("core"))
	if !mq.updateMetadataCalled || mq.updateMetadataIDArg != "u4" || mq.updateMetadataKeyArg != "gl_team" {
		t.Fatalf("expected UpdateMetadata to be called with u4/gl_team")
	}
}

func stringPtr(value string) *string {
	return &value
}
