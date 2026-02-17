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
}
