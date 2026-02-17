package zitadel

import (
	"context"
	"testing"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/metadata"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object"
	objectv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc"

	zclient "github.com/jacobalberty/zitadel-ldap/internal/zitadel"
)

type fakeUserService struct {
	responses []*userv2.ListUsersResponse
	calls     int
}

func (f *fakeUserService) ListUsers(ctx context.Context, req *userv2.ListUsersRequest, opts ...grpc.CallOption) (*userv2.ListUsersResponse, error) {
	if f.calls >= len(f.responses) {
		return &userv2.ListUsersResponse{Details: &objectv2.ListDetails{TotalResult: 0}}, nil
	}
	resp := f.responses[f.calls]
	f.calls++
	return resp, nil
}

type fakeGrantService struct {
	responses []*management.ListUserGrantResponse
	calls     int
}

func (f *fakeGrantService) ListUserGrants(ctx context.Context, req *management.ListUserGrantRequest, opts ...grpc.CallOption) (*management.ListUserGrantResponse, error) {
	if f.calls >= len(f.responses) {
		return &management.ListUserGrantResponse{Details: &object.ListDetails{TotalResult: 0}}, nil
	}
	resp := f.responses[f.calls]
	f.calls++
	return resp, nil
}

type fakeProjectService struct {
	responses []*management.ListProjectsResponse
	calls     int
}

func (f *fakeProjectService) ListProjects(ctx context.Context, req *management.ListProjectsRequest, opts ...grpc.CallOption) (*management.ListProjectsResponse, error) {
	if f.calls >= len(f.responses) {
		return &management.ListProjectsResponse{Details: &object.ListDetails{TotalResult: 0}}, nil
	}
	resp := f.responses[f.calls]
	f.calls++
	return resp, nil
}

type fakeRoleService struct {
	responses []*management.ListProjectRolesResponse
	calls     int
}

func (f *fakeRoleService) ListProjectRoles(ctx context.Context, req *management.ListProjectRolesRequest, opts ...grpc.CallOption) (*management.ListProjectRolesResponse, error) {
	if f.calls >= len(f.responses) {
		return &management.ListProjectRolesResponse{Details: &object.ListDetails{TotalResult: 0}}, nil
	}
	resp := f.responses[f.calls]
	f.calls++
	return resp, nil
}

type fakeMetadataService struct {
	responses []*management.ListUserMetadataResponse
	calls     int
}

func (f *fakeMetadataService) ListUserMetadata(ctx context.Context, req *management.ListUserMetadataRequest, opts ...grpc.CallOption) (*management.ListUserMetadataResponse, error) {
	if f.calls >= len(f.responses) {
		return &management.ListUserMetadataResponse{Details: &object.ListDetails{TotalResult: 0}}, nil
	}
	resp := f.responses[f.calls]
	f.calls++
	return resp, nil
}

func TestFetchAllUsersWithService(t *testing.T) {
	gender := userv2.Gender_GENDER_MALE
	user1 := &userv2.User{UserId: "u1", Username: "alice", Type: &userv2.User_Human{Human: &userv2.HumanUser{
		Profile: &userv2.HumanProfile{GivenName: "A", FamilyName: "B", Gender: &gender},
		Email:   &userv2.HumanEmail{Email: "alice@example.com"},
	}}}
	user2 := &userv2.User{UserId: "u2", Username: "bob", Type: &userv2.User_Human{Human: &userv2.HumanUser{
		Profile: &userv2.HumanProfile{GivenName: "C", FamilyName: "D", Gender: &gender},
		Email:   &userv2.HumanEmail{Email: "bob@example.com"},
	}}}

	service := &fakeUserService{responses: []*userv2.ListUsersResponse{
		{Details: &objectv2.ListDetails{TotalResult: 2}, Result: []*userv2.User{user1}},
		{Details: &objectv2.ListDetails{TotalResult: 2}, Result: []*userv2.User{user2}},
	}}

	grantsFn := func(ctx context.Context) (*zclient.GrantResults, error) {
		return &zclient.GrantResults{Result: []zclient.Grant{{UserID: "u1", RoleKeys: []string{"roleA"}}}}, nil
	}

	res, err := fetchAllUsersWithService(context.Background(), service, grantsFn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Result) != 2 {
		t.Fatalf("expected 2 users, got %d", len(res.Result))
	}
	if len(res.Result[0].Human.Groups) != 1 {
		t.Fatalf("expected groups to be assigned")
	}
	if service.calls != 2 {
		t.Fatalf("expected 2 calls, got %d", service.calls)
	}
}

func TestFetchAllGrantsWithService(t *testing.T) {
	service := &fakeGrantService{responses: []*management.ListUserGrantResponse{
		{Details: &object.ListDetails{TotalResult: 2}, Result: []*user.UserGrant{{Id: "g1"}}},
		{Details: &object.ListDetails{TotalResult: 2}, Result: []*user.UserGrant{{Id: "g2"}}},
	}}

	res, err := fetchAllGrantsWithService(context.Background(), service)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Result) != 2 {
		t.Fatalf("expected 2 grants, got %d", len(res.Result))
	}
	if service.calls != 2 {
		t.Fatalf("expected 2 calls, got %d", service.calls)
	}
}

func TestFetchAllProjectsWithService(t *testing.T) {
	service := &fakeProjectService{responses: []*management.ListProjectsResponse{
		{Details: &object.ListDetails{TotalResult: 1}, Result: []*project.Project{{Id: "p1", Name: "proj"}}},
	}}

	res, err := fetchAllProjectsWithService(context.Background(), service)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Result) != 1 || res.Result[0].ID != "p1" {
		t.Fatalf("unexpected projects result: %#v", res.Result)
	}
}

func TestFetchRolesWithService(t *testing.T) {
	service := &fakeRoleService{responses: []*management.ListProjectRolesResponse{
		{Details: &object.ListDetails{TotalResult: 1}, Result: []*project.Role{{Key: "r1", Group: "g1"}}},
	}}

	res, err := fetchRolesWithService(context.Background(), service, "p1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Result) != 1 || res.Result[0].Key != "r1" {
		t.Fatalf("unexpected roles result: %#v", res.Result)
	}
}

func TestFetchMetadataWithService(t *testing.T) {
	service := &fakeMetadataService{responses: []*management.ListUserMetadataResponse{
		{Details: &object.ListDetails{TotalResult: 1}, Result: []*metadata.Metadata{{Key: "k1", Value: []byte("v")}}},
	}}

	res, err := fetchMetadataWithService(context.Background(), service, "u1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Result) != 1 || res.Result[0].Key != "k1" {
		t.Fatalf("unexpected metadata result: %#v", res.Result)
	}
}
