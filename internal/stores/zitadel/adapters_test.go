package zitadel

import (
	"encoding/base64"
	"testing"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/metadata"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	apperrors "github.com/jacobalberty/zitadel-ldap/internal/errors"
)

func TestConvertSDKUserToUserHuman(t *testing.T) {
	nickname := "nick"
	display := "display"
	lang := "en"
	gender := userv2.Gender_GENDER_FEMALE

	sdkUser := &userv2.User{
		UserId:             "u1",
		Username:           "alice",
		LoginNames:         []string{"alice"},
		PreferredLoginName: "alice",
		State:              userv2.UserState_USER_STATE_ACTIVE,
		Type: &userv2.User_Human{Human: &userv2.HumanUser{
			Profile: &userv2.HumanProfile{
				GivenName:         "Alice",
				FamilyName:        "Doe",
				NickName:          &nickname,
				DisplayName:       &display,
				PreferredLanguage: &lang,
				Gender:            &gender,
			},
			Email: &userv2.HumanEmail{Email: "alice@example.com", IsVerified: true},
		}},
	}

	u := convertSDKUserToUser(sdkUser)
	if u.UserID != "u1" || u.Username != "alice" {
		t.Fatalf("unexpected user fields: %#v", u)
	}
	if u.Human == nil {
		t.Fatalf("expected human user")
	}
	if u.Human.Profile.NickName != "nick" {
		t.Fatalf("unexpected nickname: %s", u.Human.Profile.NickName)
	}
	if u.Human.Email.Email != "alice@example.com" || !u.Human.Email.IsVerified {
		t.Fatalf("unexpected email: %#v", u.Human.Email)
	}
}

func TestConvertSDKUserToUserMachine(t *testing.T) {
	sdkUser := &userv2.User{
		UserId:   "m1",
		Username: "svc",
		Type: &userv2.User_Machine{Machine: &userv2.MachineUser{
			Name:            "svc",
			Description:     "service",
			HasSecret:       true,
			AccessTokenType: userv2.AccessTokenType_ACCESS_TOKEN_TYPE_BEARER,
		}},
	}

	u := convertSDKUserToUser(sdkUser)
	if u.Machine == nil {
		t.Fatalf("expected machine user")
	}
	if u.Machine.Description != "service" || !u.Machine.HasSecret {
		t.Fatalf("unexpected machine fields: %#v", u.Machine)
	}
}

func TestConvertSDKGrantToGrant(t *testing.T) {
	sdkGrant := &user.UserGrant{
		Id:           "g1",
		RoleKeys:     []string{"r1"},
		State:        user.UserGrantState_USER_GRANT_STATE_ACTIVE,
		UserId:       "u1",
		UserName:     "alice",
		Email:        "alice@example.com",
		ProjectId:    "p1",
		ProjectName:  "proj",
		OrgId:        "o1",
		OrgName:      "org",
		OrgDomain:    "example.com",
		GrantedOrgId: "go1",
	}

	g := convertSDKGrantToGrant(sdkGrant)
	if g.ID != "g1" || g.UserID != "u1" || g.ProjectID != "p1" {
		t.Fatalf("unexpected grant fields: %#v", g)
	}
	if len(g.RoleKeys) != 1 || g.RoleKeys[0] != "r1" {
		t.Fatalf("unexpected role keys: %#v", g.RoleKeys)
	}
}

func TestConvertSDKProjectToProjectResult(t *testing.T) {
	created := timestamppb.Now()
	changed := timestamppb.Now()
	proj := &project.Project{
		Id:                   "p1",
		Name:                 "proj",
		State:                project.ProjectState_PROJECT_STATE_ACTIVE,
		ProjectRoleCheck:     true,
		ProjectRoleAssertion: true,
		Details: &object.ObjectDetails{
			Sequence:      42,
			CreationDate:  created,
			ChangeDate:    changed,
			ResourceOwner: "org",
		},
	}

	p := convertSDKProjectToProjectResult(proj)
	if p.ID != "p1" || p.Name != "proj" {
		t.Fatalf("unexpected project fields: %#v", p)
	}
	if p.Details.Sequence != "42" || p.Details.ResourceOwner != "org" {
		t.Fatalf("unexpected project details: %#v", p.Details)
	}
	if p.Details.CreationDate.IsZero() || p.Details.ChangeDate.IsZero() {
		t.Fatalf("expected timestamps to be set")
	}
}

func TestConvertSDKRoleToRoleResult(t *testing.T) {
	role := &project.Role{
		Key:         "role1",
		DisplayName: "Role 1",
		Group:       "group",
		Details: &object.ObjectDetails{
			Sequence:      7,
			ResourceOwner: "org",
		},
	}

	r := convertSDKRoleToRoleResult(role)
	if r.Key != "role1" || r.Group != "group" {
		t.Fatalf("unexpected role fields: %#v", r)
	}
	if r.Details.Sequence != "7" {
		t.Fatalf("unexpected role sequence: %s", r.Details.Sequence)
	}
}

func TestConvertSDKMetadataToMetadataResult(t *testing.T) {
	m := &metadata.Metadata{Key: "k1", Value: []byte("data")}
	res := convertSDKMetadataToMetadataResult(m)
	expected := base64.StdEncoding.EncodeToString([]byte("data"))
	if res.Value != expected {
		t.Fatalf("unexpected value: %s", res.Value)
	}
}

func TestUserAdapterAndHumanAdapter(t *testing.T) {
	name := "Nick"
	gender := userv2.Gender_GENDER_MALE
	profile := &userv2.HumanProfile{GivenName: "A", FamilyName: "B", NickName: &name, Gender: &gender}
	human := &userv2.HumanUser{Profile: profile, Email: &userv2.HumanEmail{Email: "a@b.com"}}

	out := humanUserAdapter(human)
	if out == nil || out.Profile.GivenName != "A" {
		t.Fatalf("unexpected human adapter result")
	}

	sdkUser := &userv2.User{UserId: "u1", Username: "alice", Type: &userv2.User_Human{Human: human}}
	adapted, err := userAdapter(sdkUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if adapted.UserID != "u1" {
		t.Fatalf("unexpected user ID: %s", adapted.UserID)
	}
}

func TestGetStringValue(t *testing.T) {
	if getStringValue(nil) != "" {
		t.Fatalf("expected empty string")
	}
	value := "val"
	if getStringValue(&value) != "val" {
		t.Fatalf("expected val")
	}
}

func TestClassifyLoginErrorUnauthorized(t *testing.T) {
	err := classifyLoginError(statusErrorUnauthenticated())
	if err == nil {
		t.Fatalf("expected error")
	}
	if !apperrors.IsUnauthorized(err) {
		t.Fatalf("expected unauthorized error")
	}
}

func statusErrorUnauthenticated() error {
	return status.Error(codes.Unauthenticated, "bad creds")
}
