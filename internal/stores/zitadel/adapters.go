package zitadel

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/metadata"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"

	zclient "github.com/jacobalberty/zitadel-ldap/internal/zitadel"
)

func convertSDKUserToUser(zuser *userv2.User) zclient.User {
	u := zclient.User{
		UserID:             zuser.UserId,
		State:              zuser.State.String(),
		Username:           zuser.Username,
		LoginNames:         zuser.LoginNames,
		PreferredLoginName: zuser.PreferredLoginName,
	}

	if humanUser := zuser.GetHuman(); humanUser != nil {
		u.Human = &zclient.Human{
			Profile: zclient.Profile{
				GivenName:         humanUser.Profile.GivenName,
				FamilyName:        humanUser.Profile.FamilyName,
				NickName:          humanUser.Profile.GetNickName(),
				DisplayName:       getStringValue(humanUser.Profile.DisplayName),
				PreferredLanguage: getStringValue(humanUser.Profile.PreferredLanguage),
				Gender:            humanUser.Profile.Gender.String(),
			},
			Email: zclient.Email{
				Email:      humanUser.Email.Email,
				IsVerified: humanUser.Email.IsVerified,
			},
			PasswordChanged: time.Now(),
			Groups:          []string{},
		}
	}

	if machineUser := zuser.GetMachine(); machineUser != nil {
		u.Machine = &zclient.Machine{
			Name:            machineUser.Name,
			Description:     machineUser.GetDescription(),
			HasSecret:       machineUser.HasSecret,
			AccessTokenType: machineUser.AccessTokenType.String(),
		}
	}

	return u
}

func convertSDKGrantToGrant(sdkGrant *user.UserGrant) zclient.Grant {
	return zclient.Grant{
		ID:                 sdkGrant.GetId(),
		RoleKeys:           sdkGrant.GetRoleKeys(),
		State:              sdkGrant.GetState().String(),
		UserID:             sdkGrant.GetUserId(),
		UserName:           sdkGrant.GetUserName(),
		FirstName:          sdkGrant.GetFirstName(),
		LastName:           sdkGrant.GetLastName(),
		Email:              sdkGrant.GetEmail(),
		DisplayName:        sdkGrant.GetDisplayName(),
		OrgID:              sdkGrant.GetOrgId(),
		OrgName:            sdkGrant.GetOrgName(),
		OrgDomain:          sdkGrant.GetOrgDomain(),
		ProjectID:          sdkGrant.GetProjectId(),
		ProjectName:        sdkGrant.GetProjectName(),
		PreferredLoginName: sdkGrant.GetPreferredLoginName(),
		UserType:           sdkGrant.GetUserType().String(),
		GrantedOrgID:       sdkGrant.GetGrantedOrgId(),
		GrantedOrgName:     sdkGrant.GetGrantedOrgName(),
		GrantedOrgDomain:   sdkGrant.GetGrantedOrgDomain(),
	}
}

func convertSDKProjectToProjectResult(sdkProject *project.Project) zclient.ProjectResult {
	return zclient.ProjectResult{
		ID:                   sdkProject.GetId(),
		Name:                 sdkProject.GetName(),
		State:                sdkProject.GetState().String(),
		ProjectRoleCheck:     sdkProject.GetProjectRoleCheck(),
		ProjectRoleAssertion: sdkProject.GetProjectRoleAssertion(),
		Details: zclient.ProjectDetails{
			Sequence: func() string {
				if sdkProject.GetDetails() != nil {
					return fmt.Sprintf("%d", sdkProject.GetDetails().GetSequence())
				}
				return ""
			}(),
			CreationDate: func() time.Time {
				if sdkProject.GetDetails() != nil && sdkProject.GetDetails().GetCreationDate() != nil {
					return sdkProject.GetDetails().GetCreationDate().AsTime()
				}
				return time.Time{}
			}(),
			ChangeDate: func() time.Time {
				if sdkProject.GetDetails() != nil && sdkProject.GetDetails().GetChangeDate() != nil {
					return sdkProject.GetDetails().GetChangeDate().AsTime()
				}
				return time.Time{}
			}(),
			ResourceOwner: func() string {
				if sdkProject.GetDetails() != nil {
					return sdkProject.GetDetails().GetResourceOwner()
				}
				return ""
			}(),
		},
	}
}

func convertSDKRoleToRoleResult(sdkRole *project.Role) zclient.RoleResult {
	return zclient.RoleResult{
		Key:         sdkRole.GetKey(),
		DisplayName: sdkRole.GetDisplayName(),
		Group:       sdkRole.GetGroup(),
		Details: zclient.RoleDetails{
			Sequence: func() string {
				if sdkRole.GetDetails() != nil {
					return fmt.Sprintf("%d", sdkRole.GetDetails().GetSequence())
				}
				return ""
			}(),
			CreationDate: func() time.Time {
				if sdkRole.GetDetails() != nil && sdkRole.GetDetails().GetCreationDate() != nil {
					return sdkRole.GetDetails().GetCreationDate().AsTime()
				}
				return time.Time{}
			}(),
			ChangeDate: func() time.Time {
				if sdkRole.GetDetails() != nil && sdkRole.GetDetails().GetChangeDate() != nil {
					return sdkRole.GetDetails().GetChangeDate().AsTime()
				}
				return time.Time{}
			}(),
			ResourceOwner: func() string {
				if sdkRole.GetDetails() != nil {
					return sdkRole.GetDetails().GetResourceOwner()
				}
				return ""
			}(),
		},
	}
}

func convertSDKMetadataToMetadataResult(sdkMetadata *metadata.Metadata) zclient.MetadataResult {
	return zclient.MetadataResult{
		Key:   sdkMetadata.GetKey(),
		Value: base64.StdEncoding.EncodeToString(sdkMetadata.GetValue()),
	}
}

// Helper functions
func getStringValue(ptr *string) string {
	if ptr != nil {
		return *ptr
	}
	return ""
}

// Legacy adapter function for backwards compatibility
func userAdapter(zuser *userv2.User) (*zclient.User, error) {
	u := convertSDKUserToUser(zuser)
	return &u, nil
}

func humanUserAdapter(humanUser *userv2.HumanUser) *zclient.Human {
	if humanUser == nil {
		return nil
	}

	return &zclient.Human{
		Profile: zclient.Profile{
			GivenName:         humanUser.Profile.GivenName,
			FamilyName:        humanUser.Profile.FamilyName,
			NickName:          humanUser.Profile.GetNickName(),
			DisplayName:       getStringValue(humanUser.Profile.DisplayName),
			PreferredLanguage: getStringValue(humanUser.Profile.PreferredLanguage),
			Gender:            humanUser.Profile.Gender.String(),
		},
		Email: zclient.Email{
			Email:      humanUser.Email.Email,
			IsVerified: humanUser.Email.IsVerified,
		},
		PasswordChanged: time.Now(),
		Groups:          []string{},
	}
}
