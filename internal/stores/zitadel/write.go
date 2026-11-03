package zitadel

import (
	"context"
	"fmt"

	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"

	"github.com/jacobalberty/zitadel-ldap/internal/retry"
	"github.com/jacobalberty/zitadel-ldap/internal/stores/cache"
	zclient "github.com/jacobalberty/zitadel-ldap/internal/zitadel"
)

// CreateUser creates a new human user in Zitadel.
func (q *querier) CreateUser(ctx context.Context, req *zclient.UserCreateRequest) (*zclient.User, error) {
	if req == nil {
		return nil, fmt.Errorf("create request cannot be nil")
	}

	// Build the Zitadel request
	createReq := &userv2.CreateUserRequest{
		OrganizationId: "", // Empty means use the organization from auth context
		Username:       &req.Username,
		UserType: &userv2.CreateUserRequest_Human_{
			Human: &userv2.CreateUserRequest_Human{
				Profile: &userv2.SetHumanProfile{
					GivenName:         req.GivenName,
					FamilyName:        req.FamilyName,
					NickName:          &req.NickName,
					DisplayName:       &req.DisplayName,
					PreferredLanguage: &req.PreferredLanguage,
					Gender: func() *userv2.Gender {
						if req.Gender == "" {
							return nil
						}
						switch req.Gender {
						case "male":
							return ptr(userv2.Gender_GENDER_MALE)
						case "female":
							return ptr(userv2.Gender_GENDER_FEMALE)
						case "diverse":
							return ptr(userv2.Gender_GENDER_DIVERSE)
						default:
							return ptr(userv2.Gender_GENDER_UNSPECIFIED)
						}
					}(),
				},
				Email: &userv2.SetHumanEmail{
					Email: req.Email,
					Verification: &userv2.SetHumanEmail_IsVerified{
						IsVerified: true, // Mark email as verified
					},
				},
			},
		},
	}

	// Add phone if provided
	if req.Phone != "" {
		createReq.GetHuman().Phone = &userv2.SetHumanPhone{
			Phone: req.Phone,
			Verification: &userv2.SetHumanPhone_IsVerified{
				IsVerified: true, // Mark phone as verified
			},
		}
	}

	// Add password if provided
	if req.Password != "" {
		createReq.GetHuman().PasswordType = &userv2.CreateUserRequest_Human_Password{
			Password: &userv2.Password{
				Password:       req.Password,
				ChangeRequired: false,
			},
		}
	}

	// Add metadata if provided
	if len(req.Metadata) > 0 {
		metadata := make([]*userv2.Metadata, 0, len(req.Metadata))
		for key, value := range req.Metadata {
			metadata = append(metadata, &userv2.Metadata{
				Key:   key,
				Value: value, // Value is already []byte
			})
		}
		createReq.GetHuman().Metadata = metadata
	}

	// Execute the request with retry
	retryConfig := retry.DefaultConfig()
	resp, err := retry.Do(ctx, retryConfig, func() (*userv2.CreateUserResponse, error) {
		resp, callErr := q.zitadelClient.UserServiceV2().CreateUser(ctx, createReq)
		if callErr != nil {
			return nil, classifyError("CreateUser", callErr)
		}
		return resp, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	if resp.Id == "" {
		return nil, fmt.Errorf("got empty user ID from Zitadel")
	}

	// Invalidate users cache by creating a new cache instance
	q.usersCache = cache.NewCacher[CacheKey, *zclient.UserResults]()

	// Build simplified user response
	return &zclient.User{
		UserID:   resp.Id,
		Username: req.Username,
		Human: &zclient.Human{
			Profile: zclient.Profile{
				GivenName:  req.GivenName,
				FamilyName: req.FamilyName,
			},
			Email: zclient.Email{
				Email: req.Email,
			},
		},
	}, nil
}

// UpdateUser updates an existing user in Zitadel.
func (q *querier) UpdateUser(ctx context.Context, userID string, req *zclient.UserUpdateRequest) error {
	if req == nil {
		return fmt.Errorf("update request cannot be nil")
	}
	if userID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}

	// Cached logins may be stale after any (even partially failed) update.
	defer q.loginCache.Clear()

	// Build the Zitadel request
	updateReq := &userv2.UpdateUserRequest{
		UserId: userID,
	}

	// Build human profile update
	humanUpdate := &userv2.UpdateUserRequest_Human_{
		Human: &userv2.UpdateUserRequest_Human{},
	}
	needsUpdate := false

	// Profile updates
	if req.GivenName != nil || req.FamilyName != nil || req.NickName != nil ||
		req.DisplayName != nil || req.PreferredLanguage != nil || req.Gender != nil {
		humanUpdate.Human.Profile = &userv2.UpdateUserRequest_Human_Profile{
			GivenName:         req.GivenName,
			FamilyName:        req.FamilyName,
			NickName:          req.NickName,
			DisplayName:       req.DisplayName,
			PreferredLanguage: req.PreferredLanguage,
		}
		if req.Gender != nil {
			switch *req.Gender {
			case "male":
				humanUpdate.Human.Profile.Gender = ptr(userv2.Gender_GENDER_MALE)
			case "female":
				humanUpdate.Human.Profile.Gender = ptr(userv2.Gender_GENDER_FEMALE)
			case "diverse":
				humanUpdate.Human.Profile.Gender = ptr(userv2.Gender_GENDER_DIVERSE)
			default:
				humanUpdate.Human.Profile.Gender = ptr(userv2.Gender_GENDER_UNSPECIFIED)
			}
		}
		needsUpdate = true
	}

	// Email update
	if req.Email != nil {
		humanUpdate.Human.Email = &userv2.SetHumanEmail{
			Email: *req.Email,
			Verification: &userv2.SetHumanEmail_IsVerified{
				IsVerified: true,
			},
		}
		needsUpdate = true
	}

	// Phone update
	if req.Phone != nil {
		humanUpdate.Human.Phone = &userv2.SetHumanPhone{
			Phone: *req.Phone,
			Verification: &userv2.SetHumanPhone_IsVerified{
				IsVerified: true,
			},
		}
		needsUpdate = true
	}

	// Username update
	if req.Username != nil {
		updateReq.Username = req.Username
		needsUpdate = true
	}

	if needsUpdate {
		updateReq.UserType = humanUpdate

		// Execute the update
		retryConfig := retry.DefaultConfig()
		_, err := retry.Do(ctx, retryConfig, func() (*userv2.UpdateUserResponse, error) {
			resp, callErr := q.zitadelClient.UserServiceV2().UpdateUser(ctx, updateReq)
			if callErr != nil {
				return nil, classifyError("UpdateUser", callErr)
			}
			return resp, nil
		})
		if err != nil {
			return fmt.Errorf("failed to update user: %w", err)
		}
	}

	// Handle password update separately if requested
	if req.Password != nil {
		if err := q.SetUserPassword(ctx, userID, *req.Password); err != nil {
			return fmt.Errorf("failed to update password: %w", err)
		}
	}

	// Handle metadata updates
	if len(req.Metadata) > 0 {
		for key, value := range req.Metadata {
			if err := q.UpdateMetadata(ctx, userID, key, value); err != nil {
				return fmt.Errorf("failed to update metadata %s: %w", key, err)
			}
		}
	}

	// Invalidate caches
	q.loginCache.Clear()
	q.usersCache = cache.NewCacher[CacheKey, *zclient.UserResults]()
	q.metadataCache = cache.NewCacher[CacheKey, *zclient.MetadataResults]()

	return nil
}

// DeleteUser deletes a user from Zitadel.
func (q *querier) DeleteUser(ctx context.Context, userID string) error {
	if userID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}

	deleteReq := &userv2.DeleteUserRequest{
		UserId: userID,
	}

	retryConfig := retry.DefaultConfig()
	_, err := retry.Do(ctx, retryConfig, func() (*userv2.DeleteUserResponse, error) {
		resp, callErr := q.zitadelClient.UserServiceV2().DeleteUser(ctx, deleteReq)
		if callErr != nil {
			return nil, classifyError("DeleteUser", callErr)
		}
		return resp, nil
	})
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	// Invalidate caches
	q.loginCache.Clear()
	q.usersCache = cache.NewCacher[CacheKey, *zclient.UserResults]()
	q.grantsCache = cache.NewCacher[CacheKey, *zclient.GrantResults]()
	q.metadataCache = cache.NewCacher[CacheKey, *zclient.MetadataResults]()

	return nil
}

// SetUserPassword sets the password for a user.
// This requires admin privileges as no current password verification is used.
func (q *querier) SetUserPassword(ctx context.Context, userID, password string) error {
	if userID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	setPasswordReq := &userv2.SetPasswordRequest{
		UserId: userID,
		NewPassword: &userv2.Password{
			Password:       password,
			ChangeRequired: false,
		},
		// No verification means admin privileges are required
	}

	retryConfig := retry.DefaultConfig()
	_, err := retry.Do(ctx, retryConfig, func() (*userv2.SetPasswordResponse, error) {
		resp, callErr := q.zitadelClient.UserServiceV2().SetPassword(ctx, setPasswordReq)
		if callErr != nil {
			return nil, classifyError("SetPassword", callErr)
		}
		return resp, nil
	})
	if err != nil {
		return fmt.Errorf("failed to set password: %w", err)
	}

	// Invalidate login cache
	q.loginCache.Clear()

	return nil
}

// UpdateMetadata updates a single metadata entry for a user.
func (q *querier) UpdateMetadata(ctx context.Context, userID, key string, value []byte) error {
	if userID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}
	if key == "" {
		return fmt.Errorf("metadata key cannot be empty")
	}

	metadata := []*userv2.Metadata{
		{
			Key:   key,
			Value: value, // Value is already []byte
		},
	}

	setMetadataReq := &userv2.SetUserMetadataRequest{
		UserId:   userID,
		Metadata: metadata,
	}

	retryConfig := retry.DefaultConfig()
	_, err := retry.Do(ctx, retryConfig, func() (*userv2.SetUserMetadataResponse, error) {
		resp, callErr := q.zitadelClient.UserServiceV2().SetUserMetadata(ctx, setMetadataReq)
		if callErr != nil {
			return nil, classifyError("SetUserMetadata", callErr)
		}
		return resp, nil
	})
	if err != nil {
		return fmt.Errorf("failed to set metadata: %w", err)
	}

	// Invalidate metadata cache
	q.metadataCache = cache.NewCacher[CacheKey, *zclient.MetadataResults]()

	return nil
}

// ptr is a helper function to get a pointer to a value
func ptr[T any](v T) *T {
	return &v
}
