package repository

import (
	"context"

	zclient "github.com/jacobalberty/zitadel-ldap/internal/zitadel"
)

// UserRepository defines operations for user data
type UserRepository interface {
	// ListUsers retrieves all users with pagination
	ListUsers(ctx context.Context) (*zclient.UserResults, error)

	// FindUserByName finds a user by username
	FindUserByName(ctx context.Context, name string) (*zclient.UserResults, error)

	// FindUserByMail finds a user by email address
	FindUserByMail(ctx context.Context, mail string) (*zclient.UserResults, error)
}

// GrantRepository defines operations for user grant data
type GrantRepository interface {
	// ListGrants retrieves all user grants with pagination
	ListGrants(ctx context.Context) (*zclient.GrantResults, error)
}

// ProjectRepository defines operations for project data
type ProjectRepository interface {
	// ListProjects retrieves all projects with pagination
	ListProjects(ctx context.Context) (*zclient.ProjectResults, error)

	// ListRoles retrieves all roles for a specific project with pagination
	ListRoles(ctx context.Context, projectID string) (*zclient.RoleResults, error)
}

// MetadataRepository defines operations for user metadata
type MetadataRepository interface {
	// ListMetadata retrieves all metadata for a specific user with pagination
	ListMetadata(ctx context.Context, userID string) (*zclient.MetadataResults, error)
}

// AuthRepository defines authentication operations
type AuthRepository interface {
	// Login authenticates a user and returns true if successful
	Login(ctx context.Context, username, password string) (bool, error)
}

// WriteRepository defines user write operations
type WriteRepository interface {
	// CreateUser creates a new human user
	CreateUser(ctx context.Context, req *zclient.UserCreateRequest) (*zclient.User, error)

	// UpdateUser updates an existing user
	UpdateUser(ctx context.Context, userID string, req *zclient.UserUpdateRequest) error

	// DeleteUser deletes an existing user
	DeleteUser(ctx context.Context, userID string) error

	// SetUserPassword updates a user's password
	SetUserPassword(ctx context.Context, userID, password string) error

	// UpdateMetadata sets or updates a metadata key for a user
	UpdateMetadata(ctx context.Context, userID, key string, value []byte) error
}

// Repository aggregates all repository interfaces
type Repository interface {
	UserRepository
	GrantRepository
	ProjectRepository
	MetadataRepository
	AuthRepository
	WriteRepository
}
