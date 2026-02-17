package repository

import (
	"context"

	"github.com/jacobalberty/zitadel-ldap/internal/stores/zitadel"
	zclient "github.com/jacobalberty/zitadel-ldap/internal/zitadel"
)

// ZitadelRepository implements Repository interface using Zitadel SDK
type ZitadelRepository struct {
	querier zitadel.Querier
}

// NewZitadelRepository creates a new Zitadel repository
func NewZitadelRepository(querier zitadel.Querier) *ZitadelRepository {
	return &ZitadelRepository{
		querier: querier,
	}
}

// ListUsers retrieves all users with pagination
func (r *ZitadelRepository) ListUsers(ctx context.Context) (*zclient.UserResults, error) {
	return r.querier.ListUsers(ctx)
}

// FindUserByName finds a user by username
func (r *ZitadelRepository) FindUserByName(ctx context.Context, name string) (*zclient.UserResults, error) {
	return r.querier.FindUserByName(ctx, name)
}

// FindUserByMail finds a user by email address
func (r *ZitadelRepository) FindUserByMail(ctx context.Context, mail string) (*zclient.UserResults, error) {
	return r.querier.FindUserByMail(ctx, mail)
}

// ListGrants retrieves all user grants with pagination
func (r *ZitadelRepository) ListGrants(ctx context.Context) (*zclient.GrantResults, error) {
	return r.querier.ListGrants(ctx)
}

// ListProjects retrieves all projects with pagination
func (r *ZitadelRepository) ListProjects(ctx context.Context) (*zclient.ProjectResults, error) {
	return r.querier.ListProjects(ctx)
}

// ListRoles retrieves all roles for a specific project with pagination
func (r *ZitadelRepository) ListRoles(ctx context.Context, projectID string) (*zclient.RoleResults, error) {
	return r.querier.ListRoles(ctx, projectID)
}

// ListMetadata retrieves all metadata for a specific user with pagination
func (r *ZitadelRepository) ListMetadata(ctx context.Context, userID string) (*zclient.MetadataResults, error) {
	return r.querier.ListMetadata(ctx, userID)
}

// Login authenticates a user and returns true if successful
func (r *ZitadelRepository) Login(ctx context.Context, username, password string) (bool, error) {
	return r.querier.Login(ctx, username, password)
}

// Ensure ZitadelRepository implements Repository interface
var _ Repository = (*ZitadelRepository)(nil)
