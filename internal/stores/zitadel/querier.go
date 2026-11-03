package zitadel

import (
	"context"

	"github.com/zitadel/zitadel-go/v3/pkg/client"

	"github.com/jacobalberty/zitadel-ldap/internal/stores/cache"
	zclient "github.com/jacobalberty/zitadel-ldap/internal/zitadel"
)

type Querier interface {
	Login(ctx context.Context, username, password string) (bool, error)
	ListGrants(ctx context.Context) (*zclient.GrantResults, error)
	ListMetadata(ctx context.Context, id string) (*zclient.MetadataResults, error)
	ListProjects(ctx context.Context) (*zclient.ProjectResults, error)
	ListRoles(ctx context.Context, projectID string) (*zclient.RoleResults, error)
	ListUsers(ctx context.Context) (*zclient.UserResults, error)
	FindUserByName(ctx context.Context, name string) (*zclient.UserResults, error)
	FindUserByMail(ctx context.Context, mail string) (*zclient.UserResults, error)
	CreateUser(ctx context.Context, req *zclient.UserCreateRequest) (*zclient.User, error)
	UpdateUser(ctx context.Context, userID string, req *zclient.UserUpdateRequest) error
	DeleteUser(ctx context.Context, userID string) error
	SetUserPassword(ctx context.Context, userID, password string) error
	UpdateMetadata(ctx context.Context, userID, key string, value []byte) error
}

type querier struct {
	zitadelClient *client.Client
	loginCache    cache.Cacher[CacheKey, bool]
	usersCache    cache.Cacher[CacheKey, *zclient.UserResults]
	grantsCache   cache.Cacher[CacheKey, *zclient.GrantResults]
	projectsCache cache.Cacher[CacheKey, *zclient.ProjectResults]
	rolesCache    cache.Cacher[CacheKey, *zclient.RoleResults]
	metadataCache cache.Cacher[CacheKey, *zclient.MetadataResults]
}

func newQuerier(client *client.Client) Querier {
	return &querier{
		zitadelClient: client,
		loginCache:    cache.NewCacher[CacheKey, bool](),
		usersCache:    cache.NewCacher[CacheKey, *zclient.UserResults](),
		grantsCache:   cache.NewCacher[CacheKey, *zclient.GrantResults](),
		projectsCache: cache.NewCacher[CacheKey, *zclient.ProjectResults](),
		rolesCache:    cache.NewCacher[CacheKey, *zclient.RoleResults](),
		metadataCache: cache.NewCacher[CacheKey, *zclient.MetadataResults](),
	}
}
