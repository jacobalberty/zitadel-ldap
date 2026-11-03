package zitadel

import (
	"context"
	"os"
	"strconv"
	"time"

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

// Cache tuning (environment):
//
//	ZITADEL_LDAP_CACHE_TTL            data cache lifetime, Go duration (default 1h)
//	ZITADEL_LDAP_METADATA_CACHE_SIZE  per-user metadata entries (default 10000)
//	ZITADEL_LDAP_ROLES_CACHE_SIZE     per-project role entries (default 1000)
const (
	defaultDataCacheTTL      = time.Hour
	defaultMetadataCacheSize = 10000
	defaultRolesCacheSize    = 1000
)

func envDuration(name string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(os.Getenv(name)); err == nil && d > 0 {
		return d
	}
	return def
}

func envInt(name string, def int) int {
	if n, err := strconv.Atoi(os.Getenv(name)); err == nil && n > 0 {
		return n
	}
	return def
}

func newQuerier(client *client.Client) Querier {
	ttl := envDuration("ZITADEL_LDAP_CACHE_TTL", defaultDataCacheTTL)
	return &querier{
		zitadelClient: client,
		loginCache:    cache.NewCacher(cache.WithTTL[CacheKey, bool](loginCacheTTL()), cache.WithCapacity[CacheKey, bool](1000)),
		usersCache:    cache.NewCacher(cache.WithTTL[CacheKey, *zclient.UserResults](ttl)),
		grantsCache:   cache.NewCacher(cache.WithTTL[CacheKey, *zclient.GrantResults](ttl)),
		projectsCache: cache.NewCacher(cache.WithTTL[CacheKey, *zclient.ProjectResults](ttl)),
		rolesCache: cache.NewCacher(cache.WithTTL[CacheKey, *zclient.RoleResults](ttl),
			cache.WithCapacity[CacheKey, *zclient.RoleResults](envInt("ZITADEL_LDAP_ROLES_CACHE_SIZE", defaultRolesCacheSize))),
		metadataCache: cache.NewCacher(cache.WithTTL[CacheKey, *zclient.MetadataResults](ttl),
			cache.WithCapacity[CacheKey, *zclient.MetadataResults](envInt("ZITADEL_LDAP_METADATA_CACHE_SIZE", defaultMetadataCacheSize))),
	}
}
