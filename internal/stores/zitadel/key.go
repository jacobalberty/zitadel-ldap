package zitadel

type CacheKeyType string

const (
	CacheKeyTypeUser     CacheKeyType = "user"
	CacheKeyTypeUsers    CacheKeyType = "users"
	CacheKeyTypeGrants   CacheKeyType = "grants"
	CacheKeyTypeProjects CacheKeyType = "projects"
	CacheKeyTypeRoles    CacheKeyType = "roles"
	CacheKeyTypeMetadata CacheKeyType = "metadata"
)

type CacheKey struct {
	Type CacheKeyType
	ID   string
}
