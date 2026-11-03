package zitadel

import (
	"context"
	"testing"

	"github.com/jacobalberty/zitadel-ldap/internal/stores/cache"
	zclient "github.com/jacobalberty/zitadel-ldap/internal/zitadel"
)

type fakeCacher[K comparable, V any] struct {
	value   V
	err     error
	got     bool
	lastKey K
}

func (f *fakeCacher[K, V]) Get(ctx context.Context, key K, loaderFunc cache.LoaderFunc[V]) (V, error) {
	f.got = true
	f.lastKey = key
	if f.err != nil {
		return *new(V), f.err
	}
	return f.value, nil
}

func (f *fakeCacher[K, V]) Clear() {}

func TestListUsersUsesCacheKey(t *testing.T) {
	users := &zclient.UserResults{Result: []zclient.User{{UserID: "u1", Username: "alice", Human: &zclient.Human{}}}}
	usersCache := &fakeCacher[CacheKey, *zclient.UserResults]{value: users}
	q := &querier{usersCache: usersCache}

	res, err := q.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil || len(res.Result) != 1 {
		t.Fatalf("unexpected users result")
	}
	if !usersCache.got || usersCache.lastKey.Type != CacheKeyTypeUsers || usersCache.lastKey.ID != "all" {
		t.Fatalf("unexpected cache key: %#v", usersCache.lastKey)
	}
}

func TestFindUserByNameAndMail(t *testing.T) {
	users := &zclient.UserResults{Result: []zclient.User{
		{UserID: "u1", Username: "alice", Human: &zclient.Human{Email: zclient.Email{Email: "alice@example.com"}}},
		{UserID: "u2", Username: "bob", Human: &zclient.Human{Email: zclient.Email{Email: "bob@example.com"}}},
	}}
	usersCache := &fakeCacher[CacheKey, *zclient.UserResults]{value: users}
	q := &querier{usersCache: usersCache}

	byName, err := q.FindUserByName(context.Background(), "bob")
	if err != nil || len(byName.Result) != 1 || byName.Result[0].UserID != "u2" {
		t.Fatalf("unexpected FindUserByName result: %#v, err=%v", byName, err)
	}

	byMail, err := q.FindUserByMail(context.Background(), "alice@example.com")
	if err != nil || len(byMail.Result) != 1 || byMail.Result[0].UserID != "u1" {
		t.Fatalf("unexpected FindUserByMail result: %#v, err=%v", byMail, err)
	}
}

func TestListRolesAndMetadataCacheKeys(t *testing.T) {
	rolesCache := &fakeCacher[CacheKey, *zclient.RoleResults]{value: &zclient.RoleResults{}}
	metadataCache := &fakeCacher[CacheKey, *zclient.MetadataResults]{value: &zclient.MetadataResults{}}
	q := &querier{rolesCache: rolesCache, metadataCache: metadataCache}

	_, _ = q.ListRoles(context.Background(), "proj1")
	if rolesCache.lastKey.Type != CacheKeyTypeRoles || rolesCache.lastKey.ID != "proj1" {
		t.Fatalf("unexpected roles cache key: %#v", rolesCache.lastKey)
	}

	_, _ = q.ListMetadata(context.Background(), "user1")
	if metadataCache.lastKey.Type != CacheKeyTypeMetadata || metadataCache.lastKey.ID != "user1" {
		t.Fatalf("unexpected metadata cache key: %#v", metadataCache.lastKey)
	}
}

func TestHashLoginDeterministic(t *testing.T) {
	q := &querier{}
	first := q.hashLogin("alice", "secret")
	second := q.hashLogin("alice", "secret")
	if first != second {
		t.Fatalf("expected deterministic hash")
	}
}
