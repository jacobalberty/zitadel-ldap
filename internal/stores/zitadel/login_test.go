package zitadel

import "testing"

func TestHashLoginNoConcatenationCollision(t *testing.T) {
	q := &querier{}
	if q.hashLogin("bob", "xsecret") == q.hashLogin("bobx", "secret") {
		t.Fatal("distinct (username,password) pairs must not share a cache key")
	}
}

func TestHashLoginDeterministicAndPasswordSensitive(t *testing.T) {
	q := &querier{}
	first, second := q.hashLogin("bob", "pw"), q.hashLogin("bob", "pw")
	if first != second {
		t.Fatal("hash must be stable within a process")
	}
	if q.hashLogin("bob", "pw") == q.hashLogin("bob", "pw2") {
		t.Fatal("different passwords must produce different keys")
	}
}

func TestLoginCacheTTLEnv(t *testing.T) {
	t.Setenv("ZITADEL_LDAP_LOGIN_CACHE_TTL", "")
	if loginCacheTTL() != defaultLoginCacheTTL {
		t.Fatal("expected default")
	}
	t.Setenv("ZITADEL_LDAP_LOGIN_CACHE_TTL", "5s")
	if loginCacheTTL().Seconds() != 5 {
		t.Fatal("expected 5s")
	}
	t.Setenv("ZITADEL_LDAP_LOGIN_CACHE_TTL", "garbage")
	if loginCacheTTL() != defaultLoginCacheTTL {
		t.Fatal("expected default on bad value")
	}
}
