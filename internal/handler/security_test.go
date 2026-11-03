package handler

import (
	"context"
	"encoding/base64"
	"net"
	"sync/atomic"
	"testing"

	"github.com/glauth/ldap"
	ber "github.com/go-asn1-ber/asn1-ber"

	zclient "github.com/jacobalberty/zitadel-ldap/internal/zitadel"
)

const (
	adminDN = "cn=admin,ou=users,dc=example,dc=com"
	bobDN   = "cn=bob,ou=users,dc=example,dc=com"
)

// writerRepo returns a repo where "admin" has cap_write (if withCap) and
// counts write calls.
func writerRepo(withCap bool, creates, deletes, updates *int32) *mockRepository {
	return &mockRepository{
		findUserByNameFn: func(ctx context.Context, name string) (*zclient.UserResults, error) {
			return &zclient.UserResults{Result: []zclient.User{{
				UserID: "id-" + name, Username: name, State: "USER_STATE_ACTIVE",
				Human: &zclient.Human{Email: zclient.Email{Email: name + "@example.com"}},
			}}}, nil
		},
		listMetadataFn: func(ctx context.Context, userID string) (*zclient.MetadataResults, error) {
			res := &zclient.MetadataResults{}
			if withCap && userID == "id-admin" {
				res.Result = append(res.Result, zclient.MetadataResult{
					Key: "cap_write", Value: base64.StdEncoding.EncodeToString([]byte("*")),
				})
			}
			return res, nil
		},
		createUserFn: func(ctx context.Context, req *zclient.UserCreateRequest) (*zclient.User, error) {
			atomic.AddInt32(creates, 1)
			return &zclient.User{UserID: "new"}, nil
		},
		deleteUserFn: func(ctx context.Context, id string) error { atomic.AddInt32(deletes, 1); return nil },
		updateUserFn: func(ctx context.Context, id string, r *zclient.UserUpdateRequest) error {
			atomic.AddInt32(updates, 1)
			return nil
		},
	}
}

func writeHandler(withCap, enabled bool) (*zitadelHandler, *int32, *int32, *int32) {
	var c, d, u int32
	h := newTestHandler(writerRepo(withCap, &c, &d, &u))
	h.writesEnabled = enabled
	return h, &c, &d, &u
}

func TestWritesDisabledByDefault(t *testing.T) {
	h, _, d, _ := writeHandler(true, false)
	code, err := h.Delete(adminDN, bobDN, nil)
	if err == nil || code != ldap.LDAPResultInsufficientAccessRights || *d != 0 {
		t.Fatalf("delete must be rejected when writes disabled: code=%d err=%v deletes=%d", code, err, *d)
	}
}

func TestAnonymousWriteRejected(t *testing.T) {
	h, c, d, u := writeHandler(true, true)
	if code, _ := h.Delete("", bobDN, nil); code != ldap.LDAPResultInsufficientAccessRights {
		t.Fatalf("anonymous delete code=%d", code)
	}
	if code, _ := h.Modify("", ldap.ModifyRequest{Dn: bobDN}, nil); code != ldap.LDAPResultInsufficientAccessRights {
		t.Fatalf("anonymous modify code=%d", code)
	}
	if code, _ := h.Add("", ldap.AddRequest{}, nil); code != ldap.LDAPResultInsufficientAccessRights && code != ldap.LDAPResultInvalidDNSyntax {
		t.Fatalf("anonymous add code=%d", code)
	}
	if *c+*d+*u != 0 {
		t.Fatal("no write may reach the repository")
	}
}

func TestWriteWithoutCapabilityRejected(t *testing.T) {
	h, _, d, _ := writeHandler(false, true)
	code, _ := h.Delete(adminDN, bobDN, nil)
	if code != ldap.LDAPResultInsufficientAccessRights || *d != 0 {
		t.Fatalf("code=%d deletes=%d", code, *d)
	}
}

func TestWriteWithCapabilityAllowed(t *testing.T) {
	h, _, d, u := writeHandler(true, true)
	if code, err := h.Delete(adminDN, bobDN, nil); code != ldap.LDAPResultSuccess || err != nil || *d != 1 {
		t.Fatalf("delete code=%d err=%v deletes=%d", code, err, *d)
	}
	if code, err := h.Modify(adminDN, ldap.ModifyRequest{Dn: bobDN}, nil); code != ldap.LDAPResultSuccess || err != nil || *u != 1 {
		t.Fatalf("modify code=%d err=%v updates=%d", code, err, *u)
	}
}

func TestWriteTargetMustBeUserDN(t *testing.T) {
	h, _, d, _ := writeHandler(true, true)
	for _, dn := range []string{
		"cn=admins,ou=groups,dc=example,dc=com",
		"cn=bob,ou=users,ou=extra,dc=example,dc=com",
		"cn=bob,ou=users,dc=other,dc=com",
		"cn=bob,dc=example,dc=com",
		"ou=users,dc=example,dc=com",
		"uid=bob,ou=users,dc=example,dc=com",
	} {
		if code, _ := h.Delete(adminDN, dn, nil); code != ldap.LDAPResultInvalidDNSyntax {
			t.Errorf("delete %q: code=%d, want InvalidDNSyntax", dn, code)
		}
	}
	if *d != 0 {
		t.Fatalf("no delete may reach repository, got %d", *d)
	}
}

// Regression: a real Add packet used to panic (reflect Interface() on
// unexported fields), taking down the whole server.
func addPacket(dn string, attrs map[string]string) *ber.Packet {
	req := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ldap.ApplicationAddRequest), nil, "Add")
	req.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "DN"))
	list := ber.NewSequence("Attributes")
	for k, v := range attrs {
		a := ber.NewSequence("Attribute")
		a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, k, "Type"))
		vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Vals")
		vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "Val"))
		a.AppendChild(vals)
		list.AppendChild(a)
	}
	req.AppendChild(list)
	return req
}

func TestAddRealPacketDoesNotPanic(t *testing.T) {
	h, c, _, _ := writeHandler(true, true)
	pkt := addPacket("cn=carol,ou=users,dc=example,dc=com", map[string]string{
		"mail": "carol@example.com", "givenName": "Carol", "sn": "C",
	})
	var conn net.Conn
	code := ldap.HandleAddRequest(pkt, adminDN, map[string]ldap.Adder{"": h}, conn)
	if code != ldap.LDAPResultSuccess || *c != 1 {
		t.Fatalf("code=%d creates=%d", code, *c)
	}
}

func TestAddRealPacketAnonymousRejected(t *testing.T) {
	h, c, _, _ := writeHandler(true, true)
	pkt := addPacket("cn=carol,ou=users,dc=example,dc=com", map[string]string{
		"mail": "carol@example.com", "givenName": "Carol", "sn": "C",
	})
	code := ldap.HandleAddRequest(pkt, "", map[string]ldap.Adder{"": h}, nil)
	if code == ldap.LDAPResultSuccess || *c != 0 {
		t.Fatalf("anonymous add must fail: code=%d creates=%d", code, *c)
	}
}

func TestPanicInRepositoryIsRecovered(t *testing.T) {
	var c, d, u int32
	repo := writerRepo(true, &c, &d, &u)
	repo.deleteUserFn = func(ctx context.Context, id string) error { panic("boom") }
	h := newTestHandler(repo)
	h.writesEnabled = true
	code, err := h.Delete(adminDN, bobDN, nil)
	if err == nil || code != ldap.LDAPResultOperationsError {
		t.Fatalf("expected recovered OperationsError, got code=%d err=%v", code, err)
	}
}

func TestBindEmptyPasswordRejected(t *testing.T) {
	called := false
	h := newTestHandler(&mockRepository{loginFn: func(ctx context.Context, u, p string) (bool, error) {
		called = true
		return true, nil
	}})
	code, err := h.Bind(bobDN, "", nil)
	if code == ldap.LDAPResultSuccess || err == nil || called {
		t.Fatalf("empty password must be rejected without calling Zitadel: code=%d called=%v", code, called)
	}
}

func TestBindParsesEscapedDN(t *testing.T) {
	var got string
	h := newTestHandler(&mockRepository{loginFn: func(ctx context.Context, u, p string) (bool, error) {
		got = u
		return true, nil
	}})
	if code, _ := h.Bind(`cn=smith\, bob,ou=users,dc=example,dc=com`, "pw", nil); code != ldap.LDAPResultSuccess {
		t.Fatalf("code=%d", code)
	}
	if got != "smith, bob" {
		t.Fatalf("login user = %q", got)
	}
}

func TestAnonymousBindConfigurable(t *testing.T) {
	h := newTestHandler(&mockRepository{})
	if code, _ := h.Bind("", "", nil); code != ldap.LDAPResultSuccess {
		t.Fatalf("anonymous allowed by default, code=%d", code)
	}
	h.denyAnonymousBind = true
	if code, _ := h.Bind("", "", nil); code != ldap.LDAPResultInappropriateAuthentication {
		t.Fatalf("anonymous must be rejected when disabled, code=%d", code)
	}
}
