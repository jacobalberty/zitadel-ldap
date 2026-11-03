package handler

import "testing"

func TestBuildGroupMembershipFilter(t *testing.T) {
	uidFilter := BuildGroupMembershipFilter("alice", false)
	if uidFilter != "(memberUid=alice)" {
		t.Fatalf("unexpected UID filter: %s", uidFilter)
	}

	dnFilter := BuildGroupMembershipFilter("cn=alice,ou=users,dc=example,dc=com", true)
	if dnFilter != "(uniqueMember=cn=alice,ou=users,dc=example,dc=com)" {
		t.Fatalf("unexpected DN filter: %s", dnFilter)
	}
}

func TestBuildMetadataFilter(t *testing.T) {
	filter, err := BuildMetadataFilter("department", "engineering")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if filter != "(gl_department=engineering)" {
		t.Fatalf("unexpected metadata filter: %s", filter)
	}
}

func TestBuildUserIdentityFilter(t *testing.T) {
	filter := BuildUserIdentityFilter("alice", "alice@example.com")
	if filter != "(|(cn=alice)(mail=alice@example.com))" {
		t.Fatalf("unexpected identity filter: %s", filter)
	}

	filter = BuildUserIdentityFilter("alice", "")
	if filter != "(cn=alice)" {
		t.Fatalf("unexpected username-only filter: %s", filter)
	}
}
