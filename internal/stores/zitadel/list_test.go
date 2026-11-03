package zitadel

import (
	"errors"
	"testing"

	apperrors "github.com/jacobalberty/zitadel-ldap/internal/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestClassifyErrorNil(t *testing.T) {
	if err := classifyError("ListUsers", nil); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestClassifyErrorMappings(t *testing.T) {
	cases := []struct {
		name        string
		code        codes.Code
		msg         string
		wantErr     error
		wantRetry   bool
		wantAuthErr bool
		wantTimeout bool
	}{
		{"not_found", codes.NotFound, "missing", apperrors.ErrNotFound, false, false, false},
		{"unauthenticated", codes.Unauthenticated, "bad auth", apperrors.ErrUnauthorized, false, true, false},
		{"permission_denied", codes.PermissionDenied, "no perms", apperrors.ErrForbidden, false, false, false},
		{"invalid_argument", codes.InvalidArgument, "bad input", apperrors.ErrInvalidInput, false, false, false},
		{"resource_exhausted", codes.ResourceExhausted, "rate limit", apperrors.ErrRateLimited, true, false, false},
		{"unavailable", codes.Unavailable, "down", apperrors.ErrServiceUnavailable, true, false, false},
		{"deadline", codes.DeadlineExceeded, "timeout", apperrors.ErrTimeout, true, false, true},
	}

	for _, c := range cases {
		err := classifyError("ListUsers", status.Error(c.code, c.msg))
		if err == nil {
			t.Fatalf("%s: expected error", c.name)
		}
		if !errors.Is(err, c.wantErr) {
			t.Fatalf("%s: expected error %v, got %v", c.name, c.wantErr, err)
		}
		if apperrors.IsRetryable(err) != c.wantRetry {
			t.Fatalf("%s: retryable mismatch", c.name)
		}
		if apperrors.IsUnauthorized(err) != c.wantAuthErr {
			t.Fatalf("%s: unauthorized mismatch", c.name)
		}
		if apperrors.IsTimeout(err) != c.wantTimeout {
			t.Fatalf("%s: timeout mismatch", c.name)
		}
	}
}

func TestClassifyErrorInternalConnection(t *testing.T) {
	err := classifyError("ListUsers", status.Error(codes.Internal, "connection reset by peer"))
	if !errors.Is(err, apperrors.ErrServiceUnavailable) {
		t.Fatalf("expected service unavailable for transient internal error")
	}
	if !apperrors.IsRetryable(err) {
		t.Fatalf("expected retryable for transient internal error")
	}
}

func TestClassifyErrorInternalNonTransient(t *testing.T) {
	err := classifyError("ListUsers", status.Error(codes.Internal, "unexpected failure"))
	if !errors.Is(err, apperrors.ErrInternal) {
		t.Fatalf("expected internal error for non-transient internal error")
	}
	if apperrors.IsRetryable(err) {
		t.Fatalf("expected non-retryable for internal error")
	}
}
