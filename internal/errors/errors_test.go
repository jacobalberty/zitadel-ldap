package errors

import (
	"errors"
	"strings"
	"testing"
)

func TestNewZitadelErrorAndUnwrap(t *testing.T) {
	baseErr := errors.New("boom")
	zerr := NewZitadelError("ListUsers", baseErr, true)

	if !strings.Contains(zerr.Error(), "ListUsers") {
		t.Fatalf("expected error message to contain operation name")
	}

	if !errors.Is(zerr, baseErr) {
		t.Fatalf("expected wrapped error to be detectable")
	}

	if !IsRetryable(zerr) {
		t.Fatalf("expected retryable error")
	}
}

func TestIsRetryableSentinels(t *testing.T) {
	cases := []struct {
		err   error
		label string
	}{
		{ErrServiceUnavailable, "service unavailable"},
		{ErrTimeout, "timeout"},
		{ErrRateLimited, "rate limited"},
	}

	for _, c := range cases {
		if !IsRetryable(c.err) {
			t.Fatalf("expected retryable for %s", c.label)
		}
	}
}

func TestErrorHelpers(t *testing.T) {
	if !IsNotFound(ErrNotFound) {
		t.Fatalf("expected ErrNotFound to be detected")
	}
	if !IsUnauthorized(ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized to be detected")
	}
	if !IsTimeout(ErrTimeout) {
		t.Fatalf("expected ErrTimeout to be detected")
	}
}
