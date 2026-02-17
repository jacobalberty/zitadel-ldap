package zitadel

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	apperrors "github.com/jacobalberty/zitadel-ldap/internal/errors"
)

func TestClassifyError_OK(t *testing.T) {
	err := classifyError("test", nil)
	if err != nil {
		t.Fatalf("expected nil for nil error, got %v", err)
	}

	grpcOK := status.Error(codes.OK, "ok")
	err = classifyError("test", grpcOK)
	if err != nil {
		t.Fatalf("expected nil for OK status, got %v", err)
	}
}

func TestClassifyError_Timeout(t *testing.T) {
	grpcErr := status.Error(codes.DeadlineExceeded, "timeout")
	err := classifyError("test", grpcErr)
	if err == nil {
		t.Fatal("expected error")
	}
	if !apperrors.IsTimeout(err) {
		t.Fatal("expected timeout error")
	}
	if !apperrors.IsRetryable(err) {
		t.Fatal("expected retryable error")
	}
}

func TestClassifyError_Canceled(t *testing.T) {
	grpcErr := status.Error(codes.Canceled, "canceled")
	err := classifyError("test", grpcErr)
	if err == nil {
		t.Fatal("expected error")
	}
	if !apperrors.IsTimeout(err) {
		t.Fatal("expected timeout error")
	}
	if !apperrors.IsRetryable(err) {
		t.Fatal("expected retryable error")
	}
}

func TestClassifyError_NotFound(t *testing.T) {
	grpcErr := status.Error(codes.NotFound, "not found")
	err := classifyError("test", grpcErr)
	if err == nil {
		t.Fatal("expected error")
	}
	if !apperrors.IsNotFound(err) {
		t.Fatal("expected not found error")
	}
	if apperrors.IsRetryable(err) {
		t.Fatal("expected non-retryable error")
	}
}

func TestClassifyError_Unauthenticated(t *testing.T) {
	grpcErr := status.Error(codes.Unauthenticated, "unauthenticated")
	err := classifyError("test", grpcErr)
	if err == nil {
		t.Fatal("expected error")
	}
	if !apperrors.IsUnauthorized(err) {
		t.Fatal("expected unauthorized error")
	}
	if apperrors.IsRetryable(err) {
		t.Fatal("expected non-retryable error")
	}
}

func TestClassifyError_PermissionDenied(t *testing.T) {
	grpcErr := status.Error(codes.PermissionDenied, "permission denied")
	err := classifyError("test", grpcErr)
	if err == nil {
		t.Fatal("expected error")
	}
	if apperrors.IsRetryable(err) {
		t.Fatal("expected non-retryable error")
	}
}

func TestClassifyError_InvalidArgument(t *testing.T) {
	grpcErr := status.Error(codes.InvalidArgument, "invalid")
	err := classifyError("test", grpcErr)
	if err == nil {
		t.Fatal("expected error")
	}
	if apperrors.IsRetryable(err) {
		t.Fatal("expected non-retryable error")
	}
}

func TestClassifyError_FailedPrecondition(t *testing.T) {
	grpcErr := status.Error(codes.FailedPrecondition, "precondition failed")
	err := classifyError("test", grpcErr)
	if err == nil {
		t.Fatal("expected error")
	}
	if apperrors.IsRetryable(err) {
		t.Fatal("expected non-retryable error")
	}
}

func TestClassifyError_OutOfRange(t *testing.T) {
	grpcErr := status.Error(codes.OutOfRange, "out of range")
	err := classifyError("test", grpcErr)
	if err == nil {
		t.Fatal("expected error")
	}
	if apperrors.IsRetryable(err) {
		t.Fatal("expected non-retryable error")
	}
}

func TestClassifyError_ResourceExhausted(t *testing.T) {
	grpcErr := status.Error(codes.ResourceExhausted, "rate limited")
	err := classifyError("test", grpcErr)
	if err == nil {
		t.Fatal("expected error")
	}
	if !apperrors.IsRetryable(err) {
		t.Fatal("expected retryable error")
	}
}

func TestClassifyError_Unavailable(t *testing.T) {
	grpcErr := status.Error(codes.Unavailable, "unavailable")
	err := classifyError("test", grpcErr)
	if err == nil {
		t.Fatal("expected error")
	}
	if !apperrors.IsRetryable(err) {
		t.Fatal("expected retryable error")
	}
}

func TestClassifyError_Internal_WithConnectionKeyword(t *testing.T) {
	grpcErr := status.Error(codes.Internal, "connection reset")
	err := classifyError("test", grpcErr)
	if err == nil {
		t.Fatal("expected error")
	}
	if !apperrors.IsRetryable(err) {
		t.Fatal("expected retryable error for connection issue")
	}
}

func TestClassifyError_Internal_WithTimeoutKeyword(t *testing.T) {
	grpcErr := status.Error(codes.Internal, "timeout occurred")
	err := classifyError("test", grpcErr)
	if err == nil {
		t.Fatal("expected error")
	}
	if !apperrors.IsRetryable(err) {
		t.Fatal("expected retryable error for timeout issue")
	}
}

func TestClassifyError_Internal_WithTemporaryKeyword(t *testing.T) {
	grpcErr := status.Error(codes.Internal, "temporary failure")
	err := classifyError("test", grpcErr)
	if err == nil {
		t.Fatal("expected error")
	}
	if !apperrors.IsRetryable(err) {
		t.Fatal("expected retryable error for temporary issue")
	}
}

func TestClassifyError_Internal_NonTransient(t *testing.T) {
	grpcErr := status.Error(codes.Internal, "database corruption")
	err := classifyError("test", grpcErr)
	if err == nil {
		t.Fatal("expected error")
	}
	if apperrors.IsRetryable(err) {
		t.Fatal("expected non-retryable error for non-transient internal issue")
	}
}

func TestClassifyError_Unknown_WithConnectionKeyword(t *testing.T) {
	grpcErr := status.Error(codes.Unknown, "connection error")
	err := classifyError("test", grpcErr)
	if err == nil {
		t.Fatal("expected error")
	}
	if !apperrors.IsRetryable(err) {
		t.Fatal("expected retryable error for connection issue")
	}
}

func TestClassifyError_DataLoss_WithTemporary(t *testing.T) {
	grpcErr := status.Error(codes.DataLoss, "temporary data loss")
	err := classifyError("test", grpcErr)
	if err == nil {
		t.Fatal("expected error")
	}
	if !apperrors.IsRetryable(err) {
		t.Fatal("expected retryable error")
	}
}

func TestClassifyError_DataLoss_Permanent(t *testing.T) {
	grpcErr := status.Error(codes.DataLoss, "permanent data loss")
	err := classifyError("test", grpcErr)
	if err == nil {
		t.Fatal("expected error")
	}
	if apperrors.IsRetryable(err) {
		t.Fatal("expected non-retryable error")
	}
}

func TestClassifyError_UnknownCode(t *testing.T) {
	// Use a less common code
	grpcErr := status.Error(codes.Aborted, "aborted")
	err := classifyError("test", grpcErr)
	if err == nil {
		t.Fatal("expected error")
	}
	if apperrors.IsRetryable(err) {
		t.Fatal("expected non-retryable error for unknown code")
	}
}

func TestClassifyError_NonGRPCError(t *testing.T) {
	nonGrpcErr := status.Error(codes.Internal, "test")
	// Wrap it to make it not a gRPC error
	wrapped := apperrors.NewZitadelError("test", nonGrpcErr, false)
	err := classifyError("test", wrapped)
	if err == nil {
		t.Fatal("expected error")
	}
	if apperrors.IsRetryable(err) {
		t.Fatal("expected non-retryable error for non-gRPC error")
	}
}

func TestClassifyLoginError_Unauthorized(t *testing.T) {
	grpcErr := status.Error(codes.Unauthenticated, "invalid credentials")
	err := classifyLoginError(grpcErr)
	if err == nil {
		t.Fatal("expected error")
	}
	if !apperrors.IsUnauthorized(err) {
		t.Fatal("expected unauthorized error")
	}
	if apperrors.IsRetryable(err) {
		t.Fatal("expected non-retryable error for auth failure")
	}
}

func TestClassifyLoginError_Unavailable(t *testing.T) {
	grpcErr := status.Error(codes.Unavailable, "service unavailable")
	err := classifyLoginError(grpcErr)
	if err == nil {
		t.Fatal("expected error")
	}
	if !apperrors.IsRetryable(err) {
		t.Fatal("expected retryable error for unavailable service")
	}
}
