package errors

import (
	"errors"
	"fmt"
)

// Error types for better classification and handling
var (
	// ErrNotFound indicates the requested resource was not found
	ErrNotFound = errors.New("resource not found")

	// ErrUnauthorized indicates authentication failed
	ErrUnauthorized = errors.New("unauthorized")

	// ErrForbidden indicates the operation is not allowed
	ErrForbidden = errors.New("forbidden")

	// ErrInvalidInput indicates invalid input parameters
	ErrInvalidInput = errors.New("invalid input")

	// ErrAlreadyExists indicates the resource already exists
	ErrAlreadyExists = errors.New("resource already exists")

	// ErrServiceUnavailable indicates the Zitadel service is temporarily unavailable
	ErrServiceUnavailable = errors.New("service unavailable")

	// ErrTimeout indicates the operation timed out
	ErrTimeout = errors.New("operation timed out")

	// ErrRateLimited indicates too many requests
	ErrRateLimited = errors.New("rate limited")

	// ErrInternal indicates an internal error
	ErrInternal = errors.New("internal error")
)

// ZitadelError wraps Zitadel API errors with additional context
type ZitadelError struct {
	Operation string // The operation that failed (e.g., "ListUsers", "CreateSession")
	Err       error  // The underlying error
	Retryable bool   // Whether the error is retryable
}

func (e *ZitadelError) Error() string {
	return fmt.Sprintf("zitadel %s: %v", e.Operation, e.Err)
}

func (e *ZitadelError) Unwrap() error {
	return e.Err
}

// NewZitadelError creates a new ZitadelError
func NewZitadelError(operation string, err error, retryable bool) *ZitadelError {
	return &ZitadelError{
		Operation: operation,
		Err:       err,
		Retryable: retryable,
	}
}

// IsRetryable checks if an error is retryable
func IsRetryable(err error) bool {
	var zitErr *ZitadelError
	if errors.As(err, &zitErr) {
		return zitErr.Retryable
	}

	// Check for known retryable errors
	return errors.Is(err, ErrServiceUnavailable) ||
		errors.Is(err, ErrTimeout) ||
		errors.Is(err, ErrRateLimited)
}

// IsNotFound checks if an error indicates a resource was not found
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// IsUnauthorized checks if an error indicates unauthorized access
func IsUnauthorized(err error) bool {
	return errors.Is(err, ErrUnauthorized)
}

// IsTimeout checks if an error indicates a timeout
func IsTimeout(err error) bool {
	return errors.Is(err, ErrTimeout)
}

// IsAlreadyExists checks if an error indicates the resource already exists
func IsAlreadyExists(err error) bool {
	return errors.Is(err, ErrAlreadyExists)
}

// IsForbidden checks if an error indicates a permission failure
func IsForbidden(err error) bool {
	return errors.Is(err, ErrForbidden)
}
