package retry

import (
	"context"
	"errors"
	"testing"
	"time"

	apperrors "github.com/jacobalberty/zitadel-ldap/internal/errors"
)

func TestRetrySuccess(t *testing.T) {
	cfg := Config{
		MaxAttempts:  3,
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
		Multiplier:   2.0,
	}

	attempts := 0
	result, err := Do(context.Background(), cfg, func() (string, error) {
		attempts++
		if attempts < 3 {
			return "", apperrors.NewZitadelError("test", apperrors.ErrServiceUnavailable, true)
		}
		return "success", nil
	})

	if err != nil {
		t.Fatalf("Expected success, got error: %v", err)
	}

	if result != "success" {
		t.Fatalf("Expected 'success', got '%s'", result)
	}

	if attempts != 3 {
		t.Fatalf("Expected 3 attempts, got %d", attempts)
	}
}

func TestRetryNonRetryable(t *testing.T) {
	cfg := DefaultConfig()

	attempts := 0
	_, err := Do(context.Background(), cfg, func() (string, error) {
		attempts++
		return "", apperrors.NewZitadelError("test", apperrors.ErrNotFound, false)
	})

	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if attempts != 1 {
		t.Fatalf("Expected 1 attempt (no retry for non-retryable), got %d", attempts)
	}
}

func TestRetryContextCancellation(t *testing.T) {
	cfg := Config{
		MaxAttempts:  10,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Multiplier:   2.0,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attempts := 0
	done := make(chan error, 1)

	go func() {
		_, err := Do(ctx, cfg, func() (string, error) {
			attempts++
			return "", apperrors.NewZitadelError("test", apperrors.ErrServiceUnavailable, true)
		})
		done <- err
	}()

	// Cancel after a short delay
	time.Sleep(50 * time.Millisecond)
	cancel()

	err := <-done
	if err == nil {
		t.Fatal("Expected error from context cancellation, got nil")
	}

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Expected context.Canceled error, got: %v", err)
	}
}

func TestRetryMaxAttemptsExhausted(t *testing.T) {
	cfg := Config{
		MaxAttempts:  3,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
		Multiplier:   2.0,
	}

	attempts := 0
	_, err := Do(context.Background(), cfg, func() (string, error) {
		attempts++
		return "", apperrors.NewZitadelError("test", apperrors.ErrServiceUnavailable, true)
	})

	if err == nil {
		t.Fatal("Expected error after max attempts, got nil")
	}

	if attempts != 3 {
		t.Fatalf("Expected 3 attempts, got %d", attempts)
	}
}

func TestDoNoRetryConfigRunsOnce(t *testing.T) {
	calls := 0
	_, err := Do(context.Background(), NoRetryConfig(), func() (int, error) {
		calls++
		return 0, apperrors.ErrServiceUnavailable
	})
	if err == nil || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestDoZeroAttemptsStillRunsOnce(t *testing.T) {
	calls := 0
	v, err := Do(context.Background(), Config{}, func() (int, error) {
		calls++
		return 7, nil
	})
	if err != nil || v != 7 || calls != 1 {
		t.Fatalf("v=%d calls=%d err=%v", v, calls, err)
	}
}

func TestDoDeadlinePreservesErrTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	cfg := Config{MaxAttempts: 5, InitialDelay: time.Second, MaxDelay: time.Second, Multiplier: 1}
	_, err := Do(ctx, cfg, func() (int, error) { return 0, apperrors.ErrServiceUnavailable })
	if !apperrors.IsTimeout(err) {
		t.Fatalf("expected ErrTimeout, got %v", err)
	}
}

func TestJitterWithinBounds(t *testing.T) {
	for i := 0; i < 1000; i++ {
		d := jitter(100 * time.Millisecond)
		if d < 50*time.Millisecond || d > 100*time.Millisecond {
			t.Fatalf("jitter out of range: %v", d)
		}
	}
}
