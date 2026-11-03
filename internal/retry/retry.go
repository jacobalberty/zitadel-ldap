package retry

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"time"

	apperrors "github.com/jacobalberty/zitadel-ldap/internal/errors"
)

// Config holds retry configuration
type Config struct {
	// MaxAttempts is the maximum number of retry attempts
	MaxAttempts int
	// InitialDelay is the initial delay before the first retry
	InitialDelay time.Duration
	// MaxDelay is the maximum delay between retries
	MaxDelay time.Duration
	// Multiplier is the backoff multiplier
	Multiplier float64
}

// DefaultConfig returns a sensible default retry configuration
func DefaultConfig() Config {
	return Config{
		MaxAttempts:  3,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     5 * time.Second,
		Multiplier:   2.0,
	}
}

// NoRetryConfig runs the call exactly once. Use it for non-idempotent
// operations (create, set password, create session) where a retry after a
// lost response could duplicate or wrongly fail the operation.
func NoRetryConfig() Config {
	return Config{MaxAttempts: 1}
}

// Do executes fn with exponential backoff retry logic
// It returns the result of fn or the last error encountered
func Do[T any](ctx context.Context, cfg Config, fn func() (T, error)) (T, error) {
	var result T
	var err error

	if cfg.MaxAttempts < 1 {
		cfg.MaxAttempts = 1
	}

	for attempt := 0; attempt < cfg.MaxAttempts; attempt++ {
		result, err = fn()
		if err == nil {
			return result, nil
		}

		// Check if error is retryable
		if !apperrors.IsRetryable(err) {
			return result, err
		}

		// Don't retry if this was the last attempt
		if attempt == cfg.MaxAttempts-1 {
			break
		}

		// Check if context is cancelled
		if ctx.Err() != nil {
			return result, cancelErr(ctx, err)
		}

		// Calculate backoff delay
		delay := jitter(calculateBackoff(attempt, cfg))

		// Wait before retrying
		select {
		case <-time.After(delay):
			// Continue to next attempt
		case <-ctx.Done():
			return result, cancelErr(ctx, err)
		}
	}

	if cfg.MaxAttempts == 1 {
		return result, err
	}
	return result, fmt.Errorf("retry failed after %d attempts: %w", cfg.MaxAttempts, err)
}

// cancelErr reports a cancelled/expired context while keeping the last
// attempt's error and mapping a deadline to ErrTimeout so callers (e.g. Bind)
// can answer "busy" via apperrors.IsTimeout.
func cancelErr(ctx context.Context, last error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("retry cancelled: %w (last error: %v)", apperrors.ErrTimeout, last)
	}
	return fmt.Errorf("retry cancelled: %w (last error: %v)", ctx.Err(), last)
}

// calculateBackoff computes the backoff delay for a given attempt
func calculateBackoff(attempt int, cfg Config) time.Duration {
	delay := float64(cfg.InitialDelay) * math.Pow(cfg.Multiplier, float64(attempt))
	if delay > float64(cfg.MaxDelay) {
		delay = float64(cfg.MaxDelay)
	}
	return time.Duration(delay)
}

// jitter applies "equal jitter": a random delay in [d/2, d] so concurrent
// callers do not retry in lockstep.
func jitter(d time.Duration) time.Duration {
	if d <= 1 {
		return d
	}
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(d-half)+1))
}
