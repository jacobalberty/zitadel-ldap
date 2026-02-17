package retry

import (
	"context"
	"fmt"
	"math"
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

// Do executes fn with exponential backoff retry logic
// It returns the result of fn or the last error encountered
func Do[T any](ctx context.Context, cfg Config, fn func() (T, error)) (T, error) {
	var result T
	var err error

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
			return result, fmt.Errorf("retry cancelled: %w", ctx.Err())
		}

		// Calculate backoff delay
		delay := calculateBackoff(attempt, cfg)

		// Wait before retrying
		select {
		case <-time.After(delay):
			// Continue to next attempt
		case <-ctx.Done():
			return result, fmt.Errorf("retry cancelled: %w", ctx.Err())
		}
	}

	return result, fmt.Errorf("retry failed after %d attempts: %w", cfg.MaxAttempts, err)
}

// calculateBackoff computes the backoff delay for a given attempt
func calculateBackoff(attempt int, cfg Config) time.Duration {
	delay := float64(cfg.InitialDelay) * math.Pow(cfg.Multiplier, float64(attempt))
	if delay > float64(cfg.MaxDelay) {
		delay = float64(cfg.MaxDelay)
	}
	return time.Duration(delay)
}
