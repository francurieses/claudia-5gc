package store

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// ConnectOptions parameterises ConnectWithRetry.
type ConnectOptions struct {
	// Attempts is the maximum number of connect calls (minimum 1).
	Attempts int
	// Backoff is the wait between failed attempts.
	Backoff time.Duration
	// Connect opens the store; typically a closure over New.
	Connect func(ctx context.Context) (*Store, error)
}

// ConnectWithRetry calls opts.Connect up to opts.Attempts times, waiting
// opts.Backoff between failures and logging each failed attempt. It returns
// promptly with the context error when ctx is cancelled during a wait.
func ConnectWithRetry(ctx context.Context, opts ConnectOptions) (*Store, error) {
	attempts := opts.Attempts
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for n := 1; n <= attempts; n++ {
		s, err := opts.Connect(ctx)
		if err == nil {
			return s, nil
		}
		lastErr = err
		slog.Warn("postgres connect attempt failed", "attempt", fmt.Sprintf("%d/%d", n, attempts), "err", err)
		if n == attempts {
			break
		}
		t := time.NewTimer(opts.Backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, fmt.Errorf("mgmt-portal: connect store: %w", ctx.Err())
		case <-t.C:
		}
	}
	return nil, fmt.Errorf("mgmt-portal: connect store after %d attempts: %w", attempts, lastErr)
}
