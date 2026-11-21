package store

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"errors"

	"github.com/francurieses/claudia-5gc/shared/storewait"
)

// TestStoreWaitUnreachablePostgres proves the OPS-002 startup path for this store:
// against an address where nothing listens, storewait.Open gives up within the
// budget with a retryable (not permanent) error after several attempts, and
// STORE_REQUIRED decides between exit 1 and the in-memory fallback.
func TestStoreWaitUnreachablePostgres(t *testing.T) {
	opts := storewait.Options{
		Store: "Postgres", Interface: "Postgres",
		Policy:         storewait.Policy{Budget: time.Second, Required: true},
		AttemptTimeout: 500 * time.Millisecond,
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     200 * time.Millisecond,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	start := time.Now()
	_, err := storewait.Open(context.Background(), opts, func(ctx context.Context) (any, error) {
		v, err := NewPostgres(ctx, "postgres://u:p@127.0.0.1:1/db?sslmode=disable&connect_timeout=1")
		return v, err
	})
	if err == nil {
		t.Fatal("Open succeeded against an unreachable address")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Open gave up after %s, want within the 1 s budget (+ one attempt)", d)
	}
	if storewait.IsPermanent(err) {
		t.Fatalf("connect failure marked permanent, want retryable: %v", err)
	}
	var we *storewait.Error
	if !errors.As(err, &we) || we.Attempts < 2 {
		t.Fatalf("err = %v, want *storewait.Error with >= 2 attempts", err)
	}
	if fallback, code := storewait.Decide(context.Background(), opts, err); fallback || code != 1 {
		t.Fatalf("required store: Decide = %v, %d; want exit 1", fallback, code)
	}
	opts.Policy.Required = false
	if fallback, code := storewait.Decide(context.Background(), opts, err); !fallback || code != 0 {
		t.Fatalf("optional store: Decide = %v, %d; want in-memory fallback", fallback, code)
	}
}
