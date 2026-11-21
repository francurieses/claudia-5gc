// Package storewait waits for an NF's backing store (PostgreSQL, Redis) at
// startup and decides what the NF does when the store stays unreachable.
//
// Without it an NF tried its store once and, on failure, ran in-memory for the
// rest of its life. On a Docker daemon restart the NFs and the data tier start
// in parallel (depends_on is not applied), so one lost race silently disabled
// persistence until the NF was restarted by hand (OPS-002).
//
// Open retries a store constructor with backoff for a bounded time. A store
// that answers on the first attempt costs no delay and no extra log line.
// Decide then turns a final failure into either the NF's existing in-memory
// fallback (STORE_REQUIRED=false) or a loud exit, so the container restart
// policy retries the whole NF with clean state. There is no hot reconnect:
// state created in memory before a swap would never reach the store.
//
// This package carries no 3GPP behaviour; it changes no message on any
// interface.
package storewait

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment variables read by PolicyFromEnv. Empty means "built-in default".
const (
	// EnvTimeout is the total time Open keeps retrying, as a Go duration
	// ("60s", "2m"). "0" means a single attempt (the pre-OPS-002 timing).
	EnvTimeout = "STORE_CONNECT_TIMEOUT"
	// EnvRequired is "true" (default) to exit when the store stays
	// unreachable, or "false" to keep the NF's in-memory fallback.
	EnvRequired = "STORE_REQUIRED"
)

// Defaults. Operational values, not 3GPP timers.
const (
	// DefaultBudget covers the docker-compose postgres healthcheck
	// (start_period 10 s + 10 retries of 5 s) with margin.
	DefaultBudget = 60 * time.Second
	// DefaultAttemptTimeout bounds one attempt, including the migrations a
	// PostgreSQL constructor runs after its ping.
	DefaultAttemptTimeout = 10 * time.Second
	// DefaultInitialBackoff is the wait after the first failed attempt.
	DefaultInitialBackoff = time.Second
	// DefaultMaxBackoff caps the doubling backoff.
	DefaultMaxBackoff = 5 * time.Second
)

// logSpecRef is the spec_ref value of every log line from this package.
const logSpecRef = "N/A (operational)"

// Policy is the operator's choice for one NF process.
type Policy struct {
	// Budget is the total retry time; 0 means one attempt.
	Budget time.Duration
	// Required makes Decide exit instead of falling back to memory.
	Required bool
}

// DefaultPolicy is the policy used when both environment variables are empty.
func DefaultPolicy() Policy { return Policy{Budget: DefaultBudget, Required: true} }

// PolicyFromEnv reads STORE_CONNECT_TIMEOUT and STORE_REQUIRED. An invalid
// value is an error: the caller treats it like any other startup config error.
func PolicyFromEnv() (Policy, error) {
	return ParsePolicy(os.Getenv(EnvTimeout), os.Getenv(EnvRequired))
}

// ParsePolicy parses the two environment values; empty strings mean defaults.
func ParsePolicy(timeout, required string) (Policy, error) {
	p := DefaultPolicy()
	if t := strings.TrimSpace(timeout); t != "" {
		if t == "0" {
			p.Budget = 0
		} else {
			d, err := time.ParseDuration(t)
			if err != nil {
				return Policy{}, fmt.Errorf("storewait: %s=%q: %w", EnvTimeout, timeout, err)
			}
			if d < 0 {
				return Policy{}, fmt.Errorf("storewait: %s=%q: must not be negative", EnvTimeout, timeout)
			}
			p.Budget = d
		}
	}
	if r := strings.TrimSpace(required); r != "" {
		b, err := strconv.ParseBool(r)
		if err != nil {
			return Policy{}, fmt.Errorf("storewait: %s=%q: want true or false", EnvRequired, required)
		}
		p.Required = b
	}
	return p, nil
}

// Options configures one Open call.
type Options struct {
	// Store names the store in log lines and errors, e.g. "postgres".
	Store string
	// Interface is the mandatory log field value, e.g. "Postgres" or "Redis".
	Interface string
	// Policy holds the retry budget and the exit choice.
	Policy Policy
	// AttemptTimeout, InitialBackoff and MaxBackoff default to the package
	// constants when zero.
	AttemptTimeout time.Duration
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	// Logger receives one WARN per failed attempt that will be retried. Nil
	// means slog.Default().
	Logger *slog.Logger
}

func (o Options) withDefaults() Options {
	if o.AttemptTimeout <= 0 {
		o.AttemptTimeout = DefaultAttemptTimeout
	}
	if o.InitialBackoff <= 0 {
		o.InitialBackoff = DefaultInitialBackoff
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = DefaultMaxBackoff
	}
	if o.MaxBackoff < o.InitialBackoff {
		o.MaxBackoff = o.InitialBackoff
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return o
}

// permanentError marks an error that a retry cannot fix.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// Permanent marks err as not retryable (for example a migration checksum
// mismatch). Open returns it after the attempt that produced it. Nil stays nil.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &permanentError{err: err}
}

// IsPermanent reports whether err, or an error it wraps, was marked Permanent.
func IsPermanent(err error) bool {
	var p *permanentError
	return errors.As(err, &p)
}

// Error is the error Open returns when it gives up. It wraps the last error
// of the store constructor, or the context error when ctx ended.
type Error struct {
	Store    string
	Attempts int
	Elapsed  time.Duration
	Err      error
}

func (e *Error) Error() string {
	return fmt.Sprintf("storewait: %s unavailable after %d attempt(s) in %s: %v",
		e.Store, e.Attempts, e.Elapsed.Round(time.Millisecond), e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// Open calls open until it succeeds, it returns a Permanent error, ctx ends or
// the policy budget is spent. Each attempt gets its own context bounded by
// AttemptTimeout, and Open stops waiting for an attempt when that context ends
// even if open ignores it (pgx keeps dialling after a cancel; shared/aka's
// Redis constructor takes no context at all). The first attempt runs at once,
// so a reachable store adds no delay and no log line.
func Open[T any](ctx context.Context, o Options, open func(context.Context) (T, error)) (T, error) {
	o = o.withDefaults()
	var zero T
	start := time.Now()
	backoff := o.InitialBackoff
	for attempt := 1; ; attempt++ {
		v, err := attemptOnce(ctx, o.AttemptTimeout, open)
		if err == nil {
			if attempt > 1 {
				o.Logger.Info("store connected after retry", "procedure", "StoreConnect",
					"interface", o.Interface, "direction", "OUT", "result", "OK",
					"store", o.Store, "attempts", attempt,
					"duration_ms", time.Since(start).Milliseconds(), "spec_ref", logSpecRef)
			}
			return v, nil
		}
		fail := func(cause error) (T, error) {
			return zero, &Error{Store: o.Store, Attempts: attempt, Elapsed: time.Since(start), Err: cause}
		}
		if IsPermanent(err) {
			return fail(err)
		}
		if ctx.Err() != nil {
			return fail(ctx.Err())
		}
		remaining := o.Policy.Budget - time.Since(start)
		if remaining <= 0 {
			return fail(err)
		}
		wait := min(backoff, remaining)
		o.Logger.Warn("store connect attempt failed, retrying", "procedure", "StoreConnect",
			"interface", o.Interface, "direction", "OUT", "result", "FAILURE",
			"store", o.Store, "attempt", attempt, "retry_in_ms", wait.Milliseconds(),
			"budget_ms", o.Policy.Budget.Milliseconds(), "cause", err.Error(), "spec_ref", logSpecRef)
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return fail(ctx.Err())
		case <-t.C:
		}
		backoff = min(2*backoff, o.MaxBackoff)
	}
}

// result carries one attempt's outcome from its goroutine.
type result[T any] struct {
	v   T
	err error
}

// attemptOnce runs open in a goroutine and returns when it finishes or when
// the attempt context ends, whichever is first. An abandoned attempt that
// still succeeds later has its store closed in the background, so giving up
// on a slow attempt never leaks a connected pool or client.
func attemptOnce[T any](ctx context.Context, timeout time.Duration, open func(context.Context) (T, error)) (T, error) {
	actx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ch := make(chan result[T], 1)
	go func() {
		v, err := open(actx)
		ch <- result[T]{v: v, err: err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-actx.Done():
		go func() {
			if r := <-ch; r.err == nil {
				closeQuietly(r.v)
			}
		}()
		var zero T
		return zero, actx.Err()
	}
}

// closeQuietly closes v if it has a Close method of either common shape.
func closeQuietly(v any) {
	switch c := v.(type) {
	case interface{ Close() error }:
		_ = c.Close()
	case interface{ Close() }:
		c.Close()
	}
}

// Decide tells an NF what to do after Open returned err. fallback=true means
// keep the NF's existing in-memory fallback (and its existing WARN line).
// fallback=false means the NF must stop now with os.Exit(exitCode): 0 when ctx
// ended (SIGTERM during the wait), 1 when the store is required. Decide logs
// the exit cases itself; it logs nothing for the fallback case.
func Decide(ctx context.Context, o Options, err error) (fallback bool, exitCode int) {
	o = o.withDefaults()
	attempts, elapsed := 0, time.Duration(0)
	var we *Error
	if errors.As(err, &we) {
		attempts, elapsed = we.Attempts, we.Elapsed
	}
	if ctx.Err() != nil {
		o.Logger.Info("startup cancelled while waiting for store", "procedure", "StoreConnect",
			"interface", o.Interface, "direction", "OUT", "store", o.Store,
			"attempts", attempts, "duration_ms", elapsed.Milliseconds(), "spec_ref", logSpecRef)
		return false, 0
	}
	if !o.Policy.Required {
		return true, 0
	}
	msg := fmt.Sprintf("%s unavailable after %s, exiting so the container restart policy retries",
		o.Store, elapsed.Round(time.Second))
	if IsPermanent(err) {
		msg = fmt.Sprintf("%s setup failed (not retryable), exiting", o.Store)
	}
	o.Logger.Error(msg, "procedure", "StoreConnect", "interface", o.Interface, "direction", "OUT",
		"result", "FAILURE", "store", o.Store, "attempts", attempts,
		"duration_ms", elapsed.Milliseconds(), "cause", err.Error(),
		"hint", EnvRequired+"=false keeps the in-memory fallback", "spec_ref", logSpecRef)
	return false, 1
}
