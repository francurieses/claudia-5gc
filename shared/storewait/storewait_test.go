package storewait

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recorder is a slog.Handler that keeps every record for assertions.
type recorder struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (r *recorder) Enabled(context.Context, slog.Level) bool { return true }
func (r *recorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recs = append(r.recs, rec)
	return nil
}
func (r *recorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *recorder) WithGroup(string) slog.Handler      { return r }

func (r *recorder) count(level slog.Level) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, rec := range r.recs {
		if rec.Level == level {
			n++
		}
	}
	return n
}

func (r *recorder) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.recs)
}

// fast returns options with millisecond backoffs and a capturing logger.
func fast(budget time.Duration) (Options, *recorder) {
	rec := &recorder{}
	return Options{
		Store: "postgres", Interface: "Postgres",
		Policy:         Policy{Budget: budget, Required: true},
		AttemptTimeout: 200 * time.Millisecond,
		InitialBackoff: 5 * time.Millisecond,
		MaxBackoff:     20 * time.Millisecond,
		Logger:         slog.New(rec),
	}, rec
}

var errDown = errors.New("connection refused")

func TestOpenFirstAttemptSucceedsWithoutDelayOrLog(t *testing.T) {
	o, rec := fast(time.Minute)
	o.InitialBackoff = time.Hour // would hang if Open ever slept
	start := time.Now()
	v, err := Open(context.Background(), o, func(context.Context) (int, error) { return 7, nil })
	if err != nil || v != 7 {
		t.Fatalf("Open = %d, %v; want 7, nil", v, err)
	}
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("first-try success took %s, want no delay", d)
	}
	if n := rec.total(); n != 0 {
		t.Fatalf("logged %d records on first-try success, want 0", n)
	}
}

func TestOpenRetriesTransientErrorsThenSucceeds(t *testing.T) {
	o, rec := fast(time.Minute)
	var calls atomic.Int32
	v, err := Open(context.Background(), o, func(context.Context) (string, error) {
		if calls.Add(1) < 3 {
			return "", errDown
		}
		return "ok", nil
	})
	if err != nil || v != "ok" {
		t.Fatalf("Open = %q, %v; want ok, nil", v, err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("calls = %d, want 3", got)
	}
	if w, i := rec.count(slog.LevelWarn), rec.count(slog.LevelInfo); w != 2 || i != 1 {
		t.Fatalf("logs: %d WARN, %d INFO; want 2 WARN (one per retry) and 1 INFO (connected after retry)", w, i)
	}
}

func TestOpenGivesUpWhenBudgetIsSpent(t *testing.T) {
	o, _ := fast(60 * time.Millisecond)
	start := time.Now()
	_, err := Open(context.Background(), o, func(context.Context) (int, error) { return 0, errDown })
	if err == nil {
		t.Fatal("Open succeeded, want error")
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("gave up after %s, want about the 60 ms budget", d)
	}
	var we *Error
	if !errors.As(err, &we) || we.Attempts < 2 || we.Store != "postgres" {
		t.Fatalf("err = %#v, want *Error with >= 2 attempts", err)
	}
	if !errors.Is(err, errDown) {
		t.Fatalf("err %v does not wrap the last constructor error", err)
	}
}

func TestOpenZeroBudgetIsSingleAttempt(t *testing.T) {
	o, rec := fast(0)
	var calls atomic.Int32
	_, err := Open(context.Background(), o, func(context.Context) (int, error) {
		calls.Add(1)
		return 0, errDown
	})
	if err == nil || calls.Load() != 1 {
		t.Fatalf("calls = %d, err = %v; want exactly 1 call and an error", calls.Load(), err)
	}
	if n := rec.total(); n != 0 {
		t.Fatalf("logged %d records with a zero budget, want 0 (pre-OPS-002 timing)", n)
	}
}

func TestOpenDoesNotRetryPermanentErrors(t *testing.T) {
	o, _ := fast(time.Minute)
	var calls atomic.Int32
	migrateErr := errors.New("checksum mismatch")
	_, err := Open(context.Background(), o, func(context.Context) (int, error) {
		calls.Add(1)
		return 0, Permanent(migrateErr)
	})
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1 (permanent errors are not retried)", calls.Load())
	}
	if !IsPermanent(err) || !errors.Is(err, migrateErr) {
		t.Fatalf("err = %v, want a permanent error wrapping the cause", err)
	}
}

func TestOpenReturnsPromptlyWhenContextIsCancelled(t *testing.T) {
	o, _ := fast(time.Hour)
	o.InitialBackoff, o.MaxBackoff = 10*time.Second, 10*time.Second
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	start := time.Now()
	_, err := Open(ctx, o, func(context.Context) (int, error) { return 0, errDown })
	if d := time.Since(start); d > 120*time.Millisecond {
		t.Fatalf("Open returned %s after cancel, want < 100 ms", d-20*time.Millisecond)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestOpenBoundsEachAttempt(t *testing.T) {
	o, _ := fast(0)
	o.AttemptTimeout = 30 * time.Millisecond
	start := time.Now()
	_, err := Open(context.Background(), o, func(ctx context.Context) (int, error) {
		<-ctx.Done() // a store that never answers
		return 0, ctx.Err()
	})
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("attempt took %s, want about AttemptTimeout", d)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
}

// ignoresCtx simulates a constructor that does not honour its context (pgx
// still dialling after a cancel, shared/aka's ctx-less Redis constructor).
func ignoresCtx[T any](d time.Duration, v T, err error) func(context.Context) (T, error) {
	return func(context.Context) (T, error) {
		time.Sleep(d)
		return v, err
	}
}

func TestOpenBoundsAttemptsThatIgnoreTheirContext(t *testing.T) {
	o, _ := fast(0)
	o.AttemptTimeout = 30 * time.Millisecond
	start := time.Now()
	_, err := Open(context.Background(), o, ignoresCtx(time.Second, 0, errDown))
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("attempt took %s, want about AttemptTimeout even though open ignores ctx", d)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
}

func TestOpenCancelInterruptsABlockedAttempt(t *testing.T) {
	o, _ := fast(time.Hour)
	o.AttemptTimeout = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel) // SIGTERM while a dial hangs
	start := time.Now()
	_, err := Open(ctx, o, ignoresCtx(5*time.Second, 0, errDown))
	if d := time.Since(start); d > 120*time.Millisecond {
		t.Fatalf("Open returned %s after start, want promptly after the 20 ms cancel", d)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// closer counts Close calls; both Close shapes are covered.
type closer struct{ n *atomic.Int32 }

func (c closer) Close() error { c.n.Add(1); return nil }

type closerNoErr struct{ n *atomic.Int32 }

func (c closerNoErr) Close() { c.n.Add(1) }

func TestOpenClosesAnAbandonedAttemptThatSucceedsLate(t *testing.T) {
	for _, tc := range []struct {
		name string
		mk   func(*atomic.Int32) any
	}{
		{"Close() error", func(n *atomic.Int32) any { return closer{n} }},
		{"Close()", func(n *atomic.Int32) any { return closerNoErr{n} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var closed atomic.Int32
			o, _ := fast(0)
			o.AttemptTimeout = 20 * time.Millisecond
			_, err := Open(context.Background(), o, ignoresCtx(60*time.Millisecond, tc.mk(&closed), nil))
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("err = %v, want DeadlineExceeded", err)
			}
			deadline := time.Now().Add(time.Second)
			for closed.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if closed.Load() != 1 {
				t.Fatalf("late success closed %d times, want 1 (no leaked pool/client)", closed.Load())
			}
		})
	}
}

func TestParsePolicy(t *testing.T) {
	tests := []struct {
		timeout, required string
		want              Policy
		wantErr           bool
	}{
		{"", "", Policy{Budget: DefaultBudget, Required: true}, false},
		{"  ", " ", Policy{Budget: DefaultBudget, Required: true}, false},
		{"0", "", Policy{Budget: 0, Required: true}, false},
		{"90s", "false", Policy{Budget: 90 * time.Second, Required: false}, false},
		{"2m", "TRUE", Policy{Budget: 2 * time.Minute, Required: true}, false},
		{"abc", "", Policy{}, true},
		{"-5s", "", Policy{}, true},
		{"60", "", Policy{}, true}, // a bare number has no unit
		{"", "maybe", Policy{}, true},
	}
	for _, tc := range tests {
		got, err := ParsePolicy(tc.timeout, tc.required)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParsePolicy(%q, %q) err = %v, wantErr %v", tc.timeout, tc.required, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("ParsePolicy(%q, %q) = %+v, want %+v", tc.timeout, tc.required, got, tc.want)
		}
	}
}

func TestPolicyFromEnv(t *testing.T) {
	t.Setenv(EnvTimeout, "15s")
	t.Setenv(EnvRequired, "false")
	p, err := PolicyFromEnv()
	if err != nil || p != (Policy{Budget: 15 * time.Second, Required: false}) {
		t.Fatalf("PolicyFromEnv = %+v, %v", p, err)
	}
}

func TestDecide(t *testing.T) {
	failure := &Error{Store: "redis", Attempts: 4, Elapsed: time.Second, Err: errDown}

	t.Run("required store exits 1 and logs one ERROR", func(t *testing.T) {
		o, rec := fast(time.Second)
		fallback, code := Decide(context.Background(), o, failure)
		if fallback || code != 1 {
			t.Fatalf("Decide = %v, %d; want false, 1", fallback, code)
		}
		if rec.count(slog.LevelError) != 1 {
			t.Fatalf("want exactly one ERROR record, got %d", rec.count(slog.LevelError))
		}
	})
	t.Run("optional store falls back silently", func(t *testing.T) {
		o, rec := fast(time.Second)
		o.Policy.Required = false
		fallback, code := Decide(context.Background(), o, failure)
		if !fallback || code != 0 {
			t.Fatalf("Decide = %v, %d; want true, 0", fallback, code)
		}
		if rec.total() != 0 {
			t.Fatalf("logged %d records; the NF logs its own fallback WARN", rec.total())
		}
	})
	t.Run("cancelled startup exits 0", func(t *testing.T) {
		o, rec := fast(time.Second)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		fallback, code := Decide(ctx, o, failure)
		if fallback || code != 0 {
			t.Fatalf("Decide = %v, %d; want false, 0", fallback, code)
		}
		if rec.count(slog.LevelInfo) != 1 || rec.count(slog.LevelError) != 0 {
			t.Fatal("want one INFO and no ERROR for a cancelled startup")
		}
	})
	t.Run("permanent error exits 1 even before the budget", func(t *testing.T) {
		o, _ := fast(time.Hour)
		fallback, code := Decide(context.Background(), o, Permanent(errDown))
		if fallback || code != 1 {
			t.Fatalf("Decide = %v, %d; want false, 1", fallback, code)
		}
	})
}
