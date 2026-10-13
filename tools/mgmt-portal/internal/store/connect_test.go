package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestConnectWithRetrySucceedsAfterFailures(t *testing.T) {
	calls := 0
	want := &Store{}
	got, err := ConnectWithRetry(context.Background(), ConnectOptions{
		Attempts: 5,
		Backoff:  time.Millisecond,
		Connect: func(context.Context) (*Store, error) {
			calls++
			if calls < 3 {
				return nil, errors.New("no such host")
			}
			return want, nil
		},
	})
	if err != nil || got != want || calls != 3 {
		t.Fatalf("got=%v err=%v calls=%d, want store after 3 calls", got, err, calls)
	}
}

func TestConnectWithRetryExhausted(t *testing.T) {
	calls := 0
	_, err := ConnectWithRetry(context.Background(), ConnectOptions{
		Attempts: 3,
		Backoff:  time.Millisecond,
		Connect: func(context.Context) (*Store, error) {
			calls++
			return nil, errors.New("down")
		},
	})
	if err == nil || calls != 3 {
		t.Fatalf("err=%v calls=%d, want error after 3 calls", err, calls)
	}
}

func TestConnectWithRetryCancelDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	start := time.Now()
	_, err := ConnectWithRetry(ctx, ConnectOptions{
		Attempts: 10,
		Backoff:  time.Hour,
		Connect: func(context.Context) (*Store, error) {
			calls++
			cancel()
			return nil, errors.New("down")
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want context.Canceled", err)
	}
	if calls != 1 || time.Since(start) > time.Second {
		t.Fatalf("calls=%d elapsed=%v, want 1 call and prompt return", calls, time.Since(start))
	}
}
