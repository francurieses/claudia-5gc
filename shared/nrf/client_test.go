package nrf

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeNRF is a minimal Nnrf_NFManagement stub counting PUT/PATCH requests.
type fakeNRF struct {
	puts        atomic.Int32
	patches     atomic.Int32
	failPuts    int32 // number of initial PUTs answered with 503 (-1 = always)
	patchStatus int   // status for PATCH (0 = 204)
	hbTimer     int   // heartBeatTimer returned on successful PUT
}

func (f *fakeNRF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		n := f.puts.Add(1)
		if f.failPuts < 0 || n <= f.failPuts {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"nfInstanceId":"x","nfType":"UDM","nfStatus":"REGISTERED","heartBeatTimer":`+strconv.Itoa(f.hbTimer)+`}`)
	case http.MethodPatch:
		f.patches.Add(1)
		if f.patchStatus != 0 {
			w.WriteHeader(f.patchStatus)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func testClient(url string) *Client {
	c := New(url, &http.Client{Timeout: time.Second}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.retryInitial = 5 * time.Millisecond
	c.retryMax = 20 * time.Millisecond
	return c
}

func testProfile() *NFProfile {
	return &NFProfile{NFInstanceID: "11111111-1111-1111-1111-111111111111", NFType: "UDM", NFStatus: "REGISTERED"}
}

// waitFor polls cond until true or the deadline expires.
func waitFor(t *testing.T, d time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for: %s", msg)
}

// waitGoroutines asserts every background goroutine of c exits within d.
func waitGoroutines(t *testing.T, c *Client, d time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() { c.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatal("background goroutines did not exit after ctx cancel")
	}
}

func TestRegisterAndStartHeartbeat_RetriesUntilRegistered(t *testing.T) {
	f := &fakeNRF{failPuts: 3}
	srv := httptest.NewServer(f)
	defer srv.Close()

	c := testClient(srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := c.RegisterAndStartHeartbeat(ctx, testProfile(), 10*time.Millisecond)
	if err == nil {
		t.Fatal("expected initial register error")
	}
	if !strings.Contains(err.Error(), "retrying in background") {
		t.Fatalf("error should mention background retry, got %q", err)
	}

	waitFor(t, time.Second, func() bool { return f.puts.Load() >= 4 }, "4 PUT attempts")
	waitFor(t, time.Second, func() bool { return f.patches.Load() >= 2 }, "heartbeats after registration")
	if got := f.puts.Load(); got != 4 {
		t.Fatalf("expected exactly 4 PUTs (3 failed + 1 ok), got %d", got)
	}

	cancel()
	waitGoroutines(t, c, time.Second)
}

func TestRegisterAndStartHeartbeat_RetriesOnConnectionRefused(t *testing.T) {
	// Reserve a port, then free it so the first attempts get ECONNREFUSED.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	c := testClient("http://" + addr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = c.RegisterAndStartHeartbeat(ctx, testProfile(), 10*time.Millisecond)
	if err == nil {
		t.Fatal("expected initial register error (connection refused)")
	}

	// NRF comes up later on the same address.
	f := &fakeNRF{}
	srv := httptest.NewUnstartedServer(f)
	ln2, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("could not rebind reserved port %s: %v", addr, err)
	}
	srv.Listener = ln2
	time.Sleep(30 * time.Millisecond)
	srv.Start()
	defer srv.Close()

	waitFor(t, time.Second, func() bool { return f.puts.Load() >= 1 }, "PUT after NRF came up")
	waitFor(t, time.Second, func() bool { return f.patches.Load() >= 1 }, "heartbeat after registration")

	cancel()
	waitGoroutines(t, c, time.Second)
}

func TestRegisterAndStartHeartbeat_CancelStopsRetry(t *testing.T) {
	f := &fakeNRF{failPuts: -1}
	srv := httptest.NewServer(f)
	defer srv.Close()

	c := testClient(srv.URL)
	ctx, cancel := context.WithCancel(context.Background())

	if err := c.RegisterAndStartHeartbeat(ctx, testProfile(), 10*time.Millisecond); err == nil {
		t.Fatal("expected initial register error")
	}
	waitFor(t, time.Second, func() bool { return f.puts.Load() >= 3 }, "some retries")

	cancel()
	waitGoroutines(t, c, time.Second)

	n := f.puts.Load()
	time.Sleep(50 * time.Millisecond)
	if got := f.puts.Load(); got != n {
		t.Fatalf("retries continued after cancel: %d -> %d", n, got)
	}
	if f.patches.Load() != 0 {
		t.Fatal("heartbeat must not start without a successful registration")
	}
}

func TestRegisterAndStartHeartbeat_SuccessPathUnchanged(t *testing.T) {
	f := &fakeNRF{}
	srv := httptest.NewServer(f)
	defer srv.Close()

	c := testClient(srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := c.RegisterAndStartHeartbeat(ctx, testProfile(), 10*time.Millisecond); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitFor(t, time.Second, func() bool { return f.patches.Load() >= 3 }, "heartbeats")
	if got := f.puts.Load(); got != 1 {
		t.Fatalf("expected a single PUT on success path, got %d", got)
	}

	cancel()
	waitGoroutines(t, c, time.Second)
}

func TestStartHeartbeat_ReRegistersOn404(t *testing.T) {
	f := &fakeNRF{patchStatus: http.StatusNotFound}
	srv := httptest.NewServer(f)
	defer srv.Close()

	c := testClient(srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.StartHeartbeat(ctx, testProfile(), 10*time.Millisecond)
	waitFor(t, time.Second, func() bool { return f.puts.Load() >= 1 }, "re-register PUT after 404 heartbeat")

	cancel()
	waitGoroutines(t, c, time.Second)
}

func TestHeartbeatInterval(t *testing.T) {
	tests := []struct {
		name  string
		timer int
		def   time.Duration
		want  time.Duration
	}{
		{"no NRF timer", 0, 45 * time.Second, 45 * time.Second},
		{"advised shorter", 10, 45 * time.Second, 8 * time.Second},
		{"advised longer", 120, 45 * time.Second, 45 * time.Second},
		{"advised 1s floored (0.8s < 1s)", 1, 45 * time.Second, MinHeartbeatInterval},
		{"advised 2s -> 1.6s", 2, 45 * time.Second, 1600 * time.Millisecond},
		{"timer zero uses default", 0, 30 * time.Second, 30 * time.Second},
		{"negative timer uses default", -5, 30 * time.Second, 30 * time.Second},
		{"zero default clamped", 0, 0, MinHeartbeatInterval},
		{"negative default clamped", 0, -time.Second, MinHeartbeatInterval},
		{"zero default with advised 10s", 10, 0, MinHeartbeatInterval},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := heartbeatInterval(tt.timer, tt.def); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStartHeartbeat_NonPositiveIntervalDoesNotPanic(t *testing.T) {
	f := &fakeNRF{}
	srv := httptest.NewServer(f)
	defer srv.Close()

	for _, iv := range []time.Duration{0, -time.Second} {
		c := testClient(srv.URL)
		ctx, cancel := context.WithCancel(context.Background())
		c.StartHeartbeat(ctx, testProfile(), iv) // time.NewTicker(<=0) would panic
		cancel()
		waitGoroutines(t, c, time.Second)
	}
}

func TestRegisterAndStartHeartbeat_ErrorWrapsCause(t *testing.T) {
	f := &fakeNRF{failPuts: -1}
	srv := httptest.NewServer(f)
	defer srv.Close()

	c := testClient(srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	err := c.RegisterAndStartHeartbeat(ctx, testProfile(), time.Second)
	cancel()
	waitGoroutines(t, c, time.Second)
	if err == nil || errors.Unwrap(err) == nil {
		t.Fatalf("expected wrapped error, got %v", err)
	}
}
