package logging

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeSched records the scheduled revert so the test fires it on demand.
type fakeSched struct {
	fn       func()
	ttl      time.Duration
	canceled bool
}

func (f *fakeSched) schedule(d time.Duration, fn func()) func() {
	f.ttl, f.fn = d, fn
	return func() { f.canceled = true }
}

func newTestAdmin(t *testing.T, base slog.Level) (*LevelAdmin, *slog.LevelVar, *fakeSched) {
	t.Helper()
	lv := &slog.LevelVar{}
	lv.Set(base)
	fs := &fakeSched{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	return newLevelAdmin(lv, logger, fs.schedule, func() time.Time { return now }), lv, fs
}

func put(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/log-level", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]slog.Level{"": slog.LevelInfo, "DEBUG": slog.LevelDebug,
		"warning": slog.LevelWarn, "error": slog.LevelError} {
		got, err := ParseLevel(in)
		if err != nil || got != want {
			t.Errorf("%q: got (%v,%v), want %v", in, got, err, want)
		}
	}
	if _, err := ParseLevel("trace"); err == nil {
		t.Error("trace is not a supported level")
	}
}

func TestEnvSetsStartupLevel(t *testing.T) {
	if lv := newLevelVar("debug"); lv.Level() != slog.LevelDebug {
		t.Errorf("LOG_LEVEL=debug: got %v", lv.Level())
	}
	if lv := newLevelVar("nonsense"); lv.Level() != slog.LevelInfo {
		t.Errorf("bad LOG_LEVEL must fall back to info, got %v", lv.Level())
	}
}

func TestPutChangesLevelAndRevertsAfterTTL(t *testing.T) {
	a, lv, fs := newTestAdmin(t, slog.LevelInfo)
	if rec := put(t, a, `{"level":"debug","ttl_s":300}`); rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if lv.Level() != slog.LevelDebug {
		t.Fatalf("level after PUT: %v", lv.Level())
	}
	if fs.ttl != 300*time.Second {
		t.Errorf("TTL scheduled: %v", fs.ttl)
	}
	fs.fn() // the TTL ends
	if lv.Level() != slog.LevelInfo {
		t.Errorf("level after TTL: %v, want info (base)", lv.Level())
	}
}

func TestSecondPutCancelsFirstRevert(t *testing.T) {
	a, _, fs := newTestAdmin(t, slog.LevelInfo)
	put(t, a, `{"level":"debug","ttl_s":60}`)
	first := fs.canceled
	put(t, a, `{"level":"warn","ttl_s":120}`)
	if first || !fs.canceled {
		t.Errorf("a new change must cancel the previous timer")
	}
}

func TestDefaultTTLIs900s(t *testing.T) {
	a, _, fs := newTestAdmin(t, slog.LevelInfo)
	put(t, a, `{"level":"debug"}`)
	if fs.ttl != DefaultLevelTTL {
		t.Errorf("default TTL: %v, want %v", fs.ttl, DefaultLevelTTL)
	}
}

func TestRejectsBadInput(t *testing.T) {
	a, lv, _ := newTestAdmin(t, slog.LevelInfo)
	for _, body := range []string{`{"level":"trace"}`, `{}`, `{"level":"debug","ttl_s":3601}`,
		`{"level":"debug","ttl_s":-5}`, `not json`} {
		if rec := put(t, a, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", body, rec.Code)
		}
	}
	if lv.Level() != slog.LevelInfo {
		t.Errorf("a rejected PUT must not change the level: %v", lv.Level())
	}
}

func TestGetReportsState(t *testing.T) {
	a, _, _ := newTestAdmin(t, slog.LevelWarn)
	put(t, a, `{"level":"debug","ttl_s":200}`)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/v1/log-level", nil))
	var st map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &st)
	if st["level"] != "DEBUG" || st["base_level"] != "WARN" || st["revert_in_s"] != float64(200) {
		t.Errorf("state: %v", st)
	}
}

func TestOtherMethodsNotAllowed(t *testing.T) {
	a, _, _ := newTestAdmin(t, slog.LevelInfo)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/v1/log-level", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: status %d", rec.Code)
	}
}
