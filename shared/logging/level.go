// Package logging also holds the process-wide log level. Every NF builds its JSON
// handler with Level, so an operator can change verbosity on a running NF through
// the admin endpoint that NewLevelAdmin serves, without a restart.
package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Level is the process-wide level. It starts from LOG_LEVEL (default info).
var Level = newLevelVar(os.Getenv("LOG_LEVEL"))

// Default and maximum time a runtime change lasts before the level reverts to the
// startup value. A change is never permanent by accident.
const (
	DefaultLevelTTL = 900 * time.Second
	MaxLevelTTL     = 3600 * time.Second
)

func newLevelVar(env string) *slog.LevelVar {
	lv := &slog.LevelVar{}
	if l, err := ParseLevel(env); err == nil {
		lv.Set(l)
	} else {
		lv.Set(slog.LevelInfo)
	}
	return lv
}

// ParseLevel accepts debug, info, warn or error (any case). An empty string is info.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("log level must be debug|info|warn|error, got %q", s)
	}
}

// scheduler runs f after d. Tests replace it to drive the revert without sleeping.
type scheduler func(d time.Duration, f func()) (cancel func())

// LevelAdmin serves GET and PUT /admin/v1/log-level for one process.
//
//	GET  → {"level":"info","base_level":"info","revert_in_s":0}
//	PUT  {"level":"debug","ttl_s":300} → sets the level; it reverts to base_level
//	     when the TTL ends (default 900 s, at most 3600 s).
//
// The endpoint has no authentication: it sits on the metrics port, next to
// /metrics, and is reachable inside the internal network only. Do not publish that
// port. It is an operator tool, not a control-plane API.
type LevelAdmin struct {
	lv     *slog.LevelVar
	base   slog.Level
	logger *slog.Logger
	sched  scheduler
	now    func() time.Time

	mu       sync.Mutex
	cancel   func()
	revertAt time.Time
}

// NewLevelAdmin builds the handler for lv. base is the level the process started
// with, to which a timed change reverts. logger records every change.
func NewLevelAdmin(lv *slog.LevelVar, logger *slog.Logger) *LevelAdmin {
	return newLevelAdmin(lv, logger, func(d time.Duration, f func()) func() {
		t := time.AfterFunc(d, f)
		return func() { t.Stop() }
	}, time.Now)
}

func newLevelAdmin(lv *slog.LevelVar, logger *slog.Logger, sched scheduler, now func() time.Time) *LevelAdmin {
	return &LevelAdmin{lv: lv, base: lv.Level(), logger: logger.With("component", "log-level"),
		sched: sched, now: now}
}

// ServeHTTP implements http.Handler for /admin/v1/log-level.
func (a *LevelAdmin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.writeState(w)
	case http.MethodPut:
		a.set(w, r)
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *LevelAdmin) set(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Level string `json:"level"`
		TTLs  int    `json:"ttl_s"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	level, err := ParseLevel(req.Level)
	if err != nil || strings.TrimSpace(req.Level) == "" {
		http.Error(w, "level must be debug|info|warn|error", http.StatusBadRequest)
		return
	}
	ttl := DefaultLevelTTL
	if req.TTLs != 0 {
		ttl = time.Duration(req.TTLs) * time.Second
	}
	if ttl <= 0 || ttl > MaxLevelTTL {
		http.Error(w, "ttl_s must be 1-3600", http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	if a.cancel != nil {
		a.cancel()
	}
	previous := a.lv.Level()
	a.lv.Set(level)
	a.revertAt = a.now().Add(ttl)
	a.cancel = a.sched(ttl, a.revert)
	a.mu.Unlock()

	a.logger.Warn("log level changed", "procedure", "LogLevelChange", "result", "OK",
		"from", previous.String(), "to", level.String(), "ttl_s", int(ttl.Seconds()))
	a.writeState(w)
}

// revert restores the base level when the TTL ends.
func (a *LevelAdmin) revert() {
	a.mu.Lock()
	defer a.mu.Unlock()
	from := a.lv.Level()
	a.lv.Set(a.base)
	a.cancel = nil
	a.revertAt = time.Time{}
	a.logger.Warn("log level reverted", "procedure", "LogLevelChange", "result", "OK",
		"from", from.String(), "to", a.base.String())
}

func (a *LevelAdmin) writeState(w http.ResponseWriter) {
	a.mu.Lock()
	defer a.mu.Unlock()
	revertIn := 0
	if !a.revertAt.IsZero() {
		revertIn = int(a.revertAt.Sub(a.now()).Seconds())
		if revertIn < 0 {
			revertIn = 0
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"level":       a.lv.Level().String(),
		"base_level":  a.base.String(),
		"revert_in_s": revertIn,
	})
}
