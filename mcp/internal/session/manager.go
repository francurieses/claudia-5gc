package session

import (
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Manager is a concurrency-safe registry of live SSE sessions, backed by a
// sync.Map keyed by session UUID. It never leaks: Deregister closes the
// session's channel and removes it from the map.
type Manager struct {
	sessions sync.Map // map[string]*Session
	logger   *slog.Logger
}

// NewManager returns a Manager that logs connect/disconnect events.
func NewManager(logger *slog.Logger) *Manager {
	return &Manager{logger: logger.With("component", "session-manager")}
}

// Register creates and stores a new session for a connecting client. The caller
// (the SSE handler) supplies the client's remote address and user-agent.
func (m *Manager) Register(remoteAddr, userAgent string) *Session {
	now := time.Now()
	s := &Session{
		ID:           uuid.NewString(),
		RemoteAddr:   remoteAddr,
		UserAgent:    userAgent,
		ConnectedAt:  now,
		lastSeenUnix: now.UnixNano(),
		ch:           make(chan Event, eventBuffer),
	}
	m.sessions.Store(s.ID, s)
	m.logger.Info("MCP client connected",
		"session_id", s.ID,
		"remote_addr", remoteAddr,
		"user_agent", userAgent,
		"connected_at", now.UTC().Format(time.RFC3339Nano),
	)
	return s
}

// Deregister removes a session and closes its event channel. Idempotent.
func (m *Manager) Deregister(id string) {
	v, ok := m.sessions.LoadAndDelete(id)
	if !ok {
		return
	}
	s := v.(*Session)
	if s.closed.CompareAndSwap(false, true) {
		close(s.ch)
	}
	m.logger.Info("MCP client disconnected",
		"session_id", s.ID,
		"remote_addr", s.RemoteAddr,
		"message_count", s.MessageCount(),
		"duration_ms", time.Since(s.ConnectedAt).Milliseconds(),
	)
}

// Get returns the session with the given id.
func (m *Manager) Get(id string) (*Session, bool) {
	v, ok := m.sessions.Load(id)
	if !ok {
		return nil, false
	}
	return v.(*Session), true
}

// SendTo delivers an event to a single session. It reports whether the session
// existed and the event was queued (a closed or full channel returns false).
func (m *Manager) SendTo(id string, ev Event) bool {
	s, ok := m.Get(id)
	if !ok || s.closed.Load() {
		return false
	}
	select {
	case s.ch <- ev:
		return true
	default:
		// Slow consumer: drop rather than block the sender.
		m.logger.Warn("dropping event: session queue full", "session_id", id)
		return false
	}
}

// Broadcast delivers an event to every live session, returning the count reached.
func (m *Manager) Broadcast(ev Event) int {
	var n int
	m.sessions.Range(func(_, v any) bool {
		s := v.(*Session)
		if s.closed.Load() {
			return true
		}
		select {
		case s.ch <- ev:
			n++
		default:
			m.logger.Warn("dropping broadcast: session queue full", "session_id", s.ID)
		}
		return true
	})
	return n
}

// Count returns the number of live sessions.
func (m *Manager) Count() int {
	var n int
	m.sessions.Range(func(_, _ any) bool { n++; return true })
	return n
}

// Views returns JSON-safe snapshots of all live sessions for the debug endpoint.
func (m *Manager) Views() []View {
	out := make([]View, 0)
	m.sessions.Range(func(_, v any) bool {
		out = append(out, v.(*Session).view())
		return true
	})
	return out
}
