// Package session tracks live MCP client sessions for the SSE transport. Each
// connected client (one GET /mcp/sse stream) is a Session identified by a UUID.
// The manager is concurrency-safe and emits structured slog events on connect
// and disconnect so operators can audit who is attached.
package session

import (
	"sync/atomic"
	"time"
)

// Event is a server→client message queued for delivery over a session's SSE
// stream. Name maps to the SSE "event:" field; Data is the JSON payload.
type Event struct {
	Name string
	Data []byte
}

// Session is a single connected MCP client.
type Session struct {
	ID           string    `json:"id"`
	RemoteAddr   string    `json:"remote_addr"`
	UserAgent    string    `json:"user_agent"`
	ConnectedAt  time.Time `json:"connected_at"`
	lastSeenUnix int64     // atomic; nanoseconds
	messageCount int64     // atomic

	// ch delivers events to the session's SSE writer goroutine. Buffered so a
	// slow client briefly backpressures rather than blocking the sender.
	ch     chan Event
	closed atomic.Bool
}

// LastSeen returns the timestamp of the session's most recent activity.
func (s *Session) LastSeen() time.Time {
	return time.Unix(0, atomic.LoadInt64(&s.lastSeenUnix))
}

// MessageCount returns how many messages the session has processed.
func (s *Session) MessageCount() int64 { return atomic.LoadInt64(&s.messageCount) }

// Touch updates last-seen and increments the message counter.
func (s *Session) Touch() {
	atomic.StoreInt64(&s.lastSeenUnix, time.Now().UnixNano())
	atomic.AddInt64(&s.messageCount, 1)
}

// Events exposes the read side of the delivery channel for the SSE writer.
func (s *Session) Events() <-chan Event { return s.ch }

// View is a JSON-safe snapshot of a Session for the /mcp/sessions debug endpoint.
type View struct {
	ID           string    `json:"id"`
	RemoteAddr   string    `json:"remote_addr"`
	UserAgent    string    `json:"user_agent"`
	ConnectedAt  time.Time `json:"connected_at"`
	LastSeen     time.Time `json:"last_seen"`
	MessageCount int64     `json:"message_count"`
}

func (s *Session) view() View {
	return View{
		ID:           s.ID,
		RemoteAddr:   s.RemoteAddr,
		UserAgent:    s.UserAgent,
		ConnectedAt:  s.ConnectedAt,
		LastSeen:     s.LastSeen(),
		MessageCount: s.MessageCount(),
	}
}

// eventBuffer is the per-session outbound queue depth.
const eventBuffer = 32
