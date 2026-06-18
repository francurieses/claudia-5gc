package api

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

const maxReconnectDelay = 10 * time.Second

// handleLogsWS streams Docker container logs to a WebSocket client.
// When the container stops or restarts the Docker stream closes with EOF; the
// handler reconnects automatically so the WebSocket connection stays open.
func (d Deps) handleLogsWS(w http.ResponseWriter, r *http.Request) {
	container := chi.URLParam(r, "container")

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Warn("logs ws upgrade failed", "container", container, "err", err)
		return
	}
	defer conn.Close()

	if d.Docker == nil {
		conn.WriteMessage(websocket.TextMessage, []byte(`{"error":"docker unavailable"}`)) //nolint:errcheck
		return
	}

	tail := r.URL.Query().Get("tail")
	if tail == "" {
		tail = "100"
	}

	ctx := r.Context()
	delay := 2 * time.Second

	for {
		stream, err := d.Docker.Logs(ctx, container, tail)
		if err != nil {
			notice := fmt.Sprintf(`{"level":"warn","msg":"--- %s: waiting for container (%s) ---"}`, container, err)
			_ = conn.WriteMessage(websocket.TextMessage, []byte(notice))
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
				if delay < maxReconnectDelay {
					delay *= 2
				}
			}
			continue
		}
		delay = 2 * time.Second // reset backoff on successful connect

		wsErr := streamDockerLogs(stream, conn)
		stream.Close()
		if wsErr != nil {
			return // WebSocket write failed — client disconnected
		}

		// Docker stream ended cleanly (container stopped or restarted).
		// After reconnect use tail=0 so we only follow new output.
		tail = "0"
		notice := fmt.Sprintf(`{"level":"warn","msg":"--- %s: container restarted, reconnecting... ---"}`, container)
		_ = conn.WriteMessage(websocket.TextMessage, []byte(notice))

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
			if delay < maxReconnectDelay {
				delay *= 2
			}
		}
	}
}

// streamDockerLogs copies Docker's multiplexed log stream to the WebSocket.
// Returns nil on clean Docker EOF (container stopped); non-nil on WebSocket
// write failure (client disconnected).
func streamDockerLogs(stream io.Reader, conn *websocket.Conn) error {
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(stream, hdr); err != nil {
			return nil // Docker EOF — container stopped/restarted
		}
		size := binary.BigEndian.Uint32(hdr[4:8])
		buf := make([]byte, size)
		if _, err := io.ReadFull(stream, buf); err != nil {
			return nil // EOF mid-frame
		}
		if err := conn.WriteMessage(websocket.TextMessage, buf); err != nil {
			return err // WebSocket write error — client gone
		}
	}
}
