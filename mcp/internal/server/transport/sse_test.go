package transport

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/config"
	"github.com/francurieses/claudia-5gc/mcp/internal/server"
	"github.com/francurieses/claudia-5gc/mcp/internal/session"
	nastools "github.com/francurieses/claudia-5gc/mcp/internal/tools/nas"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

func testSSE(t *testing.T) *httptest.Server {
	t.Helper()
	reg := registry.New()
	if err := reg.RegisterAll(nastools.All()...); err != nil {
		t.Fatalf("register: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	disp := server.NewDispatcher(reg, logger)
	mgr := session.NewManager(logger)
	cfg := &config.Config{Transport: config.TransportSSE, SSE: config.SSE{Debug: true}}
	sse := NewSSE(disp, reg, mgr, cfg, logger)
	return httptest.NewServer(sse.Handler())
}

func TestHealthAndTools(t *testing.T) {
	srv := testSSE(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/mcp/health")
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status: %d", resp.StatusCode)
	}

	resp2, err := http.Get(srv.URL + "/mcp/tools")
	if err != nil {
		t.Fatalf("tools: %v", err)
	}
	defer resp2.Body.Close()
	var tl struct {
		Tools []registry.ManifestEntry `json:"tools"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&tl); err != nil {
		t.Fatalf("decode tools: %v", err)
	}
	if len(tl.Tools) != 4 {
		t.Fatalf("tools: got %d, want 4", len(tl.Tools))
	}
}

// sseClient opens a /mcp/sse stream and returns its session id plus a channel
// of decoded "message" event payloads.
func sseClient(t *testing.T, ctx context.Context, baseURL string) (string, <-chan []byte) {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/mcp/sse", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("open sse: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })

	reader := bufio.NewReader(resp.Body)
	// First event is the endpoint announcement carrying ?session=<id>.
	sid := resp.Header.Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("missing Mcp-Session-Id header")
	}

	msgs := make(chan []byte, 4)
	go func() {
		defer close(msgs)
		var event, data string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\n")
			switch {
			case strings.HasPrefix(line, "event: "):
				event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				data = strings.TrimPrefix(line, "data: ")
			case line == "": // dispatch on blank separator
				if event == "message" && data != "" {
					msgs <- []byte(data)
				}
				event, data = "", ""
			}
		}
	}()
	return sid, msgs
}

func postCall(t *testing.T, baseURL, sid, hex string, id int) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":` + strconv.Itoa(id) + `,"method":"tools/call","params":{"name":"nas_decode","arguments":{"hex":"` + hex + `"}}}`
	resp, err := http.Post(baseURL+"/mcp?session="+sid, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("post status: got %d, want 202", resp.StatusCode)
	}
}

// TestMultiSessionNoBleed is the core concurrency guarantee: two SSE clients
// each call nas_decode with distinct inputs and must receive only their own
// response on their own stream.
func TestMultiSessionNoBleed(t *testing.T) {
	srv := testSSE(t)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sidA, msgsA := sseClient(t, ctx, srv.URL)
	sidB, msgsB := sseClient(t, ctx, srv.URL)
	if sidA == sidB {
		t.Fatal("sessions share an id")
	}
	waitSessions(t, srv.URL, 2)

	// Distinct inputs: A decodes a RegistrationRequest, B an Identity request body.
	postCall(t, srv.URL, sidA, "7e004111000100", 1)
	postCall(t, srv.URL, sidB, "7e005c0007", 2)

	gotA := awaitMsg(t, msgsA)
	gotB := awaitMsg(t, msgsB)

	if !strings.Contains(gotA, `"id":1`) {
		t.Errorf("session A got wrong response id: %s", gotA)
	}
	if !strings.Contains(gotB, `"id":2`) {
		t.Errorf("session B got wrong response id: %s", gotB)
	}
	if strings.Contains(gotA, `"id":2`) || strings.Contains(gotB, `"id":1`) {
		t.Fatal("session bleed: a response reached the wrong stream")
	}

	// Disconnecting drops the live session count back to zero.
	cancel()
	waitSessions(t, srv.URL, 0)
}

func awaitMsg(t *testing.T, ch <-chan []byte) string {
	t.Helper()
	select {
	case b := <-ch:
		return string(b)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for SSE message")
		return ""
	}
}

func waitSessions(t *testing.T, baseURL string, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/mcp/sessions")
		if err == nil {
			var s struct {
				Sessions []session.View `json:"sessions"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&s)
			resp.Body.Close()
			if len(s.Sessions) == want {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("session count never reached %d", want)
}
