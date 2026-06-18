//go:build functional

// Package features holds the godog BDD suite for the MCP server. Run with:
//
//	go test -tags=functional ./mcp/tests/features/...
package features

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cucumber/godog"

	"github.com/francurieses/claudia-5gc/mcp/internal/config"
	"github.com/francurieses/claudia-5gc/mcp/internal/server"
	"github.com/francurieses/claudia-5gc/mcp/internal/server/transport"
	"github.com/francurieses/claudia-5gc/mcp/internal/session"
	nastools "github.com/francurieses/claudia-5gc/mcp/internal/tools/nas"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

type mcpCtx struct {
	srv     *httptest.Server
	content map[string]any // last tool result content (decoded JSON)
	isError bool
	encoded string

	// multi-session state
	cancel   context.CancelFunc
	sessions []sseConn
}

type sseConn struct {
	id   string
	msgs <-chan []byte
}

func (c *mcpCtx) startServer(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
	reg := registry.New()
	if err := reg.RegisterAll(nastools.All()...); err != nil {
		return ctx, err
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	disp := server.NewDispatcher(reg, logger)
	mgr := session.NewManager(logger)
	cfg := &config.Config{Transport: config.TransportSSE, SSE: config.SSE{Debug: true}}
	sse := transport.NewSSE(disp, reg, mgr, cfg, logger)
	c.srv = httptest.NewServer(sse.Handler())
	return ctx, nil
}

func (c *mcpCtx) stopServer(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
	if c.cancel != nil {
		c.cancel()
	}
	if c.srv != nil {
		c.srv.Close()
	}
	return ctx, nil
}

// callInline POSTs a tools/call without a session and parses the inline result.
func (c *mcpCtx) callInline(name string, args map[string]any) error {
	argsJSON, _ := json.Marshal(args)
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":%s}}`,
		name, argsJSON)
	resp, err := http.Post(c.srv.URL+"/mcp", "application/json", strings.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var rpc struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rpc); err != nil {
		return err
	}
	if len(rpc.Result.Content) == 0 {
		return fmt.Errorf("empty content")
	}
	c.isError = rpc.Result.IsError
	c.content = map[string]any{}
	return json.Unmarshal([]byte(rpc.Result.Content[0].Text), &c.content)
}

func (c *mcpCtx) theMCPServerIsRunning() error {
	if c.srv == nil {
		return fmt.Errorf("server not started")
	}
	return nil
}

func (c *mcpCtx) iCallWithHex(name, hex string) error {
	return c.callInline(name, map[string]any{"hex": hex})
}

func (c *mcpCtx) theCallSucceeds() error {
	if c.isError {
		return fmt.Errorf("tool reported an error: %v", c.content)
	}
	return nil
}

func (c *mcpCtx) theDecodedMessageTypeNameIs(want string) error {
	got, _ := c.content["message_type_name"].(string)
	if got != want {
		return fmt.Errorf("message_type_name: got %q, want %q", got, want)
	}
	return nil
}

func (c *mcpCtx) theResultIsInvalidWithOffset(off int) error {
	if valid, _ := c.content["valid"].(bool); valid {
		return fmt.Errorf("expected invalid result")
	}
	errs, ok := c.content["errors"].([]any)
	if !ok || len(errs) == 0 {
		return fmt.Errorf("no errors reported")
	}
	first, _ := errs[0].(map[string]any)
	gotOff, _ := first["offset"].(float64)
	if int(gotOff) != off {
		return fmt.Errorf("first error offset: got %v, want %d", gotOff, off)
	}
	return nil
}

func (c *mcpCtx) iEncodeMessageTypeWithBody(mt, body string) error {
	if err := c.callInline("nas_encode", map[string]any{"message_type": mt, "body_hex": body}); err != nil {
		return err
	}
	if c.isError {
		return fmt.Errorf("encode failed: %v", c.content)
	}
	c.encoded, _ = c.content["hex"].(string)
	if c.encoded == "" {
		return fmt.Errorf("encode produced empty hex")
	}
	return nil
}

func (c *mcpCtx) iDecodeTheEncodedHex() error {
	return c.iCallWithHex("nas_decode", c.encoded)
}

// ---- multi-session steps --------------------------------------------------

func (c *mcpCtx) twoSSEClientsConnected() error {
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	for i := 0; i < 2; i++ {
		conn, err := openSSE(ctx, c.srv.URL)
		if err != nil {
			return err
		}
		c.sessions = append(c.sessions, conn)
	}
	if c.sessions[0].id == c.sessions[1].id {
		return fmt.Errorf("sessions share an id")
	}
	return waitSessions(c.srv.URL, 2)
}

func (c *mcpCtx) bothClientsCallConcurrently() error {
	hexes := []string{"7e004111000100", "7e005c0007"}
	var wg sync.WaitGroup
	errs := make([]error, len(c.sessions))
	for i, s := range c.sessions {
		wg.Add(1)
		go func(i int, sid, hx string) {
			defer wg.Done()
			body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"nas_decode","arguments":{"hex":%q}}}`, i+1, hx)
			resp, err := http.Post(c.srv.URL+"/mcp?session="+sid, "application/json", strings.NewReader(body))
			if err != nil {
				errs[i] = err
				return
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusAccepted {
				errs[i] = fmt.Errorf("post status %d", resp.StatusCode)
			}
		}(i, s.id, hexes[i])
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func (c *mcpCtx) eachClientReceivesOnlyItsOwnResponse() error {
	for i, s := range c.sessions {
		wantID := fmt.Sprintf(`"id":%d`, i+1)
		select {
		case msg := <-s.msgs:
			if !strings.Contains(string(msg), wantID) {
				return fmt.Errorf("session %d got wrong response: %s", i, msg)
			}
			for j := range c.sessions {
				if j != i && strings.Contains(string(msg), fmt.Sprintf(`"id":%d`, j+1)) {
					return fmt.Errorf("session bleed: session %d received id of %d", i, j)
				}
			}
		case <-time.After(3 * time.Second):
			return fmt.Errorf("session %d timed out waiting for response", i)
		}
	}
	return nil
}

func (c *mcpCtx) sessionCountReturnsToZero() error {
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	return waitSessions(c.srv.URL, 0)
}

// ---- SSE helpers ----------------------------------------------------------

func openSSE(ctx context.Context, baseURL string) (sseConn, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/mcp/sse", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return sseConn{}, err
	}
	sid := resp.Header.Get("Mcp-Session-Id")
	if sid == "" {
		resp.Body.Close()
		return sseConn{}, fmt.Errorf("missing Mcp-Session-Id")
	}
	msgs := make(chan []byte, 4)
	go func() {
		defer resp.Body.Close()
		defer close(msgs)
		reader := bufio.NewReader(resp.Body)
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
			case line == "":
				if event == "message" && data != "" {
					msgs <- []byte(data)
				}
				event, data = "", ""
			}
		}
	}()
	return sseConn{id: sid, msgs: msgs}, nil
}

func waitSessions(baseURL string, want int) error {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/mcp/sessions")
		if err == nil {
			var s struct {
				Sessions []json.RawMessage `json:"sessions"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&s)
			resp.Body.Close()
			if len(s.Sessions) == want {
				return nil
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("session count never reached %d", want)
}

// ---- Godog wiring ---------------------------------------------------------

func InitializeScenario(sc *godog.ScenarioContext) {
	c := &mcpCtx{}
	sc.Before(c.startServer)
	sc.After(c.stopServer)

	sc.Step(`^the MCP server is running$`, c.theMCPServerIsRunning)
	sc.Step(`^I call "([^"]+)" with hex "([^"]+)"$`, c.iCallWithHex)
	sc.Step(`^the call succeeds$`, c.theCallSucceeds)
	sc.Step(`^the decoded message type name is "([^"]+)"$`, c.theDecodedMessageTypeNameIs)
	sc.Step(`^the result is reported invalid with first error offset (\d+)$`, c.theResultIsInvalidWithOffset)
	sc.Step(`^I encode message type "([^"]+)" with body "([^"]+)"$`, c.iEncodeMessageTypeWithBody)
	sc.Step(`^I decode the encoded hex$`, c.iDecodeTheEncodedHex)
	sc.Step(`^two SSE clients are connected$`, c.twoSSEClientsConnected)
	sc.Step(`^both clients call "([^"]+)" concurrently with distinct inputs$`, func(string) error {
		return c.bothClientsCallConcurrently()
	})
	sc.Step(`^each client receives only its own response$`, c.eachClientReceivesOnlyItsOwnResponse)
	sc.Step(`^the live session count returns to zero after both disconnect$`, c.sessionCountReturnsToZero)
}

func TestFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"./"},
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("non-zero exit status from godog test suite")
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
