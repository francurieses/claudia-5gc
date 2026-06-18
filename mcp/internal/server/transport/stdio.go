// Package transport provides the stdio and HTTP SSE adapters that feed the
// shared MCP dispatcher. Each adapter parses a JSON-RPC frame, attaches the
// session id to the context, calls Dispatch, and writes the response back over
// its own medium.
package transport

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/francurieses/claudia-5gc/mcp/internal/jsonrpc"
	"github.com/francurieses/claudia-5gc/mcp/internal/server"
)

// maxFrameBytes bounds a single newline-delimited JSON-RPC frame on stdin.
const maxFrameBytes = 4 << 20 // 4 MiB

// Stdio is the stdio JSON-RPC transport for local process clients (Claude
// Desktop / Claude Code). Frames are newline-delimited JSON per the MCP stdio
// transport. All logging MUST go to stderr — stdout is the protocol channel.
type Stdio struct {
	disp   *server.Dispatcher
	in     io.Reader
	out    io.Writer
	logger *slog.Logger
	mu     sync.Mutex // serialises writes to out
}

// NewStdio builds a stdio transport. Pass os.Stdin/os.Stdout in production.
func NewStdio(disp *server.Dispatcher, in io.Reader, out io.Writer, logger *slog.Logger) *Stdio {
	return &Stdio{disp: disp, in: in, out: out, logger: logger.With("transport", "stdio")}
}

// Run reads frames until ctx is cancelled or the input reaches EOF.
func (s *Stdio) Run(ctx context.Context) error {
	scanner := bufio.NewScanner(s.in)
	scanner.Buffer(make([]byte, 0, 64*1024), maxFrameBytes)

	// Stop scanning promptly on cancellation by closing a closer if available.
	done := make(chan struct{})
	defer close(done)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		// Copy: scanner reuses its buffer.
		frame := make([]byte, len(line))
		copy(frame, line)
		s.handle(ctx, frame)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("stdio: read: %w", err)
	}
	return nil
}

func (s *Stdio) handle(ctx context.Context, frame []byte) {
	req, perr := jsonrpc.ParseRequest(frame)
	if perr != nil {
		s.write(jsonrpc.NewError(nil, perr))
		return
	}
	resp := s.disp.Dispatch(ctx, req)
	if req.IsNotification() {
		return // no response for notifications
	}
	s.write(resp)
}

func (s *Stdio) write(resp jsonrpc.Response) {
	b, err := jsonrpc.WriteFrame(resp)
	if err != nil {
		s.logger.Error("encode response", "error", err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.out.Write(append(b, '\n')); err != nil {
		s.logger.Error("write response", "error", err)
	}
}
