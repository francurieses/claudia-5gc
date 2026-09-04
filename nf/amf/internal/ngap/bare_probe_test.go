package ngap

// bare_probe_test.go — regression test for the nil pointer dereference panic
// in handleGNBConn when a bare SCTP association is opened and closed again
// before any NGAP PDU is exchanged (e.g. a liveness/preflight probe such as
// nrlib/orchestrator.py's sctp_reachable()).
//
// Root cause: github.com/ishidawataru/sctp's SCTPConn.RemoteAddr() returns a
// nil net.Addr once the kernel can no longer report peer addresses for the
// association (which happens once the peer has closed it). The old code did
// `conn.RemoteAddr().String()` unconditionally, which panics with a nil
// pointer dereference — this crashed the AMF (see ngap.go:637 pre-fix) and
// forced a container restart on every preflight probe.

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/ishidawataru/sctp"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestHandleGNBConn_BareProbe_NoPanic reproduces the exact failure mode: a
// client opens a real SCTP association to the server's listener and closes
// it immediately, without sending any data. Before the fix, the server's
// handleGNBConn goroutine panicked on conn.RemoteAddr().String() once the
// kernel dropped the peer address info for the now-closed association. The
// test passes if handleGNBConn returns cleanly (no panic) and never
// registers a GNBContext for the probe connection.
func TestHandleGNBConn_BareProbe_NoPanic(t *testing.T) {
	sctpAddr, err := sctp.ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("SCTP not available in this environment: %v", err)
	}
	ln, err := sctp.ListenSCTP("sctp", sctpAddr)
	if err != nil {
		t.Skipf("SCTP not available in this environment: %v", err)
	}
	defer ln.Close()

	laddr := ln.Addr().(*sctp.SCTPAddr)

	mgr := amfctx.NewManager(amfctx.AMFIdentity{}, nil, nil, nil)
	srv := &Server{
		mgr:    mgr,
		gnbs:   make(map[string]*GNBContext),
		logger: discardLogger(),
	}

	accepted := make(chan *sctp.SCTPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := ln.AcceptSCTP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	// Client: connect and immediately close, sending no NGAP data at all —
	// this is exactly what sctp_reachable() in nrlib/orchestrator.py does.
	clientAddr, err := sctp.ResolveSCTPAddr("sctp", net.JoinHostPort("127.0.0.1", strconv.Itoa(laddr.Port)))
	if err != nil {
		t.Fatalf("resolve client addr: %v", err)
	}
	client, err := sctp.DialSCTP("sctp", nil, clientAddr)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	client.Close()

	var serverConn *sctp.SCTPConn
	select {
	case serverConn = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("accept error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server to accept the probe connection")
	}

	// Give the kernel a moment to tear down the association so
	// RemoteAddr() is in the nil-returning state the panic depended on.
	time.Sleep(200 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// This must not panic. Pre-fix, this line crashed the whole AMF
		// process (see ngap.go:637 stack trace in evidence/*.md).
		srv.handleGNBConn(context.Background(), serverConn)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleGNBConn did not return — probably blocked on Read() waiting for data that never arrives")
	}

	srv.mu.RLock()
	n := len(srv.gnbs)
	srv.mu.RUnlock()
	if n != 0 {
		t.Fatalf("expected no GNBContext registered for a bare probe connection, got %d", n)
	}
}
