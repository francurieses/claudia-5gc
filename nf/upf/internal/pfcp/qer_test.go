package pfcp

// qer_test.go — round-trip test of QER handling over a real PFCP/UDP exchange:
// the test plays the SMF role, sending Session Establishment with Create QER
// and Session Modification with Update QER, and asserts the UPF stores the QoS
// enforcement state. Ref: TS 29.244 §7.5.2.5, §8.2.7, §8.2.8
import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"
)

func startTestUPF(t *testing.T) (*Server, *SessionTable, *net.UDPAddr, context.CancelFunc) {
	t.Helper()
	table := NewSessionTable()
	srv, err := New(Config{Address: "127.0.0.1:0", NodeIP: "127.0.0.1"},
		slog.New(slog.NewTextHandler(os.Stderr, nil)), table)
	if err != nil {
		t.Fatalf("New UPF PFCP server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Start(ctx) }()
	return srv, table, srv.conn.LocalAddr().(*net.UDPAddr), func() {
		cancel()
		_ = srv.Close()
	}
}

func sendAndRecv(t *testing.T, addr *net.UDPAddr, msg pfcpmsg.Message) pfcpmsg.Message {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	b := make([]byte, msg.MarshalLen())
	if err := msg.MarshalTo(b); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := conn.Write(b); err != nil {
		t.Fatalf("send: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no response: %v", err)
	}
	resp, err := pfcpmsg.Parse(buf[:n])
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	return resp
}

// TestSessionEstablishmentStoresQER verifies the UPF extracts QER ID, QFI,
// gate status and MBR from Create QER, and that Update QER replaces them.
func TestSessionEstablishmentStoresQER(t *testing.T) {
	_, table, addr, stop := startTestUPF(t)
	defer stop()

	const seid = uint64(42)
	const ulTEID = uint32(7)

	est := pfcpmsg.NewSessionEstablishmentRequest(
		0, 0, 0, 1, 0,
		pfcpie.NewNodeID("", "", "smf"),
		pfcpie.NewFSEID(seid, net.ParseIP("127.0.0.1"), nil),
		pfcpie.NewCreatePDR(
			pfcpie.NewPDRID(1),
			pfcpie.NewPrecedence(100),
			pfcpie.NewPDI(
				pfcpie.NewSourceInterface(pfcpie.SrcInterfaceAccess),
				pfcpie.NewFTEID(0x01, ulTEID, net.ParseIP("127.0.0.1"), nil, 0),
				pfcpie.NewUEIPAddress(0x02, "10.60.0.5", "", 0, 0),
			),
			pfcpie.NewOuterHeaderRemoval(0, 0),
			pfcpie.NewFARID(1),
			pfcpie.NewQERID(1),
		),
		pfcpie.NewCreateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x02)),
		pfcpie.NewCreateQER(
			pfcpie.NewQERID(1),
			pfcpie.NewGateStatus(0, 0),
			pfcpie.NewMBR(100_000, 100_000), // kbps
			pfcpie.NewQFI(1),
		),
	)
	resp := sendAndRecv(t, addr, est)
	if _, ok := resp.(*pfcpmsg.SessionEstablishmentResponse); !ok {
		t.Fatalf("expected SessionEstablishmentResponse, got %s", resp.MessageTypeName())
	}

	sess := table.GetByULTEID(ulTEID)
	if sess == nil {
		t.Fatal("session not stored")
	}
	if sess.QER.QERID != 1 || sess.QER.QFI != 1 {
		t.Errorf("QER id/qfi: got %d/%d want 1/1", sess.QER.QERID, sess.QER.QFI)
	}
	if sess.QER.MBRULKbps != 100_000 || sess.QER.MBRDLKbps != 100_000 {
		t.Errorf("QER MBR: got %d/%d want 100000/100000", sess.QER.MBRULKbps, sess.QER.MBRDLKbps)
	}
	if sess.QER.GateUL != 0 || sess.QER.GateDL != 0 {
		t.Errorf("QER gates: got %d/%d want OPEN/OPEN (0/0)", sess.QER.GateUL, sess.QER.GateDL)
	}

	// NW-initiated QoS modification: new MBR via Update QER.
	mod := pfcpmsg.NewSessionModificationRequest(
		0, 0, seid, 2, 0,
		pfcpie.NewUpdateQER(
			pfcpie.NewQERID(1),
			pfcpie.NewGateStatus(0, 0),
			pfcpie.NewMBR(50_000, 200_000),
			pfcpie.NewQFI(1),
		),
	)
	resp = sendAndRecv(t, addr, mod)
	if _, ok := resp.(*pfcpmsg.SessionModificationResponse); !ok {
		t.Fatalf("expected SessionModificationResponse, got %s", resp.MessageTypeName())
	}
	if sess.QER.MBRULKbps != 50_000 || sess.QER.MBRDLKbps != 200_000 {
		t.Errorf("QER MBR after update: got %d/%d want 50000/200000", sess.QER.MBRULKbps, sess.QER.MBRDLKbps)
	}
}
