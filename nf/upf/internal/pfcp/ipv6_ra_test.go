package pfcp

// ipv6_ra_test.go — SMF-002 data-plane: UPF parsing of the granted-type-aware
// UE IP Address IE (TS 29.244 §8.2.62) plus the per-session Router
// Advertisement advertiser (TS 23.501 §5.8.2.2.2, RFC 4861). Exercises real
// PFCP/UDP round trips (same style as qer_test.go) and a fake RASender to
// observe downlink RA delivery without a real GTP-U server.

import (
	"context"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"
)

// fakeRASender records every downlink packet handed to it by the PFCP
// server's RA advertiser, standing in for the GTP-U server in these tests.
type fakeRASender struct {
	mu    sync.Mutex
	calls []fakeRACall
}

type fakeRACall struct {
	sess *Session
	pkt  []byte
}

func (f *fakeRASender) SendDownlink(sess *Session, pkt []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fakeRACall{sess: sess, pkt: pkt})
}

func (f *fakeRASender) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeRASender) last() fakeRACall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

// startTestUPFWithRA is startTestUPF (qer_test.go) plus a fakeRASender wired
// in and a short, test-injected RA interval.
func startTestUPFWithRA(t *testing.T, raInterval time.Duration) (*Server, *SessionTable, *net.UDPAddr, *fakeRASender, context.CancelFunc) {
	t.Helper()
	table := NewSessionTable()
	srv, err := New(Config{Address: "127.0.0.1:0", NodeIP: "127.0.0.1", RAInterval: raInterval},
		slog.New(slog.NewTextHandler(os.Stderr, nil)), table)
	if err != nil {
		t.Fatalf("New UPF PFCP server: %v", err)
	}
	sender := &fakeRASender{}
	srv.SetRASender(sender)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Start(ctx) }()
	return srv, table, srv.conn.LocalAddr().(*net.UDPAddr), sender, func() {
		cancel()
		_ = srv.Close()
	}
}

func establishIPv6Session(t *testing.T, addr *net.UDPAddr, seid uint64, seq uint32, ulTEID uint32, flags uint8, v4, v6, dnn string) pfcpmsg.Message {
	t.Helper()
	est := pfcpmsg.NewSessionEstablishmentRequest(
		0, 0, 0, seq, 0,
		pfcpie.NewNodeID("", "", "smf"),
		pfcpie.NewFSEID(seid, net.ParseIP("127.0.0.1"), nil),
		pfcpie.NewCreatePDR(
			pfcpie.NewPDRID(1),
			pfcpie.NewPrecedence(100),
			pfcpie.NewPDI(
				pfcpie.NewSourceInterface(pfcpie.SrcInterfaceAccess),
				pfcpie.NewFTEID(0x01, ulTEID, net.ParseIP("127.0.0.1"), nil, 0),
				pfcpie.NewUEIPAddress(flags, v4, v6, 0, 0),
				pfcpie.NewNetworkInstance(dnn),
			),
			pfcpie.NewOuterHeaderRemoval(0, 0),
			pfcpie.NewFARID(1),
			pfcpie.NewQERID(1),
		),
		pfcpie.NewCreateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x02)),
		pfcpie.NewCreateQER(
			pfcpie.NewQERID(1),
			pfcpie.NewGateStatus(0, 0),
			pfcpie.NewMBR(100_000, 100_000),
			pfcpie.NewQFI(1),
		),
	)
	return sendAndRecv(t, addr, est)
}

func modifyDLTunnel(t *testing.T, addr *net.UDPAddr, seid uint64, seq uint32, dlTEID uint32, gnbIP string) pfcpmsg.Message {
	t.Helper()
	mod := pfcpmsg.NewSessionModificationRequest(
		0, 0, seid, seq, 0,
		pfcpie.NewUpdateFAR(
			pfcpie.NewFARID(1),
			pfcpie.NewApplyAction(0x02),
			pfcpie.NewUpdateForwardingParameters(
				pfcpie.NewOuterHeaderCreation(0x0100, dlTEID, gnbIP, "", 0, 0, 0),
			),
		),
	)
	return sendAndRecv(t, addr, mod)
}

// TestHandleSessionEstablishment_ParsesIPv6AndDNN proves the UPF extracts the
// V6 UE IP Address IE field and the Network Instance (DNN) from the PDI.
func TestHandleSessionEstablishment_ParsesIPv6AndDNN(t *testing.T) {
	_, table, addr, _, stop := startTestUPFWithRA(t, time.Hour)
	defer stop()

	const ulTEID = uint32(70)
	resp := establishIPv6Session(t, addr, 100, 1, ulTEID, 0x01, "", "2001:db8:61::1", "ims")
	if _, ok := resp.(*pfcpmsg.SessionEstablishmentResponse); !ok {
		t.Fatalf("expected SessionEstablishmentResponse, got %s", resp.MessageTypeName())
	}

	sess := table.GetByULTEID(ulTEID)
	if sess == nil {
		t.Fatal("session not stored")
	}
	table.mu.RLock()
	defer table.mu.RUnlock()
	if sess.UEIP != nil {
		t.Errorf("expected nil IPv4 UE address for V6-only flags, got %s", sess.UEIP)
	}
	wantV6 := net.ParseIP("2001:db8:61::1")
	if !sess.UEIPv6.Equal(wantV6) {
		t.Errorf("UEIPv6 = %s, want %s", sess.UEIPv6, wantV6)
	}
	if sess.DNN != "ims" {
		t.Errorf("DNN = %q, want %q", sess.DNN, "ims")
	}
}

// TestHandleSessionEstablishment_IPv4UnchangedNoV6 proves the existing IPv4
// path stores no UEIPv6 and never starts an RA advertiser (zero
// regression).
func TestHandleSessionEstablishment_IPv4UnchangedNoV6(t *testing.T) {
	_, table, addr, sender, stop := startTestUPFWithRA(t, 50*time.Millisecond)
	defer stop()

	const ulTEID = uint32(71)
	resp := establishIPv6Session(t, addr, 101, 1, ulTEID, 0x02, "10.60.0.9", "", "internet")
	if _, ok := resp.(*pfcpmsg.SessionEstablishmentResponse); !ok {
		t.Fatalf("expected SessionEstablishmentResponse, got %s", resp.MessageTypeName())
	}

	sess := table.GetByULTEID(ulTEID)
	if sess == nil {
		t.Fatal("session not stored")
	}
	table.mu.RLock()
	v6 := sess.UEIPv6
	v4 := sess.UEIP
	table.mu.RUnlock()
	if v6 != nil {
		t.Errorf("expected nil UEIPv6 for IPv4-only session, got %s", v6)
	}
	if !v4.Equal(net.ParseIP("10.60.0.9")) {
		t.Errorf("UEIP = %s, want 10.60.0.9", v4)
	}

	time.Sleep(200 * time.Millisecond)
	if n := sender.count(); n != 0 {
		t.Errorf("expected no RA sent for IPv4-only session, got %d", n)
	}
}

// TestRAAdvertiser_SkipsUntilDLTunnelKnown proves the periodic advertiser
// does not emit a Router Advertisement until the DL tunnel (DL TEID + gNB
// IP) is learned via PFCP Session Modification, then emits once it is.
func TestRAAdvertiser_SkipsUntilDLTunnelKnown(t *testing.T) {
	_, _, addr, sender, stop := startTestUPFWithRA(t, 30*time.Millisecond)
	defer stop()

	const seid = uint64(200)
	const ulTEID = uint32(72)
	resp := establishIPv6Session(t, addr, seid, 1, ulTEID, 0x01, "", "2001:db8:62::1", "internet")
	if _, ok := resp.(*pfcpmsg.SessionEstablishmentResponse); !ok {
		t.Fatalf("expected SessionEstablishmentResponse, got %s", resp.MessageTypeName())
	}

	// No DL tunnel yet: advertiser ticks should be silently skipped.
	time.Sleep(100 * time.Millisecond)
	if n := sender.count(); n != 0 {
		t.Fatalf("expected no RA before DL tunnel is known, got %d", n)
	}

	// Learn the DL tunnel via Session Modification.
	modResp := modifyDLTunnel(t, addr, seid, 2, 555, "127.0.0.2")
	if _, ok := modResp.(*pfcpmsg.SessionModificationResponse); !ok {
		t.Fatalf("expected SessionModificationResponse, got %s", modResp.MessageTypeName())
	}

	deadline := time.Now().Add(2 * time.Second)
	for sender.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if sender.count() == 0 {
		t.Fatal("expected at least one RA after DL tunnel became known")
	}
	call := sender.last()
	if len(call.pkt) == 0 {
		t.Error("RA packet is empty")
	}
	// ICMPv6 type (134) must appear at byte offset 40 (after the IPv6 header).
	if len(call.pkt) < 41 || call.pkt[40] != 134 {
		t.Errorf("RA packet ICMPv6 type byte = %v, want 134", call.pkt)
	}
}

// TestTriggerSolicitedRA_ImmediateSend proves a solicited RA is sent
// immediately (independent of the periodic ticker) once the DL tunnel is
// known.
func TestTriggerSolicitedRA_ImmediateSend(t *testing.T) {
	srv, table, addr, sender, stop := startTestUPFWithRA(t, time.Hour) // long tick: only the solicited path should fire
	defer stop()

	const seid = uint64(300)
	const ulTEID = uint32(73)
	resp := establishIPv6Session(t, addr, seid, 1, ulTEID, 0x01, "", "2001:db8:63::1", "internet")
	if _, ok := resp.(*pfcpmsg.SessionEstablishmentResponse); !ok {
		t.Fatalf("expected SessionEstablishmentResponse, got %s", resp.MessageTypeName())
	}
	modResp := modifyDLTunnel(t, addr, seid, 2, 777, "127.0.0.3")
	if _, ok := modResp.(*pfcpmsg.SessionModificationResponse); !ok {
		t.Fatalf("expected SessionModificationResponse, got %s", modResp.MessageTypeName())
	}

	sess := table.GetByULTEID(ulTEID)
	if sess == nil {
		t.Fatal("session not found")
	}

	srv.TriggerSolicitedRA(context.Background(), sess, net.ParseIP("fe80::1234"))

	deadline := time.Now().Add(2 * time.Second)
	for sender.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if sender.count() != 1 {
		t.Fatalf("expected exactly one solicited RA, got %d", sender.count())
	}
	dst := net.IP(sender.last().pkt[24:40])
	if !dst.Equal(net.ParseIP("fe80::1234")) {
		t.Errorf("solicited RA dst = %s, want fe80::1234 (unicast)", dst)
	}
}

// TestHandleSessionDeletion_StopsAdvertiser proves the advertiser goroutine
// is cancelled on session deletion — no further RA sends after deletion.
func TestHandleSessionDeletion_StopsAdvertiser(t *testing.T) {
	_, _, addr, sender, stop := startTestUPFWithRA(t, 20*time.Millisecond)
	defer stop()

	const seid = uint64(400)
	const ulTEID = uint32(74)
	resp := establishIPv6Session(t, addr, seid, 1, ulTEID, 0x01, "", "2001:db8:64::1", "internet")
	if _, ok := resp.(*pfcpmsg.SessionEstablishmentResponse); !ok {
		t.Fatalf("expected SessionEstablishmentResponse, got %s", resp.MessageTypeName())
	}
	modResp := modifyDLTunnel(t, addr, seid, 2, 888, "127.0.0.4")
	if _, ok := modResp.(*pfcpmsg.SessionModificationResponse); !ok {
		t.Fatalf("expected SessionModificationResponse, got %s", modResp.MessageTypeName())
	}

	// Wait for at least one RA to prove the advertiser was running.
	deadline := time.Now().Add(2 * time.Second)
	for sender.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if sender.count() == 0 {
		t.Fatal("expected at least one RA before deletion")
	}

	del := pfcpmsg.NewSessionDeletionRequest(0, 0, seid, 3, 0)
	delResp := sendAndRecv(t, addr, del)
	if _, ok := delResp.(*pfcpmsg.SessionDeletionResponse); !ok {
		t.Fatalf("expected SessionDeletionResponse, got %s", delResp.MessageTypeName())
	}

	countAtDeletion := sender.count()
	time.Sleep(150 * time.Millisecond)
	if n := sender.count(); n != countAtDeletion {
		t.Errorf("advertiser kept running after deletion: count went from %d to %d", countAtDeletion, n)
	}
}
