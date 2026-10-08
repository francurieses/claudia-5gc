package pfcp

// recovery_test.go — Recovery Time Stamp in Association Setup / Heartbeat
// responses (TS 29.244 §7.4.2.2, §7.4.4.2, §8.2.65) and Cause 65 on deletion
// of an unknown session (TS 29.244 §7.5.7).

import (
	"testing"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"
)

func TestAssociationSetupResponseCarriesRecoveryTimeStamp(t *testing.T) {
	srv, _, addr, stop := startTestUPF(t)
	defer stop()

	req := pfcpmsg.NewAssociationSetupRequest(1, pfcpie.NewNodeID("", "", "smf"),
		pfcpie.NewRecoveryTimeStamp(srv.recoveryTS))
	resp, ok := sendAndRecv(t, addr, req).(*pfcpmsg.AssociationSetupResponse)
	if !ok {
		t.Fatal("expected AssociationSetupResponse")
	}
	if resp.RecoveryTimeStamp == nil {
		t.Fatal("Recovery Time Stamp missing (mandatory, TS 29.244 §7.4.4.2)")
	}
	got, err := resp.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		t.Fatalf("decode RTS: %v", err)
	}
	if !got.Equal(srv.recoveryTS) {
		t.Errorf("RTS = %v, want %v", got, srv.recoveryTS)
	}

	// IE order on the wire: Node ID, Cause, Recovery Time Stamp.
	var order []uint16
	for p := resp.Payload; len(p) >= 4; {
		l := int(p[2])<<8 | int(p[3])
		order = append(order, uint16(p[0])<<8|uint16(p[1]))
		if 4+l > len(p) {
			break
		}
		p = p[4+l:]
	}
	want := []uint16{pfcpie.NodeID, pfcpie.Cause, pfcpie.RecoveryTimeStamp}
	if len(order) < 3 {
		t.Fatalf("IE order = %v, want prefix %v", order, want)
	}
	for i, w := range want {
		if order[i] != w {
			t.Fatalf("IE order = %v, want prefix %v", order, want)
		}
	}
}

func TestHeartbeatResponseCarriesRecoveryTimeStamp(t *testing.T) {
	srv, _, addr, stop := startTestUPF(t)
	defer stop()

	req := pfcpmsg.NewHeartbeatRequest(7, pfcpie.NewRecoveryTimeStamp(srv.recoveryTS), nil)
	resp, ok := sendAndRecv(t, addr, req).(*pfcpmsg.HeartbeatResponse)
	if !ok {
		t.Fatal("expected HeartbeatResponse")
	}
	if resp.RecoveryTimeStamp == nil {
		t.Fatal("Recovery Time Stamp missing (mandatory, TS 29.244 §7.4.2.2)")
	}
	got, err := resp.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		t.Fatalf("decode RTS: %v", err)
	}
	if !got.Equal(srv.recoveryTS) {
		t.Errorf("RTS = %v, want %v", got, srv.recoveryTS)
	}
}

func TestSessionDeletionUnknownSEIDCause65(t *testing.T) {
	_, _, addr, stop := startTestUPF(t)
	defer stop()

	resp, ok := sendAndRecv(t, addr, pfcpmsg.NewSessionDeletionRequest(0, 0, 0xdead, 1, 0)).(*pfcpmsg.SessionDeletionResponse)
	if !ok {
		t.Fatal("expected SessionDeletionResponse")
	}
	c, err := resp.Cause.Cause()
	if err != nil {
		t.Fatalf("decode cause: %v", err)
	}
	if c != pfcpie.CauseSessionContextNotFound {
		t.Errorf("cause = %d, want %d", c, pfcpie.CauseSessionContextNotFound)
	}
}
