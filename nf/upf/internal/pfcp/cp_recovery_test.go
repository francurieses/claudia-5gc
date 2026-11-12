package pfcp

// cp_recovery_test.go — UPF deletes the sessions of a CP function whose
// Recovery Time Stamp changed (restart), keeps them when it is unchanged.
// Ref: TS 29.244 §6.2.6, §7.4.4.1, TS 23.007 §19A.

import (
	"testing"
	"time"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"
)

func TestCPRestartDeletesSessions(t *testing.T) {
	_, table, addr, stop := startTestUPF(t)
	defer stop()
	rts1 := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)

	assoc := func(seq uint32, rts time.Time) {
		r := sendAndRecv(t, addr, pfcpmsg.NewAssociationSetupRequest(seq,
			pfcpie.NewNodeID("", "", "smf"), pfcpie.NewRecoveryTimeStamp(rts)))
		if _, ok := r.(*pfcpmsg.AssociationSetupResponse); !ok {
			t.Fatalf("expected AssociationSetupResponse, got %T", r)
		}
	}
	est := func(seid uint64, teid uint32, ip string) {
		if _, ok := establishIPv6Session(t, addr, seid, uint32(seid), teid, 0x02, ip, "", "internet").(*pfcpmsg.SessionEstablishmentResponse); !ok {
			t.Fatal("expected SessionEstablishmentResponse")
		}
	}
	count := func() int { return len(table.Snapshot()) }

	assoc(1, rts1)
	est(10, 0x100, "10.60.0.1")
	est(11, 0x101, "10.60.0.2")
	if count() != 2 {
		t.Fatalf("sessions = %d, want 2", count())
	}

	// Same RTS (SMF re-associates without restarting): sessions kept.
	assoc(2, rts1)
	if count() != 2 {
		t.Fatalf("same RTS: sessions = %d, want 2", count())
	}
	// Heartbeat with an unchanged RTS keeps them too.
	sendAndRecv(t, addr, pfcpmsg.NewHeartbeatRequest(3, pfcpie.NewRecoveryTimeStamp(rts1), nil))
	if count() != 2 {
		t.Fatalf("heartbeat same RTS: sessions = %d, want 2", count())
	}
	// Older RTS: ignored.
	assoc(4, rts1.Add(-time.Minute))
	if count() != 2 {
		t.Fatalf("older RTS: sessions = %d, want 2", count())
	}

	// Later RTS in Association Setup: SMF restarted, all its sessions go.
	assoc(5, rts1.Add(time.Minute))
	if count() != 0 {
		t.Fatalf("restart via assoc: sessions = %d, want 0", count())
	}
	if table.GetByULTEID(0x100) != nil {
		t.Error("indexes not cleaned")
	}

	// Restart detected through a Heartbeat Request.
	est(12, 0x102, "10.60.0.3")
	sendAndRecv(t, addr, pfcpmsg.NewHeartbeatRequest(6, pfcpie.NewRecoveryTimeStamp(rts1.Add(2*time.Minute)), nil))
	if count() != 0 {
		t.Fatalf("restart via heartbeat: sessions = %d, want 0", count())
	}
}

func TestCPRestartOnlyAffectsThatPeer(t *testing.T) {
	_, table, addr, stop := startTestUPF(t)
	defer stop()
	base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	sendAndRecv(t, addr, pfcpmsg.NewAssociationSetupRequest(1, pfcpie.NewNodeID("", "", "smf"), pfcpie.NewRecoveryTimeStamp(base)))
	establishIPv6Session(t, addr, 20, 20, 0x200, 0x02, "10.60.0.9", "", "internet")
	// A different CP node restarting must not touch the smf's session.
	sendAndRecv(t, addr, pfcpmsg.NewAssociationSetupRequest(2, pfcpie.NewNodeID("", "", "other"), pfcpie.NewRecoveryTimeStamp(base)))
	sendAndRecv(t, addr, pfcpmsg.NewAssociationSetupRequest(3, pfcpie.NewNodeID("", "", "other"), pfcpie.NewRecoveryTimeStamp(base.Add(time.Minute))))
	if n := len(table.Snapshot()); n != 1 {
		t.Fatalf("sessions = %d, want 1", n)
	}
}
