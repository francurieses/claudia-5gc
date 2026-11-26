package pfcp

// n9_test.go — home-routed N9 rule handling over a real PFCP/UDP round trip,
// with the rule layouts built by the SMF (nf/smf hr_vsmf.go / hr_hsmf.go).
// Ref: TS 23.502 §4.3.2.2.2; TS 29.244 §7.5.2, §7.5.4.3, §8.2.2 NOTE 1.

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"testing"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"
)

func vupfEstablishment(seid uint64, n3TEID, n9TEID uint32) *pfcpmsg.SessionEstablishmentRequest {
	return pfcpmsg.NewSessionEstablishmentRequest(0, 0, 0, 1, 0,
		pfcpie.NewNodeID("", "", "smf"),
		pfcpie.NewFSEID(seid, net.ParseIP("127.0.0.1"), nil),
		pfcpie.NewCreatePDR(pfcpie.NewPDRID(1), pfcpie.NewPrecedence(100),
			pfcpie.NewPDI(pfcpie.NewSourceInterface(pfcpie.SrcInterfaceAccess),
				pfcpie.NewFTEID(0x01, n3TEID, net.ParseIP("172.30.3.100"), nil, 0)),
			pfcpie.NewOuterHeaderRemoval(0, 0), pfcpie.NewFARID(2)),
		pfcpie.NewCreatePDR(pfcpie.NewPDRID(2), pfcpie.NewPrecedence(100),
			pfcpie.NewPDI(pfcpie.NewSourceInterface(pfcpie.SrcInterfaceCore),
				pfcpie.NewFTEID(0x01, n9TEID, net.ParseIP("172.30.20.100"), nil, 0)),
			pfcpie.NewOuterHeaderRemoval(0, 0), pfcpie.NewFARID(1)),
		pfcpie.NewCreateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x02),
			pfcpie.NewForwardingParameters(pfcpie.NewDestinationInterface(pfcpie.DstInterfaceAccess))),
		pfcpie.NewCreateFAR(pfcpie.NewFARID(2), pfcpie.NewApplyAction(0x02),
			pfcpie.NewForwardingParameters(pfcpie.NewDestinationInterface(pfcpie.DstInterfaceCore))),
	)
}

func dl(table *SessionTable, s *Session) uint32 {
	table.mu.RLock()
	defer table.mu.RUnlock()
	return s.DLTEID
}

func modify(t *testing.T, addr *net.UDPAddr, seid uint64, seq uint32, far *pfcpie.IE) {
	t.Helper()
	resp, ok := sendAndRecv(t, addr, pfcpmsg.NewSessionModificationRequest(0, 0, seid, seq, 0, far)).(*pfcpmsg.SessionModificationResponse)
	if !ok {
		t.Fatal("expected SessionModificationResponse")
	}
	if c, err := resp.Cause.Cause(); err != nil || c != pfcpie.CauseRequestAccepted {
		t.Fatalf("cause = %d (%v)", c, err)
	}
}

// TestHRVUPFRules: the V-UPF layout indexes both F-TEIDs; the later UL FAR update
// installs the N9 peer without touching the DL tunnel and the DL FAR update sets
// the gNB tunnel without touching the UL peer.
func TestHRVUPFRules(t *testing.T) {
	_, table, addr, stop := startTestUPF(t)
	defer stop()
	const seid, n3, n9 = uint64(81), uint32(0x31), uint32(0x91)
	if _, ok := sendAndRecv(t, addr, vupfEstablishment(seid, n3, n9)).(*pfcpmsg.SessionEstablishmentResponse); !ok {
		t.Fatal("expected SessionEstablishmentResponse")
	}
	sess := table.GetByULTEID(n3)
	if sess == nil || table.GetByULTEID(n9) != sess {
		t.Fatal("N3 and N9 F-TEIDs must index the same session")
	}
	if sess.ULTEID != n3 || sess.N9TEID != n9 || !sess.ULRelay || sess.ULFARID != 2 || sess.DLFARID != 1 {
		t.Fatalf("session = ul %#x n9 %#x relay %v ulfar %d dlfar %d", sess.ULTEID, sess.N9TEID, sess.ULRelay, sess.ULFARID, sess.DLFARID)
	}
	if sess.ULPeer() != nil {
		t.Fatal("UL peer must be unset before the modification")
	}

	modify(t, addr, seid, 2, pfcpie.NewUpdateFAR(pfcpie.NewFARID(2), pfcpie.NewApplyAction(0x02),
		pfcpie.NewUpdateForwardingParameters(pfcpie.NewDestinationInterface(pfcpie.DstInterfaceCore),
			pfcpie.NewOuterHeaderCreation(0x0100, 0xAB, "172.30.20.200", "", 0, 0, 0))))
	if p := sess.ULPeer(); p == nil || p.TEID != 0xAB || p.Addr.String() != "172.30.20.200" {
		t.Fatalf("UL peer = %+v", p)
	}
	if dl(table, sess) != 0 {
		t.Fatalf("UL FAR update must not set the DL tunnel: %#x", dl(table, sess))
	}

	modify(t, addr, seid, 3, pfcpie.NewUpdateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x02),
		pfcpie.NewUpdateForwardingParameters(pfcpie.NewDestinationInterface(pfcpie.DstInterfaceAccess),
			pfcpie.NewOuterHeaderCreation(0x0100, 0xCD, "172.30.3.1", "", 0, 0, 0))))
	if teid, ip := dlTunnel(table, n3); teid != 0xCD || !ip.Equal(net.ParseIP("172.30.3.1")) || sess.ULPeer() == nil {
		t.Fatalf("DL FAR update: dl %#x gnb %v peer %v", teid, ip, sess.ULPeer())
	}

	// UL FAR DROP (serving-network release step 1b) clears only the UL peer.
	modify(t, addr, seid, 4, pfcpie.NewUpdateFAR(pfcpie.NewFARID(2), pfcpie.NewApplyAction(0x01)))
	if sess.ULPeer() != nil || dl(table, sess) != 0xCD {
		t.Fatalf("UL DROP: peer %v dl %#x", sess.ULPeer(), dl(table, sess))
	}

	// Deletion removes both index entries.
	resp := sendAndRecv(t, addr, pfcpmsg.NewSessionDeletionRequest(0, 0, seid, 5, 0))
	if _, ok := resp.(*pfcpmsg.SessionDeletionResponse); !ok {
		t.Fatal("expected SessionDeletionResponse")
	}
	if table.GetByULTEID(n3) != nil || table.GetByULTEID(n9) != nil {
		t.Fatal("F-TEIDs still indexed after deletion")
	}
}

// TestHRHUPFRules: the H-UPF DL FAR carries the OHC to the V-UPF N9 F-TEID at
// establishment; the UL PDR (Source Access, F-TEID on N9) stays a plain TUN session.
func TestHRHUPFRules(t *testing.T) {
	_, table, addr, stop := startTestUPF(t)
	defer stop()
	const seid, ulTEID = uint64(82), uint32(0x41)
	est := pfcpmsg.NewSessionEstablishmentRequest(0, 0, 0, 1, 0,
		pfcpie.NewNodeID("", "", "smf"),
		pfcpie.NewFSEID(seid, net.ParseIP("127.0.0.1"), nil),
		pfcpie.NewCreatePDR(pfcpie.NewPDRID(1), pfcpie.NewPrecedence(100),
			pfcpie.NewPDI(pfcpie.NewSourceInterface(pfcpie.SrcInterfaceAccess),
				pfcpie.NewFTEID(0x01, ulTEID, net.ParseIP("172.30.20.200"), nil, 0),
				pfcpie.NewUEIPAddress(0x02, "10.70.0.5", "", 0, 0), pfcpie.NewNetworkInstance("internet")),
			pfcpie.NewOuterHeaderRemoval(0, 0), pfcpie.NewFARID(2)),
		pfcpie.NewCreatePDR(pfcpie.NewPDRID(2), pfcpie.NewPrecedence(100),
			pfcpie.NewPDI(pfcpie.NewSourceInterface(pfcpie.SrcInterfaceCore),
				pfcpie.NewUEIPAddress(0x04, "10.70.0.5", "", 0, 0), pfcpie.NewNetworkInstance("internet")),
			pfcpie.NewFARID(1)),
		pfcpie.NewCreateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x02),
			pfcpie.NewForwardingParameters(pfcpie.NewDestinationInterface(pfcpie.DstInterfaceAccess),
				pfcpie.NewOuterHeaderCreation(0x0100, 0x91, "172.30.20.100", "", 0, 0, 0))),
		pfcpie.NewCreateFAR(pfcpie.NewFARID(2), pfcpie.NewApplyAction(0x02),
			pfcpie.NewForwardingParameters(pfcpie.NewDestinationInterface(pfcpie.DstInterfaceCore))),
	)
	if _, ok := sendAndRecv(t, addr, est).(*pfcpmsg.SessionEstablishmentResponse); !ok {
		t.Fatal("expected SessionEstablishmentResponse")
	}
	sess := table.GetByULTEID(ulTEID)
	if sess == nil || sess.ULRelay || sess.N9TEID != 0 || sess.ULPeer() != nil {
		t.Fatalf("H-UPF session must not relay: %+v", sess)
	}
	if sess.DLTEID != 0x91 || !sess.GNBIP.Equal(net.ParseIP("172.30.20.100")) {
		t.Fatalf("DL tunnel = %#x %v, want V-UPF N9 F-TEID", sess.DLTEID, sess.GNBIP)
	}
	if table.GetByUEIP(net.ParseIP("10.70.0.5")) != sess {
		t.Fatal("session not indexed by UE IP")
	}
}

// TestNonHRSessionUnchanged: a plain N3 session has no N9 state, and an Update
// FAR on its UL FAR keeps the legacy behaviour (no relay interpretation).
func TestNonHRSessionUnchanged(t *testing.T) {
	_, table, addr, stop := startTestUPF(t)
	defer stop()
	const seid, ulTEID = uint64(83), uint32(0x51)
	est := pfcpmsg.NewSessionEstablishmentRequest(0, 0, 0, 1, 0,
		pfcpie.NewNodeID("", "", "smf"),
		pfcpie.NewFSEID(seid, net.ParseIP("127.0.0.1"), nil),
		pfcpie.NewCreatePDR(pfcpie.NewPDRID(1), pfcpie.NewPrecedence(100),
			pfcpie.NewPDI(pfcpie.NewSourceInterface(pfcpie.SrcInterfaceAccess),
				pfcpie.NewFTEID(0x01, ulTEID, net.ParseIP("127.0.0.1"), nil, 0),
				pfcpie.NewUEIPAddress(0x02, "10.60.0.9", "", 0, 0)),
			pfcpie.NewOuterHeaderRemoval(0, 0), pfcpie.NewFARID(2)),
		pfcpie.NewCreatePDR(pfcpie.NewPDRID(2), pfcpie.NewPrecedence(100),
			pfcpie.NewPDI(pfcpie.NewSourceInterface(pfcpie.SrcInterfaceCore),
				pfcpie.NewUEIPAddress(0x04, "10.60.0.9", "", 0, 0)),
			pfcpie.NewFARID(1)),
		pfcpie.NewCreateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x02),
			pfcpie.NewForwardingParameters(pfcpie.NewDestinationInterface(pfcpie.DstInterfaceAccess))),
		pfcpie.NewCreateFAR(pfcpie.NewFARID(2), pfcpie.NewApplyAction(0x02),
			pfcpie.NewForwardingParameters(pfcpie.NewDestinationInterface(pfcpie.DstInterfaceCore))),
	)
	if _, ok := sendAndRecv(t, addr, est).(*pfcpmsg.SessionEstablishmentResponse); !ok {
		t.Fatal("expected SessionEstablishmentResponse")
	}
	sess := table.GetByULTEID(ulTEID)
	if sess == nil || sess.ULRelay || sess.N9TEID != 0 || sess.ULPeer() != nil || sess.DLTEID != 0 {
		t.Fatalf("non-HR session carries N9 state: %+v", sess)
	}
}

// TestN9LogKeysUnique: the N9 UL peer set/cleared lines carry each JSON key once
// (the base logger already supplies nf and procedure).
func TestN9LogKeysUnique(t *testing.T) {
	var logs bytes.Buffer
	base := slog.New(slog.NewJSONHandler(&logs, nil)).With("nf", "UPF")
	srv := &Server{logger: base}
	sess := &Session{UPSEID: 7, ULFARID: 2}
	far := pfcpie.NewUpdateForwardingParameters(pfcpie.NewDestinationInterface(pfcpie.DstInterfaceCore),
		pfcpie.NewOuterHeaderCreation(0x0100, 0xAB, "172.30.20.200", "", 0, 0, 0))
	srv.updateULRelayFAR(context.Background(), sess, []*pfcpie.IE{far}, true, 0x02)
	srv.updateULRelayFAR(context.Background(), sess, nil, true, 0x00)
	lines := bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("log lines = %d, want 2: %s", len(lines), logs.String())
	}
	for _, line := range lines {
		dec := json.NewDecoder(bytes.NewReader(line))
		_, _ = dec.Token()
		seen := map[string]bool{}
		for dec.More() {
			k, _ := dec.Token()
			if seen[k.(string)] {
				t.Errorf("duplicate JSON key %q in %s", k, line)
			}
			seen[k.(string)] = true
			var v json.RawMessage
			_ = dec.Decode(&v)
		}
	}
}
