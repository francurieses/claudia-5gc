package pfcp

// farupdate_test.go — Update FAR Apply Action handling over a real PFCP/UDP
// round trip: FORW+OHC sets the DL tunnel, DROP clears it, absent Apply
// Action leaves it unchanged. Ref: TS 29.244 §7.5.4.3, §8.2.26.

import (
	"net"
	"testing"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"
)

func dlTunnel(table *SessionTable, teid uint32) (uint32, net.IP) {
	table.mu.RLock()
	defer table.mu.RUnlock()
	s := table.byULTEID[teid]
	if s == nil {
		return 0, nil
	}
	return s.DLTEID, append(net.IP(nil), s.GNBIP...)
}

func TestUpdateFARApplyAction(t *testing.T) {
	_, table, addr, stop := startTestUPF(t)
	defer stop()

	const seid = uint64(77)
	const ulTEID = uint32(9)
	est := pfcpmsg.NewSessionEstablishmentRequest(0, 0, 0, 1, 0,
		pfcpie.NewNodeID("", "", "smf"),
		pfcpie.NewFSEID(seid, net.ParseIP("127.0.0.1"), nil),
		pfcpie.NewCreatePDR(
			pfcpie.NewPDRID(1), pfcpie.NewPrecedence(100),
			pfcpie.NewPDI(
				pfcpie.NewSourceInterface(pfcpie.SrcInterfaceAccess),
				pfcpie.NewFTEID(0x01, ulTEID, net.ParseIP("127.0.0.1"), nil, 0),
				pfcpie.NewUEIPAddress(0x02, "10.60.0.9", "", 0, 0),
			),
			pfcpie.NewOuterHeaderRemoval(0, 0), pfcpie.NewFARID(1),
		),
		pfcpie.NewCreateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x02)),
	)
	if _, ok := sendAndRecv(t, addr, est).(*pfcpmsg.SessionEstablishmentResponse); !ok {
		t.Fatal("expected SessionEstablishmentResponse")
	}
	upSEID := table.GetByULTEID(ulTEID).UPSEID

	forw := func(teid uint32, ip string) *pfcpie.IE {
		return pfcpie.NewUpdateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x02),
			pfcpie.NewUpdateForwardingParameters(
				pfcpie.NewDestinationInterface(pfcpie.DstInterfaceAccess),
				pfcpie.NewOuterHeaderCreation(0x0100, teid, ip, "", 0, 0, 0)))
	}
	cases := []struct {
		name     string
		far      *pfcpie.IE
		wantTEID uint32
		wantIP   string
	}{
		{"FORW+OHC sets tunnel", forw(0x1234, "192.0.2.10"), 0x1234, "192.0.2.10"},
		{"absent Apply Action keeps tunnel", pfcpie.NewUpdateFAR(pfcpie.NewFARID(1)), 0x1234, "192.0.2.10"},
		{"DROP clears tunnel", pfcpie.NewUpdateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x01)), 0, ""},
		{"FORW+OHC re-sets tunnel", forw(0x5678, "192.0.2.20"), 0x5678, "192.0.2.20"},
		{"BUFF+NOCP clears tunnel", pfcpie.NewUpdateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x0C)), 0, ""},
	}
	for i, tc := range cases {
		mod := pfcpmsg.NewSessionModificationRequest(0, 0, upSEID, uint32(10+i), 0, tc.far)
		resp, ok := sendAndRecv(t, addr, mod).(*pfcpmsg.SessionModificationResponse)
		if !ok {
			t.Fatalf("%s: expected SessionModificationResponse", tc.name)
		}
		if c, err := resp.Cause.Cause(); err != nil || c != pfcpie.CauseRequestAccepted {
			t.Errorf("%s: cause = %d (%v), want Request accepted", tc.name, c, err)
		}
		teid, ip := dlTunnel(table, ulTEID)
		if teid != tc.wantTEID {
			t.Errorf("%s: DLTEID = %#x, want %#x", tc.name, teid, tc.wantTEID)
		}
		if tc.wantIP == "" {
			if len(ip) != 0 {
				t.Errorf("%s: GNBIP = %v, want nil", tc.name, ip)
			}
		} else if !ip.Equal(net.ParseIP(tc.wantIP)) {
			t.Errorf("%s: GNBIP = %v, want %s", tc.name, ip, tc.wantIP)
		}
	}
}
