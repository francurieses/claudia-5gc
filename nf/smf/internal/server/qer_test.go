package server

import (
	"net"
	"testing"
	"time"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"
)

// qerFields summarises the children of a (Create|Update) QER.
type qerFields struct {
	id             uint32
	hasMBR, hasQFI bool
	mbrUL, mbrDL   uint64
	qfi            uint8
}

func decodeQER(t *testing.T, ie *pfcpie.IE) qerFields {
	t.Helper()
	var children []*pfcpie.IE
	var err error
	switch ie.Type {
	case pfcpie.CreateQER:
		children, err = ie.CreateQER()
	case pfcpie.UpdateQER:
		children, err = ie.UpdateQER()
	default:
		t.Fatalf("unexpected IE type %v", ie.Type)
	}
	if err != nil {
		t.Fatalf("decode QER: %v", err)
	}
	var f qerFields
	for _, c := range children {
		switch c.Type {
		case pfcpie.QERID:
			f.id, _ = c.QERID()
		case pfcpie.MBR:
			f.hasMBR = true
			f.mbrUL, _ = c.MBRUL()
			f.mbrDL, _ = c.MBRDL()
		case pfcpie.QFI:
			f.hasQFI = true
			f.qfi, _ = c.QFI()
		}
	}
	return f
}

func TestBuildQERs(t *testing.T) {
	tests := []struct {
		name         string
		build        func() *pfcpie.IE
		wantID       uint32
		wantMBR      bool
		wantUL, want uint64
		wantQFI      bool
	}{
		{"create ambr", func() *pfcpie.IE { return buildSessionAMBRCreateQER(50000, 100000) }, sessionAMBRQERID, true, 50000, 100000, false},
		{"create ambr zero", func() *pfcpie.IE { return buildSessionAMBRCreateQER(0, 0) }, sessionAMBRQERID, false, 0, 0, false},
		{"create flow", buildDefaultFlowCreateQER, defaultFlowQERID, false, 0, 0, true},
		{"update ambr", func() *pfcpie.IE { return buildSessionAMBRUpdateQER(10000, 20000) }, sessionAMBRQERID, true, 10000, 20000, false},
		{"update ambr zero", func() *pfcpie.IE { return buildSessionAMBRUpdateQER(0, 0) }, sessionAMBRQERID, false, 0, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := decodeQER(t, tc.build())
			if f.id != tc.wantID || f.hasMBR != tc.wantMBR || f.hasQFI != tc.wantQFI {
				t.Fatalf("got %+v", f)
			}
			if tc.wantMBR && (f.mbrUL != tc.wantUL || f.mbrDL != tc.want) {
				t.Errorf("MBR UL/DL = %d/%d", f.mbrUL, f.mbrDL)
			}
			if tc.wantQFI && f.qfi != defaultQFI {
				t.Errorf("QFI = %d", f.qfi)
			}
		})
	}
}

func TestSendEstablishmentCarriesTwoQERs(t *testing.T) {
	upfConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer upfConn.Close()
	s := newTestSMFServer(t)
	s.cfg.Peers.UPF = upfConn.LocalAddr().String()
	sess := &Session{SUPI: "imsi-001010000000042", DNN: "internet",
		UEIP: net.ParseIP("10.60.0.10"), ULTEID: 5, SEID: 77, AMBRULMbps: 50, AMBRDLMbps: 100}
	s.sendPFCPSessionEstablishment(t.Context(), sess)

	buf := make([]byte, 2048)
	_ = upfConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := upfConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	m, err := pfcpmsg.Parse(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	req := m.(*pfcpmsg.SessionEstablishmentRequest)
	if len(req.CreateQER) != 2 {
		t.Fatalf("Create QERs = %d, want 2", len(req.CreateQER))
	}
	q1, q2 := decodeQER(t, req.CreateQER[0]), decodeQER(t, req.CreateQER[1])
	if q1.id != 1 || !q1.hasMBR || q1.hasQFI || q1.mbrUL != 50000 || q1.mbrDL != 100000 {
		t.Errorf("QER1 = %+v", q1)
	}
	if q2.id != 2 || q2.hasMBR || !q2.hasQFI || q2.qfi != 1 {
		t.Errorf("QER2 = %+v", q2)
	}
	pdrIEs, err := req.CreatePDR[0].CreatePDR()
	if err != nil {
		t.Fatal(err)
	}
	var ids []uint32
	for _, c := range pdrIEs {
		if c.Type == pfcpie.QERID {
			id, _ := c.QERID()
			ids = append(ids, id)
		}
	}
	if len(ids) != 2 || ids[0] != 1 || ids[1] != 2 {
		t.Errorf("PDR QER IDs = %v, want [1 2]", ids)
	}
}

func TestSendQoSModificationUpdatesAMBRQEROnly(t *testing.T) {
	got := make(chan []byte, 1)
	upfConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer upfConn.Close()
	s := newTestSMFServer(t)
	s.cfg.Peers.UPF = upfConn.LocalAddr().String()
	sess := &Session{SUPI: "imsi-001010000000042", SEID: 77, AMBRULMbps: 7, AMBRDLMbps: 9, FiveQI: 9}
	go func() {
		buf := make([]byte, 2048)
		_ = upfConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, addr, err := upfConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		got <- append([]byte(nil), buf[:n]...)
		rsp := pfcpmsg.NewSessionModificationResponse(0, 0, 77, 1, 0, pfcpie.NewCause(pfcpie.CauseRequestAccepted))
		if b, err := rsp.Marshal(); err == nil {
			_, _ = upfConn.WriteToUDP(b, addr)
		}
	}()
	if !s.sendPFCPQoSModification(t.Context(), sess) {
		t.Fatal("modification not acknowledged")
	}
	m, err := pfcpmsg.Parse(<-got)
	if err != nil {
		t.Fatal(err)
	}
	req := m.(*pfcpmsg.SessionModificationRequest)
	if len(req.UpdateQER) != 1 {
		t.Fatalf("Update QERs = %d, want 1", len(req.UpdateQER))
	}
	q := decodeQER(t, req.UpdateQER[0])
	if q.id != 1 || !q.hasMBR || q.hasQFI || q.mbrUL != 7000 || q.mbrDL != 9000 {
		t.Errorf("Update QER = %+v", q)
	}
}
