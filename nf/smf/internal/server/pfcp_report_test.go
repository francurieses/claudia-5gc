package server

// pfcp_report_test.go — unit tests for the SMF-side PFCP Usage Reporting
// consumption seam (UPF-001, TS 29.244 §5.2.2.4, §7.5.5, §7.5.8, §7.5.9).
// These exercise consumeSessionReport directly (no UDP socket), matching the
// scenarios in tests/features/usage_reporting.feature.

import (
	"net"
	"testing"
	"time"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"
)

// buildUsageReportRequest constructs a PFCP Session Report Request carrying
// one Usage Report IE, mirroring the UPF's emitUsageReport encoding.
func buildUsageReportRequest(t *testing.T, seid uint64, urrID uint32, urSeqn uint32, trigger uint8, total, ul, dl uint64, duration time.Duration) *pfcpmsg.SessionReportRequest {
	t.Helper()
	req := pfcpmsg.NewSessionReportRequest(0, 0, seid, 1, 0,
		pfcpie.NewReportType(0, 0, 1, 0),
		pfcpie.NewUsageReportWithinSessionReportRequest(
			pfcpie.NewURRID(urrID),
			pfcpie.NewURSEQN(urSeqn),
			pfcpie.NewUsageReportTrigger(trigger, 0x00, 0x00),
			pfcpie.NewVolumeMeasurement(volumeMeasurementFlagsForTest, total, ul, dl, 0, 0, 0),
			pfcpie.NewDurationMeasurement(duration),
		),
	)

	// Round-trip through Marshal/Parse so the test exercises the exact same
	// decode path a real inbound UDP datagram would take.
	b, err := req.Marshal()
	if err != nil {
		t.Fatalf("marshal session report request: %v", err)
	}
	msg, err := pfcpmsg.Parse(b)
	if err != nil {
		t.Fatalf("parse session report request: %v", err)
	}
	parsed, ok := msg.(*pfcpmsg.SessionReportRequest)
	if !ok {
		t.Fatalf("parsed message is not a SessionReportRequest: %T", msg)
	}
	return parsed
}

// volumeMeasurementFlagsForTest mirrors the UPF's flags (TOVOL|ULVOL|DLVOL +
// packet counters), TS 29.244 §8.2.5.
const volumeMeasurementFlagsForTest uint8 = 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20

func newUsageReportTestSession(s *Server, seid uint64) *Session {
	sess := &Session{
		SUPI:         "imsi-001010000000099",
		PDUSessionID: 1,
		DNN:          "internet",
		UEIP:         net.ParseIP("10.60.0.9"),
		ULTEID:       9,
		SEID:         seid,
		State:        "ACTIVE",
		CreatedAt:    time.Now(),
	}
	s.sessionMu.Lock()
	s.sessions["ctx-usage-report"] = sess
	s.sessionMu.Unlock()
	return sess
}

// TestReportingTriggersBitmaskRoundTrip verifies the exact bit layout chosen
// for reportingTriggersPerioVolth: after a Marshal/Parse round trip, the
// decoded Reporting Triggers IE must report both HasPERIO() and HasVOLTH().
// This is the [VERIFY] item called out in docs/procedures/UsageReporting.md.
func TestReportingTriggersBitmaskRoundTrip(t *testing.T) {
	ie := pfcpie.NewReportingTriggers(reportingTriggersPerioVolth)
	b, err := ie.Marshal()
	if err != nil {
		t.Fatalf("marshal reporting triggers: %v", err)
	}
	parsed, err := pfcpie.Parse(b)
	if err != nil {
		t.Fatalf("parse reporting triggers: %v", err)
	}
	if !parsed.HasPERIO() {
		t.Error("expected HasPERIO() == true after round trip")
	}
	if !parsed.HasVOLTH() {
		t.Error("expected HasVOLTH() == true after round trip")
	}
}

// TestSendPFCPSessionEstablishmentInstallsURR verifies the establishment
// request now carries a Create URR (linked from the PDR) with the expected
// method/triggers/threshold/period fields.
func TestSendPFCPSessionEstablishmentInstallsURR(t *testing.T) {
	// Fake a UPF listening on an ephemeral UDP port so sendPFCPSessionEstablishment
	// has somewhere to send the request; we only inspect what was sent.
	upfConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen fake UPF: %v", err)
	}
	defer upfConn.Close()

	s := newTestSMFServer(t)
	s.cfg.Peers.UPF = upfConn.LocalAddr().String()
	s.cfg.N4.VolumeThresholdBytes = 2000000
	s.cfg.N4.MeasurementPeriodSeconds = 45

	sess := &Session{
		SUPI: "imsi-001010000000042", DNN: "internet",
		UEIP: net.ParseIP("10.60.0.10"), ULTEID: 5, SEID: 77,
		AMBRULMbps: 50, AMBRDLMbps: 100,
	}

	s.sendPFCPSessionEstablishment(t.Context(), sess)

	buf := make([]byte, 2048)
	_ = upfConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := upfConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("fake UPF did not receive establishment request: %v", err)
	}
	msg, err := pfcpmsg.Parse(buf[:n])
	if err != nil {
		t.Fatalf("parse establishment request: %v", err)
	}
	req, ok := msg.(*pfcpmsg.SessionEstablishmentRequest)
	if !ok {
		t.Fatalf("unexpected message type: %T", msg)
	}

	if len(req.CreateURR) != 1 {
		t.Fatalf("expected exactly 1 Create URR, got %d", len(req.CreateURR))
	}
	urrIEs, err := req.CreateURR[0].CreateURR()
	if err != nil {
		t.Fatalf("decode Create URR: %v", err)
	}
	var gotURRID uint32
	var gotVolThreshold uint64
	var gotPeriod time.Duration
	var gotVOLTH, gotPERIO bool
	for _, child := range urrIEs {
		switch child.Type {
		case pfcpie.URRID:
			gotURRID, _ = child.URRID()
		case pfcpie.MeasurementMethod:
			if !child.HasVOLUM() || !child.HasDURAT() {
				t.Error("expected Measurement Method VOLUM+DURAT set")
			}
		case pfcpie.ReportingTriggers:
			gotVOLTH = child.HasVOLTH()
			gotPERIO = child.HasPERIO()
		case pfcpie.VolumeThreshold:
			if vt, err := child.VolumeThreshold(); err == nil {
				gotVolThreshold = vt.TotalVolume
			}
		case pfcpie.MeasurementPeriod:
			gotPeriod, _ = child.MeasurementPeriod()
		}
	}
	if gotURRID != usageReportingURRID {
		t.Errorf("URR ID = %d, want %d", gotURRID, usageReportingURRID)
	}
	if !gotVOLTH || !gotPERIO {
		t.Errorf("Reporting Triggers VOLTH=%v PERIO=%v, want both true", gotVOLTH, gotPERIO)
	}
	if gotVolThreshold != 2000000 {
		t.Errorf("Volume Threshold = %d, want 2000000", gotVolThreshold)
	}
	if gotPeriod != 45*time.Second {
		t.Errorf("Measurement Period = %s, want 45s", gotPeriod)
	}

	// PDR must reference the same URR ID.
	if len(req.CreatePDR) != 1 {
		t.Fatalf("expected exactly 1 Create PDR, got %d", len(req.CreatePDR))
	}
	pdrURRID, err := req.CreatePDR[0].URRID()
	if err != nil {
		t.Fatalf("PDR URR ID link missing: %v", err)
	}
	if pdrURRID != usageReportingURRID {
		t.Errorf("PDR URR ID link = %d, want %d", pdrURRID, usageReportingURRID)
	}
}

// TestConsumeSessionReport_VolumeThreshold matches the feature's first
// scenario: a VOLTH Usage Report is parsed and Cause=Request accepted.
func TestConsumeSessionReport_VolumeThreshold(t *testing.T) {
	s := newTestSMFServer(t)
	newUsageReportTestSession(s, 0x1001)

	req := buildUsageReportRequest(t, 0x1001, usageReportingURRID, 1, usageReportTriggerVOLTHForTest,
		524288, 400000, 124288, 30*time.Second)

	cause, summary := s.consumeSessionReport(t.Context(), req)

	if cause != pfcpie.CauseRequestAccepted {
		t.Errorf("cause = %d, want CauseRequestAccepted", cause)
	}
	if summary.Trigger != "VOLTH" {
		t.Errorf("trigger = %q, want VOLTH", summary.Trigger)
	}
	if summary.TotalVolume != 524288 || summary.ULVolume != 400000 || summary.DLVolume != 124288 {
		t.Errorf("volume = %+v, want total=524288 ul=400000 dl=124288", summary)
	}
	if summary.DurationSeconds != 30 {
		t.Errorf("duration = %v, want 30s", summary.DurationSeconds)
	}
	if summary.URRID != usageReportingURRID {
		t.Errorf("urr id = %d, want %d", summary.URRID, usageReportingURRID)
	}
	if !summary.KnownURR {
		t.Error("expected KnownURR = true")
	}
}

// TestConsumeSessionReport_Periodic matches the feature's second scenario.
func TestConsumeSessionReport_Periodic(t *testing.T) {
	s := newTestSMFServer(t)
	newUsageReportTestSession(s, 0x1001)

	req := buildUsageReportRequest(t, 0x1001, usageReportingURRID, 2, usageReportTriggerPERIOForTest,
		1048576, 800000, 248576, 60*time.Second)

	cause, summary := s.consumeSessionReport(t.Context(), req)

	if cause != pfcpie.CauseRequestAccepted {
		t.Errorf("cause = %d, want CauseRequestAccepted", cause)
	}
	if summary.Trigger != "PERIO" {
		t.Errorf("trigger = %q, want PERIO", summary.Trigger)
	}
	if summary.TotalVolume != 1048576 {
		t.Errorf("total volume = %d, want 1048576", summary.TotalVolume)
	}
}

// TestConsumeSessionReport_UnknownSEID matches the feature's third scenario:
// no matching session → Cause = Session context not found, and no session is
// fabricated.
func TestConsumeSessionReport_UnknownSEID(t *testing.T) {
	s := newTestSMFServer(t)
	// No session seeded for this SEID.
	const unknownSEID = 0xDEADBEEF

	req := buildUsageReportRequest(t, unknownSEID, usageReportingURRID, 1, usageReportTriggerVOLTHForTest,
		100000, 60000, 40000, 10*time.Second)

	cause, _ := s.consumeSessionReport(t.Context(), req)

	if cause != pfcpie.CauseSessionContextNotFound {
		t.Errorf("cause = %d, want CauseSessionContextNotFound", cause)
	}
	if s.sessionBySEID(unknownSEID) != nil {
		t.Error("a session must not be created for an unknown SEID")
	}
}

// TestConsumeSessionReport_UnknownURRID matches the feature's fourth
// scenario: an unrecognised URR ID must not crash and still returns a
// well-formed (accepted) response with a WARN logged.
func TestConsumeSessionReport_UnknownURRID(t *testing.T) {
	s := newTestSMFServer(t)
	newUsageReportTestSession(s, 0x1001)

	req := buildUsageReportRequest(t, 0x1001, 99, 1, usageReportTriggerVOLTHForTest,
		200000, 100000, 100000, 5*time.Second)

	cause, summary := s.consumeSessionReport(t.Context(), req)

	if cause != pfcpie.CauseRequestAccepted {
		t.Errorf("cause = %d, want CauseRequestAccepted (accept + warn for unknown URR)", cause)
	}
	if summary.KnownURR {
		t.Error("expected KnownURR = false for URR ID 99")
	}
	if summary.URRID != 99 {
		t.Errorf("urr id = %d, want 99", summary.URRID)
	}
}

// TestConsumeSessionReport_TwoConsecutiveReports matches the feature's fifth
// scenario: two Usage Reports for the same session are consumed
// independently (each with its own UR-SEQN/trigger/volume), and each answers
// with Cause = Request accepted.
func TestConsumeSessionReport_TwoConsecutiveReports(t *testing.T) {
	s := newTestSMFServer(t)
	newUsageReportTestSession(s, 0x1001)

	req1 := buildUsageReportRequest(t, 0x1001, usageReportingURRID, 1, usageReportTriggerVOLTHForTest,
		300000, 200000, 100000, 15*time.Second)
	cause1, summary1 := s.consumeSessionReport(t.Context(), req1)

	req2 := buildUsageReportRequest(t, 0x1001, usageReportingURRID, 2, usageReportTriggerPERIOForTest,
		700000, 500000, 200000, 45*time.Second)
	cause2, summary2 := s.consumeSessionReport(t.Context(), req2)

	if cause1 != pfcpie.CauseRequestAccepted || cause2 != pfcpie.CauseRequestAccepted {
		t.Errorf("both reports must be accepted: cause1=%d cause2=%d", cause1, cause2)
	}
	if summary1.URSeqn != 1 || summary1.Trigger != "VOLTH" {
		t.Errorf("report 1 = %+v, want UR-SEQN=1 trigger=VOLTH", summary1)
	}
	if summary2.URSeqn != 2 || summary2.Trigger != "PERIO" {
		t.Errorf("report 2 = %+v, want UR-SEQN=2 trigger=PERIO", summary2)
	}
}

// usageReportTriggerVOLTHForTest / usageReportTriggerPERIOForTest mirror the
// UPF's trigger octet constants (TS 29.244 §8.2.44 Figure 8.2.44-1): PERIO =
// bit 1 (0x01), VOLTH = bit 2 (0x02).
const (
	usageReportTriggerPERIOForTest uint8 = 0x01
	usageReportTriggerVOLTHForTest uint8 = 0x02
)
