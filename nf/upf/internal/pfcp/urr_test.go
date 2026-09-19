package pfcp

// urr_test.go — PFCP Usage Reporting (URR) unit tests: parsing Create URR at
// Session Establishment, wire round-trip of the Session Report Request Usage
// Report, and VOLTH threshold arithmetic exercised through the real
// sweepUsageReports sweep. Ref: TS 29.244 §5.2.2.4, §7.5.2.4, §7.5.5, §7.5.8.
import (
	"context"
	"net"
	"testing"
	"time"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"
)

// newEstablishmentWithURR builds a Session Establishment Request carrying a
// Create PDR/FAR (minimal, mirrors qer_test.go) plus a Create URR with both
// VOLTH and PERIO triggers armed.
func newEstablishmentWithURR(t *testing.T, seid uint64, ulTEID uint32, urrID uint32, volThreshold uint64, period time.Duration) *pfcpmsg.SessionEstablishmentRequest {
	t.Helper()
	return pfcpmsg.NewSessionEstablishmentRequest(
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
			pfcpie.NewURRID(urrID),
		),
		pfcpie.NewCreateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x02)),
		pfcpie.NewCreateURR(
			pfcpie.NewURRID(urrID),
			pfcpie.NewMeasurementMethod(0, 1, 1), // event=0, volum=1, durat=1
			// Reporting Triggers is a 2-octet IE (TS 29.244 §8.2.41); octet 1
			// (PERIO=bit1/0x01, VOLTH=bit2/0x02) is the *high* byte of the
			// big-endian uint16 the go-pfcp constructor takes.
			pfcpie.NewReportingTriggers(0x0300), // VOLTH + PERIO in octet 1
			pfcpie.NewVolumeThreshold(0x01, volThreshold, 0, 0),
			pfcpie.NewMeasurementPeriod(period),
		),
	)
}

// TestSessionEstablishmentStoresURR verifies the UPF extracts URR ID,
// VOLTH/PERIO triggers, volume threshold and measurement period from a
// Create URR, and marks the URR as installed.
func TestSessionEstablishmentStoresURR(t *testing.T) {
	_, table, addr, stop := startTestUPF(t)
	defer stop()

	const seid = uint64(100)
	const ulTEID = uint32(11)
	const urrID = uint32(1)
	const volThreshold = uint64(1_000_000) // 1 MB
	const period = 60 * time.Second

	est := newEstablishmentWithURR(t, seid, ulTEID, urrID, volThreshold, period)
	resp := sendAndRecv(t, addr, est)
	if _, ok := resp.(*pfcpmsg.SessionEstablishmentResponse); !ok {
		t.Fatalf("expected SessionEstablishmentResponse, got %s", resp.MessageTypeName())
	}

	sess := table.GetByULTEID(ulTEID)
	if sess == nil {
		t.Fatal("session not stored")
	}
	if !sess.URRState.Installed {
		t.Fatal("URRState.Installed = false, want true")
	}
	if sess.URRState.URRID != urrID {
		t.Errorf("URR ID: got %d want %d", sess.URRState.URRID, urrID)
	}
	if !sess.URRState.TriggerVOLTH {
		t.Error("TriggerVOLTH = false, want true")
	}
	if !sess.URRState.TriggerPERIO {
		t.Error("TriggerPERIO = false, want true")
	}
	if !sess.URRState.MeasureVolume || !sess.URRState.MeasureDuration {
		t.Errorf("MeasureVolume/MeasureDuration = %v/%v, want true/true",
			sess.URRState.MeasureVolume, sess.URRState.MeasureDuration)
	}
	if sess.URRState.VolumeThreshold != volThreshold {
		t.Errorf("VolumeThreshold: got %d want %d", sess.URRState.VolumeThreshold, volThreshold)
	}
	if sess.URRState.MeasurementPeriod != period {
		t.Errorf("MeasurementPeriod: got %v want %v", sess.URRState.MeasurementPeriod, period)
	}
	if sess.URRState.StartTime.IsZero() {
		t.Error("StartTime not set")
	}
	if sess.SMFAddr == nil || sess.SMFAddr.Port != smfPFCPPort {
		t.Errorf("SMFAddr not captured correctly: %+v", sess.SMFAddr)
	}
}

// TestNoURRNeverInstalled verifies a session established without a Create
// URR never sets Installed, and that AddULVolume/AddDLVolume are no-ops for
// it — such sessions must never emit reports.
func TestNoURRNeverInstalled(t *testing.T) {
	_, table, addr, stop := startTestUPF(t)
	defer stop()

	const seid = uint64(101)
	const ulTEID = uint32(12)

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
				pfcpie.NewUEIPAddress(0x02, "10.60.0.6", "", 0, 0),
			),
			pfcpie.NewOuterHeaderRemoval(0, 0),
			pfcpie.NewFARID(1),
		),
		pfcpie.NewCreateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x02)),
	)
	resp := sendAndRecv(t, addr, est)
	if _, ok := resp.(*pfcpmsg.SessionEstablishmentResponse); !ok {
		t.Fatalf("expected SessionEstablishmentResponse, got %s", resp.MessageTypeName())
	}

	sess := table.GetByULTEID(ulTEID)
	if sess == nil {
		t.Fatal("session not stored")
	}
	if sess.URRState.Installed {
		t.Error("URRState.Installed = true, want false (no Create URR sent)")
	}

	sess.AddULVolume(10_000_000)
	sess.AddDLVolume(5_000_000)
	if sess.URRState.ULVolume.Load() != 0 || sess.URRState.DLVolume.Load() != 0 {
		t.Errorf("AddULVolume/AddDLVolume should be no-ops without an installed URR, got ul=%d dl=%d",
			sess.URRState.ULVolume.Load(), sess.URRState.DLVolume.Load())
	}
}

// usageReportChild extracts a specific IE type from a Usage Report grouped
// IE. Several accessor helpers on *pfcpie.IE only dispatch through wrapper
// types they explicitly special-case (e.g. VolumeMeasurement, DurationMeasurement,
// URRID) — UsageReportTrigger's Has* bit helpers and URSEQN() do not,
// so tests must pull the child IE out first and call the accessor on it
// directly.
func usageReportChild(t *testing.T, ur *pfcpie.IE, typ uint16) *pfcpie.IE {
	t.Helper()
	children, err := ur.UsageReport()
	if err != nil {
		t.Fatalf("UsageReport(): %v", err)
	}
	for _, c := range children {
		if c.Type == typ {
			return c
		}
	}
	t.Fatalf("child IE type %d not found in Usage Report", typ)
	return nil
}

// TestUsageReportWireRoundTrip builds a Session Report Request Usage Report
// exactly as emitUsageReport does, marshals it, and re-parses it via
// pfcpmsg.Parse — proving the wire format is well-formed (critical for the
// SMF and Wireshark to dissect it). Ref: TS 29.244 §7.5.5, §7.5.8.
func TestUsageReportWireRoundTrip(t *testing.T) {
	const cpSEID = uint64(555)
	const urrID = uint32(1)
	const urSeqn = uint32(3)
	const ul = uint64(600_000)
	const dl = uint64(400_000)
	const ulPkt = uint64(500)
	const dlPkt = uint64(300)
	total := ul + dl
	totalPkt := ulPkt + dlPkt
	duration := 42 * time.Second

	report := pfcpmsg.NewSessionReportRequest(0, 0, cpSEID, 7, 0,
		pfcpie.NewReportType(0, 0, 1, 0),
		pfcpie.NewUsageReportWithinSessionReportRequest(
			pfcpie.NewURRID(urrID),
			pfcpie.NewURSEQN(urSeqn),
			pfcpie.NewUsageReportTrigger(usageReportTriggerVOLTH, 0x00, 0x00),
			pfcpie.NewVolumeMeasurement(volumeMeasurementFlags, total, ul, dl, totalPkt, ulPkt, dlPkt),
			pfcpie.NewDurationMeasurement(duration),
		),
	)

	b := make([]byte, report.MarshalLen())
	if err := report.MarshalTo(b); err != nil {
		t.Fatalf("marshal: %v", err)
	}

	parsed, err := pfcpmsg.Parse(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	srr, ok := parsed.(*pfcpmsg.SessionReportRequest)
	if !ok {
		t.Fatalf("expected SessionReportRequest, got %T", parsed)
	}
	if srr.SEID() != cpSEID {
		t.Errorf("SEID: got %d want %d", srr.SEID(), cpSEID)
	}
	if srr.ReportType == nil || !srr.ReportType.HasUSAR() {
		t.Fatal("Report Type missing or USAR bit not set")
	}
	if len(srr.UsageReport) != 1 {
		t.Fatalf("expected 1 Usage Report, got %d", len(srr.UsageReport))
	}

	ur := srr.UsageReport[0]
	gotID, err := ur.URRID()
	if err != nil {
		t.Fatalf("URRID: %v", err)
	}
	if gotID != urrID {
		t.Errorf("URR ID: got %d want %d", gotID, urrID)
	}

	seqIE := usageReportChild(t, ur, pfcpie.URSEQN)
	gotSeq, err := seqIE.URSEQN()
	if err != nil {
		t.Fatalf("URSEQN: %v", err)
	}
	if gotSeq != urSeqn {
		t.Errorf("UR-SEQN: got %d want %d", gotSeq, urSeqn)
	}

	trigIE := usageReportChild(t, ur, pfcpie.UsageReportTrigger)
	if !trigIE.HasVOLTH() {
		t.Error("Usage Report Trigger: HasVOLTH() = false, want true")
	}
	if trigIE.HasPERIO() {
		t.Error("Usage Report Trigger: HasPERIO() = true, want false")
	}

	vol, err := ur.VolumeMeasurement()
	if err != nil {
		t.Fatalf("VolumeMeasurement: %v", err)
	}
	if vol.TotalVolume != total || vol.UplinkVolume != ul || vol.DownlinkVolume != dl {
		t.Errorf("VolumeMeasurement: got total=%d ul=%d dl=%d, want total=%d ul=%d dl=%d",
			vol.TotalVolume, vol.UplinkVolume, vol.DownlinkVolume, total, ul, dl)
	}

	dm, err := ur.DurationMeasurement()
	if err != nil {
		t.Fatalf("DurationMeasurement: %v", err)
	}
	if dm != duration {
		t.Errorf("DurationMeasurement: got %v want %v", dm, duration)
	}
}

// TestUsageReportPERIOTrigger mirrors the VOLTH round-trip but for a PERIO
// report, confirming the trigger octet distinguishes the two cases.
func TestUsageReportPERIOTrigger(t *testing.T) {
	report := pfcpmsg.NewSessionReportRequest(0, 0, 1, 1, 0,
		pfcpie.NewReportType(0, 0, 1, 0),
		pfcpie.NewUsageReportWithinSessionReportRequest(
			pfcpie.NewURRID(1),
			pfcpie.NewURSEQN(1),
			pfcpie.NewUsageReportTrigger(usageReportTriggerPERIO, 0x00, 0x00),
			pfcpie.NewVolumeMeasurement(volumeMeasurementFlags, 100, 60, 40, 10, 6, 4),
			pfcpie.NewDurationMeasurement(60*time.Second),
		),
	)
	b := make([]byte, report.MarshalLen())
	if err := report.MarshalTo(b); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := pfcpmsg.Parse(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	srr := parsed.(*pfcpmsg.SessionReportRequest)
	ur := srr.UsageReport[0]
	trigIE := usageReportChild(t, ur, pfcpie.UsageReportTrigger)
	if !trigIE.HasPERIO() {
		t.Error("HasPERIO() = false, want true")
	}
	if trigIE.HasVOLTH() {
		t.Error("HasVOLTH() = true, want false")
	}
}

// recvSessionReport reads one PFCP message from conn (with a generous
// deadline) and asserts it decodes as a SessionReportRequest.
func recvSessionReport(t *testing.T, conn *net.UDPConn) *pfcpmsg.SessionReportRequest {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("expected a Session Report Request, got no message: %v", err)
	}
	msg, err := pfcpmsg.Parse(buf[:n])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	srr, ok := msg.(*pfcpmsg.SessionReportRequest)
	if !ok {
		t.Fatalf("expected SessionReportRequest, got %s", msg.MessageTypeName())
	}
	return srr
}

// assertNoMessage asserts no PFCP message arrives on conn within d.
func assertNoMessage(t *testing.T, conn *net.UDPConn, d time.Duration) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err == nil {
		t.Fatalf("expected no message, got %d bytes", n)
	}
}

// TestSweepUsageReportsVOLTHThreshold drives the real Server.sweepUsageReports
// against a session whose volume crosses VolumeThreshold, verifying: (1) a
// session below threshold does not emit; (2) crossing the threshold emits a
// VOLTH report and re-arms the baseline; (3) a second crossing (after the
// baseline moved) fires again.
func TestSweepUsageReportsVOLTHThreshold(t *testing.T) {
	srv, table, _, stop := startTestUPF(t)
	defer stop()

	smfConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen fake SMF: %v", err)
	}
	defer smfConn.Close()

	sess := &Session{CPSEID: 900, UPSEID: 900, SMFAddr: smfConn.LocalAddr().(*net.UDPAddr)}
	sess.URRState.Installed = true
	sess.URRState.URRID = 1
	sess.URRState.TriggerVOLTH = true
	sess.URRState.VolumeThreshold = 1000
	sess.URRState.StartTime = time.Now()
	table.store(sess)

	ctx := context.Background()

	// Below threshold: sweep must not emit.
	sess.URRState.ULVolume.Store(500)
	srv.sweepUsageReports(ctx)
	assertNoMessage(t, smfConn, 300*time.Millisecond)

	// Crosses threshold: sweep must emit VOLTH and re-arm the baseline.
	sess.URRState.ULVolume.Store(1200)
	srv.sweepUsageReports(ctx)
	srr := recvSessionReport(t, smfConn)
	ur := srr.UsageReport[0]
	trigIE := usageReportChild(t, ur, pfcpie.UsageReportTrigger)
	if !trigIE.HasVOLTH() {
		t.Error("expected VOLTH trigger on first crossing")
	}
	vol, err := ur.VolumeMeasurement()
	if err != nil {
		t.Fatalf("VolumeMeasurement: %v", err)
	}
	if vol.TotalVolume != 1200 {
		t.Errorf("total volume: got %d want 1200", vol.TotalVolume)
	}

	// Baseline re-armed at 1200: no new growth => no emit.
	srv.sweepUsageReports(ctx)
	assertNoMessage(t, smfConn, 300*time.Millisecond)

	// Grows by another 1100 bytes past the new baseline: fires again.
	sess.URRState.ULVolume.Store(2300)
	srv.sweepUsageReports(ctx)
	srr2 := recvSessionReport(t, smfConn)
	vol2, err := srr2.UsageReport[0].VolumeMeasurement()
	if err != nil {
		t.Fatalf("VolumeMeasurement: %v", err)
	}
	if vol2.TotalVolume != 2300 {
		t.Errorf("total volume on re-crossing: got %d want 2300", vol2.TotalVolume)
	}
}

// TestSweepUsageReportsSkipsUninstalled verifies a session with no URR
// installed is never selected by the sweep, regardless of accumulated
// volume — the Installed guard must be checked before any threshold math.
func TestSweepUsageReportsSkipsUninstalled(t *testing.T) {
	srv, table, _, stop := startTestUPF(t)
	defer stop()

	smfConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen fake SMF: %v", err)
	}
	defer smfConn.Close()

	sess := &Session{CPSEID: 901, UPSEID: 901, SMFAddr: smfConn.LocalAddr().(*net.UDPAddr)}
	sess.URRState.Installed = false // no Create URR was ever parsed
	sess.URRState.TriggerVOLTH = true
	sess.URRState.VolumeThreshold = 1
	sess.URRState.ULVolume.Store(1_000_000)
	table.store(sess)

	srv.sweepUsageReports(context.Background())
	assertNoMessage(t, smfConn, 300*time.Millisecond)
}
