//go:build functional

// godog step definitions for PFCP Usage Reporting consumption at the SMF
// (UPF-001, TS 29.244 §5.2.2.4, §7.5.5 Session Report Request, §7.5.8 Usage
// Report IE, §7.5.9 Session Report Response, §8.2.44 Usage Report Trigger,
// §8.2.5 Volume Measurement, §8.2.42 Duration Measurement).
//
// These steps drive the real production seam (Server.consumeSessionReport)
// in-process: no PFCP UDP socket is opened. Requests are built with the same
// go-pfcp constructors the UPF uses and round-tripped through Marshal/Parse
// so the decode path under test matches a real inbound datagram exactly.
//
// Run with: go test -tags=functional ./nf/smf/...  (see Makefile test-functional)
package server

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cucumber/godog"
	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
)

// usageReportWorld holds the state threaded through a single scenario of
// usage_reporting.feature. The underlying *Server and its session table are
// shared across scenarios in the suite (mirroring the ipv6World pattern in
// ipv6_functional_test.go); per-scenario transient state (log buffer,
// causes/summaries collected) is reset in a Before hook so scenarios stay
// order-independent.
type usageReportWorld struct {
	s      *Server
	logBuf *bytes.Buffer

	lastCause   uint8
	lastSummary UsageSummary
	causes      []uint8
	summaries   []UsageSummary

	buildErr error
}

// newUsageReportWorld constructs a Server sufficient to exercise
// consumeSessionReport without opening any socket: an in-memory config, a
// slog logger writing to a resettable buffer (so log-content steps can
// assert on it), and a nil persistence store (Server tolerates nil store —
// see newTestSMFServer in smf_modify_test.go for the same pattern).
func newUsageReportWorld() *usageReportWorld {
	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(buf, nil))
	cfg := &config.Config{UEIPPool: "10.60.0.0/24"}
	s, err := New(cfg, logger, nil)
	if err != nil {
		// New() only fails on a malformed UEIPPool CIDR; the literal above is
		// valid, so this indicates a real regression worth failing loudly on.
		panic(fmt.Sprintf("usage_reporting steps: New(server): %v", err))
	}
	return &usageReportWorld{s: s, logBuf: buf}
}

// parseSEIDHex parses a CP F-SEID string as it appears in the feature file,
// e.g. "0x1001" or "0xDEADBEEF", into a uint64.
func parseSEIDHex(hex string) (uint64, error) {
	trimmed := strings.TrimPrefix(strings.TrimPrefix(hex, "0X"), "0x")
	v, err := strconv.ParseUint(trimmed, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("parse SEID %q: %w", hex, err)
	}
	return v, nil
}

// triggerByteFor maps the feature file's trigger name to the trigger octet
// the UPF would set (TS 29.244 §8.2.44 Figure 8.2.44-1): PERIO = bit 1
// (0x01), VOLTH = bit 2 (0x02). Reuses the constants declared for the unit
// tests in pfcp_report_test.go (same package, no build tag).
func triggerByteFor(name string) (uint8, error) {
	switch name {
	case "VOLTH":
		return usageReportTriggerVOLTHForTest, nil
	case "PERIO":
		return usageReportTriggerPERIOForTest, nil
	default:
		return 0, fmt.Errorf("unknown Usage Report trigger name %q", name)
	}
}

// causeByteFor maps the feature file's Cause name to the go-pfcp Cause value
// (TS 29.244 §8.2.1 / IANA PFCP Cause values).
func causeByteFor(name string) (uint8, error) {
	switch name {
	case "Request accepted":
		return pfcpie.CauseRequestAccepted, nil
	case "Session context not found":
		return pfcpie.CauseSessionContextNotFound, nil
	default:
		return 0, fmt.Errorf("unknown Cause name %q", name)
	}
}

// buildSessionReportRequestForStep constructs a PFCP Session Report Request
// carrying one Usage Report IE, mirroring the UPF's emitUsageReport encoding
// and buildUsageReportRequest in pfcp_report_test.go — but returning an error
// instead of taking a *testing.T, since godog step functions must never
// panic/t.Fatal (per house rules) and godog.T(ctx) only yields a TestingT
// interface, not the concrete *testing.T that helper requires.
func buildSessionReportRequestForStep(seid uint64, urrID uint32, urSeqn uint32, trigger uint8, total, ul, dl uint64, duration time.Duration) (*pfcpmsg.SessionReportRequest, error) {
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

	// Round-trip through Marshal/Parse so the step exercises the exact same
	// decode path a real inbound UDP datagram would take (TS 29.244 §6.2.1).
	b, err := req.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal session report request: %w", err)
	}
	msg, err := pfcpmsg.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("parse session report request: %w", err)
	}
	parsed, ok := msg.(*pfcpmsg.SessionReportRequest)
	if !ok {
		return nil, fmt.Errorf("parsed message is not a SessionReportRequest: %T", msg)
	}
	return parsed, nil
}

// anActivePDUSession implements the Background step: registers a session in
// the Server's session table keyed by the given CP F-SEID, with URR id 1
// installed (matching usageReportingURRID, TS 29.244 §7.5.2.5).
func (w *usageReportWorld) anActivePDUSession(seidHex string, urrID int) error {
	seid, err := parseSEIDHex(seidHex)
	if err != nil {
		return err
	}
	if uint32(urrID) != usageReportingURRID {
		return fmt.Errorf("scenario declares URR id %d but the SMF installs URR id %d — feature/production drift", urrID, usageReportingURRID)
	}
	newUsageReportTestSession(w.s, seid)
	return nil
}

// theSMFReceivesAReport implements the When step: builds a real Session
// Report Request from the feature's table values, drives the production
// consumeSessionReport seam, and records the returned cause + UsageSummary.
func (w *usageReportWorld) theSMFReceivesAReport(seidHex, triggerName string, urrID, urSeqn, total, ul, dl, durationSeconds int) error {
	seid, err := parseSEIDHex(seidHex)
	if err != nil {
		return err
	}
	trigger, err := triggerByteFor(triggerName)
	if err != nil {
		return err
	}

	req, err := buildSessionReportRequestForStep(seid, uint32(urrID), uint32(urSeqn), trigger,
		uint64(total), uint64(ul), uint64(dl), time.Duration(durationSeconds)*time.Second)
	if err != nil {
		w.buildErr = err
		return err
	}

	cause, summary := w.s.consumeSessionReport(context.Background(), req)
	w.lastCause = cause
	w.lastSummary = summary
	w.causes = append(w.causes, cause)
	w.summaries = append(w.summaries, summary)
	return nil
}

// theUsageReportIsLoggedFor implements: "the SMF logs the usage report with
// total volume N bytes and duration N seconds for that session". Asserts
// both on the parsed UsageSummary returned by the seam and on the structured
// log line actually emitted, so a regression in either the parse path or the
// logging call is caught.
func (w *usageReportWorld) theUsageReportIsLoggedFor(total, duration int) error {
	if w.lastSummary.TotalVolume != uint64(total) {
		return fmt.Errorf("summary.TotalVolume = %d, want %d", w.lastSummary.TotalVolume, total)
	}
	if w.lastSummary.DurationSeconds != float64(duration) {
		return fmt.Errorf("summary.DurationSeconds = %v, want %d", w.lastSummary.DurationSeconds, duration)
	}
	logs := w.logBuf.String()
	if !strings.Contains(logs, "PFCP Usage Report consumed") {
		return fmt.Errorf("expected a %q log line, got:\n%s", "PFCP Usage Report consumed", logs)
	}
	wantTotal := fmt.Sprintf("total_volume=%d", total)
	if !strings.Contains(logs, wantTotal) {
		return fmt.Errorf("expected log to contain %q, got:\n%s", wantTotal, logs)
	}
	wantDuration := fmt.Sprintf("duration_s=%d", duration)
	if !strings.Contains(logs, wantDuration) {
		return fmt.Errorf("expected log to contain %q, got:\n%s", wantDuration, logs)
	}
	return nil
}

// theResponseHasCause implements: "the SMF returns a PFCP Session Report
// Response with Cause "...."". Also proves the response actually marshals to
// a well-formed PFCP message, mirroring handleSessionReport's response
// construction (production code path, TS 29.244 §7.5.9), without needing a
// UDP socket.
func (w *usageReportWorld) theResponseHasCause(causeName string) error {
	wantCause, err := causeByteFor(causeName)
	if err != nil {
		return err
	}
	if w.lastCause != wantCause {
		return fmt.Errorf("cause = %d, want %d (%s)", w.lastCause, wantCause, causeName)
	}
	return assertWellFormedSessionReportResponse(w.lastSummary.SEID, w.lastCause)
}

// assertWellFormedSessionReportResponse mirrors handleSessionReport's
// response construction (pfcp_report.go) and asserts it marshals cleanly.
func assertWellFormedSessionReportResponse(seid uint64, cause uint8) error {
	resp := pfcpmsg.NewSessionReportResponse(
		0, 0, seid, 1, 0,
		pfcpie.NewCause(cause),
	)
	b := make([]byte, resp.MarshalLen())
	if err := resp.MarshalTo(b); err != nil {
		return fmt.Errorf("session report response did not marshal: %w", err)
	}
	if len(b) == 0 {
		return fmt.Errorf("session report response marshalled to zero bytes")
	}
	// Round-trip: a real PFCP peer (or Wireshark) must be able to re-parse it.
	if _, err := pfcpmsg.Parse(b); err != nil {
		return fmt.Errorf("session report response failed to re-parse: %w", err)
	}
	return nil
}

// noNewSessionForSEID implements: "no new session is created for SEID
// "...."". Asserts the session table still has no entry for that SEID after
// the rejected request.
func (w *usageReportWorld) noNewSessionForSEID(seidHex string) error {
	seid, err := parseSEIDHex(seidHex)
	if err != nil {
		return err
	}
	if sess := w.s.sessionBySEID(seid); sess != nil {
		return fmt.Errorf("expected no session for SEID %s, found one: %+v", seidHex, sess)
	}
	return nil
}

// doesNotPanicWellFormed implements: "the SMF does not panic and returns a
// well-formed PFCP Session Report Response". Reaching this step at all
// proves theSMFReceivesAReport (which calls consumeSessionReport directly,
// with no recover()) did not panic; it additionally re-verifies the response
// marshals.
func (w *usageReportWorld) doesNotPanicWellFormed() error {
	if w.buildErr != nil {
		return fmt.Errorf("request construction failed: %w", w.buildErr)
	}
	return assertWellFormedSessionReportResponse(w.lastSummary.SEID, w.lastCause)
}

// warnsAboutUnknownURR implements: "the SMF logs a warning about the unknown
// URR id N for SEID "....."". Asserts both on the UsageSummary.KnownURR flag
// and the actual WARN log line.
func (w *usageReportWorld) warnsAboutUnknownURR(urrID int, seidHex string) error {
	if w.lastSummary.KnownURR {
		return fmt.Errorf("expected KnownURR = false for URR id %d", urrID)
	}
	if w.lastSummary.URRID != uint32(urrID) {
		return fmt.Errorf("summary.URRID = %d, want %d", w.lastSummary.URRID, urrID)
	}
	seid, err := parseSEIDHex(seidHex)
	if err != nil {
		return err
	}
	logs := w.logBuf.String()
	if !strings.Contains(logs, "unknown URR ID") {
		return fmt.Errorf("expected an %q log line, got:\n%s", "unknown URR ID", logs)
	}
	if !strings.Contains(logs, "level=WARN") {
		return fmt.Errorf("expected the unknown-URR log line at WARN level, got:\n%s", logs)
	}
	wantSeid := fmt.Sprintf("seid=%d", seid)
	if !strings.Contains(logs, wantSeid) {
		return fmt.Errorf("expected log to contain %q, got:\n%s", wantSeid, logs)
	}
	wantURR := fmt.Sprintf("urr_id=%d", urrID)
	if !strings.Contains(logs, wantURR) {
		return fmt.Errorf("expected log to contain %q, got:\n%s", wantURR, logs)
	}
	return nil
}

// logsNReportsForSEID implements: "the SMF logs N usage reports for SEID
// "....."". Counts the scenario-local UsageSummary entries whose SEID
// matches (the world is reset per scenario in the Before hook, so this is
// exactly the reports emitted by this scenario's When steps).
func (w *usageReportWorld) logsNReportsForSEID(n int, seidHex string) error {
	seid, err := parseSEIDHex(seidHex)
	if err != nil {
		return err
	}
	count := 0
	for _, sum := range w.summaries {
		if sum.SEID == seid {
			count++
		}
	}
	if count != n {
		return fmt.Errorf("logged %d usage reports for SEID %s, want %d", count, seidHex, n)
	}
	logCount := strings.Count(w.logBuf.String(), "PFCP Usage Report consumed")
	if logCount != n {
		return fmt.Errorf("found %d %q log lines, want %d", logCount, "PFCP Usage Report consumed", n)
	}
	return nil
}

// acceptedForEachRequest implements: "the SMF returns a PFCP Session Report
// Response with Cause "Request accepted" for each request".
func (w *usageReportWorld) acceptedForEachRequest(causeName string) error {
	wantCause, err := causeByteFor(causeName)
	if err != nil {
		return err
	}
	if len(w.causes) == 0 {
		return fmt.Errorf("no requests were recorded in this scenario")
	}
	for i, c := range w.causes {
		if c != wantCause {
			return fmt.Errorf("request %d: cause = %d, want %d (%s)", i+1, c, wantCause, causeName)
		}
	}
	return nil
}

// InitializeUsageReportingScenario wires every Given/When/Then in
// usage_reporting.feature to the usageReportWorld step functions above.
// Named distinctly from InitializeScenario (ipv6_functional_test.go) since
// godog forbids two scenario initializers with the same identifier in one
// package.
func InitializeUsageReportingScenario(ctx *godog.ScenarioContext) {
	w := newUsageReportWorld()

	// Reset per-scenario transient state before every scenario so scenarios
	// remain order-independent; the Server/session table persist (the
	// Background step re-registers/overwrites the session each scenario).
	ctx.Before(func(sctx context.Context, _ *godog.Scenario) (context.Context, error) {
		w.logBuf.Reset()
		w.lastCause = 0
		w.lastSummary = UsageSummary{}
		w.causes = nil
		w.summaries = nil
		w.buildErr = nil
		return sctx, nil
	})

	ctx.Step(`^an active PDU session with CP F-SEID "([^"]*)" and installed URR id (\d+)$`, w.anActivePDUSession)
	ctx.Step(`^the SMF receives a PFCP Session Report Request for SEID "([^"]*)" with Usage Report trigger "([^"]*)", URR id (\d+), UR-SEQN (\d+), Volume Measurement total (\d+) bytes UL (\d+) DL (\d+) bytes, and Duration Measurement (\d+) seconds$`, w.theSMFReceivesAReport)
	ctx.Step(`^the SMF logs the usage report with total volume (\d+) bytes and duration (\d+) seconds for that session$`, w.theUsageReportIsLoggedFor)
	ctx.Step(`^the SMF returns a PFCP Session Report Response with Cause "([^"]*)"$`, w.theResponseHasCause)
	ctx.Step(`^no new session is created for SEID "([^"]*)"$`, w.noNewSessionForSEID)
	ctx.Step(`^the SMF does not panic and returns a well-formed PFCP Session Report Response$`, w.doesNotPanicWellFormed)
	ctx.Step(`^the SMF logs a warning about the unknown URR id (\d+) for SEID "([^"]*)"$`, w.warnsAboutUnknownURR)
	ctx.Step(`^the SMF logs (\d+) usage reports for SEID "([^"]*)"$`, w.logsNReportsForSEID)
	ctx.Step(`^the SMF returns a PFCP Session Report Response with Cause "([^"]*)" for each request$`, w.acceptedForEachRequest)
}

// TestUsageReportingFeatures runs usage_reporting.feature against the real
// consumeSessionReport seam (TS 29.244 §5.2.2.4). Named distinctly from
// TestIPv6Features (ipv6_functional_test.go) so both suites run under a
// single `go test -tags=functional ./nf/smf/...`.
func TestUsageReportingFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeUsageReportingScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"../../tests/features/usage_reporting.feature"},
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog scenarios failed")
	}
}
