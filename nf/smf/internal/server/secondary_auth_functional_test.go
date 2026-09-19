//go:build functional

// godog step definitions for Secondary Authentication / DN-AAA during PDU
// Session Establishment (TS 23.501 §5.6.6, TS 23.502 §4.3.2.3,
// TS 24.501 §8.3.5-§8.3.7 EAP-in-5GSM, TS 24.501 §9.11.4.2 5GSM cause,
// RFC 3748 EAP framing).
//
// Like secondary_auth_test.go, these steps drive the real production
// handlers (handleCreateSMContext / handleUpdateSMContext) directly and
// in-process — no live N1 UE peer and no live DN-AAA (UERANSIM v3.2.8 has no
// secondary-auth capability; the DN-AAA is the SMF-internal simulated EAP
// server, see docs/procedures/SecondaryAuthentication.md). The
// Namf_Communication_N1N2MessageTransfer push towards the AMF is captured via
// the Server.n1n2Push test seam (same pattern as secondary_auth_test.go /
// ipv6_functional_test.go), and the DN-AAA relay itself is observed via a spy
// wrapping the Server.dnAAA seam (DNAAAClient interface).
//
// Run with: go test -tags=functional ./nf/smf/...  (see Makefile test-functional)
package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/cucumber/godog"

	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/crypto/eap"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// spyDNAAAClient wraps the real DNAAAClient seam (simulatedDNAAAClient in
// production) so scenarios can assert the SMF actually invoked the N6 relay
// (and observe whether it errored, i.e. unreachable/timeout) without adding
// any test-only branch to production code.
type spyDNAAAClient struct {
	inner   DNAAAClient
	called  bool
	lastErr error
}

func (sp *spyDNAAAClient) Authenticate(ctx context.Context, dnn string, eapResponse []byte) ([]byte, error) {
	sp.called = true
	resp, err := sp.inner.Authenticate(ctx, dnn, eapResponse)
	sp.lastErr = err
	return resp, err
}

// secondaryAuthWorld holds the state threaded through one scenario of
// secondary_authentication.feature. A fresh Server is built lazily in the
// "UE sends a PDU SESSION ESTABLISHMENT REQUEST" When-step, once all the
// Background/Given steps for that scenario have recorded the DNN's
// secondary-auth requirement and DN-AAA reachability — mirroring how
// newSecondaryAuthTestServer in secondary_auth_test.go is parameterised.
type secondaryAuthWorld struct {
	t *testing.T

	// Given-collected scenario inputs.
	dnn              string
	requiresAuth     bool
	dnaaaUnreachable bool
	// wantEAPFailureIdentity is derived from the scenario name in the Before
	// hook: the "EAP-Failure" scenario is the only one whose EAP-Response
	// identity must trigger the simulated DN-AAA's deterministic rejection
	// (identity containing "reject", see simulatedDNAAAClient.Authenticate).
	wantEAPFailureIdentity bool

	s     *Server
	calls *[]n1n2Call
	spy   *spyDNAAAClient

	supi         string
	psi, pti     uint8
	smContextRef string
	createResp   map[string]interface{}
	reservedIP   string
}

func newSecondaryAuthWorld(t *testing.T) *secondaryAuthWorld {
	return &secondaryAuthWorld{t: t}
}

func (w *secondaryAuthWorld) reset(sc *godog.Scenario) {
	w.dnn = ""
	w.requiresAuth = false
	w.dnaaaUnreachable = false
	w.wantEAPFailureIdentity = strings.Contains(sc.Name, "EAP-Failure")
	w.s = nil
	w.calls = nil
	w.spy = nil
	w.supi = ""
	w.psi, w.pti = 0, 0
	w.smContextRef = ""
	w.createResp = nil
	w.reservedIP = ""
}

// --- Background ---

func (w *secondaryAuthWorld) smfHasFetchedSmData() error {
	// Declarative context only: production fetches Nudm_SDM sm-data (and
	// reads the "secondary auth required" flag from it) inside
	// handleCreateSMContext itself. The Given steps below configure the
	// equivalent DNN-level flag the SMF gates on.
	return nil
}

// --- Given ---

func (w *secondaryAuthWorld) dnnRequiresSecondaryAuth(dnn string) error {
	w.dnn = dnn
	w.requiresAuth = true
	return nil
}

func (w *secondaryAuthWorld) dnnDoesNotRequireSecondaryAuth(dnn string) error {
	w.dnn = dnn
	w.requiresAuth = false
	return nil
}

func (w *secondaryAuthWorld) theDNAAAIsUnreachable() error {
	w.dnaaaUnreachable = true
	return nil
}

// --- server construction (invoked from the When step) ---

// buildServer constructs a fresh in-process Server whose DNN table reflects
// the Given steps collected so far: a baseline "internet" DNN (never gated)
// plus — unless the scenario's target DNN *is* "internet" — a dedicated DNN
// entry with its own IP pool so the "allocated UE IP address is released"
// assertion can observe pool state cleanly. Mirrors
// newSecondaryAuthTestServer in secondary_auth_test.go.
func (w *secondaryAuthWorld) buildServer() error {
	dnns := []config.DNNConfig{
		{Name: "internet", UEIPPool: "10.60.0.0/24"},
	}
	if w.dnn == "internet" {
		dnns[0].SecondaryAuth = w.requiresAuth
		dnns[0].DNAAAUnreachable = w.dnaaaUnreachable
	} else {
		dnns = append(dnns, config.DNNConfig{
			Name:             w.dnn,
			UEIPPool:         "10.70.0.0/24",
			SecondaryAuth:    w.requiresAuth,
			DNAAAUnreachable: w.dnaaaUnreachable,
		})
	}
	cfg := &config.Config{UEIPPool: "10.60.0.0/24", DNNs: dnns}

	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		return fmt.Errorf("secondary auth steps: New(server): %w", err)
	}

	var calls []n1n2Call
	s.n1n2Push = func(_ context.Context, supi string, psi uint8, n1SmMsg, n2SmInfo []byte, n2SmInfoType string) (string, error) {
		calls = append(calls, n1n2Call{SUPI: supi, PSI: psi, N1SmMsg: n1SmMsg, N2SmInfo: n2SmInfo, N2SmInfoType: n2SmInfoType})
		return "N1_N2_TRANSFER_INITIATED", nil
	}

	spy := &spyDNAAAClient{inner: s.dnAAA}
	s.dnAAA = spy

	w.s = s
	w.calls = &calls
	w.spy = spy
	return nil
}

// --- When ---

func (w *secondaryAuthWorld) ueSendsEstablishmentRequest(dnn string) error {
	if w.dnn != dnn {
		return fmt.Errorf("scenario DNN mismatch: Given declared %q, When references %q", w.dnn, dnn)
	}
	if err := w.buildServer(); err != nil {
		return err
	}
	w.supi = "imsi-001010000000099"
	w.psi, w.pti = 1, 7

	rr := createSMContext(w.t, w.s, w.supi, w.dnn, w.psi, w.pti)
	if rr.Code != http.StatusCreated {
		return fmt.Errorf("CreateSMContext: expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		return fmt.Errorf("decode CreateSMContext response: %w", err)
	}
	w.createResp = resp
	if ref, ok := resp["smContextRef"].(string); ok {
		w.smContextRef = ref
	}

	if w.requiresAuth {
		if w.smContextRef == "" {
			return fmt.Errorf("expected smContextRef while secondary auth is pending, got none")
		}
		if pending := w.s.getPendingAuth(w.smContextRef); pending != nil && pending.IPv4 != nil {
			w.reservedIP = pending.IPv4.String()
		}
	}
	return nil
}

// --- Then / And ---

func (w *secondaryAuthWorld) lastPush() (n1n2Call, error) {
	if w.calls == nil || len(*w.calls) == 0 {
		return n1n2Call{}, fmt.Errorf("no N1N2MessageTransfer push recorded")
	}
	return (*w.calls)[len(*w.calls)-1], nil
}

func (w *secondaryAuthWorld) theSMFSendsAuthCommand() error {
	call, err := w.lastPush()
	if err != nil {
		return err
	}
	if len(call.N1SmMsg) < 4 || nas.MessageType(call.N1SmMsg[3]) != nas.MsgTypePDUSessionAuthenticationCommand {
		return fmt.Errorf("expected AUTH COMMAND (0xC5), got % X", call.N1SmMsg)
	}
	eapReqPkt, err := nas.DecodePDUSessionAuthenticationCommandBody(call.N1SmMsg[4:])
	if err != nil {
		return fmt.Errorf("decode AUTH COMMAND body: %w", err)
	}
	if code, _ := eap.Code(eapReqPkt); code != eap.CodeRequest {
		return fmt.Errorf("expected EAP-Request, got code %d", code)
	}
	return nil
}

func (w *secondaryAuthWorld) theSMFDoesNotSendAuthCommand() error {
	if w.calls != nil && len(*w.calls) != 0 {
		return fmt.Errorf("expected no N1N2MessageTransfer push, got %d", len(*w.calls))
	}
	return nil
}

func (w *secondaryAuthWorld) ueRespondsWithAuthComplete() error {
	identity := fmt.Sprintf("user@%s", w.dnn)
	if w.wantEAPFailureIdentity {
		identity = fmt.Sprintf("reject@%s", w.dnn)
	}
	eapResp := eap.BuildIdentityResponse(1, identity)
	rr := sendAuthComplete(w.t, w.s, w.smContextRef, w.psi, w.pti, eapResp)
	if rr.Code != http.StatusOK {
		return fmt.Errorf("AUTH COMPLETE: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	return nil
}

func (w *secondaryAuthWorld) theSMFRelaysToDNAAA() error {
	if w.spy == nil || !w.spy.called {
		return fmt.Errorf("expected the SMF to relay the EAP-Response to the DN-AAA over N6, it did not")
	}
	if w.spy.lastErr != nil {
		return fmt.Errorf("expected the DN-AAA relay to succeed, got error: %v", w.spy.lastErr)
	}
	return nil
}

func (w *secondaryAuthWorld) theRelayTimesOut() error {
	if w.spy == nil || !w.spy.called {
		return fmt.Errorf("expected the SMF to attempt the DN-AAA relay over N6, it did not")
	}
	if w.spy.lastErr == nil {
		return fmt.Errorf("expected the DN-AAA relay to fail (unreachable/timeout), it succeeded")
	}
	return nil
}

func (w *secondaryAuthWorld) theDNAAAReturnsSuccess() error {
	call, err := w.lastPush()
	if err != nil {
		return err
	}
	if len(call.N1SmMsg) < 4 || nas.MessageType(call.N1SmMsg[3]) != nas.MsgTypePDUSessionEstablishmentAccept {
		return fmt.Errorf("expected ESTABLISHMENT ACCEPT (0xC2) after EAP-Success, got % X", call.N1SmMsg)
	}
	// The EAP message IE (0x78) must be ordered *before* the Authorized QoS
	// flow descriptions IE (0x79) and the DNN IE (0x25), per TS 24.501 §8.3.2
	// Table 8.3.2.1.1 — walk the self-describing optional IEs instead of
	// assuming it sits at the tail of the body.
	body := call.N1SmMsg[4:]
	offsets, err := decodeOptionalIEOffsets(body)
	if err != nil {
		return fmt.Errorf("decode ACCEPT body optional IEs: %w", err)
	}
	eapOffset, ok := offsets[nas.IEIEAPMessage]
	if !ok {
		return fmt.Errorf("expected EAP message IE (0x%02X) in the ACCEPT body: % X", nas.IEIEAPMessage, body)
	}
	if qosFlowOffset, present := offsets[nas.IEIAuthorizedQoSFlowDesc]; present && eapOffset > qosFlowOffset {
		return fmt.Errorf("IE order violation (TS 24.501 §8.3.2 Table 8.3.2.1.1): "+
			"EAP message IE (0x78)@%d must precede Authorized QoS flow descriptions IE (0x79)@%d", eapOffset, qosFlowOffset)
	}
	if dnnOffset, present := offsets[nas.IEIDNN5GSM]; present && eapOffset > dnnOffset {
		return fmt.Errorf("IE order violation (TS 24.501 §8.3.2 Table 8.3.2.1.1): "+
			"EAP message IE (0x78)@%d must precede DNN IE (0x25)@%d", eapOffset, dnnOffset)
	}
	eapTLVE := body[eapOffset:]
	eapIE, _, err := nas.DecodeEAPMessageTLVE(eapTLVE)
	if err != nil {
		return fmt.Errorf("decode EAP message TLV-E: %w", err)
	}
	if code, _ := eap.Code(eapIE); code != eap.CodeSuccess {
		return fmt.Errorf("expected EAP-Success, got code %d", code)
	}
	return nil
}

func (w *secondaryAuthWorld) theDNAAAReturnsFailure() error {
	call, err := w.lastPush()
	if err != nil {
		return err
	}
	if len(call.N1SmMsg) < 5 || nas.MessageType(call.N1SmMsg[3]) != nas.MsgTypePDUSessionEstablishmentReject {
		return fmt.Errorf("expected ESTABLISHMENT REJECT (0xC3) after EAP-Failure, got % X", call.N1SmMsg)
	}
	eapIE, _, err := nas.DecodeEAPMessageTLVE(call.N1SmMsg[5:])
	if err != nil {
		return fmt.Errorf("decode EAP-Failure TLV-E: %w", err)
	}
	if code, _ := eap.Code(eapIE); code != eap.CodeFailure {
		return fmt.Errorf("expected EAP-Failure, got code %d", code)
	}
	return nil
}

func (w *secondaryAuthWorld) theSMFCreatesN4Session() error {
	w.s.sessionMu.Lock()
	defer w.s.sessionMu.Unlock()
	for _, sess := range w.s.sessions {
		if sess.SUPI == w.supi && sess.DNN == w.dnn && sess.State == "ACTIVE" {
			return nil
		}
	}
	return fmt.Errorf("expected an ACTIVE session for supi=%s dnn=%s (N4 PFCP Session Establishment triggered)", w.supi, w.dnn)
}

func (w *secondaryAuthWorld) theSMFDoesNotCreateN4Session() error {
	w.s.sessionMu.Lock()
	defer w.s.sessionMu.Unlock()
	if _, exists := w.s.sessions[w.smContextRef]; exists {
		return fmt.Errorf("expected no session (no N4 PFCP session establishment) for smContextRef %s", w.smContextRef)
	}
	return nil
}

func (w *secondaryAuthWorld) theEstablishmentAcceptCarriesEAPSuccess(ieiStr string) error {
	if err := checkIEIHex(ieiStr, nas.IEIEAPMessage); err != nil {
		return err
	}
	return w.theDNAAAReturnsSuccess()
}

// theEstablishmentAcceptNoEAP asserts the CreateSMContext response for a
// non-gated DNN carries an Establishment Accept body with no EAP message IE
// — the accept is returned synchronously (no N1N2 push), same as the
// pre-secondary-auth flow. Mirrors
// TestSecondaryAuth_NoRegressionWhenNotRequired.
func (w *secondaryAuthWorld) theEstablishmentAcceptNoEAP() error {
	n1B64, ok := w.createResp["n1SmMsg"].(string)
	if !ok || n1B64 == "" {
		return fmt.Errorf("expected n1SmMsg (Establishment Accept) in the immediate CreateSMContext response")
	}
	n1Bytes, err := base64.StdEncoding.DecodeString(n1B64)
	if err != nil {
		return fmt.Errorf("base64 decode n1SmMsg: %w", err)
	}
	if len(n1Bytes) == 0 {
		return fmt.Errorf("n1SmMsg body must not be empty")
	}
	if n1Bytes[0] == nas.IEIEAPMessage {
		return fmt.Errorf("no EAP message IE should be present for a DNN that does not require secondary auth")
	}
	return nil
}

func (w *secondaryAuthWorld) theEstablishmentRejectCause29() error {
	call, err := w.lastPush()
	if err != nil {
		return err
	}
	if len(call.N1SmMsg) < 5 || nas.MessageType(call.N1SmMsg[3]) != nas.MsgTypePDUSessionEstablishmentReject {
		return fmt.Errorf("expected ESTABLISHMENT REJECT (0xC3), got % X", call.N1SmMsg)
	}
	if call.N1SmMsg[4] != nas.Cause5GSMUserAuthOrAuthorizationFailed {
		return fmt.Errorf("5GSM cause: got %d, want %d (29)", call.N1SmMsg[4], nas.Cause5GSMUserAuthOrAuthorizationFailed)
	}
	return nil
}

func (w *secondaryAuthWorld) theEstablishmentRejectCause29WithEAPFailure(ieiStr string) error {
	if err := checkIEIHex(ieiStr, nas.IEIEAPMessage); err != nil {
		return err
	}
	if err := w.theEstablishmentRejectCause29(); err != nil {
		return err
	}
	return w.theDNAAAReturnsFailure()
}

func (w *secondaryAuthWorld) theAllocatedIPIsReleased() error {
	if w.reservedIP == "" {
		return fmt.Errorf("no UE IP was reserved for this scenario to assert release on")
	}
	pool := w.s.ipPools[w.dnn]
	if pool == nil {
		return fmt.Errorf("no IP pool configured for DNN %q", w.dnn)
	}
	got, err := pool.Allocate()
	if err != nil {
		return fmt.Errorf("allocate after release: %w", err)
	}
	if got.String() != w.reservedIP {
		return fmt.Errorf("expected the released IP %s to be reallocated first, got %s", w.reservedIP, got)
	}
	return nil
}

// checkIEIHex parses a "0xNN" string from the feature file and compares it
// against the production IEI constant.
func checkIEIHex(ieiStr string, want uint8) error {
	var got uint8
	if _, err := fmt.Sscanf(ieiStr, "0x%02x", &got); err != nil {
		return fmt.Errorf("parse IEI %q: %w", ieiStr, err)
	}
	if got != want {
		return fmt.Errorf("EAP message IEI = 0x%02X, want 0x%02X", got, want)
	}
	return nil
}

// InitializeSecondaryAuthScenario wires every Given/When/Then in
// secondary_authentication.feature. Named distinctly from InitializeScenario
// (ipv6_functional_test.go) / InitializeUsageReportingScenario
// (usage_reporting_functional_test.go) since godog forbids two scenario
// initializers with the same identifier in one package; returns a closure so
// the shared *testing.T (needed to reuse createSMContext / sendAuthComplete
// from secondary_auth_test.go, which only use it for t.Helper()) is
// available to every step.
func InitializeSecondaryAuthScenario(t *testing.T) func(*godog.ScenarioContext) {
	return func(ctx *godog.ScenarioContext) {
		w := newSecondaryAuthWorld(t)

		// Reset per-scenario state so scenarios stay order-independent — each
		// scenario builds its own fresh Server in the When step.
		ctx.Before(func(sctx context.Context, sc *godog.Scenario) (context.Context, error) {
			w.reset(sc)
			return sctx, nil
		})

		ctx.Step(`^the SMF has fetched Nudm_SDM sm-data for the DNN/S-NSSAI subscription$`, w.smfHasFetchedSmData)
		ctx.Step(`^a DNN "([^"]*)" whose subscription requires secondary DN-AAA authentication$`, w.dnnRequiresSecondaryAuth)
		ctx.Step(`^a DNN "([^"]*)" whose subscription does not require secondary DN-AAA authentication$`, w.dnnDoesNotRequireSecondaryAuth)
		ctx.Step(`^the DN-AAA is unreachable$`, w.theDNAAAIsUnreachable)
		ctx.Step(`^a UE sends a PDU SESSION ESTABLISHMENT REQUEST for DNN "([^"]*)"$`, w.ueSendsEstablishmentRequest)
		ctx.Step(`^the SMF sends a PDU SESSION AUTHENTICATION COMMAND with an EAP-Request/Identity$`, w.theSMFSendsAuthCommand)
		ctx.Step(`^the SMF does not send any PDU SESSION AUTHENTICATION COMMAND$`, w.theSMFDoesNotSendAuthCommand)
		ctx.Step(`^the UE responds with a PDU SESSION AUTHENTICATION COMPLETE carrying EAP-Response/Identity$`, w.ueRespondsWithAuthComplete)
		ctx.Step(`^the SMF relays the EAP-Response to the DN-AAA over N6$`, w.theSMFRelaysToDNAAA)
		ctx.Step(`^the SMF relay to the DN-AAA over N6 times out$`, w.theRelayTimesOut)
		ctx.Step(`^the DN-AAA returns EAP-Success$`, w.theDNAAAReturnsSuccess)
		ctx.Step(`^the DN-AAA returns EAP-Failure$`, w.theDNAAAReturnsFailure)
		ctx.Step(`^the SMF creates the N4 PFCP session with the UPF$`, w.theSMFCreatesN4Session)
		ctx.Step(`^the SMF does not create an N4 PFCP session$`, w.theSMFDoesNotCreateN4Session)
		ctx.Step(`^the SMF returns a PDU SESSION ESTABLISHMENT ACCEPT carrying EAP-Success in IEI "([^"]*)"$`, w.theEstablishmentAcceptCarriesEAPSuccess)
		ctx.Step(`^the SMF returns a PDU SESSION ESTABLISHMENT ACCEPT with no EAP message IE present$`, w.theEstablishmentAcceptNoEAP)
		ctx.Step(`^the SMF returns a PDU SESSION ESTABLISHMENT REJECT with 5GSM cause 29 and EAP-Failure in IEI "([^"]*)"$`, w.theEstablishmentRejectCause29WithEAPFailure)
		ctx.Step(`^the SMF returns a PDU SESSION ESTABLISHMENT REJECT with 5GSM cause 29$`, w.theEstablishmentRejectCause29)
		ctx.Step(`^the allocated UE IP address is released$`, w.theAllocatedIPIsReleased)
	}
}

// TestSecondaryAuthenticationFeature runs secondary_authentication.feature
// against the real handleCreateSMContext / handleUpdateSMContext seams
// (TS 23.502 §4.3.2.3). Named distinctly from TestIPv6Features /
// TestUsageReportingFeatures so all three suites run under a single
// `go test -tags=functional ./nf/smf/...`.
func TestSecondaryAuthenticationFeature(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeSecondaryAuthScenario(t),
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"../../tests/features/secondary_authentication.feature"},
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog scenarios failed")
	}
}
