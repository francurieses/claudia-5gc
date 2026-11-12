//go:build functional

// In-process step definitions for nssaa.feature (TS 23.502 §4.2.9).
// Drives the real AMF NSSAA state machine (internal/procedures) with a fake AAA-S
// relay, so the scenarios run without a UERANSIM stack — UERANSIM v3.2.8 has no
// NSSAA peer. The slice-auth logic, EAP relay, and Allowed/Rejected-NSSAI gating
// are exercised end-to-end at the procedure layer.
package features_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"

	"github.com/cucumber/godog"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/crypto/eap"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// fakeAAA implements procedures.NSSAAClient with a configurable verdict.
type fakeAAA struct {
	success     bool
	called      bool
	unreachable bool            // transport error on every call
	challenges  int             // EAP-Requests still to relay before the terminal result
	confirms    int             // PUTs received
	perSlice    map[string]bool // verdict per "sst-sd" (true = EAP-Success), overrides success
}

func (f *fakeAAA) nonTerminal() *procedures.NSSAAAuthResult {
	f.challenges--
	return &procedures.NSSAAAuthResult{EAPRequest: []byte{eap.CodeRequest, 9, 0, 6, 4, 1}, AuthCtxID: "ctx-1"}
}

// Confirm implements procedures.NSSAAConfirmer (rel19 multi-round PUT).
func (f *fakeAAA) Confirm(ctx context.Context, supi, gpsi string, sst uint8, sd, id string, p []byte) (*procedures.NSSAAAuthResult, error) {
	f.confirms++
	if id != "ctx-1" {
		return nil, fmt.Errorf("unexpected authCtxId %q", id)
	}
	return f.Authenticate(ctx, supi, gpsi, sst, sd, p)
}

func (f *fakeAAA) Authenticate(_ context.Context, _, _ string, sst uint8, sd string, _ []byte) (*procedures.NSSAAAuthResult, error) {
	f.called = true
	if ok, set := f.perSlice[fmt.Sprintf("%d-%s", sst, sd)]; set {
		if ok {
			return &procedures.NSSAAAuthResult{AuthResult: procedures.NSSAAResultSuccess, EAPPayload: eap.BuildSuccess(1)}, nil
		}
		return &procedures.NSSAAAuthResult{AuthResult: procedures.NSSAAResultFailure, EAPPayload: eap.BuildFailure(1)}, nil
	}
	if f.unreachable {
		return nil, errors.New("amf: nssaa create: connection refused")
	}
	if f.challenges > 0 {
		return f.nonTerminal(), nil
	}
	if f.success {
		return &procedures.NSSAAAuthResult{AuthResult: procedures.NSSAAResultSuccess, EAPPayload: eap.BuildSuccess(1)}, nil
	}
	return &procedures.NSSAAAuthResult{AuthResult: procedures.NSSAAResultFailure, EAPPayload: eap.BuildFailure(1)}, nil
}

type nssaaWorld struct {
	h         *procedures.RegistrationHandler
	aaa       *fakeAAA
	ue        *amfctx.UEContext
	lastCmd   *nas.NSSAAuthCommand
	outcome   *procedures.NSSAACompleteOutcome
	revoked   bool
	cfgUpdate *nas.NSSAI
	codecCmd  *nas.NSSAAuthCommand
	codecDec  *nas.NSSAAuthCommand
	commands  []*nas.NSSAAuthCommand // every COMMAND sent to the UE, in order
	results   []*nas.NSSAAuthResult  // every RESULT sent to the UE, in order

	cucCount    int                        // CONFIGURATION UPDATE COMMANDs the AMF would send
	cucAllowed  nas.NSSAI                  // Allowed NSSAI of the last CUC
	cucRejected []nas.RejectedSNSSAI       // Rejected NSSAI IE of the last CUC (rel19)
	cucExtended *nas.ExtendedRejectedNSSAI // Extended rejected NSSAI IE of the last CUC (rel19, ER-NSSAI UE)
	cucErr      error                      // encode/decode failure of the last CUC
	accept      *nas.RegistrationAccept

	deregs   int                          // network-initiated de-registrations the AMF would perform
	deregReq *nas.DeregistrationRequestNW // the DEREGISTRATION REQUEST (UE terminated) as decoded from its bytes
	deregRaw []byte                       // its body bytes
}

func (w *nssaaWorld) reset() {
	w.aaa = &fakeAAA{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
	w.h = procedures.NewRegistrationHandler(mgr, nil, nil, nil, "amf-1", "001", "01", logger)
	w.h.WithNSSAA(w.aaa)
	w.ue = &amfctx.UEContext{SUPI: "imsi-001010000000003"}
	w.lastCmd, w.outcome, w.revoked, w.cfgUpdate = nil, nil, false, nil
	w.codecCmd, w.codecDec = nil, nil
	w.commands, w.results = nil, nil
	w.cucCount, w.cucAllowed, w.cucRejected, w.cucExtended, w.cucErr, w.accept = 0, nas.NSSAI{}, nil, nil, nil, nil
	w.deregs, w.deregReq, w.deregRaw = 0, nil, nil
}

// ---- rel19 multi-round / PENDING retry ----

func (w *nssaaWorld) rel19Profile() error {
	w.h.WithNSSAASpecLiteral(true)
	w.ue.GPSI = "msisdn-12025550100"
	return nil
}

func (w *nssaaWorld) aaaChallenges(n int) error {
	w.aaa.challenges = n
	w.aaa.success = true
	return nil
}

func (w *nssaaWorld) aaaUnreachable() error { w.aaa.unreachable = true; return nil }

func (w *nssaaWorld) aaaReachableAgain(result string) error {
	w.aaa.unreachable = false
	return w.aaaWillReturn(result)
}

// ueAnswersUntilResult plays the UE: it answers every COMMAND with a COMPLETE
// until the AMF stops sending COMMANDs for the slice.
func (w *nssaaWorld) ueAnswersUntilResult() error {
	w.h.SplitPendingNSSAA(w.ue)
	return w.driveUE()
}

func (w *nssaaWorld) driveUE() error {
	cmd, started := w.h.StartNSSAA(context.Background(), w.ue)
	if !started {
		return nil
	}
	for i := 0; cmd != nil; i++ {
		if i > procedures.NSSAAMaxEAPRounds+2 {
			return fmt.Errorf("exchange does not terminate")
		}
		w.commands = append(w.commands, cmd)
		out, err := w.h.ProcessNSSAAComplete(context.Background(), w.ue, &nas.NSSAAuthComplete{
			SNSSAI:     cmd.SNSSAI,
			EAPMessage: eap.BuildIdentityResponse(w.ue.NSSAAEAPID, "ue@nssaa.example"),
		})
		if err != nil {
			return err
		}
		w.outcome = out
		if out.Result != nil {
			w.results = append(w.results, out.Result)
		}
		w.recordConfigUpdate(out)
		cmd = out.NextCommand
	}
	return nil
}

// recordConfigUpdate notes the CONFIGURATION UPDATE COMMAND the NAS layer sends
// when the outcome asks for one: the new Allowed NSSAI and, under rel19, the
// Rejected NSSAI with the failed-NSSAA cause.
func (w *nssaaWorld) recordConfigUpdate(out *procedures.NSSAACompleteOutcome) {
	if out.Deregister {
		if err := w.recordDeregistration(); err != nil {
			w.deregs = -1
		}
		return
	}
	if !out.ConfigUpdate {
		return
	}
	w.recordCUC()
}

// recordCUC builds the CONFIGURATION UPDATE COMMAND with the production builder
// (procedures.NSSAAConfigUpdateCommand, the one nas.sendNSSAAConfigUpdate uses),
// encodes it and decodes the bytes back, so the assertions read the wire form.
func (w *nssaaWorld) recordCUC() {
	cmd, _ := w.h.NSSAAConfigUpdateCommand(w.ue, w.h.UseExtendedRejectedNSSAI(w.ue))
	raw, err := nas.EncodeConfigurationUpdateCommand(cmd)
	if err == nil {
		cmd, err = nas.DecodeConfigurationUpdateCommand(raw)
	}
	w.cucCount++
	if err != nil {
		w.cucErr = err
		return
	}
	w.cucAllowed = nas.NSSAI{}
	if cmd.AllowedNSSAI != nil {
		w.cucAllowed = *cmd.AllowedNSSAI
	}
	w.cucRejected, w.cucExtended = cmd.RejectedNSSAI, cmd.ExtendedRejectedNSSAI
}

// ueNeverAnswers plays a silent UE: the COMMAND is sent, T3575 expires five
// times (the retransmissions and the timer itself are covered by the nas-layer
// unit tests) and the AMF aborts the exchange.
func (w *nssaaWorld) ueNeverAnswers() error {
	w.h.SplitPendingNSSAA(w.ue)
	cmd, started := w.h.StartNSSAA(context.Background(), w.ue)
	if !started {
		return fmt.Errorf("no COMMAND started")
	}
	w.commands = append(w.commands, cmd)
	out := w.h.AbortNSSAA(w.ue, errors.New("T3575 expired"))
	if out == nil {
		return fmt.Errorf("abort not performed")
	}
	w.outcome = out
	if out.Result != nil {
		w.results = append(w.results, out.Result)
	}
	w.recordConfigUpdate(out)
	return nil
}

func (w *nssaaWorld) sliceNotPending(slice string) error {
	if w.sliceIsPending(slice) == nil {
		return fmt.Errorf("%s is unexpectedly PENDING", slice)
	}
	return nil
}

func (w *nssaaWorld) subscriptionMarksTwo(a, b string) error {
	sa, sb := parseSNSSAI(a), parseSNSSAI(b)
	sa.SubjectToNSSAA, sb.SubjectToNSSAA = true, true
	w.ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}, sa, sb}
	return nil
}

func (w *nssaaWorld) aaaPerSlice(okSlice, failSlice string) error {
	w.aaa.perSlice = map[string]bool{}
	s, f := parseSNSSAI(okSlice), parseSNSSAI(failSlice)
	w.aaa.perSlice[fmt.Sprintf("%d-%s", s.SST, s.SD)] = true
	w.aaa.perSlice[fmt.Sprintf("%d-%s", f.SST, f.SD)] = false
	return nil
}

func (w *nssaaWorld) amfSendsNCUC(n int) error {
	if w.cucErr != nil {
		return fmt.Errorf("Configuration Update Command encode/decode: %w", w.cucErr)
	}
	if w.cucCount != n {
		return fmt.Errorf("%d Configuration Update Command(s), want %d", w.cucCount, n)
	}
	return nil
}

func (w *nssaaWorld) cucAllowedHas(slice string) error {
	want := parseSNSSAI(slice)
	for _, s := range w.cucAllowed.SNSSAIs {
		if s.SST == want.SST && s.SD == nas.SDFromString(want.SD) {
			return nil
		}
	}
	return fmt.Errorf("%s not in the CUC Allowed NSSAI %+v", slice, w.cucAllowed)
}

func (w *nssaaWorld) cucRejectedHas(slice, cause string) error {
	want := parseSNSSAI(slice)
	if cause != fmt.Sprint(nas.RejectedCauseNSSAAFailedOrRevoked) {
		return fmt.Errorf("the failed-NSSAA Rejected NSSAI cause is %d, not %s", nas.RejectedCauseNSSAAFailedOrRevoked, cause)
	}
	for _, r := range w.cucRejected {
		if r.SNSSAI.SST == want.SST && r.SNSSAI.SD == nas.SDFromString(want.SD) && r.Cause == nas.RejectedCauseNSSAAFailedOrRevoked {
			return nil
		}
	}
	return fmt.Errorf("%s not in the CUC Rejected NSSAI %+v", slice, w.cucRejected)
}

func (w *nssaaWorld) amfBuildsRegistrationAccept() error {
	w.h.SplitPendingNSSAA(w.ue)
	ra, err := w.h.BuildRegistrationUpdateAccept(context.Background(), w.ue)
	if err != nil {
		return err
	}
	w.accept = ra
	return nil
}

func (w *nssaaWorld) acceptPendingHas(slice string) error {
	want := parseSNSSAI(slice)
	if w.accept == nil || w.accept.PendingNSSAI == nil {
		return fmt.Errorf("Registration Accept has no Pending NSSAI")
	}
	for _, s := range w.accept.PendingNSSAI.SNSSAIs {
		if s.SST == want.SST && s.SD == nas.SDFromString(want.SD) {
			return nil
		}
	}
	return fmt.Errorf("%s not in the Pending NSSAI %+v", slice, w.accept.PendingNSSAI)
}

func (w *nssaaWorld) acceptNoPending() error {
	if w.accept == nil || w.accept.PendingNSSAI != nil || len(w.accept.RejectedNSSAI) != 0 {
		return fmt.Errorf("rel17 Registration Accept carries NSSAA IEs: %+v", w.accept)
	}
	return nil
}

func (w *nssaaWorld) ueRegistersAgain() error {
	// a registration recomputes the Allowed NSSAI from the subscription
	w.ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}, {SST: 1, SD: "000003", SubjectToNSSAA: true}}
	w.commands, w.results, w.lastCmd = nil, nil, nil
	return w.ueAnswersUntilResult()
}

func (w *nssaaWorld) amfRelaysFurtherRequests(n int, slice string) error {
	want := parseSNSSAI(slice)
	if len(w.commands) != n+1 {
		return fmt.Errorf("%d COMMANDs sent, want %d (identity + %d EAP-Requests)", len(w.commands), n+1, n)
	}
	for i, c := range w.commands {
		if c.SNSSAI.SST != want.SST || c.SNSSAI.SD != nas.SDFromString(want.SD) {
			return fmt.Errorf("COMMAND %d is for %v, want %s", i, c.SNSSAI, slice)
		}
	}
	if w.aaa.confirms != n {
		return fmt.Errorf("%d PUTs to the open context, want %d", w.aaa.confirms, n)
	}
	return nil
}

func (w *nssaaWorld) sliceIsPending(slice string) error {
	s := parseSNSSAI(slice)
	for _, e := range w.ue.NSSAAPendingStatus {
		if e.SST == s.SST && e.SD == s.SD {
			if w.sliceInAllowed(slice) == nil || w.sliceInRejected(slice) == nil {
				return fmt.Errorf("%s PENDING but also allowed/rejected", slice)
			}
			return nil
		}
	}
	return fmt.Errorf("%s is not PENDING (%+v)", slice, w.ue.NSSAAPendingStatus)
}

func (w *nssaaWorld) amfSendsNoCommandAgain() error {
	if len(w.commands) != 0 {
		return fmt.Errorf("%d COMMAND(s) sent, want none", len(w.commands))
	}
	return nil
}

func (w *nssaaWorld) amfSendsNoResult() error {
	if len(w.results) != 0 {
		return fmt.Errorf("a RESULT was sent for a PENDING slice")
	}
	return nil
}

func parseSNSSAI(s string) amfctx.SNSSAISubscribed {
	parts := strings.SplitN(s, "-", 2)
	sst, _ := strconv.Atoi(parts[0])
	sd := ""
	if len(parts) == 2 {
		sd = parts[1]
	}
	return amfctx.SNSSAISubscribed{SST: uint8(sst), SD: sd}
}

func (w *nssaaWorld) subscriptionMarksSubjectToNSSAA(slice string) error {
	s := parseSNSSAI(slice)
	s.SubjectToNSSAA = true
	w.ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}, s}
	return nil
}

func (w *nssaaWorld) subscriptionMarksNoSubjectToNSSAA() error {
	w.ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}}
	return nil
}

func (w *nssaaWorld) aaaWillReturn(result string) error {
	w.aaa.success = strings.Contains(result, "Success")
	return nil
}

func (w *nssaaWorld) amfStartsNSSAA() error {
	w.h.SplitPendingNSSAA(w.ue)
	cmd, started := w.h.StartNSSAA(context.Background(), w.ue)
	w.lastCmd = cmd
	if !started {
		return nil // skip scenario — nothing pending
	}
	// Simulate the UE's COMPLETE and process it.
	complete := &nas.NSSAAuthComplete{
		SNSSAI:     cmd.SNSSAI,
		EAPMessage: eap.BuildIdentityResponse(w.ue.NSSAAEAPID, "ue@nssaa.example"),
	}
	out, err := w.h.ProcessNSSAAComplete(context.Background(), w.ue, complete)
	if err != nil {
		return err
	}
	w.outcome = out
	return nil
}

func (w *nssaaWorld) amfSendsCommandFor(slice string) error {
	if w.lastCmd == nil {
		return fmt.Errorf("no COMMAND was emitted")
	}
	want := parseSNSSAI(slice)
	if w.lastCmd.SNSSAI.SST != want.SST {
		return fmt.Errorf("COMMAND SST = %d, want %d", w.lastCmd.SNSSAI.SST, want.SST)
	}
	if c, _ := eap.Code(w.lastCmd.EAPMessage); c != eap.CodeRequest {
		return fmt.Errorf("COMMAND EAP code = %d, want Request", c)
	}
	return nil
}

func (w *nssaaWorld) amfRelaysEAPToAUSF() error {
	if !w.aaa.called {
		return fmt.Errorf("AAA relay was not called")
	}
	return nil
}

func (w *nssaaWorld) amfSendsResultCarrying(kind string) error {
	if w.outcome == nil || w.outcome.Result == nil {
		return fmt.Errorf("no RESULT was produced")
	}
	c, _ := eap.Code(w.outcome.Result.EAPMessage)
	if strings.Contains(kind, "Success") && c != eap.CodeSuccess {
		return fmt.Errorf("RESULT EAP code = %d, want Success", c)
	}
	if strings.Contains(kind, "Failure") && c != eap.CodeFailure {
		return fmt.Errorf("RESULT EAP code = %d, want Failure", c)
	}
	return nil
}

func (w *nssaaWorld) sliceInAllowed(slice string) error {
	s := parseSNSSAI(slice)
	for _, e := range w.ue.AllowedNSSAI {
		if e.SST == s.SST && e.SD == s.SD {
			return nil
		}
	}
	return fmt.Errorf("%s not in Allowed NSSAI (%+v)", slice, w.ue.AllowedNSSAI)
}

func (w *nssaaWorld) sliceNotInAllowed(slice string) error {
	if w.sliceInAllowed(slice) == nil {
		return fmt.Errorf("%s unexpectedly in Allowed NSSAI", slice)
	}
	return nil
}

// sliceInRejected reports whether slice is in the UE's Rejected NSSAI.
func (w *nssaaWorld) sliceInRejected(slice string) error {
	s := parseSNSSAI(slice)
	for _, e := range w.ue.RejectedNSSAI {
		if e.SST == s.SST && e.SD == s.SD {
			return nil
		}
	}
	return fmt.Errorf("%s not in Rejected NSSAI (%+v)", slice, w.ue.RejectedNSSAI)
}

// sliceInRejectedCauseFailedNSSAA checks the Rejected NSSAI entry and that it is
// reported with nas.RejectedCauseNSSAAFailedOrRevoked (2, TS 24.501 Table
// 9.11.3.46.1) - not the "#3" the legacy text used.
func (w *nssaaWorld) sliceInRejectedCauseFailedNSSAA(slice, cause string) error {
	if err := w.sliceInRejected(slice); err != nil {
		return err
	}
	if cause != fmt.Sprint(nas.RejectedCauseNSSAAFailedOrRevoked) {
		return fmt.Errorf("feature says cause %s, the failed-NSSAA cause is %d", cause, nas.RejectedCauseNSSAAFailedOrRevoked)
	}
	list, _ := procedures.NASRejectedNSSAI(w.ue.RejectedNSSAI)
	want := parseSNSSAI(slice)
	for _, r := range list {
		if r.SNSSAI.SST == want.SST && r.SNSSAI.SD == nas.SDFromString(want.SD) && r.Cause == nas.RejectedCauseNSSAAFailedOrRevoked {
			return nil
		}
	}
	return fmt.Errorf("%s is not reported with cause %d", slice, nas.RejectedCauseNSSAAFailedOrRevoked)
}

func (w *nssaaWorld) amfSendsNoCommand() error {
	if w.lastCmd != nil {
		return fmt.Errorf("unexpected COMMAND emitted")
	}
	return nil
}

func (w *nssaaWorld) allowedUnchanged() error {
	if len(w.ue.AllowedNSSAI) != 1 || w.ue.AllowedNSSAI[0].SD != "000001" {
		return fmt.Errorf("Allowed NSSAI changed: %+v", w.ue.AllowedNSSAI)
	}
	return nil
}

func (w *nssaaWorld) sliceWasPreviouslyAuthorized(slice string) error {
	s := parseSNSSAI(slice)
	w.ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}, s}
	return nil
}

func (w *nssaaWorld) aaaRevokes(slice string) error {
	s := parseSNSSAI(slice)
	w.revoked = w.h.RevokeNSSAA(w.ue, s.SST, s.SD)
	if !w.revoked {
		return fmt.Errorf("revoke reported no change")
	}
	nssai := procedures.NASAllowedNSSAI(w.ue.AllowedNSSAI)
	w.cfgUpdate = &nssai
	return nil
}

func (w *nssaaWorld) sliceRemovedFromAllowed(slice string) error {
	return w.sliceNotInAllowed(slice)
}

func (w *nssaaWorld) amfSendsConfigUpdate() error {
	if w.cfgUpdate == nil {
		return fmt.Errorf("no Configuration Update Command (Allowed NSSAI) was built")
	}
	return nil
}

func (w *nssaaWorld) commandWithEAPRequest(slice string) error {
	s := parseSNSSAI(slice)
	w.codecCmd = &nas.NSSAAuthCommand{
		SNSSAI:     nas.SNSSAI{SST: s.SST, SD: nas.SDFromString(s.SD)},
		EAPMessage: eap.BuildIdentityRequest(7),
	}
	return nil
}

func (w *nssaaWorld) messageEncodedDecoded() error {
	msg := &nas.Message{
		Header: nas.Header{
			ExtendedProtocolDiscriminator: nas.PDMobilityManagement,
			SecurityHeaderType:            nas.SecurityHeaderPlainNAS,
			MessageType:                   nas.MsgTypeNetworkSliceSpecificAuthCommand,
		},
		Body: w.codecCmd,
	}
	raw, err := nas.Encode(msg)
	if err != nil {
		return err
	}
	dec, err := nas.Decode(raw)
	if err != nil {
		return err
	}
	body, ok := dec.Body.(*nas.NSSAAuthCommand)
	if !ok {
		return fmt.Errorf("decoded body type = %T", dec.Body)
	}
	w.codecDec = body
	return nil
}

func (w *nssaaWorld) decodedMatches() error {
	if w.codecDec.SNSSAI != w.codecCmd.SNSSAI {
		return fmt.Errorf("S-NSSAI mismatch: %v vs %v", w.codecDec.SNSSAI, w.codecCmd.SNSSAI)
	}
	if string(w.codecDec.EAPMessage) != string(w.codecCmd.EAPMessage) {
		return fmt.Errorf("EAP payload mismatch")
	}
	return nil
}

func initNSSAASteps(sc *godog.ScenarioContext) {
	w := &nssaaWorld{}
	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		w.reset()
		return ctx, nil
	})

	sc.Step(`^the subscription marks S-NSSAI "([^"]+)" as subject to NSSAA$`, w.subscriptionMarksSubjectToNSSAA)
	sc.Step(`^the subscription marks no S-NSSAI as subject to NSSAA$`, w.subscriptionMarksNoSubjectToNSSAA)
	sc.Step(`^the AAA-S will return (EAP-Success|EAP-Failure) for the slice$`, w.aaaWillReturn)
	sc.Step(`^the AMF starts NSSAA after registration$`, w.amfStartsNSSAA)
	sc.Step(`^the AMF runs the rel19 NSSAA profile$`, w.rel19Profile)
	sc.Step(`^the AAA-S will challenge the UE (\d+) times before returning EAP-Success$`, w.aaaChallenges)
	sc.Step(`^the AAA-S is unreachable$`, w.aaaUnreachable)
	sc.Step(`^the AAA-S is reachable again and will return (EAP-Success|EAP-Failure) for the slice$`, w.aaaReachableAgain)
	sc.Step(`^the UE answers every COMMAND until the NSSAA procedure ends$`, w.ueAnswersUntilResult)
	sc.Step(`^the UE registers again$`, w.ueRegistersAgain)
	sc.Step(`^the AMF relays (\d+) EAP-Requests in COMMANDs for "([^"]+)" and PUTs each answer to the open context$`, w.amfRelaysFurtherRequests)
	sc.Step(`^S-NSSAI "([^"]+)" is PENDING$`, w.sliceIsPending)
	sc.Step(`^the AMF sends no COMMAND for the new registration$`, w.amfSendsNoCommandAgain)
	sc.Step(`^the AMF sends no NETWORK SLICE-SPECIFIC AUTHENTICATION RESULT$`, w.amfSendsNoResult)
	sc.Step(`^the AMF sends a NETWORK SLICE-SPECIFIC AUTHENTICATION COMMAND for "([^"]+)"$`, w.amfSendsCommandFor)
	sc.Step(`^on the UE's COMPLETE the AMF relays the EAP payload to AUSF$`, w.amfRelaysEAPToAUSF)
	sc.Step(`^the AMF sends a NETWORK SLICE-SPECIFIC AUTHENTICATION RESULT carrying (EAP-Success|EAP-Failure)$`, w.amfSendsResultCarrying)
	sc.Step(`^S-NSSAI "([^"]+)" is in the Allowed NSSAI$`, w.sliceInAllowed)
	sc.Step(`^S-NSSAI "([^"]+)" is not in the Allowed NSSAI$`, w.sliceNotInAllowed)
	sc.Step(`^S-NSSAI "([^"]+)" is in the Rejected NSSAI with cause (\d+)$`, w.sliceInRejectedCauseFailedNSSAA)
	sc.Step(`^the UE never answers the COMMAND until T3575 expires for the fifth time$`, w.ueNeverAnswers)
	sc.Step(`^S-NSSAI "([^"]+)" is not PENDING$`, w.sliceNotPending)
	sc.Step(`^the subscription marks S-NSSAI "([^"]+)" and S-NSSAI "([^"]+)" as subject to NSSAA$`, w.subscriptionMarksTwo)
	sc.Step(`^the AAA-S will return EAP-Success for S-NSSAI "([^"]+)" and EAP-Failure for S-NSSAI "([^"]+)"$`, w.aaaPerSlice)
	sc.Step(`^the AMF sends exactly (\d+) Configuration Update Command$`, w.amfSendsNCUC)
	sc.Step(`^the Configuration Update Command carries S-NSSAI "([^"]+)" in the Allowed NSSAI$`, w.cucAllowedHas)
	sc.Step(`^the Configuration Update Command carries S-NSSAI "([^"]+)" in the Rejected NSSAI with cause (\d+)$`, w.cucRejectedHas)
	sc.Step(`^the AMF builds the Registration Accept$`, w.amfBuildsRegistrationAccept)
	sc.Step(`^the Registration Accept carries S-NSSAI "([^"]+)" in the Pending NSSAI$`, w.acceptPendingHas)
	sc.Step(`^the Registration Accept carries no Pending NSSAI$`, w.acceptNoPending)
	sc.Step(`^the AMF sends no NETWORK SLICE-SPECIFIC AUTHENTICATION COMMAND$`, w.amfSendsNoCommand)
	sc.Step(`^the only subscribed S-NSSAI is "([^"]+)", subject to NSSAA$`, w.onlySubscribed)
	sc.Step(`^the UE has an emergency PDU session$`, w.ueHasEmergencySession)
	sc.Step(`^the AAA-S revokes authorization for the last allowed S-NSSAI "([^"]+)"$`, w.revokesOnlyAllowed)
	sc.Step(`^the AMF performs a network-initiated de-registration instead of a Configuration Update Command$`, w.amfDeregisters)
	sc.Step(`^the AMF performs no network-initiated de-registration$`, w.amfDoesNotDeregister)
	sc.Step(`^the DEREGISTRATION REQUEST has 5GMM cause 62, re-registration not required and S-NSSAI "([^"]+)" in the Rejected NSSAI with cause (\d+)$`, w.deregCarries)
	sc.Step(`^the AMF sends no Configuration Update Command$`, w.amfSendsNoCUC)
	sc.Step(`^the UE supports extended rejected NSSAI$`, w.ueSupportsER)
	sc.Step(`^the DEREGISTRATION REQUEST carries S-NSSAI "([^"]+)" with cause (\d+) in the Extended rejected NSSAI instead of the Rejected NSSAI$`, w.deregCarriesExtended)
	sc.Step(`^the Configuration Update Command carries S-NSSAI "([^"]+)" with cause (\d+) in the Extended rejected NSSAI instead of the Rejected NSSAI$`, w.cucCarriesExtended)
	sc.Step(`^S-NSSAI "([^"]+)" is also subscribed as a default S-NSSAI not subject to NSSAA$`, w.defaultSubscribed)
	sc.Step(`^the Allowed NSSAI is unchanged$`, w.allowedUnchanged)
	sc.Step(`^S-NSSAI "([^"]+)" was previously authorized by NSSAA$`, w.sliceWasPreviouslyAuthorized)
	sc.Step(`^the AAA-S revokes authorization for S-NSSAI "([^"]+)"$`, w.aaaRevokes)
	sc.Step(`^S-NSSAI "([^"]+)" is removed from the Allowed NSSAI$`, w.sliceRemovedFromAllowed)
	sc.Step(`^the AMF sends a Configuration Update Command with the new Allowed NSSAI$`, w.amfSendsConfigUpdate)
	sc.Step(`^a NETWORK SLICE-SPECIFIC AUTHENTICATION COMMAND for S-NSSAI "([^"]+)" with an EAP-Request$`, w.commandWithEAPRequest)
	sc.Step(`^the message is encoded and decoded$`, w.messageEncodedDecoded)
	sc.Step(`^the decoded S-NSSAI and EAP payload match the originals$`, w.decodedMatches)
}

// ---- AMF-022: network-initiated de-registration with the Rejected NSSAI ----

// recordDeregistration builds the DEREGISTRATION REQUEST (UE terminated) with the
// production builder (procedures.NSSAADeregRequest, the one nas.deregisterForNSSAA
// uses, including the UE's ER-NSSAI capability), encodes it and decodes the bytes
// back, so the assertions read the wire form.
func (w *nssaaWorld) recordDeregistration() error {
	body, err := nas.EncodeDeregistrationRequestNW(procedures.NSSAADeregRequest(w.ue, w.h.UseExtendedRejectedNSSAI(w.ue)))
	if err != nil {
		return err
	}
	req, err := nas.DecodeDeregistrationRequestNW(body)
	if err != nil {
		return err
	}
	w.deregs++
	w.deregReq = req
	w.deregRaw = body
	return nil
}

func (w *nssaaWorld) onlySubscribed(slice string) error {
	s := parseSNSSAI(slice)
	s.SubjectToNSSAA = true
	w.ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{s}
	w.ue.SubscribedNSSAI = []amfctx.SNSSAISubscribed{s}
	return nil
}

func (w *nssaaWorld) ueHasEmergencySession() error {
	w.ue.EmergencyPDUSession = true
	return nil
}

// revokesOnlyAllowed runs the revocation decision of the production path
// (RegistrationHandler.ApplyNSSAARevocation, shared with nas.RevokeNSSAASlice)
// and records the message the NAS layer would send for it with the same builders.
func (w *nssaaWorld) revokesOnlyAllowed(slice string) error {
	s := parseSNSSAI(slice)
	revoked, dereg, cuc := w.h.ApplyNSSAARevocation(w.ue, s.SST, s.SD)
	if !revoked {
		return fmt.Errorf("revoke reported no change")
	}
	switch {
	case dereg:
		return w.recordDeregistration()
	case cuc:
		w.recordCUC()
	}
	return nil
}

func (w *nssaaWorld) amfDeregisters() error {
	if w.deregs != 1 || w.deregReq == nil {
		return fmt.Errorf("network-initiated de-registrations = %d, want 1", w.deregs)
	}
	if w.cucCount != 0 {
		return fmt.Errorf("%d Configuration Update Commands sent besides the de-registration", w.cucCount)
	}
	return nil
}

func (w *nssaaWorld) amfDoesNotDeregister() error {
	if w.deregs != 0 {
		return fmt.Errorf("unexpected network-initiated de-registration (%d)", w.deregs)
	}
	return nil
}

func (w *nssaaWorld) deregCarries(slice string, cause int) error {
	if w.deregReq == nil {
		return fmt.Errorf("no DEREGISTRATION REQUEST")
	}
	r := w.deregReq
	if r.Cause5GMM != 62 || r.ReregistrationRequired || r.AccessType != 1 {
		return fmt.Errorf("de-registration = %+v, want cause #62, re-registration not required, 3GPP access", r)
	}
	if len(w.deregRaw) == 0 || w.deregRaw[0]&0xF0 != 0 {
		return fmt.Errorf("de-registration octet 4 = % x, want spare half octet 0", w.deregRaw)
	}
	s := parseSNSSAI(slice)
	if r.ExtendedRejectedNSSAI != nil {
		return fmt.Errorf("Extended rejected NSSAI IE sent to a UE without ER-NSSAI support: %+v", r.ExtendedRejectedNSSAI)
	}
	for _, e := range r.RejectedNSSAI {
		if e.SNSSAI.SST == s.SST && e.SNSSAI.SD == nas.SDFromString(s.SD) && int(e.Cause) == cause {
			return nil
		}
	}
	return fmt.Errorf("S-NSSAI %s with cause %d not in the Rejected NSSAI %+v", slice, cause, r.RejectedNSSAI)
}

func (w *nssaaWorld) ueSupportsER() error {
	w.ue.ERNSSAISupported = true
	return nil
}

func (w *nssaaWorld) deregCarriesExtended(slice string, cause int) error {
	if w.deregReq == nil {
		return fmt.Errorf("no DEREGISTRATION REQUEST")
	}
	if len(w.deregReq.RejectedNSSAI) != 0 {
		return fmt.Errorf("Rejected NSSAI IE sent besides the Extended rejected NSSAI IE: %+v", w.deregReq.RejectedNSSAI)
	}
	return w.extendedHas(w.deregReq.ExtendedRejectedNSSAI, slice, cause)
}

func (w *nssaaWorld) cucCarriesExtended(slice string, cause int) error {
	if len(w.cucRejected) != 0 {
		return fmt.Errorf("Rejected NSSAI IE sent besides the Extended rejected NSSAI IE: %+v", w.cucRejected)
	}
	return w.extendedHas(w.cucExtended, slice, cause)
}

func (w *nssaaWorld) extendedHas(x *nas.ExtendedRejectedNSSAI, slice string, cause int) error {
	s := parseSNSSAI(slice)
	if x != nil {
		for _, l := range x.Lists {
			for _, e := range l.Elements {
				if e.SNSSAI.SST == s.SST && e.SNSSAI.SD == nas.SDFromString(s.SD) && int(e.Cause) == cause {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("S-NSSAI %s with cause %d not in the Extended rejected NSSAI %+v", slice, cause, x)
}

func (w *nssaaWorld) defaultSubscribed(slice string) error {
	s := parseSNSSAI(slice) // not subject to NSSAA, not requested: a default S-NSSAI
	w.ue.SubscribedNSSAI = append(w.ue.SubscribedNSSAI, s)
	return nil
}

func (w *nssaaWorld) amfSendsNoCUC() error {
	if w.cucCount != 0 {
		return fmt.Errorf("%d Configuration Update Commands, want none", w.cucCount)
	}
	return nil
}
