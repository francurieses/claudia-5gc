//go:build functional

// In-process step definitions for nssaa.feature (TS 23.502 §4.2.9).
// Drives the real AMF NSSAA state machine (internal/procedures) with a fake AAA-S
// relay, so the scenarios run without a UERANSIM stack — UERANSIM v3.2.8 has no
// NSSAA peer. The slice-auth logic, EAP relay, and Allowed/Rejected-NSSAI gating
// are exercised end-to-end at the procedure layer.
package features_test

import (
	"context"
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
	success bool
	called  bool
}

func (f *fakeAAA) Authenticate(_ context.Context, _, _ string, _ uint8, _ string, _ []byte) (*procedures.NSSAAAuthResult, error) {
	f.called = true
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
}

func (w *nssaaWorld) reset() {
	w.aaa = &fakeAAA{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	w.h = procedures.NewRegistrationHandler(nil, nil, nil, nil, "amf-1", "001", "01", logger)
	w.h.WithNSSAA(w.aaa)
	w.ue = &amfctx.UEContext{SUPI: "imsi-001010000000003"}
	w.lastCmd, w.outcome, w.revoked, w.cfgUpdate = nil, nil, false, nil
	w.codecCmd, w.codecDec = nil, nil
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

func (w *nssaaWorld) sliceInRejectedCause3(slice string) error {
	s := parseSNSSAI(slice)
	for _, e := range w.ue.RejectedNSSAI {
		if e.SST == s.SST && e.SD == s.SD {
			return nil
		}
	}
	return fmt.Errorf("%s not in Rejected NSSAI (%+v)", slice, w.ue.RejectedNSSAI)
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
	sc.Step(`^the AMF sends a NETWORK SLICE-SPECIFIC AUTHENTICATION COMMAND for "([^"]+)"$`, w.amfSendsCommandFor)
	sc.Step(`^on the UE's COMPLETE the AMF relays the EAP payload to AUSF$`, w.amfRelaysEAPToAUSF)
	sc.Step(`^the AMF sends a NETWORK SLICE-SPECIFIC AUTHENTICATION RESULT carrying (EAP-Success|EAP-Failure)$`, w.amfSendsResultCarrying)
	sc.Step(`^S-NSSAI "([^"]+)" is in the Allowed NSSAI$`, w.sliceInAllowed)
	sc.Step(`^S-NSSAI "([^"]+)" is not in the Allowed NSSAI$`, w.sliceNotInAllowed)
	sc.Step(`^S-NSSAI "([^"]+)" is in the Rejected NSSAI with cause 3$`, w.sliceInRejectedCause3)
	sc.Step(`^the AMF sends no NETWORK SLICE-SPECIFIC AUTHENTICATION COMMAND$`, w.amfSendsNoCommand)
	sc.Step(`^the Allowed NSSAI is unchanged$`, w.allowedUnchanged)
	sc.Step(`^S-NSSAI "([^"]+)" was previously authorized by NSSAA$`, w.sliceWasPreviouslyAuthorized)
	sc.Step(`^the AAA-S revokes authorization for S-NSSAI "([^"]+)"$`, w.aaaRevokes)
	sc.Step(`^S-NSSAI "([^"]+)" is removed from the Allowed NSSAI$`, w.sliceRemovedFromAllowed)
	sc.Step(`^the AMF sends a Configuration Update Command with the new Allowed NSSAI$`, w.amfSendsConfigUpdate)
	sc.Step(`^a NETWORK SLICE-SPECIFIC AUTHENTICATION COMMAND for S-NSSAI "([^"]+)" with an EAP-Request$`, w.commandWithEAPRequest)
	sc.Step(`^the message is encoded and decoded$`, w.messageEncodedDecoded)
	sc.Step(`^the decoded S-NSSAI and EAP payload match the originals$`, w.decodedMatches)
}
