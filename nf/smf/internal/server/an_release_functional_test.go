//go:build functional

// godog step definitions for an_release.feature (SMF-008): the N4 leg of the AN release.
// The real handleUpdateSMContext runs behind an httptest.ResponseRecorder against the
// responding fake UPF of the SMF-005 harness (hoStepsUPF); the PFCP bytes the UPF receives are
// decoded and the Update FAR is asserted (FAR ID 1, Apply Action 0x0C, no forwarding
// parameters, no BAR). The detached AN release goroutine is not tracked by the SMF, so every
// "after" assertion polls with a deadline; negative assertions synchronise on a log record.
// Run with: go test -tags=functional ./nf/smf/...
// Ref: TS 23.502 §4.2.6 steps 5-7; TS 29.244 §7.5.4.3, §7.5.5, §8.2.26; TS 23.501 §5.8.2.19.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
)

const (
	anRelRef = "sm-ctx-an-1"
	// anRelWithin bounds every poll; the silent-UPF case needs hoN4Timeout (1.5 s) to elapse.
	anRelWithin = 6 * time.Second
	// anRelImmediate: the SMF answers the AMF before the N4 transaction; far below hoN4Timeout.
	anRelImmediate = 500 * time.Millisecond
	// FAR Apply Action bits, TS 29.244 §8.2.26.
	anRelBUFF = 0x04
	anRelNOCP = 0x08
)

type anRelWorld struct{ hoStepsWorld }

func (w *anRelWorld) startUPF() error {
	w.close()
	upf, err := newHOStepsUPF()
	if err != nil {
		return err
	}
	w.upf = upf
	return nil
}

func (w *anRelWorld) startSMF() error {
	if w.upf == nil {
		return fmt.Errorf("fake UPF not started")
	}
	w.amf = newHOStepsAMF(http.StatusNoContent)
	w.logs = &hoLogStore{}
	cfg := &config.Config{UEIPPool: "10.60.0.0/24", UPFN3Addr: hoStepsUPFN3}
	cfg.Peers.UPF = w.upf.addr()
	cfg.Peers.AMFMgmt = w.amf.host()
	srv, err := New(cfg, slog.New(hoLogHandler{store: w.logs}), nil)
	if err != nil {
		return fmt.Errorf("new SMF server: %w", err)
	}
	w.srv = srv
	w.srv.pfcpTimers.t1, w.srv.pfcpTimers.n1 = 3*time.Second, 1
	return nil
}

func (w *anRelWorld) activeSession(supi string, psi int) error {
	if w.srv == nil {
		return fmt.Errorf("SMF not started")
	}
	w.sess = &Session{SUPI: supi, PDUSessionID: uint8(psi), DNN: "internet", SEID: 42, State: "ACTIVE",
		ULTEID: hoStepsULTEID, FiveQI: hoStepsFiveQI, AMBRULMbps: 100, AMBRDLMbps: 200}
	w.srv.sessionMu.Lock()
	w.srv.sessions[anRelRef] = w.sess
	w.srv.sessionMu.Unlock()
	return nil
}

func (w *anRelWorld) upfAnswers(cause int) error { w.upf.setMode("respond", uint8(cause)); return nil }
func (w *anRelWorld) upfSilentMode() error       { return w.upfSilent() }

func (w *anRelWorld) setState(state string) error {
	w.srv.sessionMu.Lock()
	w.sess.State = state
	w.srv.sessionMu.Unlock()
	return nil
}

func (w *anRelWorld) targetFailedSession() error {
	if err := w.preparedWithTunnel(anRelRef); err != nil {
		return err
	}
	if err := w.resAllocFailValid(anRelRef); err != nil {
		return err
	}
	// TS 29.502 §5.2.2.3.4: the SMF answers the failed allocation with 403 HANDOVER_PREP_FAIL.
	if err := w.respondsStatus(http.StatusForbidden); err != nil {
		return fmt.Errorf("precondition HANDOVER_RES_ALLOC_FAIL: %w", err)
	}
	return w.targetFailed(true)
}

func (w *anRelWorld) deactivatedFor(ref string) error {
	return w.post(ref, map[string]interface{}{"upCnxState": "DEACTIVATED"})
}

func (w *anRelWorld) deactivatedSession() error { return w.deactivatedFor(anRelRef) }
func (w *anRelWorld) deactivatedUnknown() error { return w.deactivatedFor("sm-ctx-unknown") }

func (w *anRelWorld) resSetupFail() error {
	tr, err := hoStepsMarshal(ngapType.PDUSessionResourceSetupUnsuccessfulTransfer{
		Cause: ngapCause(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentRadioResourcesNotAvailable)})
	if err != nil {
		return err
	}
	return w.post(anRelRef, map[string]interface{}{
		"n2SmInfoType": "PDU_RES_SETUP_FAIL", "n2SmInfo": b64(tr)})
}

// ---- Thens ----------------------------------------------------------------------------------

func (w *anRelWorld) http200() error { return w.respondsStatus(200) }

func (w *anRelWorld) http200Immediately() error {
	if err := w.respondsStatus(200); err != nil {
		return err
	}
	if d := w.postEnd.Sub(w.postStart); d > anRelImmediate {
		return fmt.Errorf("UpdateSMContext took %s, want < %s (must not wait for the N4 transaction)", d, anRelImmediate)
	}
	return nil
}

func (w *anRelWorld) http404(cause string) error { return w.respondsProblem(404, cause) }

// firstModification polls until the fake UPF has received a message and returns it as a
// Session Modification Request.
func (w *anRelWorld) firstModification() (*pfcpmsg.SessionModificationRequest, error) {
	if err := hoStepsPoll(anRelWithin, func() error {
		if w.upf.count() == 0 {
			return fmt.Errorf("no PFCP message reached the fake UPF within %s", anRelWithin)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return w.upf.modification(0)
}

func (w *anRelWorld) receivesModWithSEID() error {
	req, err := w.firstModification()
	if err != nil {
		return err
	}
	if !req.HasSEID() || req.SEID() != w.sess.SEID {
		return fmt.Errorf("PFCP header SEID = %d (present %v), want session SEID %d", req.SEID(), req.HasSEID(), w.sess.SEID)
	}
	return nil
}

// updateFARChildren returns the children of the single Update FAR and checks FAR ID 1.
func (w *anRelWorld) updateFARChildren() ([]*pfcpie.IE, error) {
	req, err := w.firstModification()
	if err != nil {
		return nil, err
	}
	if len(req.UpdateFAR) != 1 || req.UpdateFAR[0] == nil {
		return nil, fmt.Errorf("Session Modification Request carries %d Update FAR, want exactly 1", len(req.UpdateFAR))
	}
	children, err := req.UpdateFAR[0].UpdateFAR()
	if err != nil {
		return nil, fmt.Errorf("Update FAR does not parse: %w", err)
	}
	for _, c := range children {
		if c.Type == pfcpie.FARID {
			if id, _ := c.FARID(); id != 1 {
				return nil, fmt.Errorf("Update FAR FAR ID = %d, want 1", id)
			}
			return children, nil
		}
	}
	return nil, fmt.Errorf("Update FAR has no FAR ID")
}

func (w *anRelWorld) oneUpdateFARID1() error {
	if _, err := w.updateFARChildren(); err != nil {
		return err
	}
	return nil
}

func (w *anRelWorld) applyActionIs(want uint8) error {
	children, err := w.updateFARChildren()
	if err != nil {
		return err
	}
	for _, c := range children {
		if c.Type == pfcpie.ApplyAction {
			got, err := c.ApplyAction()
			if err != nil {
				return fmt.Errorf("Apply Action does not parse: %w", err)
			}
			if got != want {
				return fmt.Errorf("Update FAR Apply Action = %#04x, want %#04x", got, want)
			}
			return nil
		}
	}
	return fmt.Errorf("Update FAR has no Apply Action")
}

func (w *anRelWorld) applyBuffNocp() error {
	if err := w.applyActionIs(anRelBUFF | anRelNOCP); err != nil {
		return err
	}
	return nil // exact 0x0C implies BUFF and NOCP set, FORW and DROP clear
}

func (w *anRelWorld) applyDrop() error { return w.applyActionIs(hoStepsApplyDROP) }

func (w *anRelWorld) modWithFARAndAction(action int) error {
	if err := w.oneUpdateFARID1(); err != nil {
		return err
	}
	return w.applyActionIs(uint8(action))
}

func (w *anRelWorld) noFwdNoBARID() error {
	children, err := w.updateFARChildren()
	if err != nil {
		return err
	}
	for _, c := range children {
		switch c.Type {
		case pfcpie.UpdateForwardingParameters:
			return fmt.Errorf("Update FAR carries Update Forwarding Parameters")
		case pfcpie.BARID:
			return fmt.Errorf("Update FAR carries a BAR ID")
		}
	}
	return nil
}

func (w *anRelWorld) noBAR() error {
	req, err := w.firstModification()
	if err != nil {
		return err
	}
	if req.CreateBAR != nil || req.UpdateBAR != nil {
		return fmt.Errorf("Session Modification Request carries a Create BAR or Update BAR")
	}
	return nil
}

func (w *anRelWorld) stateEventually(want string) error {
	return hoStepsPoll(anRelWithin, func() error { return w.stateIs(want) })
}

func (w *anRelWorld) logs4N(dir, key, val, spec string) error {
	return hoStepsPoll(anRelWithin, func() error {
		if _, ok := w.logs.find(func(r hoRec) bool {
			return r.attrs["procedure"] == "AnRelease" && r.attrs["interface"] == "N4" &&
				r.attrs["direction"] == dir && r.attrs[key] == val && r.attrs["spec_ref"] == spec
		}); !ok {
			return fmt.Errorf("no log with procedure AnRelease interface N4 direction %s %s=%q spec_ref %q", dir, key, val, spec)
		}
		return nil
	})
}

func (w *anRelWorld) logsWarn(dir, result, key, val string) error {
	return hoStepsPoll(anRelWithin, func() error {
		if _, ok := w.logs.find(func(r hoRec) bool {
			return r.level == slog.LevelWarn && r.attrs["procedure"] == "AnRelease" &&
				r.attrs["direction"] == dir && r.attrs["result"] == result && r.attrs[key] == val
		}); !ok {
			return fmt.Errorf("no WARN log with procedure AnRelease direction %s result %s %s=%q", dir, result, key, val)
		}
		return nil
	})
}

func (w *anRelWorld) logsRejectCause(cause int) error {
	return w.logsWarn("IN", "REJECT", "pfcp_cause", strconv.Itoa(cause))
}

func (w *anRelWorld) logsTimeout(cause string) error {
	return w.logsWarn("IN", "FAILURE", "cause", cause)
}

// noDropFallback runs after the REJECT log; the rejection path returns without further N4.
func (w *anRelWorld) noDropFallback() error {
	for i := 0; i < w.upf.count(); i++ {
		req, err := w.upf.modification(i)
		if err != nil {
			return err
		}
		for _, f := range req.UpdateFAR {
			children, err := f.UpdateFAR()
			if err != nil {
				return err
			}
			for _, c := range children {
				if c.Type == pfcpie.ApplyAction {
					if aa, _ := c.ApplyAction(); aa&hoStepsApplyDROP != 0 {
						return fmt.Errorf("PFCP request #%d carries Apply Action DROP (%#04x)", i, aa)
					}
				}
			}
		}
	}
	if n := w.upf.count(); n != 1 {
		return fmt.Errorf("fake UPF received %d PFCP messages, want exactly 1 (no fallback)", n)
	}
	return nil
}

// noPFCPObserved: the SMF launches the AN release asynchronously, so a RELEASING session is
// observed through the "PFCP SessionDeactivation skipped" record (the goroutine's only effect);
// a synchronous 404 has no goroutine to wait for.
func (w *anRelWorld) noPFCPObserved() error {
	if w.rec != nil && w.rec.Code == http.StatusOK {
		if err := hoStepsPoll(anRelWithin, func() error {
			if _, ok := w.logs.find(func(r hoRec) bool {
				return r.msg == "PFCP SessionDeactivation skipped — session RELEASING after UPF restart/failure"
			}); !ok {
				return fmt.Errorf("N4 skip record of the RELEASING session not seen")
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if err := w.drain(); err != nil {
		return err
	}
	if n := w.upf.count(); n != 0 {
		return fmt.Errorf("fake UPF received %d PFCP messages, want none", n)
	}
	return nil
}

func (w *anRelWorld) noAnReleaseBuffLog() error {
	if err := w.drain(); err != nil {
		return err
	}
	if _, ok := w.logs.find(func(r hoRec) bool {
		return r.attrs["procedure"] == "AnRelease" && r.attrs["apply_action"] == "BUFF+NOCP"
	}); ok {
		return fmt.Errorf("unexpected AnRelease log with apply_action BUFF+NOCP")
	}
	return nil
}

// dropAfterDrain waits for the detached deactivation to finish before asserting its FAR.
func (w *anRelWorld) afterDrain(f func() error) func() error {
	return func() error {
		if _, err := w.firstModification(); err != nil {
			return err
		}
		if err := w.drain(); err != nil {
			return err
		}
		return f()
	}
}

// InitializeAnReleaseScenario wires an_release.feature.
func InitializeAnReleaseScenario(ctx *godog.ScenarioContext) {
	w := &anRelWorld{}
	ctx.After(func(c context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		w.close()
		return c, nil
	})

	ctx.Step(`^a fake UPF PFCP peer listening on a loopback UDP socket that answers PFCP Session Modification Requests with Cause "Request accepted"$`, w.startUPF)
	ctx.Step(`^the SMF is running in-process with the fake UPF as N4 peer$`, w.startSMF)
	ctx.Step(`^the SMF holds an ACTIVE PDU session "([^"]+)" PSI (\d+) with DL FAR 1 forwarding to the AN tunnel$`, w.activeSession)
	ctx.Step(`^the fake UPF answers PFCP Session Modification Requests with Cause (\d+) "Request rejected"$`, w.upfAnswers)
	ctx.Step(`^the fake UPF receives PFCP Session Modification Requests without answering$`, w.upfSilentMode)
	ctx.Step(`^the SMF PDU session is in state "([A-Z]+)"$`, w.setState)
	ctx.Step(`^the SMF PDU session is a handover target-failed session after "HANDOVER_RES_ALLOC_FAIL"$`, w.targetFailedSession)

	ctx.Step(`^the AMF sends Nsmf_PDUSession_UpdateSMContext with upCnxState "DEACTIVATED" for the session$`, w.deactivatedSession)
	ctx.Step(`^the AMF sends Nsmf_PDUSession_UpdateSMContext with upCnxState "DEACTIVATED" for an unknown smContextRef$`, w.deactivatedUnknown)
	ctx.Step(`^the AMF reports "PDU_RES_SETUP_FAIL" for the session$`, w.resSetupFail)

	ctx.Step(`^the SMF answers the UpdateSMContext with HTTP 200$`, w.http200)
	ctx.Step(`^the SMF answers the UpdateSMContext with HTTP 200 without waiting for the N4 transaction$`, w.http200Immediately)
	ctx.Step(`^the SMF answers the UpdateSMContext with HTTP 404 and ProblemDetails cause "([^"]+)"$`, w.http404)
	ctx.Step(`^the fake UPF receives a PFCP Session Modification Request with the UP SEID of the session in the header$`, w.receivesModWithSEID)
	ctx.Step(`^the PFCP Session Modification Request contains exactly one Update FAR with FAR ID 1$`, w.oneUpdateFARID1)
	ctx.Step(`^the Update FAR Apply Action is exactly 0x0C with BUFF set, NOCP set, FORW not set and DROP not set$`, w.applyBuffNocp)
	ctx.Step(`^the Update FAR Apply Action is exactly 0x01 with DROP set, BUFF not set, NOCP not set and FORW not set$`, w.afterDrain(w.applyDrop))
	ctx.Step(`^the Update FAR contains no Update Forwarding Parameters and no BAR ID$`, w.noFwdNoBARID)
	ctx.Step(`^the PFCP Session Modification Request contains no Create BAR and no Update BAR$`, w.noBAR)
	ctx.Step(`^the fake UPF receives a PFCP Session Modification Request with Update FAR 1 and Apply Action (0x0C)$`,
		func(string) error { return w.modWithFARAndAction(0x0C) })
	ctx.Step(`^the fake UPF receives a PFCP Session Modification Request with Update FAR 1$`, w.oneUpdateFARID1)
	ctx.Step(`^the SMF PDU session state is "([A-Z]+)"$`, w.stateEventually)
	ctx.Step(`^the fake UPF receives no PFCP message within the observation window$`, w.noPFCPObserved)
	ctx.Step(`^the SMF sends no PFCP Session Modification Request with Apply Action DROP as fallback$`, w.noDropFallback)

	ctx.Step(`^the SMF logs procedure "AnRelease" interface "N4" direction "OUT" with apply_action "([^"]+)" and spec_ref "([^"]+)"$`,
		func(aa, spec string) error { return w.logs4N("OUT", "apply_action", aa, spec) })
	ctx.Step(`^the SMF logs procedure "AnRelease" interface "N4" direction "IN" with result "([^"]+)" and spec_ref "([^"]+)"$`,
		func(res, spec string) error { return w.logs4N("IN", "result", res, spec) })
	ctx.Step(`^the SMF logs a warning with procedure "AnRelease" direction "IN" result "REJECT" and cause (\d+)$`, w.logsRejectCause)
	ctx.Step(`^the SMF logs a warning with procedure "AnRelease" direction "IN" result "FAILURE" and cause "([^"]+)" within the deadline$`, w.logsTimeout)
	ctx.Step(`^the SMF logs no procedure "AnRelease" with apply_action "BUFF\+NOCP" for the session$`, w.noAnReleaseBuffLog)
}

// TestAnReleaseFeatures runs an_release.feature against the real handleUpdateSMContext.
func TestAnReleaseFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeAnReleaseScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"../../tests/features/an_release.feature"},
			TestingT: t,
			Strict:   true,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog scenarios failed")
	}
}
