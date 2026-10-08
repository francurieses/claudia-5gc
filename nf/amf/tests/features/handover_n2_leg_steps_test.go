//go:build functional

// handover_n2_leg_steps_test.go — in-process godog steps for the AMF-012 follow-up scenarios of
// handover_smf_leg.feature: the N2 PREPARING leg at HANDOVER REQUIRED, the target-failed PDU
// sessions (HANDOVER_RES_ALLOC_FAIL, IE 78) of the HANDOVER REQUEST ACKNOWLEDGE and the
// COMPLETED leg after HANDOVER NOTIFY.
//
// It reuses the world, the SMF fake and the helpers of handover_smf_leg_steps_test.go and
// xn_handover_steps_test.go; the only SMF seam is the injectable fake registered through the
// ngap.Server hooks (the JSON fields hoState / n2SmInfoType / targetId are added by
// HTTPSMFClient and covered by nf/amf/cmd/amf/smf_update_test.go; the fake asserts the hook
// kind it was registered on and the decoded arguments it received).
//
// Ordering / blocking assertions use channels and polling with deadlines, never bare sleeps.
//
// Ref: TS 23.502 §4.9.1.3.2 steps 3-12, §4.9.1.3.3; TS 29.502 §5.2.2.3.4; TS 38.413 §8.4.1-§8.4.3.
package features_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/free5gc/aper"
	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"github.com/prometheus/client_golang/prometheus"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	amfngap "github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
)

// hoSnapshotMetrics returns fivegc_procedure_total{nf="AMF"} per "procedure/result" so a
// scenario asserts deltas (the counters are process-global and never reset).
func hoSnapshotMetrics() map[string]float64 {
	out := map[string]float64{}
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return out
	}
	for _, mf := range mfs {
		if mf.GetName() != "fivegc_procedure_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			l := map[string]string{}
			for _, lp := range m.GetLabel() {
				l[lp.GetName()] = lp.GetValue()
			}
			if l["nf"] == "AMF" {
				out[l["procedure"]+"/"+l["result"]] = m.GetCounter().GetValue()
			}
		}
	}
	return out
}

// hoRequiredTransfer is a valid HandoverRequiredTransfer (TS 38.413 §9.3.4.14). The bytes
// differ between odd and even PDU session ids (Direct Forwarding Path Availability present
// only for odd ids) so a per-PDU-session relay assertion is meaningful.
func hoRequiredTransfer(psi uint8) ([]byte, error) {
	tr := ngapType.HandoverRequiredTransfer{}
	if psi%2 == 1 {
		tr.DirectForwardingPathAvailability = &ngapType.DirectForwardingPathAvailability{
			Value: ngapType.DirectForwardingPathAvailabilityPresentDirectPathAvailable}
	}
	b, err := aper.MarshalWithParams(tr, "valueExt")
	if err != nil {
		return nil, fmt.Errorf("marshal HandoverRequiredTransfer: %w", err)
	}
	return b, nil
}

func hoPSIArgs(a, b string) []uint8 {
	var out []uint8
	for _, s := range []string{a, b} {
		if s == "" {
			continue
		}
		n, _ := strconv.Atoi(s)
		out = append(out, uint8(n))
	}
	return out
}

// hoRadioCause maps the radioNetwork cause names used by the feature to their TS 38.413 values.
func hoRadioCause(name string) (aper.Enumerated, error) {
	m := map[string]aper.Enumerated{
		"unspecified":            ngapType.CauseRadioNetworkPresentUnspecified,
		"unknown-PDU-session-ID": ngapType.CauseRadioNetworkPresentUnknownPDUSessionID,
		"successful-handover":    ngapType.CauseRadioNetworkPresentSuccessfulHandover,
		"ho-failure-in-target-5GC-ngran-node-or-target-system": ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem,
	}
	v, ok := m[name]
	if !ok {
		return 0, fmt.Errorf("feature uses unmapped radioNetwork cause %q", name)
	}
	return v, nil
}

// hoCauseIs asserts a radioNetwork cause by name AND by its numeric TS 38.413 value.
func hoCauseIs(c ngapType.Cause, name string, num int) error {
	v, err := hoRadioCause(name)
	if err != nil {
		return err
	}
	if int(v) != num {
		return fmt.Errorf("feature maps cause %q to %d, TS 38.413 has %d", name, num, v)
	}
	if c.Present != ngapType.CausePresentRadioNetwork || c.RadioNetwork == nil || c.RadioNetwork.Value != v {
		return fmt.Errorf("cause = %+v, want radioNetwork %s (%d)", c, name, num)
	}
	return nil
}

func hoLogAll(pred func(r xnRec) bool) []xnRec {
	xnW.logs.mu.Lock()
	defer xnW.logs.mu.Unlock()
	var out []xnRec
	for _, r := range xnW.logs.recs {
		if pred(r) {
			out = append(out, r)
		}
	}
	return out
}

// ---- decoding of what the AMF wrote ------------------------------------------------------------

func hoLastTarget() ([]byte, error) {
	sent := xnW.tgtLn.pdus()
	if len(sent) == 0 {
		return nil, fmt.Errorf("nothing written to the target gNB")
	}
	return sent[len(sent)-1].raw, nil
}

func hoLastHandoverRequest() (*ngapType.HandoverRequest, error) {
	raw, err := hoLastTarget()
	if err != nil {
		return nil, err
	}
	pdu, err := libngap.Decoder(raw)
	if err != nil {
		return nil, fmt.Errorf("free5gc/ngap decode: %w", err)
	}
	if pdu.InitiatingMessage == nil || pdu.InitiatingMessage.Value.HandoverRequest == nil {
		return nil, fmt.Errorf("last PDU written to the target gNB is not a HANDOVER REQUEST")
	}
	return pdu.InitiatingMessage.Value.HandoverRequest, nil
}

// hoReqItems returns the PDUSessionResourceSetupListHOReq of the last HANDOVER REQUEST.
func hoReqItems() (map[int64][]byte, []int64, error) {
	hr, err := hoLastHandoverRequest()
	if err != nil {
		return nil, nil, err
	}
	items, order := map[int64][]byte{}, []int64{}
	for _, ie := range hr.ProtocolIEs.List {
		if l := ie.Value.PDUSessionResourceSetupListHOReq; l != nil {
			for _, it := range l.List {
				items[it.PDUSessionID.Value] = []byte(it.HandoverRequestTransfer)
				order = append(order, it.PDUSessionID.Value)
			}
		}
	}
	return items, order, nil
}

func hoLastPrepFailure() (*ngapType.HandoverPreparationFailure, error) {
	last, ok := hoW.lastSrc()
	if !ok {
		return nil, fmt.Errorf("nothing written to the source gNB")
	}
	pdu, err := libngap.Decoder(last.raw)
	if err != nil {
		return nil, fmt.Errorf("free5gc/ngap decode: %w", err)
	}
	if pdu.UnsuccessfulOutcome == nil || pdu.UnsuccessfulOutcome.Value.HandoverPreparationFailure == nil {
		return nil, fmt.Errorf("last PDU written to the source gNB is not a HANDOVER PREPARATION FAILURE")
	}
	return pdu.UnsuccessfulOutcome.Value.HandoverPreparationFailure, nil
}

// hoFindRelease returns the Cause of the UE CONTEXT RELEASE COMMAND written to the source gNB.
func hoFindRelease() (*ngapType.Cause, error) {
	for _, p := range xnW.srcLn.pdus() {
		pdu, err := libngap.Decoder(p.raw)
		if err != nil {
			return nil, err
		}
		if pdu.InitiatingMessage == nil || pdu.InitiatingMessage.Value.UEContextReleaseCommand == nil {
			continue
		}
		if p.ppid != 60 {
			return nil, fmt.Errorf("UE CONTEXT RELEASE COMMAND written with PPID %d, want 60", p.ppid)
		}
		for _, ie := range pdu.InitiatingMessage.Value.UEContextReleaseCommand.ProtocolIEs.List {
			if ie.Value.Cause != nil {
				return ie.Value.Cause, nil
			}
		}
		return nil, fmt.Errorf("UE CONTEXT RELEASE COMMAND without Cause IE")
	}
	return nil, nil
}

// captureHO decodes the last PDU of interest after a HANDOVER REQUIRED: the HANDOVER REQUEST
// on the target link or, failing that, the HANDOVER PREPARATION FAILURE on the source link, so
// the shared "decodes cleanly" / Security Context steps see it.
func (w *hoWorld) captureHO() {
	if sent := xnW.tgtLn.pdus(); len(sent) > 0 {
		xnW.decode(sent[len(sent)-1].raw)
		return
	}
	if sent := xnW.srcLn.pdus(); len(sent) > 0 {
		xnW.decode(sent[len(sent)-1].raw)
	}
}

// newRequired prepares a HANDOVER REQUIRED from the source gNB towards target listing psis.
func (w *hoWorld) newRequired(target string, psis []uint8, withTransfers bool) (*amfngap.HandoverRequiredMsg, error) {
	x := &xnW
	if x.tgt == nil || x.tgt.Name != target {
		return nil, fmt.Errorf("target gNB %q unknown", target)
	}
	req := &amfngap.HandoverRequiredMsg{
		AMFUENGAPId: x.amfID, RANUENGAPId: x.ranOld, TargetGlobalRANNodeID: x.tgt.GlobalGNBID,
		SourceToTargetTransparentContainer: []byte{9},
		Target: amfngap.HOTargetID{
			Node: amfngap.NewGlobalGNBForTest("001", "01", 0x123456, 24),
			TAI:  &amfngap.HOTargetTAI{MCC: "001", MNC: "01", TAC: "000001"},
		},
	}
	if withTransfers {
		for _, p := range psis {
			tr, err := hoRequiredTransfer(p)
			if err != nil {
				return nil, err
			}
			req.PDUSessions = append(req.PDUSessions, amfngap.PDUSessionHORqdItem{PDUSessionID: p, HandoverRequiredTransfer: tr})
		}
	}
	w.prep = true
	return req, nil
}

// runRequired handles req on the SCTP-loop path. When the test holds an SMF answer only the
// inline part runs (as on the read loop); otherwise the UE's serial task is awaited.
func (w *hoWorld) runRequired(req *amfngap.HandoverRequiredMsg) error {
	x := &xnW
	if req == nil {
		return fmt.Errorf("no HANDOVER REQUIRED prepared")
	}
	x.srcLn.reset()
	x.tgtLn.reset()
	start := time.Now()
	if w.fake != nil && w.fake.hasAnyBlock() {
		x.srv.StartHandoverRequiredForTest(w.ctx(), x.src, req)
		w.elapsed = time.Since(start)
		return nil
	}
	x.srv.HandleHandoverRequiredForTest(w.ctx(), x.src, req)
	w.elapsed = time.Since(start)
	w.captureHO()
	return nil
}

func (w *hoWorld) setOutcome(table map[uint8]*hoOutcome, psis []uint8, outcome string) error {
	for _, p := range psis {
		o, err := parseOutcome(outcome, p)
		if err != nil {
			return err
		}
		w.fake.mu.Lock()
		table[p] = o
		w.fake.mu.Unlock()
	}
	return nil
}

func (w *hoWorld) hold(table map[uint8]*hoOutcome, p uint8) {
	w.fake.mu.Lock()
	table[p] = &hoOutcome{mode: modeBlock, release: make(chan amfngap.SMFUpdateResult, 1)}
	w.fake.mu.Unlock()
	xnW.srv.SetSMFHOUpdateTimeoutForTest(hoLongTimeout) // the test, not the AMF timer, ends the wait
}

// kindOfType maps an n2SmInfoType / hoState pair of a feature step to the hook kind.
func kindOfType(typ string) (string, error) {
	switch typ {
	case "HANDOVER_REQUIRED":
		return kindPreparing, nil
	case "HANDOVER_RES_ALLOC_FAIL":
		return kindResAlloc, nil
	case "HANDOVER_REQ_ACK":
		return kindHOAck, nil
	}
	return "", fmt.Errorf("no hook kind for n2SmInfoType %q", typ)
}

// ---- registration -------------------------------------------------------------------------------

func initHandoverN2LegSteps(sc *godog.ScenarioContext) {
	w := &hoW

	// ---- Givens: HANDOVER REQUIRED
	sc.Step(`^the source gNB sends a HANDOVER REQUIRED towards "([^"]+)" listing PDU session ids? (\d+)(?: and (\d+))?(?: each)? with a (?:distinct )?valid HandoverRequiredTransfer$`,
		func(target, a, b string) error {
			req, err := w.newRequired(target, hoPSIArgs(a, b), true)
			w.hoReq = req
			return err
		})
	sc.Step(`^the source gNB sends a HANDOVER REQUIRED towards "([^"]+)" without a PDU Session Resource List HORqd$`,
		func(target string) error {
			req, err := w.newRequired(target, nil, false)
			w.hoReq = req
			return err
		})
	sc.Step(`^the UE has no PDU sessions in the AMF$`, func() error {
		xnW.ue.Lock()
		xnW.ue.PDUSessions = map[uint8]*amfctx.PDUSession{}
		xnW.ue.Unlock()
		return nil
	})
	sc.Step(`^the UE PDU session id (\d+) has a cached N2SmTransfer of known bytes$`, func(p int) error {
		known := []byte{0xC4, uint8(p), 0x5A, 0xA5}
		xnW.ue.Lock()
		defer xnW.ue.Unlock()
		s := xnW.ue.PDUSessions[uint8(p)]
		if s == nil {
			return fmt.Errorf("UE has no PDU session id %d", p)
		}
		s.N2SmTransfer = known
		if w.cached == nil {
			w.cached = map[uint8][]byte{}
		}
		w.cached[uint8(p)] = known
		return nil
	})

	// ---- Givens: SMF fake behaviour per leg
	sc.Step(`^the SMF fake (?:now )?answers the PREPARING request of PDU session ids? (\d+)(?: and (\d+))? with (.+)$`,
		func(a, b, outcome string) error { return w.setOutcome(w.fake.prep, hoPSIArgs(a, b), outcome) })
	sc.Step(`^the SMF fake answers the HANDOVER_RES_ALLOC_FAIL of PDU session ids? (\d+)(?: and (\d+))? with (.+)$`,
		func(a, b, outcome string) error { return w.setOutcome(w.fake.resAlloc, hoPSIArgs(a, b), outcome) })
	sc.Step(`^the SMF fake answers the COMPLETED request of PDU session id (\d+) with (.+)$`,
		func(p int, outcome string) error { return w.setOutcome(w.fake.complete, []uint8{uint8(p)}, outcome) })
	sc.Step(`^the SMF fake blocks the PREPARING answer for PDU session id (\d+) until released by the test$`,
		func(p int) error { w.hold(w.fake.prep, uint8(p)); return nil })
	sc.Step(`^the SMF fake blocks the COMPLETED answer for PDU session id (\d+) until released by the test$`,
		func(p int) error { w.hold(w.fake.complete, uint8(p)); return nil })

	// ---- Givens: HANDOVER REQUEST ACKNOWLEDGE with target-failed PDU sessions
	sc.Step(`^the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting (?:PDU session ids? (\d+)(?: and (\d+))?|no PDU session) and a PDU Session Resource Failed to Setup List HOAck with PDU session ids? (\d+)(?: and (\d+))? and cause "([^"]+)" (\d+)$`,
		func(a1, a2, f1, f2, kind string, val int) error {
			if kind != "radioNetwork" {
				return fmt.Errorf("feature uses unmapped cause kind %q", kind)
			}
			w.n2, w.ackSet = true, true
			w.admitted, w.failedAck = nil, nil
			w.ackTrans = map[uint8][]byte{}
			for _, p := range hoPSIArgs(a1, a2) {
				t := []byte{0xEE, p}
				w.ackTrans[p] = t
				w.admitted = append(w.admitted, amfngap.PDUSessionHOAdmittedItem{PDUSessionID: p, HandoverRequestAcknowledgeTransfer: t})
			}
			for _, p := range hoPSIArgs(f1, f2) {
				tr, err := aper.MarshalWithParams(ngapType.HandoverResourceAllocationUnsuccessfulTransfer{
					Cause: ngapType.Cause{Present: ngapType.CausePresentRadioNetwork,
						RadioNetwork: &ngapType.CauseRadioNetwork{Value: aper.Enumerated(val)}},
				}, "valueExt")
				if err != nil {
					return fmt.Errorf("marshal HandoverResourceAllocationUnsuccessfulTransfer: %w", err)
				}
				w.failedAck = append(w.failedAck, amfngap.PDUSessionHOFailedItem{PDUSessionID: p, HandoverResourceAllocationUnsuccessfulTransfer: tr})
			}
			return nil
		})

	// ---- Whens
	sc.Step(`^the AMF handles the HANDOVER REQUIRED$`, func() error { return w.runRequired(w.hoReq) })
	sc.Step(`^the AMF handles the HANDOVER REQUIRED and the HANDOVER REQUEST ACKNOWLEDGE$`, func() error { return w.handleBoth() })
	sc.Step(`^the source gNB sends a second HANDOVER REQUIRED towards "([^"]+)" listing PDU session id (\d+) with a valid HandoverRequiredTransfer$`,
		func(target string, p int) error {
			req, err := w.newRequired(target, []uint8{uint8(p)}, true)
			if err != nil {
				return err
			}
			w.hoReq2 = req
			return w.runRequired(req)
		})
	sc.Step(`^the test releases the PREPARING answer for PDU session id (\d+) with 200 hoState "([^"]+)" n2SmInfoType "([^"]+)" and a valid PDUSessionResourceSetupRequestTransfer$`,
		func(p int, state, typ string) error {
			b, err := hoValidTransfer(typ, uint8(p))
			if err != nil {
				return err
			}
			w.fake.mu.Lock()
			o := w.fake.prep[uint8(p)]
			w.fake.mu.Unlock()
			if o == nil || o.mode != modeBlock {
				return fmt.Errorf("no held PREPARING answer for PDU session id %d", p)
			}
			o.release <- amfngap.SMFUpdateResult{HTTPStatus: 200, HoState: state, N2SmInfo: b, N2SmInfoType: typ}
			if !xnW.srv.WaitUESerialForTest(xnW.amfID) {
				return fmt.Errorf("the UE serial queue did not drain")
			}
			w.captureHO()
			return nil
		})
	sc.Step(`^the target gNB sends a HANDOVER NOTIFY for the UE$`, func() error {
		x := &xnW
		notify := &amfngap.HandoverNotifyMsg{AMFUENGAPId: x.amfID, RANUENGAPId: 7}
		if w.fake != nil && w.fake.hasAnyBlock() {
			// The COMPLETED answer is held: the handler waits for it, so it runs in a goroutine and
			// the scenario observes the UE CONTEXT RELEASE COMMAND while it is still waiting.
			w.notifyDone = make(chan struct{})
			go func() {
				defer close(w.notifyDone)
				x.srv.HandleHandoverNotifyForTest(w.ctx(), x.tgt, notify)
			}()
			return nil
		}
		x.srv.HandleHandoverNotifyForTest(w.ctx(), x.tgt, notify)
		return nil
	})

	// ---- Thens: SMF fake saw ... (PREPARING leg)
	sc.Step(`^the SMF fake has received the PREPARING requests? for PDU session ids? (.+?)(?: of UE "[^"]+")?$`, func(list string) error {
		psis := hoPSIList(list)
		if !w.fake.waitFor(func() bool {
			for _, p := range psis {
				if len(w.fake.callsOf(kindPreparing, p)) == 0 {
					return false
				}
			}
			return true
		}) {
			return fmt.Errorf("the SMF fake did not receive PREPARING for PDU session ids %v within %v", psis, hoWait)
		}
		return nil
	})
	sc.Step(`^the SMF fake received exactly one UpdateSMContext per listed PDU session with hoState "PREPARING" and n2SmInfoType "HANDOVER_REQUIRED"$`, func() error {
		if w.hoReq == nil || len(w.hoReq.PDUSessions) == 0 {
			return fmt.Errorf("no listed PDU sessions prepared")
		}
		for _, it := range w.hoReq.PDUSessions {
			if n := len(w.fake.callsOf(kindPreparing, int(it.PDUSessionID))); n != 1 {
				return fmt.Errorf("PDU session id %d: %d PREPARING calls, want 1", it.PDUSessionID, n)
			}
		}
		return nil
	})
	sc.Step(`^each PREPARING n2SmInfo equals the HandoverRequiredTransfer of that PDU session in the HANDOVER REQUIRED$`, func() error {
		for _, it := range w.hoReq.PDUSessions {
			c := w.fake.callsOf(kindPreparing, int(it.PDUSessionID))
			if len(c) != 1 || !bytes.Equal(c[0].n2, it.HandoverRequiredTransfer) {
				return fmt.Errorf("PDU session id %d: relayed %d call(s) %x, HANDOVER REQUIRED carried %x",
					it.PDUSessionID, len(c), hoFirstN2(c), it.HandoverRequiredTransfer)
			}
		}
		return nil
	})
	sc.Step(`^each PREPARING request carries a targetId whose ranNodeId\.gNbId and tai\.tac equal the Target ID of the HANDOVER REQUIRED$`, func() error {
		want := w.hoReq.Target
		if want.TAI == nil || want.Node.GNBIDBitLen == 0 {
			return fmt.Errorf("the prepared HANDOVER REQUIRED carries no Target ID")
		}
		calls := w.fake.callsOf(kindPreparing, -1)
		if len(calls) == 0 {
			return fmt.Errorf("no PREPARING call recorded")
		}
		for _, c := range calls {
			got := c.target
			if got.Node.GNBID != want.Node.GNBID || got.Node.GNBIDBitLen != want.Node.GNBIDBitLen ||
				got.Node.MCC != want.Node.MCC || got.Node.MNC != want.Node.MNC {
				return fmt.Errorf("PDU session id %d: gNbId = %+v, want %+v", c.psi, got.Node, want.Node)
			}
			if got.TAI == nil || got.TAI.TAC != want.TAI.TAC || got.TAI.MCC != want.TAI.MCC || got.TAI.MNC != want.TAI.MNC {
				return fmt.Errorf("PDU session id %d: tai = %+v, want %+v", c.psi, got.TAI, want.TAI)
			}
		}
		return nil
	})
	sc.Step(`^the SMF fake received no UpdateSMContext with hoState "(PREPARING|PREPARED|COMPLETED)" for PDU session id (\d+)$`, func(state string, p int) error {
		kinds := map[string][]string{
			"PREPARING": {kindPreparing}, "PREPARED": {kindHOAck, kindResAlloc}, "COMPLETED": {kindComplete},
		}[state]
		if !w.fake.quiet(100*time.Millisecond, func() bool {
			for _, k := range kinds {
				if len(w.fake.callsOf(k, p)) > 0 {
					return true
				}
			}
			return false
		}) {
			return fmt.Errorf("the SMF fake received UpdateSMContext hoState %s for PDU session id %d", state, p)
		}
		return nil
	})

	// ---- Thens: SMF fake saw ... (RES_ALLOC_FAIL / COMPLETED)
	sc.Step(`^the SMF fake received exactly one UpdateSMContext for PDU session id (\d+) with hoState "([^"]+)" and n2SmInfoType "([^"]+)"$`,
		func(p int, _ string, typ string) error {
			// hoState / n2SmInfoType are added by HTTPSMFClient (cmd/amf/smf_update_test.go); the
			// fake asserts the hook kind the call arrived on.
			k, err := kindOfType(typ)
			if err != nil {
				return err
			}
			if n := len(w.fake.callsOf(k, p)); n != 1 {
				return fmt.Errorf("PDU session id %d: %d %s calls, want 1", p, n, typ)
			}
			return nil
		})
	sc.Step(`^that n2SmInfo equals the HandoverResourceAllocationUnsuccessfulTransfer of PDU session id (\d+) in the HANDOVER REQUEST ACKNOWLEDGE$`, func(p int) error {
		c := w.fake.callsOf(kindResAlloc, p)
		for _, f := range w.failedAck {
			if int(f.PDUSessionID) == p {
				if len(c) != 1 || !bytes.Equal(c[0].n2, f.HandoverResourceAllocationUnsuccessfulTransfer) {
					return fmt.Errorf("relayed %d call(s) %x, ACK carried %x", len(c), hoFirstN2(c), f.HandoverResourceAllocationUnsuccessfulTransfer)
				}
				return nil
			}
		}
		return fmt.Errorf("PDU session id %d is not in the Failed to Setup List HOAck", p)
	})
	sc.Step(`^the SMF fake eventually received exactly one UpdateSMContext with hoState "COMPLETED" for PDU session id (\d+)$`, func(p int) error {
		if !w.fake.waitFor(func() bool { return len(w.fake.callsOf(kindComplete, p)) >= 1 }) {
			return fmt.Errorf("no COMPLETED UpdateSMContext for PDU session id %d within %v", p, hoWait)
		}
		if n := len(w.fake.callsOf(kindComplete, p)); n != 1 {
			return fmt.Errorf("PDU session id %d: %d COMPLETED calls, want exactly 1", p, n)
		}
		return nil
	})
	sc.Step(`^that COMPLETED request carries no n2SmInfo and no n2SmInfoType$`, func() error {
		// The HandoverCompleteHook signature has no N2 SM information parameter; the JSON body
		// is {"hoState":"COMPLETED"} only (cmd/amf/smf_update_test.go). The fake recorded n2 == nil.
		calls := w.fake.callsOf(kindComplete, -1)
		if len(calls) == 0 {
			return fmt.Errorf("no COMPLETED call recorded")
		}
		for _, c := range calls {
			if len(c.n2) != 0 {
				return fmt.Errorf("COMPLETED call for PDU session id %d carried n2SmInfo", c.psi)
			}
		}
		return nil
	})

	// ---- Thens: HANDOVER REQUEST content
	sc.Step(`^the AMF sends a HANDOVER REQUEST to the target gNB$`, func() error {
		_, err := hoLastHandoverRequest()
		return err
	})
	sc.Step(`^no HANDOVER REQUEST is written to the target gNB$`, func() error {
		if n := len(xnW.tgtLn.pdus()); n != 0 {
			return fmt.Errorf("%d PDU(s) written to the target gNB, want none", n)
		}
		return nil
	})
	sc.Step(`^the PDUSessionResourceSetupListHOReq item for PDU session id (\d+) carries exactly the bytes returned by the SMF for PDU session id (\d+)$`,
		func(item, ret int) error {
			items, _, err := hoReqItems()
			if err != nil {
				return err
			}
			got, ok := items[int64(item)]
			if !ok {
				return fmt.Errorf("PDU session id %d not in the PDUSessionResourceSetupListHOReq", item)
			}
			w.fake.mu.Lock()
			want := w.fake.returnedBy[kindPreparing][uint8(ret)]
			w.fake.mu.Unlock()
			return hoEqBytes(fmt.Sprintf("HOReq item %d", item), got, want)
		})
	sc.Step(`^the PDUSessionResourceSetupListHOReq item for PDU session id (\d+) carries exactly the cached N2SmTransfer bytes$`, func(item int) error {
		items, _, err := hoReqItems()
		if err != nil {
			return err
		}
		got, ok := items[int64(item)]
		if !ok {
			return fmt.Errorf("PDU session id %d not in the PDUSessionResourceSetupListHOReq", item)
		}
		return hoEqBytes(fmt.Sprintf("HOReq item %d", item), got, w.cached[uint8(item)])
	})
	sc.Step(`^the HANDOVER REQUEST PDUSessionResourceSetupListHOReq contains only PDU session id (\d+)$`, func(p int) error {
		_, order, err := hoReqItems()
		if err != nil {
			return err
		}
		if fmt.Sprint(order) != fmt.Sprint([]int64{int64(p)}) {
			return fmt.Errorf("PDUSessionResourceSetupListHOReq = %v, want [%d]", order, p)
		}
		return nil
	})
	sc.Step(`^no item of the HANDOVER REQUEST contains the bytes "([0-9a-f]+)"$`, func(h string) error {
		items, _, err := hoReqItems()
		if err != nil {
			return err
		}
		return noBytesIn("HANDOVER REQUEST", items, h)
	})
	sc.Step(`^the Security Context Next Hop Chaining Count of the HANDOVER REQUEST is (\d+)$`, func(ncc int) error {
		raw, err := hoLastTarget()
		if err != nil {
			return err
		}
		xnW.decode(raw)
		if xnW.decErr != nil {
			return xnW.decErr
		}
		if xnW.scNCC != int64(ncc) {
			return fmt.Errorf("NCC = %d, want %d", xnW.scNCC, ncc)
		}
		return nil
	})
	sc.Step(`^the Security Context NH of the HANDOVER REQUEST equals (KNH\(.+\))$`, func(expr string) error {
		raw, err := hoLastTarget()
		if err != nil {
			return err
		}
		xnW.decode(raw)
		if xnW.decErr != nil {
			return xnW.decErr
		}
		want := xnNHn(xnW.kamf, xnW.kgnb[:], strings.Count(expr, "KNH("))
		if !bytes.Equal(xnW.scNH, want) {
			return fmt.Errorf("NH does not equal %s", expr)
		}
		return nil
	})

	// ---- Thens: HANDOVER PREPARATION FAILURE / pending state
	sc.Step(`^the AMF sent a HANDOVER PREPARATION FAILURE to the source gNB$`, func() error {
		_, err := hoLastPrepFailure()
		return err
	})
	sc.Step(`^the HANDOVER PREPARATION FAILURE carries radioNetwork cause "([^"]+)" \((\d+)\)$`, func(name string, num int) error {
		f, err := hoLastPrepFailure()
		if err != nil {
			return err
		}
		for _, ie := range f.ProtocolIEs.List {
			if ie.Value.Cause != nil {
				return hoCauseIs(*ie.Value.Cause, name, num)
			}
		}
		return fmt.Errorf("no Cause IE in the HANDOVER PREPARATION FAILURE")
	})
	sc.Step(`^no pending N2 handover state exists for AMF UE NGAP ID (\d+)$`, func(id int) error {
		if xnW.srv.HasPendingN2HandoverForTest(int64(id)) {
			return fmt.Errorf("pending N2 handover state of AMF UE NGAP ID %d exists", id)
		}
		return nil
	})
	sc.Step(`^the HANDOVER REQUEST was written after the last PREPARING response was returned$`, func() error {
		sent := xnW.tgtLn.pdus()
		if len(sent) == 0 {
			return fmt.Errorf("no HANDOVER REQUEST written")
		}
		if last := w.fake.lastAnswer(); sent[len(sent)-1].at.Before(last) {
			return fmt.Errorf("HANDOVER REQUEST written at %v, before the last PREPARING response at %v", sent[len(sent)-1].at, last)
		}
		return nil
	})

	// ---- Thens: IE 78 with numeric cause / exactly once
	sc.Step(`^the PDUSessionResourceToReleaseListHOCmd \(id 78\) contains PDU session id (\d+) with radioNetwork cause "([^"]+)" \((\d+)\)$`,
		func(p int, name string, num int) error {
			c, err := w.decodeCmd()
			if err != nil {
				return err
			}
			raw, ok := c.release[int64(p)]
			if !ok {
				return fmt.Errorf("PDU session id %d missing from the To Release List HOCmd", p)
			}
			var tr ngapType.HandoverPreparationUnsuccessfulTransfer
			if err := aper.UnmarshalWithParams(raw, &tr, "valueExt"); err != nil {
				return fmt.Errorf("decode HandoverPreparationUnsuccessfulTransfer: %w", err)
			}
			return hoCauseIs(tr.Cause, name, num)
		})
	sc.Step(`^the PDUSessionResourceToReleaseListHOCmd \(id 78\) contains exactly (\d+) items? for PDU session id (\d+)$`, func(n, p int) error {
		c, err := w.decodeCmd()
		if err != nil {
			return err
		}
		got := 0
		for _, id := range c.relOrd {
			if id == int64(p) {
				got++
			}
		}
		if got != n {
			return fmt.Errorf("To Release List HOCmd carries %d item(s) for PDU session id %d, want %d (list %v)", got, p, n, c.relOrd)
		}
		return nil
	})

	// ---- Thens: UE CONTEXT RELEASE COMMAND
	releaseIs := func(name string, num int) error {
		var c *ngapType.Cause
		if !hoEventually(hoWait, func() bool {
			var err error
			c, err = hoFindRelease()
			return err == nil && c != nil
		}) {
			if _, err := hoFindRelease(); err != nil {
				return err
			}
			return fmt.Errorf("no UE CONTEXT RELEASE COMMAND written to the source gNB within %v", hoWait)
		}
		return hoCauseIs(*c, name, num)
	}
	sc.Step(`^the AMF sends a UE CONTEXT RELEASE COMMAND with radioNetwork cause "([^"]+)" \((\d+)\) to the source gNB$`, releaseIs)
	sc.Step(`^the AMF sends a UE CONTEXT RELEASE COMMAND with radioNetwork cause "([^"]+)" \((\d+)\) to the source gNB while the COMPLETED call is still pending$`,
		func(name string, num int) error {
			if w.notifyDone == nil {
				return fmt.Errorf("no asynchronous HANDOVER NOTIFY is running (is the COMPLETED answer held?)")
			}
			if !w.fake.waitFor(func() bool { return len(w.fake.callsOf(kindComplete, -1)) > 0 }) {
				return fmt.Errorf("the COMPLETED call never reached the SMF fake")
			}
			if err := releaseIs(name, num); err != nil {
				return err
			}
			select {
			case <-w.notifyDone:
				return fmt.Errorf("the HANDOVER NOTIFY handler already returned: the COMPLETED call is not pending")
			default:
			}
			return nil
		})

	// ---- Thens: logs and metrics
	sc.Step(`^the metric fivegc_procedure_total\{nf="AMF",procedure="([^"]+)",result="([^"]+)"\} increased by (\d+)$`,
		func(proc, result string, n int) error {
			key := proc + "/" + result
			got := hoSnapshotMetrics()[key] - w.baseline[key]
			if got != float64(n) {
				return fmt.Errorf("fivegc_procedure_total{procedure=%q,result=%q} increased by %v, want %d", proc, result, got, n)
			}
			return nil
		})
	sc.Step(`^the Nsmf (request|response) log lines carry interface "([^"]+)", direction "([^"]+)", message_type "([^"]+)" and spec_ref "([^"]+)"$`,
		func(kind, iface, dir, mt, ref string) error {
			recs := hoLogAll(func(r xnRec) bool {
				return r.attrs["interface"] == "Nsmf" && r.attrs["message_type"] == mt && r.attrs["procedure"] == "N2Handover"
			})
			if len(recs) == 0 {
				return fmt.Errorf("no Nsmf %s log line with message_type %q", kind, mt)
			}
			if want := len(w.hoReq.PDUSessions); len(recs) < want {
				return fmt.Errorf("%d Nsmf %s log line(s), want at least one per listed PDU session (%d)", len(recs), kind, want)
			}
			for _, r := range recs {
				if r.attrs["interface"] != iface || r.attrs["direction"] != dir || r.attrs["spec_ref"] != ref {
					return fmt.Errorf("Nsmf %s log line %q: direction=%q spec_ref=%q, want %q / %q",
						kind, r.msg, r.attrs["direction"], r.attrs["spec_ref"], dir, ref)
				}
			}
			return nil
		})
	sc.Step(`^the Nsmf log line carries interface "([^"]+)", direction "([^"]+)" and spec_ref "([^"]+)"$`, func(iface, dir, ref string) error {
		recs := hoLogAll(func(r xnRec) bool { return r.attrs["spec_ref"] == ref && r.attrs["interface"] == iface })
		if len(recs) == 0 {
			all := hoLogAll(func(r xnRec) bool {
				return r.attrs["interface"] == iface && strings.Contains(r.attrs["spec_ref"], "23.502")
			})
			var seen []string
			for _, r := range all {
				seen = append(seen, r.attrs["spec_ref"])
			}
			return fmt.Errorf("no log line with interface %q and spec_ref %q (Nsmf spec_refs logged: %v)", iface, ref, seen)
		}
		for _, r := range recs {
			if r.attrs["direction"] == dir {
				return nil
			}
		}
		return fmt.Errorf("no log line with spec_ref %q has direction %q", ref, dir)
	})
	sc.Step(`^the Nsmf log lines carry the correlation_id of the HANDOVER REQUIRED procedure$`, func() error {
		recs := hoLogAll(func(r xnRec) bool { return r.attrs["interface"] == "Nsmf" })
		if len(recs) == 0 {
			return fmt.Errorf("no Nsmf log line")
		}
		req, ok := hoLogFind(func(r xnRec) bool { return r.attrs["message_type"] == "HandoverRequired" })
		if !ok || req.attrs["correlation_id"] == "" {
			return fmt.Errorf("the HANDOVER REQUIRED log line carries no correlation_id")
		}
		want := req.attrs["correlation_id"]
		sawComplete := false
		for _, r := range recs {
			if r.attrs["correlation_id"] != want {
				return fmt.Errorf("Nsmf log line %q carries correlation_id %q, want the HANDOVER REQUIRED's %q",
					r.msg, r.attrs["correlation_id"], want)
			}
			if r.attrs["ho_state"] == hoStateCompletedName {
				sawComplete = true
			}
		}
		if !sawComplete {
			return fmt.Errorf("no COMPLETED Nsmf log line among the %d Nsmf lines", len(recs))
		}
		return nil
	})
	sc.Step(`^the Handover Preparation is logged with result "([^"]+)" for PDU session ids (\d+) and (\d+)$`, func(result string, a, b int) error {
		for _, p := range []int{a, b} {
			if _, ok := hoLogFind(func(r xnRec) bool {
				return r.msg == "SMF prepared PDU session for handover" && r.attrs["result"] == result &&
					r.attrs["pdu_session_id"] == strconv.Itoa(p) && r.attrs["ho_state"] != ""
			}); !ok {
				return fmt.Errorf("no PREPARING log record with result %q for PDU session id %d", result, p)
			}
		}
		return nil
	})
	sc.Step(`^the failure is logged with cause "([^"]+)"$`, func(cause string) error {
		// "HandoverRequestMissingIE" names the check (codec.go); its reject carries the cause
		// "missing-ie-<IE name>".
		match := func(c string) bool {
			if cause == "HandoverRequestMissingIE" {
				return strings.HasPrefix(c, "missing-ie-")
			}
			return c == cause
		}
		if _, ok := hoLogFind(func(r xnRec) bool { return r.msg == "HandoverPreparationFailure" && match(r.attrs["cause"]) }); !ok {
			return fmt.Errorf("no HandoverPreparationFailure log record with cause %q", cause)
		}
		return nil
	})
	sc.Step(`^a WARN is logged that no SMF is configured with interface "([^"]+)" and direction "([^"]+)"$`, func(iface, dir string) error {
		if _, ok := hoLogFind(func(r xnRec) bool {
			return r.level == slog.LevelWarn && strings.Contains(r.msg, "no SMF hook configured") &&
				r.attrs["interface"] == iface && r.attrs["direction"] == dir
		}); !ok {
			return fmt.Errorf("no WARN log record about a missing SMF hook with interface %q and direction %q", iface, dir)
		}
		return nil
	})
	sc.Step(`^the COMPLETED failure is logged with level WARN and result "([^"]+)"$`, func(result string) error {
		if !hoEventually(hoWait, func() bool {
			_, ok := hoLogFind(func(r xnRec) bool {
				return r.level == slog.LevelWarn && r.attrs["result"] == result &&
					(strings.Contains(r.msg, "Handover Complete update failed") || strings.Contains(r.msg, "rejected Handover Complete"))
			})
			return ok
		}) {
			return fmt.Errorf("no WARN COMPLETED failure log record with result %q within %v", result, hoWait)
		}
		return nil
	})
	sc.Step(`^the outcome of the HANDOVER_RES_ALLOC_FAIL call is logged with level WARN$`, func() error {
		if _, ok := hoLogFind(func(r xnRec) bool {
			return r.level == slog.LevelWarn && strings.Contains(r.msg, "HANDOVER_RES_ALLOC_FAIL") && r.attrs["result"] != ""
		}); !ok {
			return fmt.Errorf("no WARN log record for the HANDOVER_RES_ALLOC_FAIL outcome")
		}
		return nil
	})
}

// hoStateCompletedName is the hoState value of the COMPLETED leg (TS 29.502 §6.1.6.3 (HoState)).
const hoStateCompletedName = "COMPLETED"

// noBytesIn asserts none of the items contains the hex-encoded bytes.
func noBytesIn(label string, items map[int64][]byte, hexs string) error {
	raw, err := hexBytes(hexs)
	if err != nil {
		return err
	}
	for psi, b := range items {
		if bytes.Contains(b, raw) {
			return fmt.Errorf("%s item of PDU session id %d contains the bytes %s", label, psi, hexs)
		}
	}
	return nil
}
