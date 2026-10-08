//go:build functional

// handover_smf_leg_steps_test.go — in-process godog steps for handover_smf_leg.feature
// (AMF-012: synchronous Nsmf_PDUSession_UpdateSMContext leg of the Xn path switch and of
// the N2 handover; SMF-provided N2 SM transfers; PATH_SWITCH_SETUP_FAIL; HANDOVER_CMD).
//
// The real *ngap.Server handlers run in-process on the world built by the AMF-011 steps
// (xn_handover_steps_test.go: fake SCTP transports, strict free5gc/ngap decoding). The SMF
// is an injectable fake registered through the four ngap.Server hooks. A hook-level fake
// cannot see the JSON fields toBeSwitched / failedToBeSwitched / hoState / n2SmInfoType /
// upCnxState: those are added by HTTPSMFClient in package main (cmd/amf) and covered by
// nf/amf/cmd/amf/smf_update_test.go. The fake therefore records the HOOK KIND (the setter
// it was registered on) and asserts that; it never pretends to see the JSON body.
//
// Ordering / blocking assertions use channels with timeouts, never select/default
// polling. The per-PSI SMF wait is shortened with SetSMFHOUpdateTimeoutForTest.
//
// Ref: TS 23.502 §4.9.1.2.2 steps 2-7, §4.9.1.3.2 steps 9-12; TS 38.413 §8.4.4.2, §9.3.4.
package features_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cucumber/godog"
	"github.com/free5gc/aper"
	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	amfngap "github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/shared/crypto/kdf"
	"github.com/francurieses/claudia-5gc/shared/logging"
)

const (
	// hoShortTimeout is the per-PSI SMF wait for scenarios that exercise the timeout.
	hoShortTimeout = 300 * time.Millisecond
	// hoLongTimeout is used when the test itself holds an SMF answer: the AMF must not
	// time out before the test releases it.
	hoLongTimeout = 20 * time.Second
	// hoWait bounds every "eventually" assertion.
	hoWait = 5 * time.Second

	kindPathSwitch = "PATH_SWITCH_REQ"
	kindSetupFail  = "PATH_SWITCH_SETUP_FAIL"
	kindHOAck      = "HANDOVER_REQ_ACK"
	kindDeact      = "DEACTIVATED"
	// AMF-012 follow-up: N2 PREPARING / RES_ALLOC_FAIL / COMPLETED legs.
	kindPreparing = "PREPARING"
	kindResAlloc  = "HANDOVER_RES_ALLOC_FAIL"
	kindComplete  = "COMPLETED"
)

// ---- the SMF fake ---------------------------------------------------------------------------

type hoCall struct {
	kind string // hook kind it arrived on
	psi  uint8
	ref  string
	n2   []byte
	at   time.Time
	// target is the Target ID relayed on the PREPARING leg (zero for the other kinds).
	target amfngap.HOTargetID
}

type hoMode int

const (
	modeAnswer hoMode = iota
	modeBlock
	modeNever
	modeTransportErr
)

type hoOutcome struct {
	mode    hoMode
	res     amfngap.SMFUpdateResult
	release chan amfngap.SMFUpdateResult // modeBlock
}

type hoFake struct {
	mu       sync.Mutex
	calls    []hoCall
	primary  map[uint8]*hoOutcome // PATH_SWITCH_REQ (Xn) / HANDOVER_REQ_ACK (N2)
	setup    map[uint8]*hoOutcome
	prep     map[uint8]*hoOutcome // PREPARING (HANDOVER_REQUIRED) answers
	resAlloc map[uint8]*hoOutcome // HANDOVER_RES_ALLOC_FAIL answers
	complete map[uint8]*hoOutcome // COMPLETED answers
	deactErr map[uint8]bool
	returned map[uint8][]byte // N2SmInfo bytes the fake returned per PSI (primary kind)
	// returnedBy holds the N2SmInfo bytes returned per hook kind and PSI.
	returnedBy map[string]map[uint8][]byte
	answered   []time.Time    // time every non-DEACTIVATED answer was returned
	arrived    chan struct{}  // one token per recorded call
	done       chan struct{}  // closed at scenario end: releases every held hook
	hooks      map[string]int // release-type hooks (delete/release) fired
}

func newHOFake() *hoFake {
	return &hoFake{
		primary: map[uint8]*hoOutcome{}, setup: map[uint8]*hoOutcome{},
		prep: map[uint8]*hoOutcome{}, resAlloc: map[uint8]*hoOutcome{}, complete: map[uint8]*hoOutcome{},
		returnedBy: map[string]map[uint8][]byte{},
		deactErr:   map[uint8]bool{}, returned: map[uint8][]byte{},
		arrived: make(chan struct{}, 4096), done: make(chan struct{}), hooks: map[string]int{},
	}
}

func hoPSIOf(ref string) uint8 {
	n, err := strconv.Atoi(strings.TrimPrefix(ref, "smctx-"))
	if err != nil {
		return 0
	}
	return uint8(n)
}

func (f *hoFake) record(kind, ref string, n2 []byte) {
	f.recordT(kind, ref, n2, amfngap.HOTargetID{})
}

func (f *hoFake) recordT(kind, ref string, n2 []byte, tgt amfngap.HOTargetID) {
	f.mu.Lock()
	f.calls = append(f.calls, hoCall{kind: kind, psi: hoPSIOf(ref), ref: ref, n2: append([]byte(nil), n2...), at: time.Now(), target: tgt})
	f.mu.Unlock()
	f.arrived <- struct{}{}
}

// answer applies the configured outcome of psi and returns the SMF result.
func (f *hoFake) answer(ctx context.Context, kind, ref string, n2 []byte, table map[uint8]*hoOutcome) amfngap.SMFUpdateResult {
	return f.answerT(ctx, kind, ref, n2, amfngap.HOTargetID{}, table)
}

// answerT is answer for a call that also carries a Target ID (PREPARING leg).
func (f *hoFake) answerT(ctx context.Context, kind, ref string, n2 []byte, tgt amfngap.HOTargetID, table map[uint8]*hoOutcome) amfngap.SMFUpdateResult {
	f.recordT(kind, ref, n2, tgt)
	psi := hoPSIOf(ref)
	f.mu.Lock()
	o := table[psi]
	f.mu.Unlock()
	res := amfngap.SMFUpdateResult{HTTPStatus: 200} // default: 200 without body
	if o != nil {
		switch o.mode {
		case modeBlock:
			select {
			case r := <-o.release:
				res = r
			case <-ctx.Done():
				return amfngap.SMFUpdateResult{Err: ctx.Err()}
			case <-f.done:
				return amfngap.SMFUpdateResult{Err: errors.New("test finished")}
			}
		case modeNever:
			select {
			case <-ctx.Done():
				return amfngap.SMFUpdateResult{Err: ctx.Err()}
			case <-f.done:
				return amfngap.SMFUpdateResult{Err: errors.New("test finished")}
			}
		case modeTransportErr:
			res = amfngap.SMFUpdateResult{Err: errors.New("dial tcp: connection refused")}
		default:
			res = o.res
		}
	}
	f.mu.Lock()
	if table[psi] == o && kind != kindSetupFail {
		if kind == kindPathSwitch || kind == kindHOAck {
			f.returned[psi] = res.N2SmInfo
		}
		if f.returnedBy[kind] == nil {
			f.returnedBy[kind] = map[uint8][]byte{}
		}
		f.returnedBy[kind][psi] = res.N2SmInfo
	}
	f.answered = append(f.answered, time.Now())
	f.mu.Unlock()
	return res
}

func (f *hoFake) callsOf(kind string, psi int) []hoCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []hoCall
	for _, c := range f.calls {
		if (kind == "" || c.kind == kind) && (psi < 0 || int(c.psi) == psi) {
			out = append(out, c)
		}
	}
	return out
}

// waitFor blocks until pred holds (re-evaluated on every recorded call) or hoWait elapses.
func (f *hoFake) waitFor(pred func() bool) bool {
	deadline := time.NewTimer(hoWait)
	defer deadline.Stop()
	for {
		if pred() {
			return true
		}
		select {
		case <-f.arrived:
		case <-deadline.C:
			return pred()
		}
	}
}

// quiet reports whether no call matching pred arrives within d (negative assertions on
// asynchronous calls: the window lets a late goroutine show up).
func (f *hoFake) quiet(d time.Duration, pred func() bool) bool {
	deadline := time.NewTimer(d)
	defer deadline.Stop()
	for {
		if pred() {
			return false
		}
		select {
		case <-f.arrived:
		case <-deadline.C:
			return !pred()
		}
	}
}

func (f *hoFake) hasBlocks() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range []map[uint8]*hoOutcome{f.primary, f.setup} {
		for _, o := range t {
			if o.mode == modeBlock {
				return true
			}
		}
	}
	return false
}

// hasAnyBlock reports whether the test holds an answer of any hook kind (including the
// PREPARING / RES_ALLOC_FAIL / COMPLETED legs).
func (f *hoFake) hasAnyBlock() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range []map[uint8]*hoOutcome{f.primary, f.setup, f.prep, f.resAlloc, f.complete} {
		for _, o := range t {
			if o.mode == modeBlock {
				return true
			}
		}
	}
	return false
}

// returnedAny returns the n2SmInfo the fake returned for psi on any kind (PREPARING first,
// then the Ack leg, then RES_ALLOC_FAIL).
func (f *hoFake) returnedAny(psi uint8) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range []string{kindPreparing, kindHOAck, kindPathSwitch, kindResAlloc} {
		if b := f.returnedBy[k][psi]; len(b) > 0 {
			return b
		}
	}
	return nil
}

func (f *hoFake) lastAnswer() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	var t time.Time
	for _, a := range f.answered {
		if a.After(t) {
			t = a
		}
	}
	return t
}

// ---- world ---------------------------------------------------------------------------------

type hoWorld struct {
	active bool
	n2     bool // scenario is an N2 handover scenario

	fake       *hoFake
	elapsed    time.Duration
	admitted   []amfngap.PDUSessionHOAdmittedItem
	ackTrans   map[uint8][]byte // HandoverRequestAcknowledgeTransfer sent per PSI
	failed     []amfngap.PDUSessionFailedSetupItem
	ue2        *amfctx.UEContext
	ulReturned bool
	nhBefore   [32]byte
	ranBase    int64

	// AMF-012 follow-up (N2 PREPARING / RES_ALLOC_FAIL / COMPLETED legs)
	prep       bool                             // scenario drives HANDOVER REQUIRED with listed PDU sessions
	hoReq      *amfngap.HandoverRequiredMsg     // prepared HANDOVER REQUIRED
	hoReq2     *amfngap.HandoverRequiredMsg     // prepared second HANDOVER REQUIRED
	cached     map[uint8][]byte                 // cached N2SmTransfer set by the scenario
	failedAck  []amfngap.PDUSessionHOFailedItem // Failed to Setup List HOAck of the prepared ACK
	ackSet     bool                             // a HANDOVER REQUEST ACKNOWLEDGE was prepared
	corr       string                           // correlation ID of the scenario's NGAP context
	notifyDone chan struct{}                    // closed when an async HANDOVER NOTIFY handler returned
	baseline   map[string]float64               // fivegc_procedure_total at scenario start
}

var hoW hoWorld

// ---- decoded HANDOVER COMMAND / PREPARATION FAILURE -------------------------------------------

type hoCmd struct {
	ies     []int64
	handled map[int64][]byte // PSI -> HandoverCommandTransfer
	order   []int64          // handled PSIs in list order
	release map[int64][]byte // PSI -> HandoverPreparationUnsuccessfulTransfer
	relOrd  []int64
	at      time.Time
}

func (w *hoWorld) lastSrc() (xnSent, bool) {
	p := xnW.srcLn.pdus()
	if len(p) == 0 {
		return xnSent{}, false
	}
	return p[len(p)-1], true
}

// decodeCmd decodes the last PDU written to the source gNB as HANDOVER COMMAND.
func (w *hoWorld) decodeCmd() (*hoCmd, error) {
	last, ok := w.lastSrc()
	if !ok {
		return nil, fmt.Errorf("nothing written to the source gNB")
	}
	pdu, err := libngap.Decoder(last.raw)
	if err != nil {
		return nil, fmt.Errorf("free5gc/ngap decode: %w", err)
	}
	if pdu.SuccessfulOutcome == nil || pdu.SuccessfulOutcome.Value.HandoverCommand == nil {
		return nil, fmt.Errorf("last PDU written to the source gNB is not a HANDOVER COMMAND")
	}
	c := &hoCmd{handled: map[int64][]byte{}, release: map[int64][]byte{}, at: last.at}
	for _, ie := range pdu.SuccessfulOutcome.Value.HandoverCommand.ProtocolIEs.List {
		c.ies = append(c.ies, ie.Id.Value)
		if l := ie.Value.PDUSessionResourceHandoverList; l != nil {
			for _, it := range l.List {
				c.handled[it.PDUSessionID.Value] = []byte(it.HandoverCommandTransfer)
				c.order = append(c.order, it.PDUSessionID.Value)
			}
		}
		if l := ie.Value.PDUSessionResourceToReleaseListHOCmd; l != nil {
			for _, it := range l.List {
				c.release[it.PDUSessionID.Value] = []byte(it.HandoverPreparationUnsuccessfulTransfer)
				c.relOrd = append(c.relOrd, it.PDUSessionID.Value)
			}
		}
	}
	return c, nil
}

// ---- When helpers ---------------------------------------------------------------------------------

func (w *hoWorld) handlePathSwitch() error {
	x := &xnW
	if x.req == nil {
		return fmt.Errorf("no PATH SWITCH REQUEST prepared")
	}
	start := time.Now()
	if w.fake != nil && w.fake.hasBlocks() {
		// The test holds an SMF answer: only the inline part runs, as on the SCTP read loop.
		x.srv.StartPathSwitchRequestForTest(context.Background(), x.tgt, x.req)
		w.elapsed = time.Since(start)
		return nil
	}
	x.srv.HandlePathSwitchRequestForTest(context.Background(), x.tgt, x.req)
	w.elapsed = time.Since(start)
	x.captureTarget()
	return nil
}

// settle waits for the UE's serial task (the SMF leg and the NGAP answer) and captures the
// last PDU written to the target gNB.
func (w *hoWorld) settle() error {
	if !xnW.srv.WaitUESerialForTest(xnW.amfID) {
		return fmt.Errorf("the UE serial queue did not drain (SMF leg wedged)")
	}
	xnW.captureTarget()
	return nil
}

func (w *hoWorld) handleBoth() error {
	x := &xnW
	if len(w.admitted) == 0 && len(w.failedAck) == 0 {
		return fmt.Errorf("no HANDOVER REQUEST ACKNOWLEDGE prepared")
	}
	ctx := w.ctx()
	x.srcLn.reset()
	x.tgtLn.reset()
	req := w.hoReq
	if req == nil {
		req = &amfngap.HandoverRequiredMsg{
			AMFUENGAPId: x.amfID, RANUENGAPId: x.ranOld, TargetGlobalRANNodeID: x.tgt.GlobalGNBID,
			SourceToTargetTransparentContainer: []byte{9},
		}
	}
	x.srv.HandleHandoverRequiredForTest(ctx, x.src, req)
	if len(x.tgtLn.pdus()) == 0 {
		return fmt.Errorf("no HANDOVER REQUEST written to the target gNB")
	}
	ack := &amfngap.HandoverRequestAckMsg{
		AMFUENGAPId: x.amfID, RANUENGAPId: 8, TargetToSourceTransparentContainer: []byte{7},
		AdmittedSessions: w.admitted, FailedSessions: w.failedAck,
	}
	start := time.Now()
	if w.fake != nil && w.fake.hasBlocks() {
		x.srv.StartHandoverRequestAcknowledgeForTest(ctx, x.tgt, ack)
		w.elapsed = time.Since(start)
		return nil
	}
	x.srv.HandleHandoverRequestAcknowledgeForTest(ctx, x.tgt, ack)
	w.elapsed = time.Since(start)
	if last, ok := w.lastSrc(); ok {
		x.decode(last.raw)
	}
	return nil
}

// ctx returns the NGAP context of the scenario: it carries one correlation ID shared by every
// handler call of the scenario (the read loop's per-association context).
func (w *hoWorld) ctx() context.Context {
	if w.corr == "" {
		w.corr = "01HOSCENARIO" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return logging.WithCorrelationID(context.Background(), w.corr)
}

// ---- outcome parsing ----------------------------------------------------------------------------

var (
	reHoCode  = regexp.MustCompile(`^(\d{3})\b`)
	reHoState = regexp.MustCompile(`hoState "([^"]+)"`)
	reHoType  = regexp.MustCompile(`n2SmInfoType "([^"]+)"`)
	reHoCause = regexp.MustCompile(`ProblemDetails cause "([^"]+)"`)
	reHoBytes = regexp.MustCompile(`the n2SmInfo bytes "([0-9a-f]+)"`)
)

func hoGTP(psi uint8) ngapType.UPTransportLayerInformation {
	ip := []byte{10, 0, psi, 1}
	teid := []byte{0, 0, psi, 0x01}
	return ngapType.UPTransportLayerInformation{
		Present: ngapType.UPTransportLayerInformationPresentGTPTunnel,
		GTPTunnel: &ngapType.GTPTunnel{
			TransportLayerAddress: ngapType.TransportLayerAddress{Value: aper.BitString{Bytes: ip, BitLength: 32}},
			GTPTEID:               ngapType.GTPTEID{Value: aper.OctetString(teid)},
		},
	}
}

func hoCauseUnspecified() ngapType.Cause {
	return ngapType.Cause{Present: ngapType.CausePresentRadioNetwork,
		RadioNetwork: &ngapType.CauseRadioNetwork{Value: ngapType.CauseRadioNetworkPresentUnspecified}}
}

// hoValidTransfer returns a valid, PSI-distinct APER transfer of the given n2SmInfoType.
func hoValidTransfer(typ string, psi uint8) ([]byte, error) {
	var v interface{}
	switch typ {
	case "PATH_SWITCH_REQ_ACK":
		g := hoGTP(psi)
		v = ngapType.PathSwitchRequestAcknowledgeTransfer{ULNGUUPTNLInformation: &g}
	case "HANDOVER_CMD":
		g := hoGTP(psi)
		v = ngapType.HandoverCommandTransfer{DLForwardingUPTNLInformation: &g}
	case "PATH_SWITCH_REQ_FAIL":
		v = ngapType.PathSwitchRequestUnsuccessfulTransfer{Cause: hoCauseUnspecified()}
	case "HANDOVER_PREP_FAIL":
		v = ngapType.HandoverPreparationUnsuccessfulTransfer{Cause: hoCauseUnspecified()}
	case "PDU_RES_SETUP_REQ":
		g := hoGTP(psi)
		v = ngapType.PDUSessionResourceSetupRequestTransfer{
			ProtocolIEs: ngapType.ProtocolIEContainerPDUSessionResourceSetupRequestTransferIEs{
				List: []ngapType.PDUSessionResourceSetupRequestTransferIEs{{
					Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDULNGUUPTNLInformation},
					Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
					Value: ngapType.PDUSessionResourceSetupRequestTransferIEsValue{
						Present:               ngapType.PDUSessionResourceSetupRequestTransferIEsPresentULNGUUPTNLInformation,
						ULNGUUPTNLInformation: &g,
					},
				}},
			},
		}
	default:
		return nil, fmt.Errorf("no valid-transfer builder for n2SmInfoType %q", typ)
	}
	b, err := aper.MarshalWithParams(v, "valueExt")
	if err != nil {
		return nil, fmt.Errorf("marshal %T: %w", v, err)
	}
	return b, nil
}

// hoTargetType returns the ngapType decode target for an n2SmInfoType.
func hoTargetType(typ string) interface{} {
	switch typ {
	case "PATH_SWITCH_REQ_ACK":
		return &ngapType.PathSwitchRequestAcknowledgeTransfer{}
	case "HANDOVER_CMD":
		return &ngapType.HandoverCommandTransfer{}
	case "PATH_SWITCH_REQ_FAIL":
		return &ngapType.PathSwitchRequestUnsuccessfulTransfer{}
	case "HANDOVER_PREP_FAIL":
		return &ngapType.HandoverPreparationUnsuccessfulTransfer{}
	}
	return nil
}

// parseOutcome turns the feature's outcome phrase into a fake outcome for psi.
func parseOutcome(s string, psi uint8) (*hoOutcome, error) {
	switch {
	case strings.HasPrefix(s, "no answer within the test timeout"):
		return &hoOutcome{mode: modeNever}, nil
	case s == "a transport error":
		return &hoOutcome{mode: modeTransportErr}, nil
	}
	m := reHoCode.FindStringSubmatch(s)
	if m == nil {
		return nil, fmt.Errorf("unrecognised SMF outcome %q", s)
	}
	code, _ := strconv.Atoi(m[1])
	res := amfngap.SMFUpdateResult{HTTPStatus: code}
	if h := reHoState.FindStringSubmatch(s); h != nil {
		res.HoState = h[1]
	}
	if c := reHoCause.FindStringSubmatch(s); c != nil {
		res.Cause = c[1]
	}
	typ := ""
	if t := reHoType.FindStringSubmatch(s); t != nil {
		typ = t[1]
	}
	noInfo := false
	for _, p := range []string{"without n2SmInfo", "and no n2SmInfo", "and no body", "with an empty body", "No Content"} {
		if strings.Contains(s, p) {
			noInfo = true
		}
	}
	switch {
	case noInfo:
	case reHoBytes.MatchString(s) || strings.Contains(s, "undecodable n2SmInfo bytes"):
		hexs := "ffffffff"
		if b := reHoBytes.FindStringSubmatch(s); b != nil {
			hexs = b[1]
		}
		raw, err := hexBytes(hexs)
		if err != nil {
			return nil, err
		}
		// Guard: the scenario is only meaningful when the AMF's strict decode rejects them.
		if typ == "PDU_RES_SETUP_REQ" {
			// The AMF also needs the UL-NGU-UP-TNLInformation IE; arbitrary bytes decode as an
			// empty IE list, so the guard rejects only a transfer that DOES carry that IE.
			var tr ngapType.PDUSessionResourceSetupRequestTransfer
			if aper.UnmarshalWithParams(raw, &tr, "valueExt") == nil {
				for _, ie := range tr.ProtocolIEs.List {
					if ie.Id.Value == ngapType.ProtocolIEIDULNGUUPTNLInformation {
						return nil, fmt.Errorf("bytes %q carry a UL-NGU-UP-TNLInformation IE — scenario would not exercise the invalid-n2SmInfo path", hexs)
					}
				}
			}
		} else if tgt := hoTargetType(typ); tgt != nil && aper.UnmarshalWithParams(raw, tgt, "valueExt") == nil {
			return nil, fmt.Errorf("bytes %q decode as a valid %s — scenario would not exercise the invalid-n2SmInfo path", hexs, typ)
		}
		res.N2SmInfo, res.N2SmInfoType = raw, typ
	case typ != "":
		b, err := hoValidTransfer(typ, psi)
		if err != nil {
			return nil, err
		}
		res.N2SmInfo, res.N2SmInfoType = b, typ
	case res.HoState != "":
		// "200 hoState "COMPLETED"": an hoState-only answer carries no n2SmInfo.
	default:
		return nil, fmt.Errorf("outcome %q carries neither n2SmInfoType, an hoState nor an explicit no-n2SmInfo phrase", s)
	}
	return &hoOutcome{mode: modeAnswer, res: res}, nil
}

// ---- assertions helpers ---------------------------------------------------------------------------

func hoEventually(d time.Duration, fn func() bool) bool {
	deadline := time.NewTimer(d)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if fn() {
			return true
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			return fn()
		}
	}
}

func hoLogFind(pred func(r xnRec) bool) (xnRec, bool) {
	xnW.logs.mu.Lock()
	defer xnW.logs.mu.Unlock()
	for _, r := range xnW.logs.recs {
		if pred(r) {
			return r, true
		}
	}
	return xnRec{}, false
}

func hoLevel(name string) slog.Level {
	if name == "ERROR" {
		return slog.LevelError
	}
	return slog.LevelWarn
}

func hoEqBytes(label string, got, want []byte) error {
	if len(want) == 0 {
		return fmt.Errorf("%s: the SMF fake returned no bytes for that PDU session", label)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("%s: got %x, want %x", label, got, want)
	}
	return nil
}

func hoAckItems(w *xnWorld) (switched map[int64][]byte, released map[int64][]byte, err error) {
	if err = w.needAck(); err != nil {
		return
	}
	switched, released = map[int64][]byte{}, map[int64][]byte{}
	for _, ie := range w.ack.ProtocolIEs.List {
		if l := ie.Value.PDUSessionResourceSwitchedList; l != nil {
			for _, it := range l.List {
				switched[it.PDUSessionID.Value] = []byte(it.PathSwitchRequestAcknowledgeTransfer)
			}
		}
		if l := ie.Value.PDUSessionResourceReleasedListPSAck; l != nil {
			for _, it := range l.List {
				released[it.PDUSessionID.Value] = []byte(it.PathSwitchRequestUnsuccessfulTransfer)
			}
		}
	}
	return
}

func hoFirstN2(c []hoCall) []byte {
	if len(c) == 0 {
		return nil
	}
	return c[0].n2
}

func hoPSIList(s string) []int {
	var out []int
	for _, m := range regexp.MustCompile(`\d+`).FindAllString(s, -1) {
		n, _ := strconv.Atoi(m)
		out = append(out, n)
	}
	return out
}

func hoE2EPending() error { return xnE2EPending() }

// ---- registration -----------------------------------------------------------------------------------

func initHandoverSMFLegSteps(sc *godog.ScenarioContext) {
	w := &hoW
	sc.Before(func(ctx context.Context, s *godog.Scenario) (context.Context, error) {
		*w = hoWorld{active: strings.HasSuffix(s.Uri, "handover_smf_leg.feature")}
		if w.active {
			w.baseline = hoSnapshotMetrics()
		}
		return ctx, nil
	})
	sc.After(func(ctx context.Context, s *godog.Scenario, _ error) (context.Context, error) {
		if !w.active || w.fake == nil {
			return ctx, nil
		}
		// Release every held hook so no serial task or goroutine outlives the scenario,
		// then restore the default SMF wait.
		close(w.fake.done)
		if w.notifyDone != nil {
			select {
			case <-w.notifyDone:
			case <-time.After(hoWait):
			}
		}
		if xnW.srv != nil {
			xnW.srv.WaitUESerialForTest(xnW.amfID)
			xnW.srv.SetSMFHOUpdateTimeoutForTest(0)
		}
		return ctx, nil
	})

	// ---- Background
	sc.Step(`^the SMF is replaced by an injectable fake that records every Nsmf_PDUSession_UpdateSMContext request and answers per PDU session id$`,
		func() error {
			f := newHOFake()
			w.fake = f
			s := xnW.srv
			s.SetPathSwitchHandler(func(ctx context.Context, ref string, n2 []byte) amfngap.SMFUpdateResult {
				return f.answer(ctx, kindPathSwitch, ref, n2, f.primary)
			})
			s.SetPathSwitchSetupFailHandler(func(ctx context.Context, ref string, n2 []byte) amfngap.SMFUpdateResult {
				return f.answer(ctx, kindSetupFail, ref, n2, f.setup)
			})
			s.SetHandoverRequestAckHandler(func(ctx context.Context, ref string, n2 []byte) amfngap.SMFUpdateResult {
				return f.answer(ctx, kindHOAck, ref, n2, f.primary)
			})
			s.SetHandoverRequiredHandler(func(ctx context.Context, ref string, n2 []byte, tgt amfngap.HOTargetID) amfngap.SMFUpdateResult {
				return f.answerT(ctx, kindPreparing, ref, n2, tgt, f.prep)
			})
			s.SetHandoverResAllocFailHandler(func(ctx context.Context, ref string, n2 []byte) amfngap.SMFUpdateResult {
				return f.answer(ctx, kindResAlloc, ref, n2, f.resAlloc)
			})
			s.SetHandoverCompleteHandler(func(ctx context.Context, ref string) amfngap.SMFUpdateResult {
				return f.answer(ctx, kindComplete, ref, nil, f.complete)
			})
			s.SetUPDeactivateHandler(func(ctx context.Context, ref string) error {
				f.record(kindDeact, ref, nil)
				f.mu.Lock()
				fail := f.deactErr[hoPSIOf(ref)]
				f.mu.Unlock()
				if fail {
					return errors.New("smf: UpdateSMContext upCnxState DEACTIVATED: 500")
				}
				return nil
			})
			// The ngap package has no DeleteSMContext/ReleaseSMContext seam; the hooks that
			// lead to one in production are recorded so the "no delete/release" assertion
			// is a real check of what the handover path can reach.
			s.SetPDUSessionReleaseHandler(func(context.Context, int64) { f.mu.Lock(); f.hooks["pdu-session-release"]++; f.mu.Unlock() })
			s.SetANReleaseHandler(func(context.Context, *amfctx.UEContext) { f.mu.Lock(); f.hooks["an-release"]++; f.mu.Unlock() })
			s.SetImplicitDetachHandler(func(context.Context, *amfctx.UEContext) { f.mu.Lock(); f.hooks["implicit-detach"]++; f.mu.Unlock() })
			s.SetGNBDisconnectHandler(func(context.Context, *amfctx.UEContext) { f.mu.Lock(); f.hooks["gnb-disconnect"]++; f.mu.Unlock() })
			return nil
		})
	sc.Step(`^the SMF UpdateSMContext wait per PDU session is bounded by a short test timeout$`, func() error {
		xnW.srv.SetSMFHOUpdateTimeoutForTest(hoShortTimeout)
		return nil
	})

	// ---- Givens: SMF fake behaviour
	sc.Step(`^the SMF fake answers PDU session ids? (\d+)(?: and (\d+))? with (.+)$`, func(a, b, outcome string) error {
		for _, p := range []string{a, b} {
			if p == "" {
				continue
			}
			n, _ := strconv.Atoi(p)
			o, err := parseOutcome(outcome, uint8(n))
			if err != nil {
				return err
			}
			w.fake.mu.Lock()
			w.fake.primary[uint8(n)] = o
			w.fake.mu.Unlock()
		}
		return nil
	})
	sc.Step(`^the SMF fake answers the PATH_SWITCH_SETUP_FAIL of PDU session id (\d+) with (.+)$`, func(p int, outcome string) error {
		o, err := parseOutcome(outcome, uint8(p))
		if err != nil {
			// "422" / "500" carry no phrase: a bare status code.
			code, cerr := strconv.Atoi(strings.TrimSpace(outcome))
			if cerr != nil {
				return err
			}
			o = &hoOutcome{mode: modeAnswer, res: amfngap.SMFUpdateResult{HTTPStatus: code}}
		}
		w.fake.mu.Lock()
		w.fake.setup[uint8(p)] = o
		w.fake.mu.Unlock()
		return nil
	})
	sc.Step(`^the SMF fake answers the DEACTIVATED request of PDU session id (\d+) with 500$`, func(p int) error {
		w.fake.mu.Lock()
		w.fake.deactErr[uint8(p)] = true
		w.fake.mu.Unlock()
		return nil
	})
	hold := func(p int) error {
		w.fake.mu.Lock()
		w.fake.primary[uint8(p)] = &hoOutcome{mode: modeBlock, release: make(chan amfngap.SMFUpdateResult, 1)}
		w.fake.mu.Unlock()
		xnW.srv.SetSMFHOUpdateTimeoutForTest(hoLongTimeout) // the test, not the AMF timer, ends the wait
		return nil
	}
	sc.Step(`^the SMF fake blocks the answer for PDU session id (\d+) until released by the test$`, hold)
	sc.Step(`^the SMF fake blocks the answer for PDU session id (\d+) of UE "[^"]+" until released by the test$`, hold)
	sc.Step(`^the SMF fake never answers PDU session ids? (\d+)(?: and (\d+))?$`, func(a, b string) error {
		for _, p := range []string{a, b} {
			if p == "" {
				continue
			}
			n, _ := strconv.Atoi(p)
			w.fake.mu.Lock()
			w.fake.primary[uint8(n)] = &hoOutcome{mode: modeNever}
			w.fake.mu.Unlock()
		}
		return nil
	})
	sc.Step(`^no SMF hook is configured in the AMF$`, func() error {
		s := xnW.srv
		s.SetPathSwitchHandler(nil)
		s.SetPathSwitchSetupFailHandler(nil)
		s.SetUPDeactivateHandler(nil)
		s.SetHandoverRequestAckHandler(nil)
		s.SetHandoverRequiredHandler(nil)
		s.SetHandoverResAllocFailHandler(nil)
		s.SetHandoverCompleteHandler(nil)
		return nil
	})

	// ---- Givens: requests
	sc.Step(`^the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID (\d+) and Source AMF UE NGAP ID (\d+) for PDU session ids? (\d+)(?: and (\d+))? and a Failed to Setup List PSReq with PDU session id (\d+)$`,
		func(ranID, amfID int, a, b string, failed int) error {
			psis, err := xnParsePSIs(a, b)
			if err != nil {
				return err
			}
			xnW.prepareRequest(int64(ranID), int64(amfID), psis)
			xnW.req.FailedToSetup = []amfngap.PDUSessionFailedSetupItem{
				{PDUSessionID: uint8(failed), PathSwitchRequestSetupFailedTransfer: []byte{0xCD, uint8(failed)}}}
			return nil
		})
	sc.Step(`^the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID (\d+) and Source AMF UE NGAP ID (\d+) for PDU session ids (\d+) and (\d+) and a Failed to Setup List PSReq with PDU session id (\d+)$`,
		func(ranID, amfID, a, b, failed int) error {
			xnW.prepareRequest(int64(ranID), int64(amfID), []uint8{uint8(a), uint8(b)})
			xnW.req.FailedToSetup = []amfngap.PDUSessionFailedSetupItem{
				{PDUSessionID: uint8(failed), PathSwitchRequestSetupFailedTransfer: []byte{0xCD, uint8(failed)}}}
			return nil
		})
	sc.Step(`^the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session ids? (\d+)(?: and (\d+))?$`,
		func(a, b string) error {
			psis, err := xnParsePSIs(a, b)
			if err != nil {
				return err
			}
			w.n2 = true
			w.admitted = nil
			w.ackTrans = map[uint8][]byte{}
			for _, p := range psis {
				t := []byte{0xEE, p}
				w.ackTrans[p] = t
				w.admitted = append(w.admitted, amfngap.PDUSessionHOAdmittedItem{PDUSessionID: p, HandoverRequestAcknowledgeTransfer: t})
			}
			return nil
		})
	sc.Step(`^a second UE with SUPI "([^"]+)" has AMF UE NGAP ID (\d+) and RAN UE NGAP ID (\d+) on source gNB "([^"]+)"$`,
		func(supi string, amfID, ranID int, _ string) error {
			ue := xnW.mgr.AllocateUEContext(int64(ranID))
			if ue.AMFUENGAPId != int64(amfID) {
				return fmt.Errorf("manager allocated AMF UE NGAP ID %d for the second UE, feature expects %d", ue.AMFUENGAPId, amfID)
			}
			ue.SUPI = supi
			ue.CMState = amfctx.CMConnected
			ue.GNBAddr = xnW.srcAddr
			xnW.src.UEs[int64(ranID)] = ue
			w.ue2 = ue
			return nil
		})

	// ---- Whens
	initHandoverN2LegSteps(sc)
	sc.Step(`^the test releases the SMF fake answer for PDU session id (\d+) with 200 n2SmInfoType "([^"]+)"$`,
		func(p int, typ string) error {
			b, err := hoValidTransfer(typ, uint8(p))
			if err != nil {
				return err
			}
			w.fake.mu.Lock()
			o := w.fake.primary[uint8(p)]
			w.fake.mu.Unlock()
			if o == nil || o.mode != modeBlock {
				return fmt.Errorf("no held SMF answer for PDU session id %d", p)
			}
			o.release <- amfngap.SMFUpdateResult{HTTPStatus: 200, N2SmInfo: b, N2SmInfoType: typ}
			if w.n2 {
				if !xnW.srv.WaitUESerialForTest(xnW.amfID) {
					return fmt.Errorf("the UE serial queue did not drain")
				}
				if last, ok := w.lastSrc(); ok {
					xnW.decode(last.raw)
				}
				return nil
			}
			return w.settle()
		})
	ulNAS := func(amfID int) error {
		if w.ue2 == nil || w.ue2.AMFUENGAPId != int64(amfID) {
			return fmt.Errorf("no second UE with AMF UE NGAP ID %d", amfID)
		}
		if w.fake == nil || !w.fake.hasAnyBlock() {
			return fmt.Errorf("the SMF call of the first UE is not held")
		}
		// The seam must return while UE A's SMF hook is blocked: run it in a goroutine and
		// wait on a channel with a deadline.
		done := make(chan struct{})
		go func() {
			defer close(done)
			xnW.srv.HandleUplinkNASTransportForTest(context.Background(), xnW.src,
				&amfngap.UplinkNASTransport{AMFUENGAPId: int64(amfID), RANUENGAPId: w.ue2.RANUENGAPId, NASPdu: []byte{0x7E, 0x00, 0x67}})
		}()
		select {
		case <-done:
			w.ulReturned = true
			return nil
		case <-time.After(hoWait):
			return fmt.Errorf("HandleUplinkNASTransportForTest did not return within %v while the SMF call of the first UE is pending", hoWait)
		}
	}
	sc.Step(`^the source gNB sends an UPLINK NAS TRANSPORT for AMF UE NGAP ID (\d+) on the same SCTP association$`, ulNAS)
	sc.Step(`^the target gNB sends an UPLINK NAS TRANSPORT for AMF UE NGAP ID (\d+) on the same SCTP association$`, ulNAS)
	sc.Step(`^the AMF has dispatched that NGAP message for UE "[^"]+" while the SMF call of UE "[^"]+" is still pending$`, func() error {
		if !w.ulReturned {
			return fmt.Errorf("the UPLINK NAS TRANSPORT dispatch did not return")
		}
		// UE B's NAS processing is observed through the NAS handler recorder (it runs on B's
		// serial queue).
		select {
		case id := <-hoNAS.seen:
			if id != w.ue2.AMFUENGAPId {
				return fmt.Errorf("NAS handler saw AMF UE NGAP ID %d, want %d", id, w.ue2.AMFUENGAPId)
			}
		case <-time.After(hoWait):
			return fmt.Errorf("the NAS handler did not process UE %d's NAS PDU within %v while UE 1's SMF call is pending", w.ue2.AMFUENGAPId, hoWait)
		}
		// UE A's SMF hook must still be held: its leg is unfinished.
		if w.n2 {
			if !xnW.srv.HasPendingN2HandoverForTest(xnW.amfID) {
				return fmt.Errorf("the N2 handover of the first UE is no longer pending")
			}
		} else if n := len(xnW.tgtLn.pdus()); n != 0 {
			return fmt.Errorf("the AMF already answered the target gNB (%d PDUs) although the SMF call is held", n)
		}
		return nil
	})

	// ---- Thens: SMF fake saw ...
	waitCalls := func(kind string, psis []int) error {
		ok := w.fake.waitFor(func() bool {
			for _, p := range psis {
				if len(w.fake.callsOf(kind, p)) == 0 {
					return false
				}
			}
			return true
		})
		if !ok {
			return fmt.Errorf("the SMF fake did not receive %s for PDU session ids %v within %v", kind, psis, hoWait)
		}
		return nil
	}
	sc.Step(`^the SMF fake has received the UpdateSMContext requests? for PDU session ids? (.+?)(?: of UE "[^"]+")?$`, func(list string) error {
		kind := kindPathSwitch
		if w.n2 {
			kind = kindHOAck
		}
		return waitCalls(kind, hoPSIList(list))
	})
	sc.Step(`^the SMF fake received one UpdateSMContext per PDU session with n2SmInfoType "PATH_SWITCH_REQ" and toBeSwitched true$`, func() error {
		// toBeSwitched is added by HTTPSMFClient.UpdatePathSwitch (covered by cmd/amf/smf_update_test.go);
		// the fake asserts the hook kind PATH_SWITCH_REQ it was registered on.
		for _, it := range xnW.req.PDUSessions {
			if n := len(w.fake.callsOf(kindPathSwitch, int(it.PDUSessionID))); n != 1 {
				return fmt.Errorf("PDU session id %d: %d PATH_SWITCH_REQ calls, want 1", it.PDUSessionID, n)
			}
		}
		return nil
	})
	sc.Step(`^each PATH_SWITCH_REQ n2SmInfo equals the PathSwitchRequestTransfer of that PDU session in the PATH SWITCH REQUEST$`, func() error {
		for _, it := range xnW.req.PDUSessions {
			c := w.fake.callsOf(kindPathSwitch, int(it.PDUSessionID))
			if len(c) != 1 || !bytes.Equal(c[0].n2, it.PathSwitchRequestTransfer) {
				return fmt.Errorf("PDU session id %d: relayed %d call(s) %x, request carried %x", it.PDUSessionID, len(c), hoFirstN2(c), it.PathSwitchRequestTransfer)
			}
		}
		return nil
	})
	sc.Step(`^the SMF fake received exactly one UpdateSMContext for PDU session id (\d+) with n2SmInfoType "PATH_SWITCH_SETUP_FAIL" and failedToBeSwitched true$`, func(p int) error {
		// failedToBeSwitched is added by HTTPSMFClient.UpdatePathSwitchSetupFail (cmd/amf/smf_update_test.go);
		// the fake asserts the hook kind PATH_SWITCH_SETUP_FAIL.
		if n := len(w.fake.callsOf(kindSetupFail, p)); n != 1 {
			return fmt.Errorf("PDU session id %d: %d PATH_SWITCH_SETUP_FAIL calls, want 1", p, n)
		}
		return nil
	})
	sc.Step(`^that n2SmInfo equals the PathSwitchRequestSetupFailedTransfer of PDU session id (\d+) in the PATH SWITCH REQUEST$`, func(p int) error {
		c := w.fake.callsOf(kindSetupFail, p)
		for _, f := range xnW.req.FailedToSetup {
			if int(f.PDUSessionID) == p {
				if len(c) != 1 || !bytes.Equal(c[0].n2, f.PathSwitchRequestSetupFailedTransfer) {
					return fmt.Errorf("relayed %d call(s) %x, request carried %x", len(c), hoFirstN2(c), f.PathSwitchRequestSetupFailedTransfer)
				}
				return nil
			}
		}
		return fmt.Errorf("PDU session id %d is not in the Failed to Setup List of the request", p)
	})
	sc.Step(`^the SMF fake received no UpdateSMContext for PDU session id (\d+)$`, func(p int) error {
		if c := w.fake.callsOf("", p); len(c) != 0 {
			return fmt.Errorf("the SMF fake received %d UpdateSMContext call(s) for PDU session id %d", len(c), p)
		}
		return nil
	})
	sc.Step(`^the SMF fake received no UpdateSMContext request$`, func() error {
		if !w.fake.quiet(100*time.Millisecond, func() bool { return len(w.fake.callsOf("", -1)) > 0 }) {
			return fmt.Errorf("the SMF fake received %d UpdateSMContext call(s), want none", len(w.fake.callsOf("", -1)))
		}
		return nil
	})
	sc.Step(`^the SMF fake received no UpdateSMContext with upCnxState "DEACTIVATED"$`, func() error {
		if !w.fake.quiet(150*time.Millisecond, func() bool { return len(w.fake.callsOf(kindDeact, -1)) > 0 }) {
			return fmt.Errorf("DEACTIVATED was sent for PDU session(s): %v", w.fake.callsOf(kindDeact, -1))
		}
		return nil
	})
	sc.Step(`^the SMF fake received no UpdateSMContext with upCnxState "DEACTIVATED" for PDU session id (\d+)$`, func(p int) error {
		if !w.fake.quiet(150*time.Millisecond, func() bool { return len(w.fake.callsOf(kindDeact, p)) > 0 }) {
			return fmt.Errorf("DEACTIVATED was sent for PDU session id %d", p)
		}
		return nil
	})
	sc.Step(`^the SMF fake eventually received exactly one UpdateSMContext with upCnxState "DEACTIVATED" for PDU session id (\d+)$`, func(p int) error {
		if !w.fake.waitFor(func() bool { return len(w.fake.callsOf(kindDeact, p)) >= 1 }) {
			return fmt.Errorf("no DEACTIVATED UpdateSMContext for PDU session id %d within %v", p, hoWait)
		}
		if n := len(w.fake.callsOf(kindDeact, p)); n != 1 {
			return fmt.Errorf("PDU session id %d: %d DEACTIVATED calls, want exactly 1", p, n)
		}
		return nil
	})
	sc.Step(`^those DEACTIVATED requests carry no n2SmInfo$`, func() error {
		// The UPDeactivateHook signature has no N2 SM information parameter at all; the fake
		// recorded n2 == nil for every DEACTIVATED call (the JSON body has only upCnxState,
		// see cmd/amf/clients.go NotifyANRelease).
		for _, c := range w.fake.callsOf(kindDeact, -1) {
			if len(c.n2) != 0 {
				return fmt.Errorf("DEACTIVATED call for PDU session id %d carried n2SmInfo", c.psi)
			}
		}
		return nil
	})
	sc.Step(`^the DEACTIVATED requests were sent after the Ack was written$`, func() error {
		sent := xnW.tgtLn.pdus()
		if len(sent) == 0 {
			return fmt.Errorf("no Ack written")
		}
		ackAt := sent[len(sent)-1].at
		for _, c := range w.fake.callsOf(kindDeact, -1) {
			if c.at.Before(ackAt) {
				return fmt.Errorf("DEACTIVATED for PDU session id %d at %v precedes the Ack at %v", c.psi, c.at, ackAt)
			}
		}
		return nil
	})
	sc.Step(`^the SMF fake received no DeleteSMContext or ReleaseSMContext request$`, func() error {
		w.fake.mu.Lock()
		defer w.fake.mu.Unlock()
		if len(w.fake.hooks) != 0 {
			return fmt.Errorf("release-type hooks fired: %v", w.fake.hooks)
		}
		for _, c := range w.fake.calls {
			if c.kind != kindPathSwitch && c.kind != kindSetupFail && c.kind != kindHOAck && c.kind != kindDeact {
				return fmt.Errorf("unexpected SMF call kind %q", c.kind)
			}
		}
		return nil
	})
	sc.Step(`^the UE still holds PDU session ids? (.+)$`, func(list string) error {
		ue := xnW.ue
		ue.Lock()
		defer ue.Unlock()
		for _, p := range hoPSIList(list) {
			if ue.PDUSessions[uint8(p)] == nil {
				return fmt.Errorf("UE lost PDU session id %d", p)
			}
		}
		return nil
	})

	// ---- Thens: ordering
	sc.Step(`^no NGAP message is written to the target gNB connection yet$`, func() error {
		if n := len(xnW.tgtLn.pdus()); n != 0 {
			return fmt.Errorf("target gNB connection received %d PDU(s) before the SMF answered", n)
		}
		return nil
	})
	sc.Step(`^the Ack was written after the last SMF response was returned$`, func() error {
		sent := xnW.tgtLn.pdus()
		if len(sent) == 0 {
			return fmt.Errorf("no Ack written")
		}
		if last := w.fake.lastAnswer(); sent[len(sent)-1].at.Before(last) {
			return fmt.Errorf("Ack written at %v, before the last SMF response at %v", sent[len(sent)-1].at, last)
		}
		return nil
	})
	sc.Step(`^the AMF sends a PATH SWITCH REQUEST ACKNOWLEDGE to the target gNB within the test deadline$`, func() error {
		if w.elapsed > hoWait {
			return fmt.Errorf("the handler took %v, deadline %v", w.elapsed, hoWait)
		}
		if len(xnW.tgtLn.pdus()) == 0 {
			return fmt.Errorf("nothing written to the target gNB")
		}
		return xnW.needAck()
	})
	sc.Step(`^the Next Hop Chaining Count of the UE is unchanged$`, func() error {
		nh, ncc, ok := xnW.ue.NHState()
		if !ok || ncc != 1 || !bytes.Equal(nh[:], kdf.KNH(xnW.kamf, xnW.kgnb[:])) {
			return fmt.Errorf("NH chain changed: valid=%v ncc=%d, want NH1/NCC 1", ok, ncc)
		}
		return nil
	})

	// ---- Thens: Ack content (Xn)
	sc.Step(`^the Switched List item for PDU session id (\d+) carries exactly the bytes returned by the SMF for PDU session id (\d+)$`,
		func(item, ret int) error {
			sw, _, err := hoAckItems(&xnW)
			if err != nil {
				return err
			}
			got, ok := sw[int64(item)]
			if !ok {
				return fmt.Errorf("PDU session id %d not in the Switched List", item)
			}
			w.fake.mu.Lock()
			want := w.fake.returned[uint8(ret)]
			w.fake.mu.Unlock()
			return hoEqBytes(fmt.Sprintf("Switched List item %d", item), got, want)
		})
	sc.Step(`^the Switched List item for PDU session id (\d+) carries an empty PathSwitchRequestAcknowledgeTransfer$`, func(item int) error {
		sw, _, err := hoAckItems(&xnW)
		if err != nil {
			return err
		}
		got, ok := sw[int64(item)]
		if !ok {
			return fmt.Errorf("PDU session id %d not in the Switched List", item)
		}
		want, err := aper.MarshalWithParams(ngapType.PathSwitchRequestAcknowledgeTransfer{}, "valueExt")
		if err != nil {
			return err
		}
		return hoEqBytes("empty PathSwitchRequestAcknowledgeTransfer", got, want)
	})
	sc.Step(`^the PDUSessionResourceReleasedListPSAck item for PDU session id (\d+) carries exactly the bytes returned by the SMF for PDU session id (\d+)$`,
		func(item, ret int) error {
			_, rel, err := hoAckItems(&xnW)
			if err != nil {
				return err
			}
			got, ok := rel[int64(item)]
			if !ok {
				return fmt.Errorf("PDU session id %d not in the Released List PSAck", item)
			}
			w.fake.mu.Lock()
			want := w.fake.returned[uint8(ret)]
			w.fake.mu.Unlock()
			return hoEqBytes(fmt.Sprintf("Released List PSAck item %d", item), got, want)
		})
	noBytes := func(label string, items map[int64][]byte, hexs string) error {
		raw, err := hexBytes(hexs)
		if err != nil {
			return err
		}
		for psi, b := range items {
			if bytes.Contains(b, raw) {
				return fmt.Errorf("%s item of PDU session id %d contains the undecodable SMF bytes %s", label, psi, hexs)
			}
		}
		return nil
	}
	sc.Step(`^no item of the Ack contains the bytes "([0-9a-f]+)"$`, func(h string) error {
		sw, rel, err := hoAckItems(&xnW)
		if err != nil {
			return err
		}
		if err := noBytes("Switched List", sw, h); err != nil {
			return err
		}
		return noBytes("Released List PSAck", rel, h)
	})
	sc.Step(`^no item of the HANDOVER COMMAND contains the bytes "([0-9a-f]+)"$`, func(h string) error {
		c, err := w.decodeCmd()
		if err != nil {
			return err
		}
		if err := noBytes("Handover List", c.handled, h); err != nil {
			return err
		}
		return noBytes("To Release List HOCmd", c.release, h)
	})

	// ---- Thens: logs (Xn + N2)
	sc.Step(`^the error is logged with cause "([^"]+)"$`, func(cause string) error {
		if _, ok := hoLogFind(func(r xnRec) bool { return r.level == slog.LevelError && r.attrs["cause"] == cause }); !ok {
			return fmt.Errorf("no ERROR log record with cause %q", cause)
		}
		return nil
	})
	sc.Step(`^the failure is logged with result "([^"]+)" and cause "([^"]+)"$`, func(result, cause string) error {
		if _, ok := hoLogFind(func(r xnRec) bool {
			msg := "PathSwitchRequestFailure"
			if w.n2 || w.prep {
				msg = "HandoverPreparationFailure"
			}
			return strings.Contains(r.msg, msg) && r.attrs["result"] == result && r.attrs["cause"] == cause
		}); !ok {
			return fmt.Errorf("no PathSwitch/HandoverPreparation failure log record with result %q and cause %q", result, cause)
		}
		return nil
	})
	sc.Step(`^the fallback is logged with level (WARN|ERROR)$`, func(level string) error {
		r, ok := hoLogFind(func(r xnRec) bool {
			if w.prep {
				// PREPARING leg: fallback to the cached N2SmTransfer.
				return strings.Contains(r.msg, "cached N2SmTransfer used for the HANDOVER REQUEST")
			}
			return strings.Contains(r.msg, "empty PathSwitchRequestAcknowledgeTransfer used") ||
				strings.Contains(r.msg, "empty HandoverCommandTransfer used")
		})
		if !ok {
			return fmt.Errorf("no fallback log record")
		}
		if r.level != hoLevel(level) {
			return fmt.Errorf("fallback %q logged at %v, want %s", r.msg, r.level, level)
		}
		return nil
	})
	sc.Step(`^the outcome of the PATH_SWITCH_SETUP_FAIL call is logged with level WARN$`, func() error {
		if _, ok := hoLogFind(func(r xnRec) bool {
			return strings.Contains(r.msg, "PATH_SWITCH_SETUP_FAIL") && r.level == slog.LevelWarn
		}); !ok {
			return fmt.Errorf("no WARN log record for the PATH_SWITCH_SETUP_FAIL outcome")
		}
		return nil
	})
	sc.Step(`^a WARN is logged with pdu_session_id (\d+)$`, func(p int) error {
		if _, ok := hoLogFind(func(r xnRec) bool {
			return r.level == slog.LevelWarn && r.attrs["pdu_session_id"] == strconv.Itoa(p)
		}); !ok {
			return fmt.Errorf("no WARN log record with pdu_session_id %d", p)
		}
		return nil
	})
	sc.Step(`^a WARN is logged that no SMF is configured$`, func() error {
		if _, ok := hoLogFind(func(r xnRec) bool {
			return r.level == slog.LevelWarn && strings.Contains(r.msg, "no SMF hook configured")
		}); !ok {
			return fmt.Errorf("no WARN log record about a missing SMF hook")
		}
		return nil
	})
	sc.Step(`^the DEACTIVATED failure is logged with level WARN$`, func() error {
		// the DEACTIVATED call runs on its own goroutine after the Ack: poll with a deadline.
		if !hoEventually(hoWait, func() bool {
			_, ok := hoLogFind(func(r xnRec) bool {
				return r.level == slog.LevelWarn && strings.Contains(r.msg, "UP deactivation of PDU session failed")
			})
			return ok
		}) {
			return fmt.Errorf("no WARN log record for the failed DEACTIVATED call within %v", hoWait)
		}
		return nil
	})

	// ---- N2 handover Thens
	sc.Step(`^the SMF fake received exactly one UpdateSMContext per admitted PDU session with hoState "PREPARED" and n2SmInfoType "HANDOVER_REQ_ACK"$`, func() error {
		// hoState is added by HTTPSMFClient.PrepareHandover (cmd/amf/smf_update_test.go);
		// the fake asserts the hook kind HANDOVER_REQ_ACK.
		for _, a := range w.admitted {
			if n := len(w.fake.callsOf(kindHOAck, int(a.PDUSessionID))); n != 1 {
				return fmt.Errorf("PDU session id %d: %d HANDOVER_REQ_ACK calls, want 1", a.PDUSessionID, n)
			}
		}
		return nil
	})
	sc.Step(`^each HANDOVER_REQ_ACK n2SmInfo equals the HandoverRequestAcknowledgeTransfer of that PDU session in the HANDOVER REQUEST ACKNOWLEDGE$`, func() error {
		for _, a := range w.admitted {
			c := w.fake.callsOf(kindHOAck, int(a.PDUSessionID))
			if len(c) != 1 || !bytes.Equal(c[0].n2, a.HandoverRequestAcknowledgeTransfer) {
				return fmt.Errorf("PDU session id %d: relayed %d call(s) %x, ack carried %x", a.PDUSessionID, len(c), hoFirstN2(c), a.HandoverRequestAcknowledgeTransfer)
			}
		}
		return nil
	})
	sc.Step(`^the AMF sends a HANDOVER COMMAND to the source gNB$`, func() error {
		_, err := w.decodeCmd()
		return err
	})
	sc.Step(`^the HANDOVER COMMAND IEs appear in this order:$`, func(t *godog.Table) error {
		names := map[string]int64{
			"AMFUENGAPID": 10, "RANUENGAPID": 85, "HandoverType": 29, "PDUSessionResourceHandoverList": 59,
			"PDUSessionResourceToReleaseListHOCmd": 78, "TargetToSourceTransparentContainer": 106,
		}
		c, err := w.decodeCmd()
		if err != nil {
			return err
		}
		var want []int64
		for _, row := range t.Rows[1:] {
			id, err := strconv.ParseInt(strings.TrimSpace(row.Cells[1].Value), 10, 64)
			if err != nil {
				return err
			}
			n := strings.TrimSpace(row.Cells[0].Value)
			if names[n] != id {
				return fmt.Errorf("table maps %q to id %d, TS 38.413 has %d", n, id, names[n])
			}
			want = append(want, id)
		}
		if fmt.Sprint(c.ies) != fmt.Sprint(want) {
			return fmt.Errorf("HANDOVER COMMAND IE order = %v, want %v", c.ies, want)
		}
		return nil
	})
	sc.Step(`^the PDUSessionResourceHandoverList \(id 59\) item for PDU session id (\d+) carries exactly the bytes returned by the SMF for PDU session id (\d+)$`,
		func(item, ret int) error {
			c, err := w.decodeCmd()
			if err != nil {
				return err
			}
			got, ok := c.handled[int64(item)]
			if !ok {
				return fmt.Errorf("PDU session id %d not in the PDU Session Resource Handover List", item)
			}
			w.fake.mu.Lock()
			want := w.fake.returned[uint8(ret)]
			w.fake.mu.Unlock()
			return hoEqBytes(fmt.Sprintf("Handover List item %d", item), got, want)
		})
	sc.Step(`^the PDUSessionResourceHandoverList \(id 59\) item for PDU session id (\d+) carries an empty HandoverCommandTransfer$`, func(item int) error {
		c, err := w.decodeCmd()
		if err != nil {
			return err
		}
		got, ok := c.handled[int64(item)]
		if !ok {
			return fmt.Errorf("PDU session id %d not in the PDU Session Resource Handover List", item)
		}
		want, err := aper.MarshalWithParams(ngapType.HandoverCommandTransfer{}, "valueExt")
		if err != nil {
			return err
		}
		return hoEqBytes("empty HandoverCommandTransfer", got, want)
	})
	sc.Step(`^the PDUSessionResourceHandoverList \(id 59\) contains only PDU session id (\d+)$`, func(p int) error {
		c, err := w.decodeCmd()
		if err != nil {
			return err
		}
		if fmt.Sprint(c.order) != fmt.Sprint([]int64{int64(p)}) {
			return fmt.Errorf("PDU Session Resource Handover List = %v, want [%d]", c.order, p)
		}
		return nil
	})
	sc.Step(`^the PDUSessionResourceToReleaseListHOCmd \(id 78\) contains PDU session id (\d+) with radioNetwork cause "([^"]+)"$`, func(p int, name string) error {
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
		return xnCauseMatches(tr.Cause, "radioNetwork", name)
	})
	sc.Step(`^the PDUSessionResourceToReleaseListHOCmd \(id 78\) item for PDU session id (\d+) carries exactly the bytes returned by the SMF for PDU session id (\d+)$`,
		func(item, ret int) error {
			c, err := w.decodeCmd()
			if err != nil {
				return err
			}
			got, ok := c.release[int64(item)]
			if !ok {
				return fmt.Errorf("PDU session id %d missing from the To Release List HOCmd", item)
			}
			return hoEqBytes(fmt.Sprintf("To Release List item %d", item), got, w.fake.returnedAny(uint8(ret)))
		})
	sc.Step(`^the HANDOVER COMMAND was written after every SMF response had returned$`, func() error {
		c, err := w.decodeCmd()
		if err != nil {
			return err
		}
		if last := w.fake.lastAnswer(); c.at.Before(last) {
			return fmt.Errorf("HANDOVER COMMAND written at %v, before the last SMF response at %v", c.at, last)
		}
		return nil
	})
	prepFailure := func() (*ngapType.HandoverPreparationFailure, error) {
		last, ok := w.lastSrc()
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
	sc.Step(`^the AMF sends a HANDOVER PREPARATION FAILURE to the source gNB$`, func() error {
		_, err := prepFailure()
		return err
	})
	sc.Step(`^the AMF sends a HANDOVER PREPARATION FAILURE to the source gNB within the test deadline$`, func() error {
		if w.elapsed > hoWait {
			return fmt.Errorf("the handler took %v, deadline %v", w.elapsed, hoWait)
		}
		_, err := prepFailure()
		return err
	})
	sc.Step(`^the HANDOVER PREPARATION FAILURE carries radioNetwork cause "([^"]+)"$`, func(name string) error {
		f, err := prepFailure()
		if err != nil {
			return err
		}
		for _, ie := range f.ProtocolIEs.List {
			if ie.Value.Cause != nil {
				return xnCauseMatches(*ie.Value.Cause, "radioNetwork", name)
			}
		}
		return fmt.Errorf("no Cause IE in the HANDOVER PREPARATION FAILURE")
	})
	sc.Step(`^no HANDOVER COMMAND is sent$`, func() error {
		for _, p := range xnW.srcLn.pdus() {
			pdu, err := libngap.Decoder(p.raw)
			if err != nil {
				return err
			}
			if pdu.SuccessfulOutcome != nil && pdu.SuccessfulOutcome.Value.HandoverCommand != nil {
				return fmt.Errorf("a HANDOVER COMMAND was sent")
			}
		}
		return nil
	})
	sc.Step(`^the pending N2 handover state of AMF UE NGAP ID (\d+) is dropped$`, func(id int) error {
		if xnW.srv.HasPendingN2HandoverForTest(int64(id)) {
			return fmt.Errorf("pending N2 handover state of AMF UE NGAP ID %d still present", id)
		}
		return nil
	})
	sc.Step(`^the UE is not registered on the target gNB$`, func() error {
		if xnW.ue.GNBAddr != xnW.srcAddr {
			return fmt.Errorf("UE GNBAddr = %q, want the source gNB %q", xnW.ue.GNBAddr, xnW.srcAddr)
		}
		for ran, u := range xnW.tgt.UEs {
			if u == xnW.ue {
				return fmt.Errorf("target gNB maps RAN UE NGAP ID %d to the UE", ran)
			}
		}
		return nil
	})

	// ---- E2E (live PacketRusher): pending, never a false pass
	sc.Step(`^"make handover-n2-test" is run$`, hoE2EPending)
	sc.Step(`^the PacketRusher N2 scenario completes the handover$`, hoE2EPending)
	sc.Step(`^the SMF logs the Nsmf_PDUSession_UpdateSMContext PATH_SWITCH_REQ before the AMF sends the PATH SWITCH REQUEST ACKNOWLEDGE$`, hoE2EPending)
	sc.Step(`^the SMF logs the Nsmf_PDUSession_UpdateSMContext HANDOVER_REQ_ACK before the AMF sends the HANDOVER COMMAND$`, hoE2EPending)
	sc.Step(`^the Ack Switched List transfers decode in Wireshark$`, hoE2EPending)
	sc.Step(`^the HANDOVER COMMAND transfers decode in Wireshark$`, hoE2EPending)
}

// hoNAS records the AMF UE NGAP ID of every NAS PDU the AMF hands to the NAS handler.
var hoNAS *hoNASRecorder

// hoNASRecorder is the NASHandler of the in-process Server for the AMF-012 suites.
type hoNASRecorder struct{ seen chan int64 }

// HandleNASMessage implements amfngap.NASHandler.
func (r *hoNASRecorder) HandleNASMessage(_ context.Context, ue *amfctx.UEContext, _ []byte) error {
	r.seen <- ue.AMFUENGAPId
	return nil
}
