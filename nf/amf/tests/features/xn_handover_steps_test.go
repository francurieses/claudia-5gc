//go:build functional

// xn_handover_steps_test.go — in-process godog steps for xn_handover.feature
// (AMF-011: Xn handover Path Switch Request Acknowledge/Failure, NH/NCC chain,
// no source-gNB release, SCTP PPID 60, HANDOVER REQUEST UE-AMBR).
//
// The real *ngap.Server handlers run in-process: each gNB gets a fake SCTP
// transport (GNBContext.SetTransportForTest) that records every PDU together
// with its SndRcvInfo, and every PDU the AMF writes is decoded with the strict
// github.com/free5gc/ngap decoder. The @e2e PacketRusher scenario needs the live
// stack and is reported pending (never a false pass).
//
// Some step texts are shared with initial_context_setup.feature (decode check,
// IE order, UE-AMBR, ...). Godog binds the first registered pattern, and the ICS
// steps are registered first, so those handlers delegate to the xn* functions
// below when xnW.active is set (scenario URI is xn_handover.feature).
//
// Ref: TS 38.413 §8.4.4, §9.2.3.9, §9.2.3.10, §9.3.1.18; TS 33.501 §6.9.2.3;
// TS 23.502 §4.9.1.2.2; TS 38.412 §7.
package features_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cucumber/godog"
	"github.com/free5gc/aper"
	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"github.com/ishidawataru/sctp"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	amfngap "github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/shared/crypto/kdf"
)

// ---- recording transport and logger -----------------------------------------------

type xnSent struct {
	raw  []byte
	ppid uint32
	at   time.Time // time of the write (ordering assertions, AMF-012)
}

type xnLink struct {
	mu   sync.Mutex
	sent []xnSent
}

func (l *xnLink) write(pdu []byte, info *sctp.SndRcvInfo) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sent = append(l.sent, xnSent{append([]byte(nil), pdu...), info.PPID, time.Now()})
	return len(pdu), nil
}

func (l *xnLink) pdus() []xnSent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]xnSent(nil), l.sent...)
}

func (l *xnLink) reset() {
	l.mu.Lock()
	l.sent = nil
	l.mu.Unlock()
}

type xnRec struct {
	level slog.Level
	msg   string
	attrs map[string]string
}

type xnLogStore struct {
	mu   sync.Mutex
	recs []xnRec
}

// xnHandler is a slog.Handler that keeps handler-level attrs (logger.With) too.
type xnHandler struct {
	store *xnLogStore
	pre   []slog.Attr
}

func (h *xnHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *xnHandler) Handle(_ context.Context, r slog.Record) error {
	rec := xnRec{level: r.Level, msg: r.Message, attrs: map[string]string{}}
	for _, a := range h.pre {
		rec.attrs[a.Key] = a.Value.String()
	}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.String()
		return true
	})
	h.store.mu.Lock()
	h.store.recs = append(h.store.recs, rec)
	h.store.mu.Unlock()
	return nil
}
func (h *xnHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &xnHandler{store: h.store, pre: append(append([]slog.Attr(nil), h.pre...), as...)}
}
func (h *xnHandler) WithGroup(string) slog.Handler { return h }

func (s *xnLogStore) find(msg string) (xnRec, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.recs {
		if strings.Contains(r.msg, msg) {
			return r, true
		}
	}
	return xnRec{}, false
}

// ---- world ---------------------------------------------------------------------------

type xnIE struct {
	id   int64
	crit aper.Enumerated
}

type xnWorld struct {
	active bool

	logs         *xnLogStore
	srv          *amfngap.Server
	mgr          *amfctx.Manager
	ue           *amfctx.UEContext
	src, tgt     *amfngap.GNBContext
	srcLn, tgtLn *xnLink
	srcAddr      string
	tgtAddr      string

	kamf    []byte
	kgnb    [32]byte
	prevNH  [32]byte
	amfID   int64
	ranOld  int64
	req     *amfngap.PathSwitchRequestMsg
	smfRefs []string
	smfMu   sync.Mutex

	// N2 HO scenario
	hoSrcRAN int64

	// decoded last message of interest
	pdu      *ngapType.NGAPPDU
	decErr   error
	ies      []xnIE
	ack      *ngapType.PathSwitchRequestAcknowledge
	fail     map[int64]ngapType.Cause
	failAMF  int64
	failRAN  int64
	scNCC    int64
	scNH     []byte
	scBits   uint64
	ambrUL   int64
	ambrDL   int64
	hasAMBR  bool
	hoSource *amfngap.GNBContext // gNB the HANDOVER REQUIRED came from
	hoTarget *amfngap.GNBContext
	hoTgtLn  *xnLink
	hoSrcLn  *xnLink
}

var xnW xnWorld

func xnActive() bool { return xnW.active }

func (w *xnWorld) reset(active bool) {
	*w = xnWorld{active: active}
}

var xnIEIDs = map[string]int64{
	"AMFUENGAPID":                          ngapType.ProtocolIEIDAMFUENGAPID,
	"RANUENGAPID":                          ngapType.ProtocolIEIDRANUENGAPID,
	"SecurityContext":                      ngapType.ProtocolIEIDSecurityContext,
	"PDUSessionResourceSwitchedList":       ngapType.ProtocolIEIDPDUSessionResourceSwitchedList,
	"PDUSessionResourceReleasedListPSAck":  ngapType.ProtocolIEIDPDUSessionResourceReleasedListPSAck,
	"PDUSessionResourceReleasedListPSFail": ngapType.ProtocolIEIDPDUSessionResourceReleasedListPSFail,
	"AllowedNSSAI":                         ngapType.ProtocolIEIDAllowedNSSAI,
	"UESecurityCapabilities":               ngapType.ProtocolIEIDUESecurityCapabilities,
	"UEAggregateMaximumBitRate":            ngapType.ProtocolIEIDUEAggregateMaximumBitRate,
}

func xnNHn(kamf, kgnb []byte, n int) []byte {
	nh := kdf.KNH(kamf, kgnb)
	for i := 1; i < n; i++ {
		nh = kdf.KNH(kamf, nh)
	}
	return nh
}

func xnHex(b []byte) string { return fmt.Sprintf("%x", b) }

func xnSD(sd string) string { return strings.ToLower(sd) }

// ---- decoding -----------------------------------------------------------------------

// decodeLast decodes pdu with the strict decoder and extracts what the steps check.
func (w *xnWorld) decode(raw []byte) {
	w.pdu, w.decErr = nil, nil
	w.ies, w.ack, w.fail, w.hasAMBR = nil, nil, nil, false
	w.scNCC, w.scNH, w.scBits = -1, nil, 0
	pdu, err := libngap.Decoder(raw)
	if err != nil {
		w.decErr = fmt.Errorf("free5gc/ngap decode: %w", err)
		return
	}
	w.pdu = pdu
	switch {
	case pdu.SuccessfulOutcome != nil && pdu.SuccessfulOutcome.Value.PathSwitchRequestAcknowledge != nil:
		w.ack = pdu.SuccessfulOutcome.Value.PathSwitchRequestAcknowledge
		for _, ie := range w.ack.ProtocolIEs.List {
			w.ies = append(w.ies, xnIE{ie.Id.Value, ie.Criticality.Value})
			if sc := ie.Value.SecurityContext; sc != nil {
				w.scNCC, w.scNH, w.scBits = sc.NextHopChainingCount.Value, sc.NextHopNH.Value.Bytes, sc.NextHopNH.Value.BitLength
			}
		}
	case pdu.UnsuccessfulOutcome != nil && pdu.UnsuccessfulOutcome.Value.PathSwitchRequestFailure != nil:
		w.fail = map[int64]ngapType.Cause{}
		for _, ie := range pdu.UnsuccessfulOutcome.Value.PathSwitchRequestFailure.ProtocolIEs.List {
			w.ies = append(w.ies, xnIE{ie.Id.Value, ie.Criticality.Value})
			switch {
			case ie.Value.AMFUENGAPID != nil:
				w.failAMF = ie.Value.AMFUENGAPID.Value
			case ie.Value.RANUENGAPID != nil:
				w.failRAN = ie.Value.RANUENGAPID.Value
			case ie.Value.PDUSessionResourceReleasedListPSFail != nil:
				for _, it := range ie.Value.PDUSessionResourceReleasedListPSFail.List {
					var tr ngapType.PathSwitchRequestUnsuccessfulTransfer
					if err := aper.UnmarshalWithParams(it.PathSwitchRequestUnsuccessfulTransfer, &tr, "valueExt"); err != nil {
						w.decErr = fmt.Errorf("decode unsuccessful transfer: %w", err)
						return
					}
					w.fail[it.PDUSessionID.Value] = tr.Cause
				}
			}
		}
	case pdu.InitiatingMessage != nil && pdu.InitiatingMessage.Value.HandoverRequest != nil:
		for _, ie := range pdu.InitiatingMessage.Value.HandoverRequest.ProtocolIEs.List {
			w.ies = append(w.ies, xnIE{ie.Id.Value, ie.Criticality.Value})
			switch {
			case ie.Value.SecurityContext != nil:
				sc := ie.Value.SecurityContext
				w.scNCC, w.scNH, w.scBits = sc.NextHopChainingCount.Value, sc.NextHopNH.Value.Bytes, sc.NextHopNH.Value.BitLength
			case ie.Value.UEAggregateMaximumBitRate != nil:
				w.hasAMBR = true
				w.ambrUL = ie.Value.UEAggregateMaximumBitRate.UEAggregateMaximumBitRateUL.Value
				w.ambrDL = ie.Value.UEAggregateMaximumBitRate.UEAggregateMaximumBitRateDL.Value
			}
		}
	}
}

func (w *xnWorld) findIE(id int64) (xnIE, bool) {
	for _, ie := range w.ies {
		if ie.id == id {
			return ie, true
		}
	}
	return xnIE{}, false
}

func (w *xnWorld) needAck() error {
	if w.decErr != nil {
		return w.decErr
	}
	if w.ack == nil {
		return fmt.Errorf("last PDU is not a PATH SWITCH REQUEST ACKNOWLEDGE")
	}
	return nil
}

func (w *xnWorld) needFail() error {
	if w.decErr != nil {
		return w.decErr
	}
	if w.fail == nil {
		return fmt.Errorf("last PDU is not a PATH SWITCH REQUEST FAILURE")
	}
	return nil
}

func (w *xnWorld) allLinks() []*xnLink {
	return []*xnLink{w.srcLn, w.tgtLn}
}

// ---- delegates used by the shared (ICS) step texts ------------------------------------

func xnDecodesCleanly() error {
	if xnW.decErr != nil {
		return xnW.decErr
	}
	if xnW.pdu == nil {
		return fmt.Errorf("no decoded PDU")
	}
	return nil
}

func xnIEOrder(t *godog.Table) error {
	w := &xnW
	var want []int64
	for _, row := range t.Rows[1:] {
		id, err := strconv.ParseInt(strings.TrimSpace(row.Cells[1].Value), 10, 64)
		if err != nil {
			return err
		}
		n := strings.TrimSpace(row.Cells[0].Value)
		if xnIEIDs[n] != id {
			return fmt.Errorf("table maps %q to id %d, builders know %d", n, id, xnIEIDs[n])
		}
		want = append(want, id)
	}
	var got []int64
	for _, ie := range w.ies {
		got = append(got, ie.id)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		return fmt.Errorf("IE order = %v, want %v", got, want)
	}
	return nil
}

func xnNotContain(name string, id int) error {
	if xnIEIDs[name] != int64(id) {
		return fmt.Errorf("feature maps %q to id %d, builders know %d", name, id, xnIEIDs[name])
	}
	if _, ok := xnW.findIE(int64(id)); ok {
		return fmt.Errorf("IE %s (id %d) is present but must be absent", name, id)
	}
	return nil
}

func xnContains(name string, id int, crit string) error {
	if xnIEIDs[name] != int64(id) {
		return fmt.Errorf("feature maps %q to id %d, builders know %d", name, id, xnIEIDs[name])
	}
	ie, ok := xnW.findIE(int64(id))
	if !ok {
		return fmt.Errorf("IE %s (id %d) missing", name, id)
	}
	if got := critName(ie.crit); got != crit {
		return fmt.Errorf("IE %s criticality %s, want %s", name, got, crit)
	}
	return nil
}

func xnAMBR(ul, dl int64) error {
	w := &xnW
	if !w.hasAMBR {
		return fmt.Errorf("no UE-AMBR in message")
	}
	if w.ambrUL != ul || w.ambrDL != dl {
		return fmt.Errorf("UE-AMBR UL/DL = %d/%d bit/s, want %d/%d", w.ambrUL, w.ambrDL, ul, dl)
	}
	return nil
}

func xnSubscribedAMBR(ulKbps, dlKbps int64) error {
	w := &xnW
	w.ue.Lock()
	w.ue.SubscribedAMBR.UL, w.ue.SubscribedAMBR.DL = uint64(ulKbps), uint64(dlKbps)
	w.ue.Unlock()
	return nil
}

func xnFailureLogged(result, specRef string) error {
	msg := "PathSwitchRequestFailure"
	if hoW.active && (hoW.n2 || hoW.prep) {
		msg = "HandoverPreparationFailure" // N2 handover scenarios of AMF-012
	}
	r, ok := xnW.logs.find(msg)
	if !ok {
		return fmt.Errorf("no %s log record", msg)
	}
	if r.attrs["result"] != result {
		return fmt.Errorf("log result = %q, want %q", r.attrs["result"], result)
	}
	if specRef != "" && r.attrs["spec_ref"] != specRef {
		return fmt.Errorf("log spec_ref = %q, want %q", r.attrs["spec_ref"], specRef)
	}
	return nil
}

// ---- setup helpers ---------------------------------------------------------------------

func (w *xnWorld) newGNB(name string, id byte, ln *xnLink, addr string) *amfngap.GNBContext {
	g := &amfngap.GNBContext{
		Name:        name,
		GlobalGNBID: []byte{0, 0, id},
		UEs:         map[int64]*amfctx.UEContext{},
		IdleUEs:     map[int64]*amfctx.UEContext{},
	}
	g.SetTransportForTest(addr, ln.write)
	w.srv.AddGNBForTest(addr, g)
	return g
}

func (w *xnWorld) runPathSwitch() error {
	if w.req == nil {
		return fmt.Errorf("no PATH SWITCH REQUEST prepared")
	}
	w.srv.HandlePathSwitchRequestForTest(context.Background(), w.tgt, w.req)
	return nil
}

func (w *xnWorld) captureTarget() {
	sent := w.tgtLn.pdus()
	if len(sent) == 0 {
		w.pdu, w.decErr = nil, nil
		w.ies, w.ack, w.fail = nil, nil, nil
		return
	}
	w.decode(sent[len(sent)-1].raw)
}

func xnParsePSIs(a, b string) ([]uint8, error) {
	var out []uint8
	for _, s := range []string{a, b} {
		if s == "" {
			continue
		}
		v, err := strconv.Atoi(s)
		if err != nil {
			return nil, err
		}
		out = append(out, uint8(v))
	}
	return out, nil
}

func (w *xnWorld) prepareRequest(ranID, amfID int64, psis []uint8) {
	w.req = &amfngap.PathSwitchRequestMsg{SourceAMFUENGAPId: amfID, RANUENGAPId: ranID}
	for _, p := range psis {
		w.req.PDUSessions = append(w.req.PDUSessions, amfngap.PDUSessionSwitchItem{
			PDUSessionID: p, PathSwitchRequestTransfer: []byte{0xAB, p}})
	}
}

func (w *xnWorld) completePathSwitches(n int) error {
	for i := 0; i < n; i++ {
		w.prepareRequest(int64(20+i), w.amfID, []uint8{5})
		if err := w.runPathSwitch(); err != nil {
			return err
		}
		w.captureTarget()
		if err := w.needAck(); err != nil {
			return fmt.Errorf("prior path switch %d: %w", i+1, err)
		}
	}
	w.srcLn.reset()
	w.tgtLn.reset()
	w.logs.mu.Lock()
	w.logs.recs = nil
	w.logs.mu.Unlock()
	w.pdu, w.ack, w.ies = nil, nil, nil
	return nil
}

// buildHandoverRequest drives HANDOVER REQUIRED from the gNB currently serving the UE.
func (w *xnWorld) buildHandoverRequest() error {
	w.hoSource, w.hoTarget, w.hoSrcLn, w.hoTgtLn = w.src, w.tgt, w.srcLn, w.tgtLn
	if w.ue.RANUENGAPId != w.ranOld {
		// UE was moved by Xn path switches: it is served by the former target.
		w.hoSource, w.hoTarget, w.hoSrcLn, w.hoTgtLn = w.tgt, w.src, w.tgtLn, w.srcLn
	}
	w.hoSrcLn.reset()
	w.hoTgtLn.reset()
	w.srv.HandleHandoverRequiredForTest(context.Background(), w.hoSource, &amfngap.HandoverRequiredMsg{
		AMFUENGAPId:                        w.amfID,
		RANUENGAPId:                        w.ue.RANUENGAPId,
		TargetGlobalRANNodeID:              w.hoTarget.GlobalGNBID,
		SourceToTargetTransparentContainer: []byte{9},
	})
	sent := w.hoTgtLn.pdus()
	if len(sent) == 0 {
		w.decErr = fmt.Errorf("no HANDOVER REQUEST written to the target gNB")
		return w.decErr
	}
	w.decode(sent[len(sent)-1].raw)
	return w.decErr
}

// ---- causes ------------------------------------------------------------------------------

func xnCauseMatches(c ngapType.Cause, kind, name string) error {
	switch kind {
	case "misc":
		if name != "unspecified" {
			return fmt.Errorf("feature uses unmapped misc cause %q", name)
		}
		if c.Present != ngapType.CausePresentMisc || c.Misc.Value != ngapType.CauseMiscPresentUnspecified {
			return fmt.Errorf("cause = %+v, want misc unspecified", c)
		}
	case "radioNetwork":
		m := map[string]aper.Enumerated{
			"unknown-local-UE-NGAP-ID":                             ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID,
			"unknown-PDU-session-ID":                               ngapType.CauseRadioNetworkPresentUnknownPDUSessionID,
			"multiple-PDU-session-ID-instances":                    ngapType.CauseRadioNetworkPresentMultiplePDUSessionIDInstances,
			"unspecified":                                          ngapType.CauseRadioNetworkPresentUnspecified,
			"ho-failure-in-target-5GC-ngran-node-or-target-system": ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem,
		}
		want, ok := m[name]
		if !ok {
			return fmt.Errorf("feature uses unmapped radioNetwork cause %q", name)
		}
		if c.Present != ngapType.CausePresentRadioNetwork || c.RadioNetwork.Value != want {
			return fmt.Errorf("cause = %+v, want radioNetwork %s", c, name)
		}
	default:
		return fmt.Errorf("unknown cause kind %q", kind)
	}
	return nil
}

func xnNSSAIList(l *ngapType.AllowedNSSAI) [][2]string {
	var out [][2]string
	for _, it := range l.List {
		out = append(out, [2]string{strconv.Itoa(int(it.SNSSAI.SST.Value[0])), xnHex(it.SNSSAI.SD.Value)})
	}
	return out
}

func (w *xnWorld) allowedNSSAI() ([][2]string, error) {
	if err := w.needAck(); err != nil {
		return nil, err
	}
	for _, ie := range w.ack.ProtocolIEs.List {
		if ie.Value.AllowedNSSAI != nil {
			return xnNSSAIList(ie.Value.AllowedNSSAI), nil
		}
	}
	return nil, fmt.Errorf("AllowedNSSAI IE missing")
}

// ---- step registration ---------------------------------------------------------------------

func initXnHandoverSteps(sc *godog.ScenarioContext) {
	w := &xnW
	sc.Before(func(ctx context.Context, s *godog.Scenario) (context.Context, error) {
		w.reset(strings.HasSuffix(s.Uri, "xn_handover.feature") || strings.HasSuffix(s.Uri, "handover_smf_leg.feature"))
		return ctx, nil
	})

	// ---- Background
	sc.Step(`^UE with SUPI "([^"]+)" has AMF UE NGAP ID (\d+) and RAN UE NGAP ID (\d+) on source gNB "([^"]+)"$`,
		func(supi string, amfID, ranID int, srcName string) error {
			w.logs = &xnLogStore{}
			w.mgr = amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
			hoNAS = &hoNASRecorder{seen: make(chan int64, 16)}
			w.srv = amfngap.NewServer("127.0.0.1:0", w.mgr, hoNAS, amfngap.AMFConfig{MCC: "001", MNC: "01"},
				slog.New(&xnHandler{store: w.logs}))
			w.srv.SetPathSwitchHandler(func(_ context.Context, ref string, _ []byte) amfngap.SMFUpdateResult {
				// AMF-012: the AMF calls the SMF hook concurrently per PDU session.
				w.smfMu.Lock()
				w.smfRefs = append(w.smfRefs, ref)
				w.smfMu.Unlock()
				return amfngap.SMFUpdateResult{HTTPStatus: 200}
			})
			w.srcLn, w.tgtLn = &xnLink{}, &xnLink{}
			w.srcAddr, w.tgtAddr = "10.0.0.1:1", "10.0.0.2:1"
			w.ranOld = int64(ranID)
			w.ue = w.mgr.AllocateUEContext(w.ranOld)
			w.amfID = w.ue.AMFUENGAPId
			if w.amfID != int64(amfID) {
				return fmt.Errorf("manager allocated AMF UE NGAP ID %d, feature expects %d", w.amfID, amfID)
			}
			w.ue.SUPI = supi
			w.ue.CMState = amfctx.CMConnected
			w.src = w.newGNB(srcName, 1, w.srcLn, w.srcAddr)
			w.src.UEs[w.ranOld] = w.ue
			w.ue.GNBAddr = w.srcAddr
			return nil
		})
	sc.Step(`^target gNB "([^"]+)" completed NG Setup with the AMF$`, func(name string) error {
		w.tgt = w.newGNB(name, 2, w.tgtLn, w.tgtAddr)
		w.srv.CompleteNGSetupForTest(w.tgt)
		return nil
	})
	sc.Step(`^the UE has a KAMF and an Allowed NSSAI of SST (\d+) SD "([0-9a-fA-F]{6})"$`, func(sst int, sd string) error {
		w.kamf = bytes.Repeat([]byte{0x11}, 32)
		w.ue.SecurityCtx.KAMF = w.kamf
		w.ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{{SST: uint8(sst), SD: xnSD(sd)}}
		return nil
	})
	sc.Step(`^the UE has PDU session id (\d+) on S-NSSAI SST (\d+) SD "([0-9a-fA-F]{6})"$`, func(id, sst int, sd string) error {
		if w.ue.PDUSessions == nil {
			w.ue.PDUSessions = map[uint8]*amfctx.PDUSession{}
		}
		w.ue.PDUSessions[uint8(id)] = &amfctx.PDUSession{
			PDUSessionID: uint8(id), SMFInstanceID: "smctx-" + strconv.Itoa(id),
			SNSSAI: amfctx.SNSSAISubscribed{SST: uint8(sst), SD: xnSD(sd)}, N2SmTransfer: []byte{1, 2, 3},
		}
		return nil
	})
	sc.Step(`^the UE has Security Capabilities stored in the AMF$`, func() error {
		w.ue.UESecCapEA[1], w.ue.UESecCapEA[2] = true, true
		w.ue.UESecCapIA[1], w.ue.UESecCapIA[2] = true, true
		return nil
	})
	sc.Step(`^an Initial Context Setup established a KgNB of (\d+) bits so the NH chain holds NH1 = KNH\(KAMF, KgNB\) with NCC 1$`,
		func(bits int) error {
			if bits != 256 {
				return fmt.Errorf("KgNB must be 256 bits, feature says %d", bits)
			}
			for i := range w.kgnb {
				w.kgnb[i] = byte(0xA0 + i)
			}
			w.ue.SetKgNB(w.kgnb)
			nh, ncc, ok := w.ue.NHState()
			if !ok || ncc != 1 || !bytes.Equal(nh[:], kdf.KNH(w.kamf, w.kgnb[:])) {
				return fmt.Errorf("NH chain after SetKgNB: valid=%v ncc=%d, want NH1/NCC 1", ok, ncc)
			}
			return nil
		})

	// ---- Givens
	sc.Step(`^the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID (\d+) and Source AMF UE NGAP ID (\d+) for PDU session ids? (\d+)(?: and (\d+))?$`,
		func(ranID, amfID int, a, b string) error {
			psis, err := xnParsePSIs(a, b)
			if err != nil {
				return err
			}
			w.prepareRequest(int64(ranID), int64(amfID), psis)
			return nil
		})
	sc.Step(`^the target gNB sends a PATH SWITCH REQUEST whose UE Security Capabilities (differ from|equal) those stored in the AMF$`,
		func(mode string) error {
			w.prepareRequest(7, w.amfID, []uint8{5})
			stored := amfngap.UESecCapBitmaps{Enc: 0xC000, Int: 0xC000} // NEA1/NEA2, NIA1/NIA2
			if mode == "equal" {
				w.req.UESecCap = &stored
			} else {
				w.req.UESecCap = &amfngap.UESecCapBitmaps{Enc: 0xE000, Int: 0xC000}
			}
			return nil
		})
	sc.Step(`^the UE already completed one Xn path switch with the AMF$`, func() error { return w.completePathSwitches(1) })
	sc.Step(`^the UE already completed (\d+) Xn path switches with the AMF$`, func(n int) error { return w.completePathSwitches(n) })
	sc.Step(`^the NH chain of the UE holds NCC (\d+)$`, func(ncc int) error {
		w.prevNH = [32]byte{0x77}
		w.ue.SetNHState(w.prevNH, uint8(ncc))
		return nil
	})
	sc.Step(`^the UE Allowed NSSAI is empty$`, func() error { w.ue.AllowedNSSAI = nil; return nil })
	sc.Step(`^the S-NSSAI of every PDU session of the UE is absent$`, func() error {
		for _, s := range w.ue.PDUSessions {
			s.SNSSAI = amfctx.SNSSAISubscribed{}
		}
		return nil
	})
	sc.Step(`^the UE Allowed NSSAI holds SST (\d+) SD "([0-9a-fA-F]{6})" twice with different DNNs$`, func(sst int, sd string) error {
		w.ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{
			{SST: uint8(sst), SD: xnSD(sd), DNN: "internet"},
			{SST: uint8(sst), SD: xnSD(sd), DNN: "ims"},
		}
		return nil
	})
	sc.Step(`^the UE has no KgNB so the NH chain was never initialised$`, func() error {
		w.ue.Lock()
		w.ue.NHValid = false
		w.ue.Unlock()
		return nil
	})
	sc.Step(`^the source gNB sends a HANDOVER REQUIRED for the UE towards "([^"]+)"$`, func(target string) error {
		if w.tgt == nil || w.tgt.Name != target {
			return fmt.Errorf("target gNB %q unknown", target)
		}
		return nil
	})
	sc.Step(`^the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE$`, func() error { return nil })

	// ---- Whens
	sc.Step(`^the AMF handles the PATH SWITCH REQUEST$`, func() error {
		if hoW.active { // AMF-012: SMF-leg scenarios may hold the SMF answer
			return hoW.handlePathSwitch()
		}
		if err := w.runPathSwitch(); err != nil {
			return err
		}
		w.captureTarget()
		return nil
	})
	sc.Step(`^the AMF builds a HANDOVER REQUEST for the UE towards the target gNB$`, w.buildHandoverRequest)
	sc.Step(`^the AMF handles both messages$`, func() error {
		if hoW.active { // AMF-012: admitted PDU sessions / SMF fake
			return hoW.handleBoth()
		}
		w.srcLn.reset()
		w.tgtLn.reset()
		ctx := context.Background()
		w.srv.HandleHandoverRequiredForTest(ctx, w.src, &amfngap.HandoverRequiredMsg{
			AMFUENGAPId: w.amfID, RANUENGAPId: w.ranOld, TargetGlobalRANNodeID: w.tgt.GlobalGNBID,
			SourceToTargetTransparentContainer: []byte{9},
		})
		w.srv.HandleHandoverRequestAcknowledgeForTest(ctx, w.tgt, &amfngap.HandoverRequestAckMsg{
			AMFUENGAPId: w.amfID, RANUENGAPId: 8, TargetToSourceTransparentContainer: []byte{7},
		})
		return nil
	})

	// ---- Thens: message kind
	sc.Step(`^the AMF sends a PATH SWITCH REQUEST ACKNOWLEDGE to the target gNB$`, func() error {
		if len(w.tgtLn.pdus()) == 0 {
			return fmt.Errorf("nothing written to the target gNB")
		}
		return w.needAck()
	})
	sc.Step(`^the AMF sends a PATH SWITCH REQUEST FAILURE to the target gNB$`, func() error {
		if n := len(w.tgtLn.pdus()); n != 1 {
			return fmt.Errorf("target gNB received %d PDUs, want exactly 1 failure", n)
		}
		if err := w.needFail(); err != nil {
			return err
		}
		var order []int64
		for _, ie := range w.ies {
			order = append(order, ie.id)
		}
		if fmt.Sprint(order) != "[10 85 69]" {
			return fmt.Errorf("failure IE order = %v, want [10 85 69]", order)
		}
		return nil
	})
	sc.Step(`^the message is a successfulOutcome of procedure code (\d+)$`, func(code int) error {
		if w.decErr != nil {
			return w.decErr
		}
		if w.pdu == nil || w.pdu.SuccessfulOutcome == nil || w.pdu.SuccessfulOutcome.ProcedureCode.Value != int64(code) {
			return fmt.Errorf("not a successfulOutcome of procedure code %d", code)
		}
		return nil
	})
	sc.Step(`^the message is an unsuccessfulOutcome of procedure code (\d+)$`, func(code int) error {
		if w.decErr != nil {
			return w.decErr
		}
		if w.pdu == nil || w.pdu.UnsuccessfulOutcome == nil || w.pdu.UnsuccessfulOutcome.ProcedureCode.Value != int64(code) {
			return fmt.Errorf("not an unsuccessfulOutcome of procedure code %d", code)
		}
		return nil
	})

	// ---- Thens: Ack content
	sc.Step(`^the AMF UE NGAP ID is (\d+) and the RAN UE NGAP ID is (\d+)$`, func(amfID, ranID int) error {
		if err := w.needAck(); err != nil {
			return err
		}
		l := w.ack.ProtocolIEs.List
		if len(l) < 2 || l[0].Value.AMFUENGAPID == nil || l[1].Value.RANUENGAPID == nil {
			return fmt.Errorf("first two IEs are not AMF/RAN UE NGAP ID")
		}
		if l[0].Value.AMFUENGAPID.Value != int64(amfID) || l[1].Value.RANUENGAPID.Value != int64(ranID) {
			return fmt.Errorf("ids = %d/%d, want %d/%d", l[0].Value.AMFUENGAPID.Value, l[1].Value.RANUENGAPID.Value, amfID, ranID)
		}
		return nil
	})
	sc.Step(`^the PDUSessionResourceSwitchedList contains 1 item for PDU session id (\d+)$`, func(psi int) error {
		return w.switchedIs([]int64{int64(psi)})
	})
	sc.Step(`^the PDUSessionResourceSwitchedList contains only PDU session id (\d+)$`, func(psi int) error {
		return w.switchedIs([]int64{int64(psi)})
	})
	sc.Step(`^the AllowedNSSAI contains SST (\d+) SD "([0-9a-fA-F]{6})"$`, func(sst int, sd string) error {
		got, err := w.allowedNSSAI()
		if err != nil {
			return err
		}
		want := [2]string{strconv.Itoa(sst), xnSD(sd)}
		for _, g := range got {
			if g == want {
				return nil
			}
		}
		return fmt.Errorf("AllowedNSSAI %v lacks %v", got, want)
	})
	sc.Step(`^the AllowedNSSAI contains exactly SST (\d+) SD "([0-9a-fA-F]{6})" and SST (\d+) SD "([0-9a-fA-F]{6})"$`,
		func(s1 int, d1 string, s2 int, d2 string) error {
			return w.allowedIs([][2]string{{strconv.Itoa(s1), xnSD(d1)}, {strconv.Itoa(s2), xnSD(d2)}})
		})
	sc.Step(`^the AllowedNSSAI contains exactly SST (\d+) SD "([0-9a-fA-F]{6})"$`, func(s1 int, d1 string) error {
		return w.allowedIs([][2]string{{strconv.Itoa(s1), xnSD(d1)}})
	})
	sc.Step(`^the Security Context NH is (\d+) bits long$`, func(bits int) error {
		if w.scBits != uint64(bits) {
			return fmt.Errorf("NH is %d bits, want %d", w.scBits, bits)
		}
		return nil
	})
	sc.Step(`^the Security Context Next Hop Chaining Count is (\d+)$`, func(ncc int) error {
		if w.decErr != nil {
			return w.decErr
		}
		if w.scNCC != int64(ncc) {
			return fmt.Errorf("NCC = %d, want %d", w.scNCC, ncc)
		}
		return nil
	})
	sc.Step(`^the Security Context NH equals (KNH\(.+\))$`, func(expr string) error {
		if w.decErr != nil {
			return w.decErr
		}
		var want []byte
		if strings.Contains(expr, "previous NH") {
			want = kdf.KNH(w.kamf, w.prevNH[:])
		} else {
			want = xnNHn(w.kamf, w.kgnb[:], strings.Count(expr, "KNH("))
		}
		if !bytes.Equal(w.scNH, want) {
			return fmt.Errorf("NH does not equal %s", expr)
		}
		return nil
	})
	sc.Step(`^the AMF logs the new "ncc" but never the NH value$`, func() error {
		nh, kg := xnHex(xnNHn(w.kamf, w.kgnb[:], 2)), xnHex(w.kgnb[:])
		w.logs.mu.Lock()
		defer w.logs.mu.Unlock()
		sawNCC := false
		for _, r := range w.logs.recs {
			for k, v := range r.attrs {
				lv := strings.ToLower(v)
				if strings.Contains(lv, nh) || strings.Contains(lv, kg) {
					return fmt.Errorf("key material in log attr %q of %q", k, r.msg)
				}
				if k == "ncc" {
					sawNCC = true
				}
			}
		}
		if !sawNCC {
			return fmt.Errorf("no log record carries the ncc attribute")
		}
		return nil
	})
	sc.Step(`^a new KgNB is established by an Initial Context Setup$`, func() error {
		for i := range w.kgnb {
			w.kgnb[i] = byte(0x30 + i)
		}
		w.ue.SetKgNB(w.kgnb)
		return nil
	})
	sc.Step(`^the stored NCC is (\d+)$`, func(ncc int) error {
		_, got, ok := w.ue.NHState()
		if !ok || int(got) != ncc {
			return fmt.Errorf("stored NCC = %d (valid=%v), want %d", got, ok, ncc)
		}
		return nil
	})
	sc.Step(`^the stored NH equals KNH\(KAMF, new KgNB\)$`, func() error {
		nh, _, _ := w.ue.NHState()
		if !bytes.Equal(nh[:], kdf.KNH(w.kamf, w.kgnb[:])) {
			return fmt.Errorf("stored NH != KNH(KAMF, new KgNB)")
		}
		return nil
	})

	// ---- Thens: no source release / rebind
	sc.Step(`^no NGAP message is written to the source gNB connection$`, func() error {
		if n := len(w.srcLn.pdus()); n != 0 {
			return fmt.Errorf("source gNB received %d PDUs, want 0", n)
		}
		return nil
	})
	sc.Step(`^no UE CONTEXT RELEASE COMMAND \(procedure code 41\) is written to any gNB connection$`, func() error {
		for _, l := range w.allLinks() {
			for _, p := range l.pdus() {
				pdu, err := libngap.Decoder(p.raw)
				if err != nil {
					return err
				}
				if pdu.InitiatingMessage != nil && pdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeUEContextRelease {
					return fmt.Errorf("UE CONTEXT RELEASE COMMAND was written")
				}
			}
		}
		return nil
	})
	sc.Step(`^the UE is not flagged for removal$`, func() error {
		if w.ue.PendingRemoval {
			return fmt.Errorf("UE flagged PendingRemoval")
		}
		return nil
	})
	sc.Step(`^the UE RAN UE NGAP ID is (\d+) and its serving gNB is "([^"]+)"$`, func(ranID int, name string) error {
		if w.ue.RANUENGAPId != int64(ranID) {
			return fmt.Errorf("UE RAN UE NGAP ID = %d, want %d", w.ue.RANUENGAPId, ranID)
		}
		if name != w.tgt.Name || w.ue.GNBAddr != w.tgtAddr {
			return fmt.Errorf("UE GNBAddr = %q, want %q (%s)", w.ue.GNBAddr, w.tgtAddr, name)
		}
		return nil
	})
	sc.Step(`^the target gNB maps RAN UE NGAP ID (\d+) to the UE$`, func(ranID int) error {
		if w.tgt.UEs[int64(ranID)] != w.ue {
			return fmt.Errorf("target gNB does not map RAN UE NGAP ID %d to the UE", ranID)
		}
		return nil
	})
	sc.Step(`^the source gNB no longer maps RAN UE NGAP ID (\d+)$`, func(ranID int) error {
		if _, ok := w.src.UEs[int64(ranID)]; ok {
			return fmt.Errorf("source gNB still maps RAN UE NGAP ID %d", ranID)
		}
		return nil
	})
	sc.Step(`^the UE stays in CM-CONNECTED$`, func() error {
		if w.ue.CMState != amfctx.CMConnected {
			return fmt.Errorf("CM state = %v, want CM-CONNECTED", w.ue.CMState)
		}
		return nil
	})
	sc.Step(`^the AMF UE NGAP ID is still (\d+)$`, func(id int) error {
		if w.ue.AMFUENGAPId != int64(id) {
			return fmt.Errorf("AMF UE NGAP ID = %d, want %d", w.ue.AMFUENGAPId, id)
		}
		return nil
	})

	// ---- Thens: PPID
	sc.Step(`^every NGAP PDU written by the AMF carries SCTP PPID 60$`, func() error {
		total := 0
		for _, l := range w.allLinks() {
			for _, p := range l.pdus() {
				total++
				if p.ppid != 60 {
					return fmt.Errorf("PDU written with PPID %d, want 60", p.ppid)
				}
			}
		}
		if total == 0 {
			return fmt.Errorf("the AMF wrote no NGAP PDU")
		}
		return nil
	})
	sc.Step(`^the HANDOVER REQUEST written to the target gNB carries SCTP PPID 60$`, func() error {
		return xnProcPPID(w.tgtLn, true, ngapType.ProcedureCodeHandoverResourceAllocation)
	})
	sc.Step(`^the HANDOVER COMMAND written to the source gNB carries SCTP PPID 60$`, func() error {
		return xnProcPPID(w.srcLn, false, ngapType.ProcedureCodeHandoverPreparation)
	})

	// ---- Thens: fallback / logs
	sc.Step(`^the fallback is logged with level WARN and allowed_nssai_fallback "([^"]+)"$`, func(val string) error {
		r, ok := w.logs.find("Allowed NSSAI empty")
		if !ok {
			return fmt.Errorf("no fallback log record")
		}
		if r.level != slog.LevelWarn || r.attrs["allowed_nssai_fallback"] != val {
			return fmt.Errorf("fallback log level=%v allowed_nssai_fallback=%q", r.level, r.attrs["allowed_nssai_fallback"])
		}
		return nil
	})
	sc.Step(`^the failure is logged with result "([^"]+)"$`, func(result string) error { return xnFailureLogged(result, "") })
	sc.Step(`^the failure is logged with level ERROR$`, func() error {
		r, ok := w.logs.find("PathSwitchRequestFailure")
		if !ok || r.level != slog.LevelError {
			return fmt.Errorf("failure log missing or level %v, want ERROR", r.level)
		}
		return nil
	})
	sc.Step(`^the mismatch is logged with level WARN$`, func() error {
		r, ok := w.logs.find("differ from stored")
		if !ok || r.level != slog.LevelWarn {
			return fmt.Errorf("capability mismatch log missing or level %v, want WARN", r.level)
		}
		return nil
	})

	// ---- Thens: Failure content
	sc.Step(`^the failure echoes AMF UE NGAP ID (\d+) and RAN UE NGAP ID (\d+)$`, func(amfID, ranID int) error {
		if err := w.needFail(); err != nil {
			return err
		}
		if w.failAMF != int64(amfID) || w.failRAN != int64(ranID) {
			return fmt.Errorf("failure ids = %d/%d, want %d/%d", w.failAMF, w.failRAN, amfID, ranID)
		}
		return nil
	})
	sc.Step(`^the PDUSessionResourceReleasedListPSFail \(id 69\) contains PDU session id (\d+) with (misc|radioNetwork) cause "([^"]+)"$`,
		func(psi int, kind, name string) error {
			if err := w.needFail(); err != nil {
				return err
			}
			c, ok := w.fail[int64(psi)]
			if !ok {
				return fmt.Errorf("PDU session id %d missing from the Released List PSFail", psi)
			}
			return xnCauseMatches(c, kind, name)
		})
	sc.Step(`^no PATH SWITCH REQUEST ACKNOWLEDGE is sent$`, func() error { return w.noAck(false) })
	sc.Step(`^no PATH SWITCH REQUEST ACKNOWLEDGE with a zero NH is sent$`, func() error { return w.noAck(true) })
	sc.Step(`^the UE is not re-bound to the target gNB$`, func() error {
		if w.ue.RANUENGAPId != w.ranOld || w.ue.GNBAddr != w.srcAddr {
			return fmt.Errorf("UE re-bound: ran=%d addr=%s", w.ue.RANUENGAPId, w.ue.GNBAddr)
		}
		if w.req != nil && w.tgt.UEs[w.req.RANUENGAPId] != nil {
			return fmt.Errorf("target gNB maps the new RAN UE NGAP ID")
		}
		if w.src.UEs[w.ranOld] != w.ue {
			return fmt.Errorf("source gNB lost the UE")
		}
		return nil
	})

	// ---- Thens: partial success / UE security capabilities
	sc.Step(`^the PDUSessionResourceReleasedListPSAck contains PDU session id (\d+) with radioNetwork cause "([^"]+)"$`,
		func(psi int, name string) error {
			if err := w.needAck(); err != nil {
				return err
			}
			for _, ie := range w.ack.ProtocolIEs.List {
				l := ie.Value.PDUSessionResourceReleasedListPSAck
				if l == nil {
					continue
				}
				for _, it := range l.List {
					if it.PDUSessionID.Value != int64(psi) {
						continue
					}
					var tr ngapType.PathSwitchRequestUnsuccessfulTransfer
					if err := aper.UnmarshalWithParams(it.PathSwitchRequestUnsuccessfulTransfer, &tr, "valueExt"); err != nil {
						return err
					}
					return xnCauseMatches(tr.Cause, "radioNetwork", name)
				}
			}
			return fmt.Errorf("PDU session id %d missing from Released List PSAck", psi)
		})
	sc.Step(`^the UESecurityCapabilities equal the capabilities stored in the AMF$`, func() error {
		if err := w.needAck(); err != nil {
			return err
		}
		for _, ie := range w.ack.ProtocolIEs.List {
			c := ie.Value.UESecurityCapabilities
			if c == nil {
				continue
			}
			bm := func(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
			enc, integ := bm(c.NRencryptionAlgorithms.Value.Bytes), bm(c.NRintegrityProtectionAlgorithms.Value.Bytes)
			if enc != 0xC000 || integ != 0xC000 {
				return fmt.Errorf("echoed capabilities enc=%#x int=%#x, stored 0xc000/0xc000", enc, integ)
			}
			return nil
		}
		return fmt.Errorf("UESecurityCapabilities IE missing")
	})

	// ---- N2 HO UE-AMBR givens not covered by the ICS steps are delegated (see initICSSteps).

	// ---- E2E (live PacketRusher) — never a false pass
	for _, pat := range []string{
		`^the live stack is up with RAN "([^"]+)" and PR_SCENARIO "([^"]+)"$`,
	} {
		sc.Step(pat, func(_, _ string) error { return xnE2EPending() })
	}
	sc.Step(`^"make handover-test" is run$`, func() error { return xnE2EPending() })
	sc.Step(`^the PacketRusher Xn scenario completes the Path Switch$`, func() error { return xnE2EPending() })
	sc.Step(`^the target gNB logs no NGAP decode error and no "([^"]+)"$`, func(string) error { return xnE2EPending() })
	sc.Step(`^the AMF logs no UE CONTEXT RELEASE COMMAND to the source gNB for the UE$`, func() error { return xnE2EPending() })
	sc.Step(`^the "([^"]+)" procedure summary reports zero failures$`, func(string) error { return xnE2EPending() })
}

// xnE2EPending: the live PacketRusher run is not automated from godog; the scenario is
// pending (not passed) whether or not E2E_TEST=1. Run `make handover-test` and check
// the AMF logs per docs/validation-commands.md.
func xnE2EPending() error {
	_ = os.Getenv("E2E_TEST")
	return godog.ErrPending
}

func (w *xnWorld) switchedIs(want []int64) error {
	if err := w.needAck(); err != nil {
		return err
	}
	for _, ie := range w.ack.ProtocolIEs.List {
		if l := ie.Value.PDUSessionResourceSwitchedList; l != nil {
			var got []int64
			for _, it := range l.List {
				got = append(got, it.PDUSessionID.Value)
			}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				return fmt.Errorf("switched list = %v, want %v", got, want)
			}
			return nil
		}
	}
	return fmt.Errorf("PDUSessionResourceSwitchedList missing")
}

func (w *xnWorld) allowedIs(want [][2]string) error {
	got, err := w.allowedNSSAI()
	if err != nil {
		return err
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		return fmt.Errorf("AllowedNSSAI = %v, want %v", got, want)
	}
	return nil
}

func (w *xnWorld) noAck(requireNonZero bool) error {
	for _, l := range w.allLinks() {
		for _, p := range l.pdus() {
			pdu, err := libngap.Decoder(p.raw)
			if err != nil {
				return err
			}
			so := pdu.SuccessfulOutcome
			if so == nil || so.Value.PathSwitchRequestAcknowledge == nil {
				continue
			}
			if !requireNonZero {
				return fmt.Errorf("a PATH SWITCH REQUEST ACKNOWLEDGE was sent")
			}
			for _, ie := range so.Value.PathSwitchRequestAcknowledge.ProtocolIEs.List {
				if sc := ie.Value.SecurityContext; sc != nil && bytes.Equal(sc.NextHopNH.Value.Bytes, make([]byte, 32)) {
					return fmt.Errorf("an Ack with a zero NH was sent")
				}
			}
			return fmt.Errorf("an Ack was sent although the UE has no usable security context")
		}
	}
	return nil
}

// xnProcPPID asserts the link carries a PDU of the given procedure code (initiating or
// successful outcome) and that it was written with PPID 60.
func xnProcPPID(l *xnLink, initiating bool, code int64) error {
	for _, p := range l.pdus() {
		pdu, err := libngap.Decoder(p.raw)
		if err != nil {
			return err
		}
		match := (initiating && pdu.InitiatingMessage != nil && pdu.InitiatingMessage.ProcedureCode.Value == code) ||
			(!initiating && pdu.SuccessfulOutcome != nil && pdu.SuccessfulOutcome.ProcedureCode.Value == code)
		if match {
			if p.ppid != 60 {
				return fmt.Errorf("procedure %d written with PPID %d, want 60", code, p.ppid)
			}
			return nil
		}
	}
	return fmt.Errorf("no PDU of procedure code %d written", code)
}
