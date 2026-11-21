//go:build functional

// ng_reset_steps_test.go -- in-process godog steps for ng_reset.feature (AMF-008, NG Reset
// initiated by the NG-RAN node, TS 38.413 §8.7.4.2.2, §9.2.6.11, §9.2.6.12).
//
// The real ngap.Server (the one of anW, backed by sbiW.mgr) receives APER-encoded NG RESET
// PDUs through DispatchNGAPForTest. Every gNB is a GNBContext with the fake SCTP transport
// seam, so the outbound PDUs and their PPID are captured and decoded (NG RESET ACKNOWLEDGE,
// ERROR INDICATION). The SMF is the shared httptest SMF of ntsrW, reached through the same
// ANRelease callback cmd/amf wires. Reused steps: Background of sbi_steps_test.go, SMF mock and
// CM / RM assertions of an_release_nw_steps_test.go, "exactly once" of network_triggered_sr.
package features_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cucumber/godog"
	"github.com/ishidawataru/sctp"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	amfngap "github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

// ngrWrite is one NGAP PDU written by the AMF to a gNB.
type ngrWrite struct {
	pdu  []byte
	ppid uint32
}

type ngrWorld struct {
	mu     sync.Mutex
	out    map[string][]ngrWrite // gNB name -> captured writes
	wired  map[string]bool       // gNB name -> transport installed
	ues    map[string]*amfctx.UEContext
	gnbOf  map[string]string // SUPI -> gNB name
	lastBy string            // gNB that sent the last NG RESET
	// last NG RESET sent (for "same list" assertions and the repeat step)
	lastItems []amfngap.ResetItem
	lastPDU   []byte
	extra     int // counter for ran ids / SMF refs of additional UEs
	// SMF deactivation attempts seen while the SMF is unreachable (smfUnreachable step).
	smfAttempts map[string]int // SUPI -> AN release callbacks run
	smfFailed   int            // SMF requests that failed to connect
	smfDownURL  string         // set once the SMF was shut down by the Given step
}

var ngrW = &ngrWorld{}

func (w *ngrWorld) reset() {
	w.out = map[string][]ngrWrite{}
	w.wired = map[string]bool{}
	w.ues = map[string]*amfctx.UEContext{}
	w.gnbOf = map[string]string{}
	w.lastBy, w.lastItems, w.lastPDU, w.extra = "", nil, nil, 0
	w.smfAttempts, w.smfFailed, w.smfDownURL = map[string]int{}, 0, ""
}

func (w *ngrWorld) writes(gnb string) []ngrWrite {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]ngrWrite(nil), w.out[gnb]...)
}

// srv is the AMF NGAP server under test (shared with the AN release world).
func (w *ngrWorld) srv() *amfngap.Server { return anW.srv }

// gnb returns the registry-step gNB of that name with the capturing transport installed.
func (w *ngrWorld) gnb(name string) (*amfngap.GNBContext, error) {
	g := gnbW.gnbs[name]
	if g == nil {
		return nil, fmt.Errorf("gNB %q is not NG_READY", name)
	}
	if !w.wired[name] {
		w.wired[name] = true
		g.SetTransportForTest("172.30.9."+fmt.Sprint(len(w.wired))+":48211",
			func(pdu []byte, info *sctp.SndRcvInfo) (int, error) {
				var ppid uint32
				if info != nil {
					ppid = info.PPID
				}
				cp := append([]byte(nil), pdu...)
				w.mu.Lock()
				w.out[name] = append(w.out[name], ngrWrite{pdu: cp, ppid: ppid})
				w.mu.Unlock()
				// Mirror everything except the NG RESET ACKNOWLEDGE into the AN release world
				// so its "no UE CONTEXT RELEASE COMMAND" step sees any other PDU.
				if _, isAck, _ := amfngap.DecodeNGResetAckForTest(cp); !isAck {
					anW.mu.Lock()
					anW.sent = append(anW.sent, anWrite{pdu: cp, ppid: ppid})
					anW.mu.Unlock()
				}
				return len(pdu), nil
			})
	}
	return g, nil
}

// attach binds a UE to a gNB: RM-REGISTERED, CM-CONNECTED, in gnb.UEs.
func (w *ngrWorld) attach(ue *amfctx.UEContext, gnbName string) error {
	g, err := w.gnb(gnbName)
	if err != nil {
		return err
	}
	ue.Lock()
	ue.State = amfctx.GMMRegistered
	ran := ue.RANUENGAPId
	ue.GNBAddr = "172.30.9.1:48211" // resolved through gnb.addr by the AMF; informational here
	supi := ue.SUPI
	ue.Unlock()
	ue.SetCMState(amfctx.CMConnected)
	g.UEs[ran] = ue // no concurrent access before the NG RESET is dispatched
	w.ues[supi] = ue
	w.gnbOf[supi] = gnbName
	return nil
}

func (w *ngrWorld) ueServedBy(gnbName string) error {
	if sbiW.ue == nil {
		return fmt.Errorf("no UE seeded")
	}
	return w.attach(sbiW.ue, gnbName)
}

func (w *ngrWorld) extraUE(supi, gnbName string) error {
	w.extra++
	ue := sbiW.mgr.AllocateUEContext(int64(10 + w.extra))
	sbiW.mgr.SetSUPI(ue, supi)
	ue.SecurityCtx = amfctx.SecurityContext{Active: true, IntegrityAlgID: 2, CipheringAlgID: 2}
	ref := fmt.Sprintf("smf-ctx-ref-%d", 100+w.extra)
	ue.PDUSessions[1] = &amfctx.PDUSession{PDUSessionID: 1, DNN: "internet", SMFInstanceID: ref,
		SNSSAI: amfctx.SNSSAISubscribed{SST: 1, SD: "000001"}}
	return w.attach(ue, gnbName)
}

func (w *ngrWorld) ue(supi string) (*amfctx.UEContext, error) {
	if sbiW.ue != nil && sbiW.ue.SUPI == supi {
		return sbiW.ue, nil
	}
	if ue, ok := w.ues[supi]; ok {
		return ue, nil
	}
	return nil, fmt.Errorf("UE %s unknown to the scenario", supi)
}

func (w *ngrWorld) ids(supi string) (amf, ran int64, err error) {
	ue, err := w.ue(supi)
	if err != nil {
		return 0, 0, err
	}
	ue.Lock()
	defer ue.Unlock()
	return ue.AMFUENGAPId, ue.RANUENGAPId, nil
}

func i64(v int64) *int64 { return &v }

// ---- When -----------------------------------------------------------------

// send encodes the NG RESET, dispatches it as the given gNB and waits for the UE serial queues.
func (w *ngrWorld) send(gnbName string, pdu []byte, items []amfngap.ResetItem) error {
	g, err := w.gnb(gnbName)
	if err != nil {
		return err
	}
	ntsrW.active = true
	if err := anW.smfMockRecords(); err != nil {
		return err
	}
	anW.wireSMFNotify()
	if w.smfDownURL != "" {
		w.wireDownSMF()
	}
	w.lastBy, w.lastItems, w.lastPDU = gnbName, items, pdu
	w.srv().DispatchNGAPForTest(context.Background(), g, pdu)
	// Drain every UE serial queue (the SMF leg runs there).
	all := []*amfctx.UEContext{sbiW.ue}
	for _, ue := range w.ues {
		all = append(all, ue)
	}
	for _, ue := range all {
		if ue == nil {
			continue
		}
		ue.Lock()
		id := ue.AMFUENGAPId
		ue.Unlock()
		if !w.srv().WaitUESerialForTest(id) {
			return fmt.Errorf("UE serial queue of %d did not drain", id)
		}
	}
	return nil
}

func (w *ngrWorld) sendParams(gnbName string, p amfngap.NGResetParams) error {
	pdu, err := amfngap.BuildNGResetForTest(p)
	if err != nil {
		return fmt.Errorf("build NG RESET: %w", err)
	}
	return w.send(gnbName, pdu, p.Items)
}

func (w *ngrWorld) resetAll(gnbName string) error {
	return w.sendParams(gnbName, amfngap.NGResetParams{ResetAll: true})
}

func (w *ngrWorld) resetAllNoCause(gnbName string) error {
	return w.sendParams(gnbName, amfngap.NGResetParams{ResetAll: true, OmitCause: true})
}

func (w *ngrWorld) fullItem(supi string) (amfngap.ResetItem, error) {
	a, r, err := w.ids(supi)
	if err != nil {
		return amfngap.ResetItem{}, err
	}
	return amfngap.ResetItem{AMF: i64(a), RAN: i64(r)}, nil
}

func (w *ngrWorld) resetListing(gnbName, supi string) error {
	it, err := w.fullItem(supi)
	if err != nil {
		return err
	}
	return w.sendParams(gnbName, amfngap.NGResetParams{Items: []amfngap.ResetItem{it}})
}

func (w *ngrWorld) resetListingFullAndRANOnly(gnbName, supi1, supi2 string) error {
	it, err := w.fullItem(supi1)
	if err != nil {
		return err
	}
	_, r2, err := w.ids(supi2)
	if err != nil {
		return err
	}
	return w.sendParams(gnbName, amfngap.NGResetParams{Items: []amfngap.ResetItem{it, {RAN: i64(r2)}}})
}

func (w *ngrWorld) resetListingFullThenUnknown(gnbName, supi string, amf, ran int64) error {
	it, err := w.fullItem(supi)
	if err != nil {
		return err
	}
	return w.sendParams(gnbName, amfngap.NGResetParams{Items: []amfngap.ResetItem{
		it, {AMF: i64(amf)}, {RAN: i64(ran)}}})
}

func (w *ngrWorld) resetListingOnlyUnknownAMF(gnbName string, amf int64) error {
	return w.sendParams(gnbName, amfngap.NGResetParams{Items: []amfngap.ResetItem{{AMF: i64(amf)}}})
}

func (w *ngrWorld) resetListingOnlyAMFOf(gnbName, supi string) error {
	a, _, err := w.ids(supi)
	if err != nil {
		return err
	}
	return w.sendParams(gnbName, amfngap.NGResetParams{Items: []amfngap.ResetItem{{AMF: i64(a)}}})
}

func (w *ngrWorld) resetListingNeither(gnbName string) error {
	return w.sendParams(gnbName, amfngap.NGResetParams{Items: []amfngap.ResetItem{{}}})
}

func (w *ngrWorld) resetWithoutResetType(gnbName string) error {
	return w.sendParams(gnbName, amfngap.NGResetParams{OmitResetType: true})
}

// resetEmptyList sends partOfNG-Interface whose UE-associated Logical NG-connection List has no
// item. APER cannot represent SIZE(1..65536) = 0 (the length determinant carries n-1), so the
// PDU is the hand-built partOfNG-Interface choice cut right after the list length: the AMF
// decoder must reject it (TS 38.413 §10.2).
func (w *ngrWorld) resetEmptyList(gnbName string) error {
	// preamble+count(1) | IE 88, criticality reject, length 2 | partOfNG-Interface, list header
	pdu := []byte{0x00, 0x14, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x58, 0x00, 0x02, 0x40, 0x01}
	return w.send(gnbName, pdu, nil)
}

// resetUnknownChoice sends Reset Type as the choice-Extensions alternative, which this AMF
// does not comprehend (TS 38.413 §9.3.1 ResetType).
func (w *ngrWorld) resetUnknownChoice(gnbName string) error {
	// The generated codec cannot encode an open-type container with no known IE, so the
	// PDU is hand-built: IE 88 (reject) whose CHOICE index 2 (choice-Extensions) carries a
	// ProtocolIE-SingleContainer {id 1, criticality ignore, empty open type}.
	pdu := []byte{0x00, 0x14, 0x00, 0x0c, 0x00, 0x00, 0x01,
		0x00, 0x58, 0x00, 0x05, 0x80, 0x00, 0x01, 0x40, 0x00}
	return w.send(gnbName, pdu, nil)
}

func (w *ngrWorld) resetAgain() error {
	if w.lastPDU == nil {
		return fmt.Errorf("no NG RESET was sent before")
	}
	return w.send(w.lastBy, w.lastPDU, w.lastItems)
}

// ---- Given ----------------------------------------------------------------

func (w *ngrWorld) smfUnreachable() error {
	if smrW.active { // smf_restart_release.feature owns its own SMF mock
		return smrW.smfDown()
	}
	if ntsrW.smf == nil {
		return fmt.Errorf("SMF mock not running")
	}
	w.smfDownURL = ntsrW.smf.URL
	ntsrW.smf.Close()
	w.wireDownSMF()
	return nil
}

// wireDownSMF installs the AN release callback used while the SMF is down. send() re-wires
// the regular callback before every NG RESET, so it re-applies this one afterwards.
func (w *ngrWorld) wireDownSMF() {
	smfURL := w.smfDownURL
	// Same wire contract as wireSMFNotify (one DEACTIVATED request per PDU session), but it
	// records the attempt and its connection failure so the scenario is not vacuous.
	w.srv().SetANReleaseHandler(func(ctx context.Context, ue *amfctx.UEContext) {
		ue.Lock()
		supi := ue.SUPI
		var refs []string
		for _, ps := range ue.PDUSessions {
			if ps.SMFInstanceID != "" {
				refs = append(refs, ps.SMFInstanceID)
			}
		}
		ue.Unlock()
		w.mu.Lock()
		w.smfAttempts[supi]++
		w.mu.Unlock()
		for _, ref := range refs {
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
				smfURL+"/nsmf-pdusession/v1/sm-contexts/"+ref+"/modify", strings.NewReader(`{"upCnxState":"DEACTIVATED"}`))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				w.mu.Lock()
				w.smfFailed++
				w.mu.Unlock()
				continue
			}
			resp.Body.Close()
		}
	})
}

// smfDeactivationAttemptedAndIdle asserts the AMF tried the SMF deactivation of the UE (it
// failed: the SMF is down) and that the UE is nevertheless CM-IDLE (TS 23.502 §4.2.6 step 5).
func (w *ngrWorld) smfDeactivationAttemptedAndIdle(supi string) error {
	deadline := time.Now().Add(3 * time.Second)
	for {
		w.mu.Lock()
		attempts, failed := w.smfAttempts[supi], w.smfFailed
		w.mu.Unlock()
		if attempts > 0 && failed > 0 {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("SMF deactivation of %s: %d attempts, %d failed requests, want both > 0", supi, attempts, failed)
		}
		time.Sleep(5 * time.Millisecond)
	}
	ue, err := w.ue(supi)
	if err != nil {
		return err
	}
	if cm := w.cmOf(ue); cm != amfctx.CMIdle {
		return fmt.Errorf("UE %s CM state = %s after the failed SMF leg, want CM-IDLE", supi, cm)
	}
	return nil
}

func (w *ngrWorld) cmOf(ue *amfctx.UEContext) amfctx.CMState {
	ue.Lock()
	defer ue.Unlock()
	return ue.CMState
}

// ---- Then -----------------------------------------------------------------

// acks returns every decoded NG RESET ACKNOWLEDGE written to the gNB, asserting PPID 60.
func (w *ngrWorld) acks(gnbName string) ([]amfngap.NGResetAckView, error) {
	var out []amfngap.NGResetAckView
	for i, wr := range w.writes(gnbName) {
		v, ok, err := amfngap.DecodeNGResetAckForTest(wr.pdu)
		if err != nil {
			return nil, fmt.Errorf("decode PDU %d: %w", i, err)
		}
		if ok {
			if wr.ppid != 60 {
				return nil, fmt.Errorf("NG RESET ACKNOWLEDGE sent with SCTP PPID %d, want 60 (TS 38.412 §7)", wr.ppid)
			}
			out = append(out, v)
		}
	}
	return out, nil
}

func (w *ngrWorld) theAck() (amfngap.NGResetAckView, error) {
	if w.lastBy == "" {
		return amfngap.NGResetAckView{}, fmt.Errorf("no NG RESET was sent")
	}
	acks, err := w.acks(w.lastBy)
	if err != nil {
		return amfngap.NGResetAckView{}, err
	}
	if len(acks) == 0 {
		return amfngap.NGResetAckView{}, fmt.Errorf("no NG RESET ACKNOWLEDGE written to gNB %q (writes: %d)",
			w.lastBy, len(w.writes(w.lastBy)))
	}
	// A retry yields one ACK per NG RESET; the latest one answers the latest request.
	return acks[len(acks)-1], nil
}

func (w *ngrWorld) ackSent(code int) error {
	v, err := w.theAck()
	if err != nil {
		return err
	}
	if v.ProcedureCode != int64(code) || code != int(ngapType.ProcedureCodeNGReset) {
		return fmt.Errorf("ACK procedure code = %d, want %d (NG Reset = %d)", v.ProcedureCode, code,
			ngapType.ProcedureCodeNGReset)
	}
	return nil
}

func (w *ngrWorld) ackPPID() error {
	_, err := w.theAck() // asserts PPID 60 on every ACK
	return err
}

func (w *ngrWorld) ackNoList() error {
	v, err := w.theAck()
	if err != nil {
		return err
	}
	if v.HasList || len(v.Items) != 0 {
		return fmt.Errorf("ACK carries a UE-associated Logical NG-connection List (%d items), want none", len(v.Items))
	}
	return nil
}

func (w *ngrWorld) ackEchoes(n int) error {
	v, err := w.theAck()
	if err != nil {
		return err
	}
	if !v.HasList {
		return fmt.Errorf("ACK carries no UE-associated Logical NG-connection List, want %d items", n)
	}
	if len(w.lastItems) != n {
		return fmt.Errorf("scenario sent %d list items, step expects %d", len(w.lastItems), n)
	}
	if len(v.Items) != n {
		return fmt.Errorf("ACK has %d list items, want %d", len(v.Items), n)
	}
	for i, want := range w.lastItems {
		got := v.Items[i]
		if !sameID(want.AMF, got.AMF) || !sameID(want.RAN, got.RAN) {
			return fmt.Errorf("ACK item %d = %s, want %s (same order, same ID presence)", i, fmtItem(got), fmtItem(want))
		}
	}
	return nil
}

func sameID(a, b *int64) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return a == nil || *a == *b
}

func fmtItem(it amfngap.ResetItem) string {
	s := "{"
	if it.AMF != nil {
		s += fmt.Sprintf("AMF=%d", *it.AMF)
	} else {
		s += "AMF=absent"
	}
	if it.RAN != nil {
		s += fmt.Sprintf(" RAN=%d", *it.RAN)
	} else {
		s += " RAN=absent"
	}
	return s + "}"
}

func (w *ngrWorld) noAck() error {
	time.Sleep(50 * time.Millisecond) // late writers get a short chance; asserts absence
	for name := range w.out {
		acks, err := w.acks(name)
		if err != nil {
			return err
		}
		if len(acks) != 0 {
			return fmt.Errorf("gNB %q received %d NG RESET ACKNOWLEDGE, want none", name, len(acks))
		}
	}
	return nil
}

func (w *ngrWorld) eis(gnbName string) ([]amfngap.ErrorIndicationView, error) {
	var out []amfngap.ErrorIndicationView
	for _, wr := range w.writes(gnbName) {
		v, ok, err := amfngap.DecodeOutboundErrorIndicationForTest(wr.pdu)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, v)
		}
	}
	return out, nil
}

func (w *ngrWorld) noEI() error {
	time.Sleep(50 * time.Millisecond)
	for name := range w.out {
		evs, err := w.eis(name)
		if err != nil {
			return err
		}
		if len(evs) != 0 {
			return fmt.Errorf("gNB %q received %d ERROR INDICATION (cause group %d value %d), want none",
				name, len(evs), evs[0].CausePresent, evs[0].CauseValue)
		}
	}
	return nil
}

var ngrProtocolCauses = map[string]int64{
	"abstract-syntax-error-falsely-constructed-message": int64(ngapType.CauseProtocolPresentAbstractSyntaxErrorFalselyConstructedMessage),
	"abstract-syntax-error-reject":                      int64(ngapType.CauseProtocolPresentAbstractSyntaxErrorReject),
	"transfer-syntax-error":                             int64(ngapType.CauseProtocolPresentTransferSyntaxError),
}

func (w *ngrWorld) eiWithProtocolCause(gnbName, cause string) error {
	want, ok := ngrProtocolCauses[cause]
	if !ok {
		return fmt.Errorf("unknown protocol cause %q in the scenario", cause)
	}
	evs, err := w.eis(gnbName)
	if err != nil {
		return err
	}
	if len(evs) != 1 {
		return fmt.Errorf("gNB %q received %d ERROR INDICATION, want exactly 1", gnbName, len(evs))
	}
	if evs[0].CausePresent != ngapType.CausePresentProtocol || evs[0].CauseValue != want {
		return fmt.Errorf("ERROR INDICATION cause = group %d value %d, want protocol %q (%d)",
			evs[0].CausePresent, evs[0].CauseValue, cause, want)
	}
	for _, wr := range w.writes(gnbName) {
		if wr.ppid != 60 {
			return fmt.Errorf("ERROR INDICATION sent with SCTP PPID %d, want 60", wr.ppid)
		}
	}
	return nil
}

func (w *ngrWorld) cmIdleWithin(supi string) error {
	ue, err := w.ue(supi)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		ue.Lock()
		cm := ue.CMState
		ue.Unlock()
		if cm == amfctx.CMIdle {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("UE %s CM state = %s, want CM-IDLE", supi, cm)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (w *ngrWorld) stillConnected(supi string) error {
	ue, err := w.ue(supi)
	if err != nil {
		return err
	}
	ue.Lock()
	defer ue.Unlock()
	if ue.CMState != amfctx.CMConnected {
		return fmt.Errorf("UE %s CM state = %s, want CM-CONNECTED", supi, ue.CMState)
	}
	return nil
}

func (w *ngrWorld) presentRegistered(supi string) error {
	ue, ok := sbiW.mgr.GetBySUPI(supi)
	if !ok {
		return fmt.Errorf("UE context for %s no longer present", supi)
	}
	ue.Lock()
	defer ue.Unlock()
	if ue.State != amfctx.GMMRegistered {
		return fmt.Errorf("UE %s 5GMM state = %v, want 5GMM-REGISTERED", supi, ue.State)
	}
	return nil
}

func (w *ngrWorld) contextRemoved() error {
	if _, ok := sbiW.mgr.GetBySUPI(sbiW.ue.SUPI); ok {
		return fmt.Errorf("UE context for %s still present", sbiW.ue.SUPI)
	}
	sbiW.ue.Lock()
	id := sbiW.ue.AMFUENGAPId
	sbiW.ue.Unlock()
	if _, ok := sbiW.mgr.GetByNGAPId(id); ok {
		return fmt.Errorf("UE context with AMF UE NGAP ID %d still present", id)
	}
	return nil
}

func (w *ngrWorld) gnbState(name, state string) error {
	// Delegates to the registry snapshot (same data as the gnb_registry step).
	for _, s := range w.srv().GNBSnapshots() {
		if s.RANNodeName == name {
			if string(s.State) != state {
				return fmt.Errorf("gNB %q state = %s, want %s", name, s.State, state)
			}
			return nil
		}
	}
	return fmt.Errorf("gNB %q not in the registry", name)
}

func (w *ngrWorld) recordedNoReset(name string) error {
	for _, s := range w.srv().GNBSnapshots() {
		if s.RANNodeName == name {
			if s.NGResetCount != 0 || s.LastNGResetAt != nil {
				return fmt.Errorf("gNB %q ng_reset_count = %d last=%v, want 0 and none", name, s.NGResetCount, s.LastNGResetAt)
			}
			return nil
		}
	}
	return fmt.Errorf("gNB %q not in the registry", name)
}

func (w *ngrWorld) noDeactivatedForUE(state, supi string) error {
	ue, err := w.ue(supi)
	if err != nil {
		return err
	}
	ue.Lock()
	var refs []string
	for _, s := range ue.PDUSessions {
		refs = append(refs, s.SMFInstanceID)
	}
	ue.Unlock()
	if len(refs) == 0 {
		return fmt.Errorf("UE %s has no PDU session; assertion would be vacuous", supi)
	}
	ntsrW.mu.Lock()
	defer ntsrW.mu.Unlock()
	for _, ref := range refs {
		for _, got := range ntsrW.requests[ref] {
			if got == state {
				return fmt.Errorf("SMF received upCnxState=%s for UE %s (%s)", state, supi, ref)
			}
		}
	}
	return nil
}

func initNGResetSteps(sc *godog.ScenarioContext) {
	w := ngrW
	sc.Before(func(ctx context.Context, s *godog.Scenario) (context.Context, error) {
		for _, t := range s.Tags {
			if t.Name == "@AMF-008" {
				w.reset()
				// The registry step of gnb_registry_steps_test.go builds its own server; the NG
				// Reset scenarios need the one that owns the UE store and the SMF callback.
				gnbW.srv = anW.srv
				break
			}
		}
		return ctx, nil
	})

	sc.Step(`^the UE is served by gNB "([^"]+)"$`, w.ueServedBy)
	sc.Step(`^a (?:second|third) UE "([^"]+)" is registered, CM-CONNECTED and served by gNB "([^"]+)"$`, w.extraUE)
	sc.Step(`^the SMF is not reachable$`, w.smfUnreachable)

	sc.Step(`^gNB "([^"]+)" sends an NG Reset with Reset Type nG-Interface reset-all$`, w.resetAll)
	sc.Step(`^gNB "([^"]+)" sends an NG Reset without the Cause IE with Reset Type nG-Interface reset-all$`, w.resetAllNoCause)
	sc.Step(`^gNB "([^"]+)" sends an NG Reset with Reset Type partOfNG-Interface listing the NGAP IDs of the UE "([^"]+)" and only the RAN UE NGAP ID of the UE "([^"]+)"$`, w.resetListingFullAndRANOnly)
	sc.Step(`^gNB "([^"]+)" sends an NG Reset with Reset Type partOfNG-Interface listing the NGAP IDs of the UE "([^"]+)" followed by an unknown AMF UE NGAP ID (\d+) and an unknown RAN UE NGAP ID (\d+)$`, w.resetListingFullThenUnknown)
	sc.Step(`^gNB "([^"]+)" sends an NG Reset with Reset Type partOfNG-Interface listing only the unknown AMF UE NGAP ID (\d+)$`, w.resetListingOnlyUnknownAMF)
	sc.Step(`^gNB "([^"]+)" sends an NG Reset with Reset Type partOfNG-Interface listing only the AMF UE NGAP ID of the UE "([^"]+)"$`, w.resetListingOnlyAMFOf)
	sc.Step(`^gNB "([^"]+)" (?:sends|sent) an NG Reset with Reset Type partOfNG-Interface listing the NGAP IDs of the UE "([^"]+)"$`, w.resetListing)
	sc.Step(`^gNB "([^"]+)" sends an NG Reset with Reset Type partOfNG-Interface listing one item with neither AMF UE NGAP ID nor RAN UE NGAP ID$`, w.resetListingNeither)
	sc.Step(`^gNB "([^"]+)" sends an NG Reset without the Reset Type IE$`, w.resetWithoutResetType)
	sc.Step(`^gNB "([^"]+)" sends an NG Reset with an unknown Reset Type choice extension$`, w.resetUnknownChoice)
	sc.Step(`^gNB "([^"]+)" sends an NG Reset with Reset Type partOfNG-Interface and an empty list$`, w.resetEmptyList)
	sc.Step(`^gNB "([^"]+)" sends the same NG Reset again$`, func(string) error { return w.resetAgain() })

	sc.Step(`^the AMF sends an NG RESET ACKNOWLEDGE with procedure code (\d+) as SuccessfulOutcome$`, w.ackSent)
	sc.Step(`^the NG RESET ACKNOWLEDGE is sent with SCTP PPID 60$`, w.ackPPID)
	sc.Step(`^the NG RESET ACKNOWLEDGE carries no UE-associated Logical NG-connection List$`, w.ackNoList)
	sc.Step(`^the NG RESET ACKNOWLEDGE carries the same (\d+) list items in the same order with the same ID presence as the NG RESET$`, w.ackEchoes)
	sc.Step(`^the AMF sends no NG RESET ACKNOWLEDGE$`, w.noAck)
	sc.Step(`^the AMF sends no ERROR INDICATION$`, w.noEI)
	sc.Step(`^the AMF sends an ERROR INDICATION to gNB "([^"]+)" with Cause protocol "([^"]+)"$`, w.eiWithProtocolCause)

	sc.Step(`^the UE "([^"]+)" becomes CM-IDLE within the test deadline$`, w.cmIdleWithin)
	sc.Step(`^the AMF attempted the SMF deactivation of the UE "([^"]+)" and the UE is still CM-IDLE$`, w.smfDeactivationAttemptedAndIdle)
	sc.Step(`^the UE "([^"]+)" is still CM-CONNECTED$`, w.stillConnected)
	sc.Step(`^the UE "([^"]+)" context is still present and RM-REGISTERED$`, w.presentRegistered)
	sc.Step(`^the UE context is removed$`, w.contextRemoved)
	sc.Step(`^the AMF sends no upCnxState "([^"]+)" request to the SMF for the UE "([^"]+)"$`, w.noDeactivatedForUE)
	sc.Step(`^gNB "([^"]+)" has recorded no NG Reset$`, w.recordedNoReset)

	_ = strings.TrimSpace
}
