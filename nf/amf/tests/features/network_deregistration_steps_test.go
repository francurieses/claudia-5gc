//go:build functional

// network_deregistration_steps_test.go -- in-process godog steps for
// network_deregistration.feature (AMF-037 slice A: UDM-triggered network-initiated
// de-registration; TS 23.502 §4.2.2.3.3, §4.11.1.5.3; TS 24.501 §5.5.2.3.1,
// §5.5.2.3.5; TS 29.503 §5.3.2.3).
//
// The real inbound SBI server (internal/sbi) serves the dereg-notify callback and
// is wired like cmd/amf: the real nasmsg.Handler.HandleUDMDeregistration first,
// and for every reason it does not handle a mirror of the cmd/amf legacy local
// removal closure (that closure lives in package main and cannot be imported).
// The N1/N2 side is the real *ngap.Server (sender of the NAS handler) in front of
// the fake SCTP gNB of an_release_nw_steps_test.go (anW), so the DL NAS PDUs, the
// UE CONTEXT RELEASE COMMAND and their SCTP PPID are the production bytes. The
// shared world steps are reused: Background UE (sbiW), SMF httptest mock (ntsrW),
// serving gNB (anW), CM state, response status, SM release.
// UDM and PCF are in-process doubles of the procedures client interfaces that
// count calls. T3522 runs on a virtual clock injected with SetTimerSchedulerForTest.
package features_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/cucumber/godog"
	"github.com/free5gc/aper"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	nasmsg "github.com/francurieses/claudia-5gc/nf/amf/internal/nas"
	amfngap "github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	amfsbi "github.com/francurieses/claudia-5gc/nf/amf/internal/sbi"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nea"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nia"
	"github.com/francurieses/claudia-5gc/shared/nas"
	libngap "github.com/francurieses/claudia-5gc/shared/ngap"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

const ndWait = 3 * time.Second

// ---- doubles ----------------------------------------------------------------

// ndUDM counts Nudm_SDM unsubscribes and Nudm_UECM deletes.
type ndUDM struct {
	mu    sync.Mutex
	unsub []string
	uecm  int
}

func (u *ndUDM) RegisterAMF(context.Context, string, string, string) error { return nil }
func (u *ndUDM) GetAMSubscriptionData(context.Context, string) (*procedures.UDMAMSubscription, error) {
	return &procedures.UDMAMSubscription{}, nil
}
func (u *ndUDM) DeregisterUECM(context.Context, string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.uecm++
	return nil
}
func (u *ndUDM) SubscribeAMData(context.Context, string) (string, error) { return "sdm-1", nil }
func (u *ndUDM) UnsubscribeSDM(_ context.Context, _, id string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.unsub = append(u.unsub, id)
	return nil
}

// ndPCF counts AM policy and UE policy association deletes.
type ndPCF struct {
	mu         sync.Mutex
	am, uePols []string
}

func (p *ndPCF) CreateUEPolicyAssociation(context.Context, string, string) (string, []byte, error) {
	return "", nil, nil
}
func (p *ndPCF) DeleteUEPolicyAssociation(_ context.Context, id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.uePols = append(p.uePols, id)
	return nil
}
func (p *ndPCF) CreateAMPolicyAssociation(context.Context, string, string, string, string) (string, int, *amfctx.ServiceAreaRestriction, error) {
	return "", 0, nil, nil
}
func (p *ndPCF) DeleteAMPolicyAssociation(_ context.Context, id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.am = append(p.am, id)
	return nil
}

// ndSender is the NAS handler sender: the real NGAP server plus the SMF release
// over HTTP (cmd/amf HTTPSMFClient.DeleteSMContext contract, via ntsrSender). It
// counts DL NAS send attempts, successful or not.
type ndSender struct {
	*amfngap.Server
	mu       sync.Mutex
	attempts int
}

func (s *ndSender) SendDownlinkNASTransport(ue *amfctx.UEContext, pdu []byte) error {
	s.mu.Lock()
	s.attempts++
	s.mu.Unlock()
	return s.Server.SendDownlinkNASTransport(ue, pdu)
}

func (s *ndSender) DeleteSMContext(ctx context.Context, ref string) error {
	return (&ntsrSender{w: ntsrW}).DeleteSMContext(ctx, ref)
}

// ndClock is a virtual clock for the supervision timers (T3522 / guard).
type ndClock struct {
	mu     sync.Mutex
	now    time.Duration
	timers []*ndTimer
}

type ndTimer struct {
	due     time.Duration
	f       func()
	stopped bool
	fired   bool
	c       *ndClock
}

func (t *ndTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	was := !t.stopped && !t.fired
	t.stopped = true
	return was
}

func (c *ndClock) after(d time.Duration, f func()) amfctx.TimerStopper {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &ndTimer{due: c.now + d, f: f, c: c}
	c.timers = append(c.timers, t)
	return t
}

// next returns the earliest live timer due at or before limit.
func (c *ndClock) next(limit time.Duration) *ndTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	var best *ndTimer
	for _, t := range c.timers {
		if t.stopped || t.fired || t.due > limit {
			continue
		}
		if best == nil || t.due < best.due {
			best = t
		}
	}
	if best != nil {
		best.fired = true
		if best.due > c.now {
			c.now = best.due
		}
	}
	return best
}

// advance moves virtual time by d, firing due timers and waiting for the expiry
// work they enqueue on the UE's serial queue.
func (c *ndClock) advance(d time.Duration, ue *amfctx.UEContext) error {
	c.mu.Lock()
	limit := c.now + d
	c.mu.Unlock()
	for {
		t := c.next(limit)
		if t == nil {
			break
		}
		t.f()
		if err := ndBarrier(ue); err != nil {
			return err
		}
	}
	c.mu.Lock()
	c.now = limit
	c.mu.Unlock()
	return nil
}

// liveDurations returns the remaining time of every live timer.
func (c *ndClock) live() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []time.Duration
	for _, t := range c.timers {
		if !t.stopped && !t.fired {
			out = append(out, t.due-c.now)
		}
	}
	return out
}

func ndBarrier(ue *amfctx.UEContext) error {
	done := make(chan struct{})
	ue.EnqueueSerial(func() { close(done) })
	select {
	case <-done:
		return nil
	case <-time.After(ndWait):
		return fmt.Errorf("UE serial queue did not drain within %s", ndWait)
	}
}

// ---- world --------------------------------------------------------------------

type ndWorld struct {
	udm   *ndUDM
	pcf   *ndPCF
	clk   *ndClock
	logs  *tcLockedBuf
	spec  bool
	n2Off bool

	h      *nasmsg.Handler
	sender *ndSender
	ts     *httptest.Server
	ready  bool

	tmsi uint32
	dl   [][]byte // DL NAS PDUs captured from the gNB, in order
}

var ndW = &ndWorld{}

func (w *ndWorld) reset() {
	if w.ts != nil {
		w.ts.Close()
	}
	w.udm, w.pcf, w.clk = &ndUDM{}, &ndPCF{}, &ndClock{}
	w.logs = &tcLockedBuf{}
	w.spec, w.n2Off = true, false
	w.h, w.sender, w.ts, w.ready = nil, nil, nil, false
	w.tmsi, w.dl = 0, nil
}

func (w *ndWorld) after() {
	if w.ts != nil {
		w.ts.Close()
		w.ts = nil
	}
}

// ---- Background ----------------------------------------------------------------

func (w *ndWorld) smfMock() error {
	if ntsrW.smf == nil {
		return fmt.Errorf("SMF mock not running")
	}
	// requireSR (shared "releases the SM context" step) wants an active scenario.
	ntsrW.active = true
	return nil
}

func (w *ndWorld) pcfMock() error {
	ue := sbiW.ue
	ue.Lock()
	ue.AMPolicyAssocID, ue.PolicyAssociationID = "am-1", "ue-1"
	ue.Unlock()
	return nil
}

func (w *ndWorld) udmMock() error {
	sbiW.ue.SetSDMSubscriptionID("sdm-1")
	return nil
}

// ---- wiring --------------------------------------------------------------------

// prepare builds the NAS handler and the SBI callback server on first use (after the
// scenario Given steps fixed the release profile, CM state and gNB).
func (w *ndWorld) prepare() error {
	if w.ready {
		return nil
	}
	ue := sbiW.ue
	if ue == nil || anW.srv == nil {
		return fmt.Errorf("no UE or NGAP server seeded")
	}
	ue.Lock()
	ue.SecurityCtx.KNASint = bytes.Repeat([]byte{0x11}, 16)
	ue.SecurityCtx.KNASenc = bytes.Repeat([]byte{0x22}, 16)
	ue.UESecCapEA[2], ue.UESecCapIA[2] = true, true
	ue.State = amfctx.GMMRegistered
	connected := ue.CMState == amfctx.CMConnected
	if ue.GUTI != nil {
		w.tmsi = ue.GUTI.TMSI
	}
	ue.Unlock()

	// A registered gNB must exist so that any wrongly sent NAS or paging is observable.
	if anW.gnb == nil {
		if err := anW.servedByGNB(); err != nil {
			return err
		}
		if !connected || w.n2Off {
			ue.Lock()
			ue.GNBAddr = ""
			ue.Unlock()
			anW.gnb.UEs = map[int64]*amfctx.UEContext{}
		}
	}

	lg := slog.New(slog.NewJSONHandler(w.logs, nil))
	reg := procedures.NewRegistrationHandler(sbiW.mgr, nil, w.udm, nil, "test-amf", "001", "01", lg)
	reg.WithPCF(w.pcf)
	reg.WithAMPolicy(w.pcf)
	reg.WithNSSAASpecLiteral(w.spec)
	w.sender = &ndSender{Server: anW.srv}
	w.h = nasmsg.NewHandler(w.sender, reg, lg)
	w.h.SetTimerSchedulerForTest(w.clk.after)

	srv, err := amfsbi.New(amfsbi.Config{Address: "127.0.0.1:0"}, sbiW.mgr, nil)
	if err != nil {
		return err
	}
	srv.SetDeregistrationHandler(w.deregHandler)
	w.ts = httptest.NewServer(srv.HTTPHandler())
	w.ready = true
	return nil
}

// deregHandler mirrors the cmd/amf SetDeregistrationHandler closure.
func (w *ndWorld) deregHandler(ctx context.Context, ue *amfctx.UEContext, reason, access string) error {
	if w.h.HandleUDMDeregistration(ctx, ue, reason, access) {
		return nil
	}
	// Legacy local removal of cmd/amf (removeUEContext(ctx, ue, releaseSM, false)).
	releaseSM := reason == "UE_INITIAL_REGISTRATION" || reason == "SUBSCRIPTION_WITHDRAWN"
	ue.Lock()
	var refs []string
	for _, s := range ue.PDUSessions {
		if releaseSM && s.SMFInstanceID != "" {
			refs = append(refs, s.SMFInstanceID)
		}
	}
	supi := ue.SUPI
	ue.Unlock()
	for _, r := range refs {
		_ = w.sender.DeleteSMContext(ctx, r)
	}
	if supi != "" {
		if id := ue.TakeSDMSubscriptionID(); id != "" {
			_ = w.udm.UnsubscribeSDM(ctx, supi, id)
		}
	}
	sbiW.mgr.Remove(ctx, ue)
	return nil
}

// ---- Given -----------------------------------------------------------------------

func (w *ndWorld) releaseProfile(p string) error {
	switch p {
	case "rel19":
		w.spec = true
	case "rel17":
		w.spec = false
	default:
		return fmt.Errorf("unknown release profile %q", p)
	}
	return nil
}

func (w *ndWorld) n2Unavailable() error {
	w.n2Off = true
	return nil
}

// ---- When: callback --------------------------------------------------------------

func (w *ndWorld) post(supi string, body map[string]string) error {
	if err := w.prepare(); err != nil {
		return err
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, w.ts.URL+amfsbi.UDMDeregCallbackPath+"/"+supi, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.ts.Client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	sbiW.resp, sbiW.body = resp, buf.Bytes()
	// The 204 is returned before the queued de-registration work ran.
	return ndBarrier(sbiW.ue)
}

func (w *ndWorld) notify(supi, reason string) error {
	return w.post(supi, map[string]string{"deregReason": reason})
}

func (w *ndWorld) notifyAccess(supi, reason, access string) error {
	return w.post(supi, map[string]string{"deregReason": reason, "accessType": access})
}

func (w *ndWorld) notifyNoReason(supi string) error {
	return w.post(supi, map[string]string{"accessType": "3GPP_ACCESS"})
}

// ---- When: UE / timers -------------------------------------------------------------

func (w *ndWorld) ueAnswersAccept() error {
	w.collect()
	ue := sbiW.ue
	if err := ndBarrier(ue); err != nil {
		return err
	}
	plain := []byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeDeregistrationAcceptNW)}
	pdu, err := protectUL(ue, plain)
	if err != nil {
		return err
	}
	if err := w.h.HandleNASMessage(context.Background(), ue, pdu); err != nil {
		return fmt.Errorf("DEREGISTRATION ACCEPT handling failed: %w", err)
	}
	return ndBarrier(ue)
}

func (w *ndWorld) t3522Expires(n int) error {
	for i := 0; i < n; i++ {
		if err := w.clk.advance(nasmsg.NWDeregT3522Duration, sbiW.ue); err != nil {
			return err
		}
	}
	return nil
}

func (w *ndWorld) t3522ExpiresFifth() error { return w.t3522Expires(1) }

func (w *ndWorld) periodElapses(n int) error { return w.t3522Expires(n) }

func (w *ndWorld) guardExpires() error {
	want := time.Duration(nasmsg.NWDeregT3522MaxRetransmissions+1) * nasmsg.NWDeregT3522Duration
	live := w.clk.live()
	if len(live) != 1 || live[0] != want-time.Duration(nasmsg.NWDeregT3522MaxRetransmissions)*nasmsg.NWDeregT3522Duration {
		return fmt.Errorf("live timers before the guard expiry = %v, want exactly one with %s left of %s",
			live, nasmsg.NWDeregT3522Duration, want)
	}
	return w.clk.advance(nasmsg.NWDeregT3522Duration, sbiW.ue)
}

func (w *ndWorld) ueSendsServiceRequest() error {
	if anW.gnb == nil {
		return fmt.Errorf("no gNB")
	}
	if w.tmsi == 0 {
		return fmt.Errorf("former 5G-TMSI unknown")
	}
	id := sbiW.mgr.AMFID
	set := aper.BitString{Bytes: []byte{byte(id.AMFSetID >> 2), byte(id.AMFSetID&0x3) << 6}, BitLength: 10}
	ptr := aper.BitString{Bytes: []byte{id.AMFID << 2}, BitLength: 6}
	t := w.tmsi
	nasPDU := buildServiceRequest(nas.ServiceTypeSignalling, t, nil)
	plmn := []byte{0x00, 0xF1, 0x10}
	ies := []ngapType.InitialUEMessageIEs{
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitialUEMessageIEsValue{Present: ngapType.InitialUEMessageIEsPresentRANUENGAPID,
				RANUENGAPID: &ngapType.RANUENGAPID{Value: 9}},
		},
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDNASPDU},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitialUEMessageIEsValue{Present: ngapType.InitialUEMessageIEsPresentNASPDU,
				NASPDU: &ngapType.NASPDU{Value: aper.OctetString(nasPDU)}},
		},
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDUserLocationInformation},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitialUEMessageIEsValue{Present: ngapType.InitialUEMessageIEsPresentUserLocationInformation,
				UserLocationInformation: &ngapType.UserLocationInformation{
					Present: ngapType.UserLocationInformationPresentUserLocationInformationNR,
					UserLocationInformationNR: &ngapType.UserLocationInformationNR{
						NRCGI: ngapType.NRCGI{PLMNIdentity: ngapType.PLMNIdentity{Value: plmn},
							NRCellIdentity: ngapType.NRCellIdentity{Value: aper.BitString{Bytes: []byte{0, 0, 0, 0, 0x10}, BitLength: 36}}},
						TAI: ngapType.TAI{PLMNIdentity: ngapType.PLMNIdentity{Value: plmn}, TAC: ngapType.TAC{Value: aper.OctetString{0, 0, 1}}},
					}}},
		},
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRRCEstablishmentCause},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.InitialUEMessageIEsValue{Present: ngapType.InitialUEMessageIEsPresentRRCEstablishmentCause,
				RRCEstablishmentCause: &ngapType.RRCEstablishmentCause{Value: ngapType.RRCEstablishmentCausePresentMoSignalling}},
		},
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDFiveGSTMSI},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitialUEMessageIEsValue{Present: ngapType.InitialUEMessageIEsPresentFiveGSTMSI,
				FiveGSTMSI: &ngapType.FiveGSTMSI{
					AMFSetID:   ngapType.AMFSetID{Value: set},
					AMFPointer: ngapType.AMFPointer{Value: ptr},
					FiveGTMSI: ngapType.FiveGTMSI{Value: aper.OctetString{
						byte(t >> 24), byte(t >> 16), byte(t >> 8), byte(t)}},
				}},
		},
	}
	b, err := libngap.Encoder(ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeInitialUEMessage},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.InitiatingMessageValue{Present: ngapType.InitiatingMessagePresentInitialUEMessage,
				InitialUEMessage: &ngapType.InitialUEMessage{ProtocolIEs: ngapType.ProtocolIEContainerInitialUEMessageIEs{List: ies}}},
		},
	})
	if err != nil {
		return fmt.Errorf("encode InitialUEMessage: %w", err)
	}
	anW.srv.DispatchNGAPForTest(context.Background(), anW.gnb, b)
	// the reject path is synchronous; wait for DL NAS + release anyway
	deadline := time.Now().Add(ndWait)
	for len(anW.writes()) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	return nil
}

// ---- NGAP capture ----------------------------------------------------------------

// collect moves the DL NAS TRANSPORT PDUs written to the gNB into w.dl (keeping
// every other PDU, e.g. the UE CONTEXT RELEASE COMMAND, in anW.sent).
func (w *ndWorld) collect() {
	anW.mu.Lock()
	defer anW.mu.Unlock()
	keep := anW.sent[:0:0]
	for _, wr := range anW.sent {
		if n, ok := ndDLNAS(wr.pdu); ok {
			w.dl = append(w.dl, n)
			continue
		}
		keep = append(keep, wr)
	}
	anW.sent = keep
}

func ndDLNAS(raw []byte) ([]byte, bool) {
	pdu, err := libngap.Decoder(raw)
	if err != nil || pdu.Present != ngapType.NGAPPDUPresentInitiatingMessage || pdu.InitiatingMessage == nil ||
		pdu.InitiatingMessage.ProcedureCode.Value != ngapType.ProcedureCodeDownlinkNASTransport {
		return nil, false
	}
	m := pdu.InitiatingMessage.Value.DownlinkNASTransport
	if m == nil {
		return nil, false
	}
	for _, ie := range m.ProtocolIEs.List {
		if ie.Value.NASPDU != nil {
			return []byte(ie.Value.NASPDU.Value), true
		}
	}
	return nil, false
}

// decodeSecuredDL verifies the NIA2 MAC, deciphers (NEA2) a DL NAS PDU sent with
// SHT 2 and returns the inner plain 5GMM message.
func decodeSecuredDL(pdu []byte) (inner []byte, sht byte, err error) {
	if len(pdu) < 8 || pdu[0] != nas.PDMobilityManagement {
		return nil, 0, fmt.Errorf("DL NAS PDU too short or wrong EPD: %x", pdu)
	}
	sht = pdu[1] & 0x0F
	if sht != byte(nas.SecurityHeaderIntegrityProtectedAndCiphered) {
		return nil, sht, fmt.Errorf("SHT = %#x, want 0x02", sht)
	}
	ue := sbiW.ue
	count := uint32(pdu[6]) // DL COUNT stays below 256 in these scenarios
	ok, err := nia.Verify(ue.SecurityCtx.KNASint, count, 0x01, 0x01, pdu[6:], pdu[2:6])
	if err != nil || !ok {
		return nil, sht, fmt.Errorf("NIA2 MAC invalid (ok=%v err=%v)", ok, err)
	}
	inner, err = nea.NEA2(ue.SecurityCtx.KNASenc, count, 0x01, 0x01, pdu[7:])
	if err != nil {
		return nil, sht, err
	}
	return inner, sht, nil
}

// deregRequests returns the decoded DEREGISTRATION REQUESTs among the DL NAS PDUs.
func (w *ndWorld) deregRequests() (inners [][]byte, err error) {
	w.collect()
	for _, p := range w.dl {
		inner, _, e := decodeSecuredDL(p)
		if e != nil {
			return nil, e
		}
		if len(inner) < 4 || inner[0] != nas.PDMobilityManagement || inner[1] != 0x00 ||
			nas.MessageType(inner[2]) != nas.MsgTypeDeregistrationRequestNW {
			return nil, fmt.Errorf("DL NAS inner message = %x, want DEREGISTRATION REQUEST (0x47)", inner)
		}
		inners = append(inners, inner)
	}
	return inners, nil
}

func (w *ndWorld) releaseCmds() ([]*ngapType.UEContextReleaseCommand, error) {
	var out []*ngapType.UEContextReleaseCommand
	for _, wr := range anW.writes() {
		pdu, err := libngap.Decoder(wr.pdu)
		if err != nil {
			return nil, err
		}
		if pdu.Present == ngapType.NGAPPDUPresentInitiatingMessage && pdu.InitiatingMessage != nil &&
			pdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeUEContextRelease &&
			pdu.InitiatingMessage.Value.UEContextReleaseCommand != nil {
			out = append(out, pdu.InitiatingMessage.Value.UEContextReleaseCommand)
		}
	}
	return out, nil
}

// ---- Then ------------------------------------------------------------------------

func (w *ndWorld) exactlyOneDereg() error {
	in, err := w.deregRequests()
	if err != nil {
		return err
	}
	if len(in) != 1 {
		return fmt.Errorf("AMF sent %d DL NAS DEREGISTRATION REQUESTs, want exactly one", len(in))
	}
	return nil
}

func (w *ndWorld) deregType(rereg, access string) error {
	in, err := w.deregRequests()
	if err != nil {
		return err
	}
	if len(in) == 0 {
		return fmt.Errorf("no DEREGISTRATION REQUEST sent")
	}
	req, err := nas.DecodeDeregistrationRequestNW(in[0][3:])
	if err != nil {
		return err
	}
	wantRereg := false
	switch rereg {
	case "re-registration required":
		wantRereg = true
	case "re-registration not required":
	default:
		return fmt.Errorf("unknown de-registration type %q", rereg)
	}
	if access != "3GPP access" {
		return fmt.Errorf("unsupported access type %q", access)
	}
	if req.ReregistrationRequired != wantRereg || req.AccessType != 1 || in[0][3]&0x08 != 0 {
		return fmt.Errorf("de-registration type octet = %#x (rereg=%v access=%d), want %s / %s",
			in[0][3], req.ReregistrationRequired, req.AccessType, rereg, access)
	}
	return nil
}

func (w *ndWorld) noCauseIE() error {
	in, err := w.deregRequests()
	if err != nil {
		return err
	}
	if len(in) == 0 {
		return fmt.Errorf("no DEREGISTRATION REQUEST sent")
	}
	req, err := nas.DecodeDeregistrationRequestNW(in[0][3:])
	if err != nil {
		return err
	}
	if req.Cause5GMM != 0 {
		return fmt.Errorf("DEREGISTRATION REQUEST carries 5GMM cause %d, want none", req.Cause5GMM)
	}
	return nil
}

func (w *ndWorld) protectedSHT2() error {
	w.collect()
	if len(w.dl) == 0 {
		return fmt.Errorf("no DL NAS PDU sent")
	}
	for _, p := range w.dl {
		if _, sht, err := decodeSecuredDL(p); err != nil {
			return fmt.Errorf("SHT %#x: %w", sht, err)
		}
	}
	return nil
}

func (w *ndWorld) ueState(want amfctx.GMM5State) error {
	ue := sbiW.ue
	ue.Lock()
	defer ue.Unlock()
	if ue.State != want {
		return fmt.Errorf("UE 5GMM state = %v, want %v", ue.State, want)
	}
	return nil
}

func (w *ndWorld) pcfDeleted(n int) error {
	w.pcf.mu.Lock()
	defer w.pcf.mu.Unlock()
	if len(w.pcf.am) != n || len(w.pcf.uePols) != n || (n == 1 && (w.pcf.am[0] != "am-1" || w.pcf.uePols[0] != "ue-1")) {
		return fmt.Errorf("PCF deletes: AM %v, UE policy %v; want %d each (am-1 / ue-1)", w.pcf.am, w.pcf.uePols, n)
	}
	return nil
}

func (w *ndWorld) pcfDeletedBoth() error { return w.pcfDeleted(1) }

func (w *ndWorld) noPCFDelete() error {
	w.pcf.mu.Lock()
	defer w.pcf.mu.Unlock()
	if len(w.pcf.am)+len(w.pcf.uePols) != 0 {
		return fmt.Errorf("PCF deletes: AM %v, UE policy %v; want none", w.pcf.am, w.pcf.uePols)
	}
	return nil
}

func (w *ndWorld) sdmOnce() error {
	w.udm.mu.Lock()
	defer w.udm.mu.Unlock()
	if len(w.udm.unsub) != 1 || w.udm.unsub[0] != "sdm-1" {
		return fmt.Errorf("SDM unsubscribes = %v, want exactly [sdm-1]", w.udm.unsub)
	}
	return nil
}

func (w *ndWorld) noSDM() error {
	w.udm.mu.Lock()
	defer w.udm.mu.Unlock()
	if len(w.udm.unsub) != 0 {
		return fmt.Errorf("SDM unsubscribes = %v, want none", w.udm.unsub)
	}
	return nil
}

func (w *ndWorld) noPCFNoSDM() error {
	if err := w.noPCFDelete(); err != nil {
		return err
	}
	return w.noSDM()
}

func (w *ndWorld) noUECMDelete() error {
	w.udm.mu.Lock()
	defer w.udm.mu.Unlock()
	if w.udm.uecm != 0 {
		return fmt.Errorf("AMF sent %d Nudm_UECM_Deregistration DELETE(s), want none", w.udm.uecm)
	}
	return nil
}

func (w *ndWorld) noSMRelease(psi int) error {
	ref := ntsrRef(psi)
	ntsrW.mu.Lock()
	defer ntsrW.mu.Unlock()
	for _, r := range ntsrW.released {
		if r == ref {
			return fmt.Errorf("SMF received a release for %s", ref)
		}
	}
	return nil
}

func (w *ndWorld) noNAS() error {
	w.collect()
	w.sender.mu.Lock()
	n := w.sender.attempts
	w.sender.mu.Unlock()
	if n != 0 || len(w.dl) != 0 {
		return fmt.Errorf("AMF attempted %d DL NAS sends, %d reached the gNB; want none", n, len(w.dl))
	}
	return nil
}

func (w *ndWorld) noPaging() error {
	for _, wr := range anW.writes() {
		pdu, err := libngap.Decoder(wr.pdu)
		if err != nil {
			return err
		}
		if pdu.InitiatingMessage != nil && pdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodePaging {
			return fmt.Errorf("AMF sent an NGAP Paging")
		}
	}
	return nil
}

func (w *ndWorld) contextRemoved() error {
	deadline := time.Now().Add(ndWait)
	for {
		if _, ok := sbiW.mgr.GetBySUPI(sbiW.ue.SUPI); !ok {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("UE context %s still present", sbiW.ue.SUPI)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (w *ndWorld) contextIntact() error {
	ue, ok := sbiW.mgr.GetBySUPI(sbiW.ue.SUPI)
	if !ok {
		return fmt.Errorf("UE context removed")
	}
	ue.Lock()
	defer ue.Unlock()
	if ue.State != amfctx.GMMRegistered {
		return fmt.Errorf("UE 5GMM state = %v, want 5GMM-REGISTERED", ue.State)
	}
	return nil
}

func (w *ndWorld) problemCause(want string) error {
	var pd amfsbi.ProblemDetails
	if err := json.Unmarshal(sbiW.body, &pd); err != nil {
		return fmt.Errorf("body is not ProblemDetails: %s", sbiW.body)
	}
	if pd.Cause != want {
		return fmt.Errorf("ProblemDetails cause = %q, want %q", pd.Cause, want)
	}
	return nil
}

func (w *ndWorld) releaseCommandNasDeregister() error {
	deadline := time.Now().Add(ndWait)
	for {
		cmds, err := w.releaseCmds()
		if err != nil {
			return err
		}
		if len(cmds) == 1 {
			for _, ie := range cmds[0].ProtocolIEs.List {
				if ie.Value.Cause == nil {
					continue
				}
				c := ie.Value.Cause
				if c.Present != ngapType.CausePresentNas || c.Nas == nil || c.Nas.Value != ngapType.CauseNasPresentDeregister {
					return fmt.Errorf("Cause = %+v, want nas deregister", c)
				}
				return nil
			}
			return fmt.Errorf("UE CONTEXT RELEASE COMMAND has no Cause IE")
		}
		if len(cmds) > 1 || time.Now().After(deadline) {
			return fmt.Errorf("gNB received %d UE CONTEXT RELEASE COMMANDs, want exactly 1", len(cmds))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (w *ndWorld) markedForRemoval() error {
	ue := sbiW.ue
	ue.Lock()
	defer ue.Unlock()
	if !ue.PendingRemoval {
		return fmt.Errorf("UE is not marked PendingRemoval")
	}
	return nil
}

func (w *ndWorld) releaseCompleteRemoves() error {
	ue := sbiW.ue
	ue.Lock()
	amfID, ranID := ue.AMFUENGAPId, ue.RANUENGAPId
	ue.Unlock()
	pdu, err := buildReleaseComplete(amfID, ranID)
	if err != nil {
		return err
	}
	anW.srv.DispatchNGAPForTest(context.Background(), anW.gnb, pdu)
	anW.srv.WaitUESerialForTest(amfID)
	return w.contextRemoved()
}

func (w *ndWorld) retransmitted(n int) error {
	in, err := w.deregRequests()
	if err != nil {
		return err
	}
	if len(in) != 1+n {
		return fmt.Errorf("AMF sent %d DEREGISTRATION REQUESTs, want the original plus %d retransmissions", len(in), n)
	}
	for i, m := range in {
		if !bytes.Equal(m, in[0]) {
			return fmt.Errorf("retransmission %d differs from the original: %x vs %x", i, m, in[0])
		}
	}
	return nil
}

func (w *ndWorld) oneInTotal() error {
	in, err := w.deregRequests()
	if err != nil {
		return err
	}
	if len(in) != 1 {
		return fmt.Errorf("AMF sent %d DEREGISTRATION REQUESTs in total, want 1", len(in))
	}
	cmds, err := w.releaseCmds()
	if err != nil {
		return err
	}
	if len(cmds) != 0 {
		return fmt.Errorf("N2 released before the local-abort guard expired")
	}
	return nil
}

func (w *ndWorld) logsDeregSendResult(result string) error {
	for _, line := range strings.Split(w.logs.String(), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if msg, _ := rec["msg"].(string); strings.Contains(msg, "DEREGISTRATION REQUEST send") && rec["result"] == result {
			return nil
		}
	}
	return fmt.Errorf("no log line for the DEREGISTRATION REQUEST send with result %q", result)
}

func (w *ndWorld) serviceReject(cause int) error {
	w.collect()
	for _, p := range w.dl {
		if len(p) >= 4 && p[1] == 0x00 && nas.MessageType(p[2]) == nas.MsgTypeServiceReject {
			if int(p[3]) != cause {
				return fmt.Errorf("SERVICE REJECT 5GMM cause = %d, want %d", p[3], cause)
			}
			return nil
		}
	}
	return fmt.Errorf("no SERVICE REJECT among %d DL NAS PDUs", len(w.dl))
}

func (w *ndWorld) releasesTempN2() error {
	deadline := time.Now().Add(ndWait)
	for {
		cmds, err := w.releaseCmds()
		if err != nil {
			return err
		}
		if len(cmds) == 1 {
			for _, ie := range cmds[0].ProtocolIEs.List {
				if ids := ie.Value.UENGAPIDs; ids != nil && ids.Present == ngapType.UENGAPIDsPresentUENGAPIDPair &&
					ids.UENGAPIDPair.RANUENGAPID.Value != 9 {
					return fmt.Errorf("release targets RAN UE NGAP ID %d, want the temporary context 9",
						ids.UENGAPIDPair.RANUENGAPID.Value)
				}
			}
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("gNB received %d UE CONTEXT RELEASE COMMANDs, want 1", len(cmds))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func initNetworkDeregistrationSteps(sc *godog.ScenarioContext) {
	w := ndW
	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		w.reset()
		return ctx, nil
	})
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		w.after()
		return ctx, nil
	})

	sc.Step(`^an SMF mock records Nsmf ReleaseSMContext requests$`, w.smfMock)
	sc.Step(`^a PCF mock records Npcf AM policy and UE policy delete requests$`, w.pcfMock)
	sc.Step(`^a UDM mock records Nudm SDM unsubscribe and UECM delete requests$`, w.udmMock)

	sc.Step(`^the release profile is "([^"]+)"$`, w.releaseProfile)
	sc.Step(`^the serving gNB N2 association is unavailable for NAS delivery$`, w.n2Unavailable)

	sc.Step(`^the UDM POSTs a dereg-notify for SUPI "([^"]+)" with deregReason "([^"]+)"$`, w.notify)
	sc.Step(`^the UDM POSTed a dereg-notify for SUPI "([^"]+)" with deregReason "([^"]+)"$`, w.notify)
	sc.Step(`^the UDM POSTs a dereg-notify for SUPI "([^"]+)" with deregReason "([^"]+)" and accessType "([^"]+)"$`, w.notifyAccess)
	sc.Step(`^the UDM POSTs a dereg-notify for SUPI "([^"]+)" with a body lacking deregReason$`, w.notifyNoReason)
	sc.Step(`^the UE answers with a DEREGISTRATION ACCEPT$`, w.ueAnswersAccept)
	sc.Step(`^T3522 expires (\d+) times and the UE never answers$`, w.t3522Expires)
	sc.Step(`^T3522 expires the 5th time$`, w.t3522ExpiresFifth)
	sc.Step(`^the T3522 period elapses (\d+) times without a UE answer$`, w.periodElapses)
	sc.Step(`^the local-abort guard of 5 x T3522 expires$`, w.guardExpires)
	sc.Step(`^the UE sends a SERVICE REQUEST with its former 5G-S-TMSI$`, w.ueSendsServiceRequest)

	sc.Step(`^the ProblemDetails cause is "([^"]+)"$`, w.problemCause)
	sc.Step(`^the AMF sends exactly one DL NAS DEREGISTRATION REQUEST \(UE terminated\) to the UE$`, w.exactlyOneDereg)
	sc.Step(`^the DEREGISTRATION REQUEST de-registration type indicates "([^"]+)" and access type "([^"]+)"$`, w.deregType)
	sc.Step(`^the DEREGISTRATION REQUEST carries no 5GMM cause IE$`, w.noCauseIE)
	sc.Step(`^the DEREGISTRATION REQUEST is integrity protected and ciphered with SHT 2$`, w.protectedSHT2)
	sc.Step(`^the UE is in 5GMM-DEREGISTERED-INITIATED$`, func() error { return w.ueState(amfctx.GMMDeregisteredInitiated) })
	sc.Step(`^the UE is 5GMM-DEREGISTERED$`, func() error { return w.ueState(amfctx.GMMDeregistered) })
	sc.Step(`^the AMF deletes the AM policy association and the UE policy association at the PCF$`, w.pcfDeletedBoth)
	sc.Step(`^the AMF unsubscribes the SDM subscription at the UDM exactly once$`, w.sdmOnce)
	sc.Step(`^the AMF does not send a UECM DELETE to the UDM$`, w.noUECMDelete)
	sc.Step(`^the AMF sends no Nsmf ReleaseSMContext for PDU session (\d+)$`, w.noSMRelease)
	sc.Step(`^the AMF sends no NAS message to the UE$`, w.noNAS)
	sc.Step(`^the AMF sends no NGAP Paging$`, w.noPaging)
	sc.Step(`^the AMF sends no Npcf delete and no Nudm SDM unsubscribe$`, w.noPCFNoSDM)
	sc.Step(`^the AMF sends no Npcf delete$`, w.noPCFDelete)
	sc.Step(`^the UE context is removed from the AMF$`, w.contextRemoved)
	sc.Step(`^the UE context is intact and the UE remains 5GMM-REGISTERED$`, w.contextIntact)
	sc.Step(`^the AMF sends a UE CONTEXT RELEASE COMMAND with Cause nas "deregister" to the serving gNB$`, w.releaseCommandNasDeregister)
	sc.Step(`^the UE is marked for removal$`, w.markedForRemoval)
	sc.Step(`^after the UE CONTEXT RELEASE COMPLETE the UE context is removed from the AMF$`, w.releaseCompleteRemoves)
	sc.Step(`^the UE context is removed from the AMF after the UE CONTEXT RELEASE COMPLETE$`, w.releaseCompleteRemoves)
	sc.Step(`^the AMF has retransmitted the same DEREGISTRATION REQUEST (\d+) times$`, w.retransmitted)
	sc.Step(`^the AMF has sent exactly one DEREGISTRATION REQUEST in total$`, w.oneInTotal)
	sc.Step(`^the AMF logs the DEREGISTRATION REQUEST send with result "([^"]+)"$`, w.logsDeregSendResult)
	sc.Step(`^the AMF returns a SERVICE REJECT with 5GMM cause (\d+)$`, w.serviceReject)
	sc.Step(`^the AMF releases the N2 connection of the temporary context$`, w.releasesTempN2)
}
