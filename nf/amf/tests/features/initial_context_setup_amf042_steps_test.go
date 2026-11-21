//go:build functional

// initial_context_setup_amf042_steps_test.go -- in-process godog steps for the
// @AMF-042 scenarios of initial_context_setup.feature: with an empty Allowed
// NSSAI no ICS Request can be sent (AMF-010), so no user plane is activated on
// a CM-IDLE registration update or Service Request, and the ICS Response log
// procedure follows the pending ICS kind.
// Ref: TS 24.501 §5.5.1.3.4, §5.6.1.4.1; TS 38.413 §8.2.1, §8.3.1.2;
// TS 23.502 §4.2.3.2 step 12
//
// The real nasmsg.Handler (with a real RegistrationHandler) is driven with
// NEA2/NIA2 protected uplink NAS; the real NGAP Server handles the ICS Response
// (DispatchNGAPForTest, world shared with ics_failure_steps_test.go).
package features_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/cucumber/godog"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	nasmsg "github.com/francurieses/claudia-5gc/nf/amf/internal/nas"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nea"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nia"
	"github.com/francurieses/claudia-5gc/shared/nas"
	libngap "github.com/francurieses/claudia-5gc/shared/ngap"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

// a42UDM answers UECM and SDM successfully with the given subscribed slices.
type a42UDM struct{ allowed []amfctx.SNSSAISubscribed }

func (a42UDM) RegisterAMF(context.Context, string, string, string) error { return nil }
func (u a42UDM) GetAMSubscriptionData(context.Context, string) (*procedures.UDMAMSubscription, error) {
	return &procedures.UDMAMSubscription{AllowedNSSAI: u.allowed, DefaultNSSAI: u.allowed}, nil
}
func (a42UDM) DeregisterUECM(context.Context, string) error { return nil }

// a42Sender records DL NAS TRANSPORT payloads, ICS Requests, PDU SESSION
// RESOURCE SETUP REQUESTs and Nsmf activations.
type a42Sender struct {
	dl          [][]byte
	ics         int
	setups      []uint8
	activations []string
}

func (s *a42Sender) SendDownlinkNASTransport(_ *amfctx.UEContext, pdu []byte) error {
	s.dl = append(s.dl, append([]byte(nil), pdu...))
	return nil
}
func (s *a42Sender) SendInitialContextSetupRequest(*amfctx.UEContext, []byte, [32]byte, byte, byte,
	uint16, uint16, []ngap.PDUSessionSetupItemCxtReq) error {
	s.ics++
	return nil
}
func (s *a42Sender) SendPDUSessionResourceSetupRequest(_ *amfctx.UEContext, psi uint8, _ []byte, _ []byte) error {
	s.setups = append(s.setups, psi)
	return nil
}
func (s *a42Sender) SendPDUSessionResourceReleaseCommand(*amfctx.UEContext, uint8, []byte) error {
	return nil
}
func (s *a42Sender) SendPDUSessionResourceModifyRequest(*amfctx.UEContext, uint8, []byte, []byte) error {
	return nil
}
func (s *a42Sender) SendUEContextReleaseCommandForUE(*amfctx.UEContext, int, int64) error {
	return nil
}
func (s *a42Sender) ActivateSMContext(_ context.Context, ref string) ([]byte, error) {
	s.activations = append(s.activations, ref)
	return []byte{0xAA}, nil
}

type a42World struct {
	mgr    *amfctx.Manager
	ue     *amfctx.UEContext
	sender *a42Sender
	logs   *tcLockedBuf
	h      *nasmsg.Handler
	dlPre  uint32
	err    error
}

var a42W = &a42World{}

// setup creates a registered UE with an active NIA2/NEA2 context and PDU
// sessions 1 and 2 (the handler is built at the When step, once the Allowed
// NSSAI Given steps ran).
func (w *a42World) setup(supi string, idle bool) {
	*w = a42World{sender: &a42Sender{}, logs: &tcLockedBuf{}}
	w.mgr = amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01", AMFRegionID: 2, AMFID: 1}, nil, nil, nil)
	ue := w.mgr.AllocateUEContext(1)
	w.mgr.SetSUPI(ue, supi)
	w.mgr.AssignGUTI(context.Background(), ue)
	ue.RANUENGAPId = 1
	ue.GNBAddr = "10.0.0.1:38412"
	ue.CMState = amfctx.CMConnected
	if idle {
		ue.CMState = amfctx.CMIdle
	}
	ue.RawUESecCap = []byte{0xe0, 0x60, 0x00, 0x00}
	ue.SecurityCtx = amfctx.SecurityContext{
		Active: true, NGKSI: 1, IntegrityAlgID: 2, CipheringAlgID: 2,
		KNASint: bytes.Repeat([]byte{0x11}, 16),
		KNASenc: bytes.Repeat([]byte{0x22}, 16),
		KAMF:    bytes.Repeat([]byte{0x33}, 32),
	}
	ue.TransitionTo(amfctx.GMMRegistered)
	ue.PDUSessions[1] = &amfctx.PDUSession{PDUSessionID: 1, SMFInstanceID: "sm-ctx-1"}
	ue.PDUSessions[2] = &amfctx.PDUSession{PDUSessionID: 2, SMFInstanceID: "sm-ctx-2"}
	w.ue = ue
}

func (w *a42World) handler() *nasmsg.Handler {
	lg := slog.New(slog.NewJSONHandler(w.logs, nil))
	reg := procedures.NewRegistrationHandler(w.mgr, nil, a42UDM{allowed: icsW.allowed}, nil, "nf", "001", "01", lg)
	return nasmsg.NewHandler(w.sender, reg, lg)
}

// securedUL wraps body in an NEA2 + NIA2 protected uplink NAS PDU (SHT 0x02).
func (w *a42World) securedUL(msgType nas.MessageType, body []byte) ([]byte, error) {
	ue := w.ue
	inner := append([]byte{nas.PDMobilityManagement, byte(nas.SecurityHeaderPlainNAS), byte(msgType)}, body...)
	count := ue.SecurityCtx.UplinkCount
	ciphered, err := nea.NEA2(ue.SecurityCtx.KNASenc, count, 0x01, 0x00, inner)
	if err != nil {
		return nil, err
	}
	sqn := byte(count & 0xFF)
	mac, err := nia.NIA2(ue.SecurityCtx.KNASint, count, 0x01, 0x00, append([]byte{sqn}, ciphered...))
	if err != nil {
		return nil, err
	}
	pdu := []byte{nas.PDMobilityManagement, byte(nas.SecurityHeaderIntegrityProtectedAndCiphered)}
	pdu = append(pdu, mac...)
	pdu = append(pdu, sqn)
	return append(pdu, ciphered...), nil
}

func (w *a42World) deliver(msgType nas.MessageType, body []byte, newN2 bool) error {
	if w.ue == nil {
		return fmt.Errorf("no UE seeded in this scenario")
	}
	if len(icsW.allowed) > 0 { // keep the UE's own Allowed NSSAI in step with the Given steps
		w.ue.AllowedNSSAI = icsW.allowed
	} else {
		w.ue.AllowedNSSAI = nil
	}
	if newN2 {
		w.ue.CMState = amfctx.CMConnected // the gNB's Initial UE Message opened the N2 connection
	}
	w.ue.NASOnNewN2Connection = newN2
	w.dlPre = w.ue.SecurityCtx.DownlinkCount
	w.sender.dl, w.sender.ics, w.sender.setups, w.sender.activations = nil, 0, nil, nil
	pdu, err := w.securedUL(msgType, body)
	if err != nil {
		return err
	}
	if w.h == nil {
		w.h = w.handler()
	}
	w.err = w.h.HandleNASMessage(context.Background(), w.ue, pdu)
	return nil
}

// updateBody is a mobility registration update (5GS registration type 2, GUTI)
// with an Uplink data status IE (0x40) for the given PSIs.
func a42UpdateBody(psis ...uint8) []byte {
	b := []byte{0x12, 0x00, 0x0b, 0xf2, 0x00, 0xf1, 0x10, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01}
	m := nas.PSIMask(psis...)
	return append(b, nas.IEIUplinkDataStatus, 0x02, byte(m>>8), byte(m))
}

// a42ServiceRequestBody is a SERVICE REQUEST (data) without Uplink data status.
func a42ServiceRequestBody() []byte {
	return []byte{nas.ServiceTypeData<<4 | 0x01, 0x00, 0x07, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
}

func (w *a42World) acceptInner(want nas.MessageType) ([]byte, error) {
	if w.err != nil {
		return nil, fmt.Errorf("NAS handling failed: %w", w.err)
	}
	if len(w.sender.dl) != 1 {
		return nil, fmt.Errorf("%d DOWNLINK NAS TRANSPORT sent, want exactly 1", len(w.sender.dl))
	}
	pdu := w.sender.dl[0]
	if len(pdu) < 7 {
		return nil, fmt.Errorf("DL NAS PDU too short: %x", pdu)
	}
	in, err := nea.NEA2(w.ue.SecurityCtx.KNASenc, w.dlPre, 0x01, 0x01, pdu[7:])
	if err != nil {
		return nil, err
	}
	if len(in) < 3 || in[2] != byte(want) {
		return nil, fmt.Errorf("inner NAS message %x, want message type 0x%02x", in, byte(want))
	}
	return in, nil
}

// pagedDropRecords returns the paged_pdu_sessions of every "paged PDU sessions
// not re-activated" log record.
func (w *a42World) pagedDropRecords() ([][]int, error) {
	var out [][]int
	sc := bufio.NewScanner(strings.NewReader(w.logs.String()))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return nil, fmt.Errorf("log line is not JSON: %w", err)
		}
		if msg, _ := rec["msg"].(string); !strings.HasPrefix(msg, "paged PDU sessions not re-activated") {
			continue
		}
		if rec["level"] != "WARN" || rec["cause"] != "empty_allowed_nssai_no_ics" {
			return nil, fmt.Errorf("paged drop log level=%v cause=%v, want WARN/empty_allowed_nssai_no_ics", rec["level"], rec["cause"])
		}
		var psis []int
		l, _ := rec["paged_pdu_sessions"].([]any)
		for _, v := range l {
			f, _ := v.(float64)
			psis = append(psis, int(f))
		}
		out = append(out, psis)
	}
	return out, nil
}

func buildICSResponseNoSessions(amfID, ranID int64) ([]byte, error) {
	ies := []ngapType.InitialContextSetupResponseIEs{
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.InitialContextSetupResponseIEsValue{
				Present:     ngapType.InitialContextSetupResponseIEsPresentAMFUENGAPID,
				AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfID},
			},
		},
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.InitialContextSetupResponseIEsValue{
				Present:     ngapType.InitialContextSetupResponseIEsPresentRANUENGAPID,
				RANUENGAPID: &ngapType.RANUENGAPID{Value: ranID},
			},
		},
	}
	return libngap.Encoder(ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentSuccessfulOutcome,
		SuccessfulOutcome: &ngapType.SuccessfulOutcome{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeInitialContextSetup},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.SuccessfulOutcomeValue{
				Present: ngapType.SuccessfulOutcomePresentInitialContextSetupResponse,
				InitialContextSetupResponse: &ngapType.InitialContextSetupResponse{
					ProtocolIEs: ngapType.ProtocolIEContainerInitialContextSetupResponseIEs{List: ies},
				},
			},
		},
	})
}

// icsResponseRecord returns the InitialContextSetupResponse log record of the
// real NGAP server, polling until the (serialised) handler has logged it.
func icsResponseRecord() (map[string]any, error) {
	w := icsFailW
	deadline := time.Now().Add(2 * time.Second)
	for {
		w.mu.Lock()
		raw := w.logs.String()
		w.mu.Unlock()
		sc := bufio.NewScanner(strings.NewReader(raw))
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var rec map[string]any
			if json.Unmarshal(sc.Bytes(), &rec) == nil && rec["message_type"] == "InitialContextSetupResponse" {
				return rec, nil
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("no InitialContextSetupResponse log record in %q", raw)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func initAMF042Steps(sc *godog.ScenarioContext) {
	w := a42W
	psis := func(a, b int) []uint8 { return []uint8{uint8(a), uint8(b)} }

	sc.Step(`^UE "([^"]+)" is in 5GMM-REGISTERED state in (CM-IDLE|CM-CONNECTED) with PDU sessions (\d+) and (\d+)$`,
		func(supi, cm string, _, _ int) error { w.setup(supi, cm == "CM-IDLE"); return nil })
	sc.Step(`^UE "([^"]+)" is in 5GMM-REGISTERED state in CM-IDLE with paged PDU sessions (\d+) and (\d+)$`,
		func(supi string, a, b int) error {
			w.setup(supi, true)
			w.ue.AddPagedPDUSession(uint8(a))
			w.ue.AddPagedPDUSession(uint8(b))
			return nil
		})
	sc.Step(`^the UE has an Allowed NSSAI of S-NSSAI SST (\d+) SD "([0-9a-f]{6})"$`,
		func(sst int, sd string) error {
			icsW.allowed = []amfctx.SNSSAISubscribed{{SST: uint8(sst), SD: sd}}
			return nil
		})

	sc.Step(`^the UE sends a Registration Request of type "mobility registration updating" on (a new|the existing) N2 connection with Uplink data status for PDU sessions (\d+) and (\d+)$`,
		func(conn string, a, b int) error {
			return w.deliver(nas.MsgTypeRegistrationRequest, a42UpdateBody(psis(a, b)...), conn == "a new")
		})
	sc.Step(`^the AMF sends no Nsmf_PDUSession_UpdateSMContext request activating the user plane$`, func() error {
		if len(w.sender.activations) != 0 {
			return fmt.Errorf("Nsmf activations %v, want none", w.sender.activations)
		}
		return nil
	})
	sc.Step(`^the AMF sends no PDU SESSION RESOURCE SETUP REQUEST$`, func() error {
		if len(w.sender.setups) != 0 {
			return fmt.Errorf("PDU SESSION RESOURCE SETUP REQUEST for PDU sessions %v, want none", w.sender.setups)
		}
		return nil
	})
	sc.Step(`^the AMF sends the Registration Accept in a DOWNLINK NAS TRANSPORT$`, func() error {
		if w.sender.ics != 0 {
			return fmt.Errorf("%d INITIAL CONTEXT SETUP REQUEST sent, want none", w.sender.ics)
		}
		_, err := w.acceptInner(nas.MsgTypeRegistrationAccept)
		return err
	})
	sc.Step(`^the Registration Accept PDU session reactivation result IE \(0x26\) reports PDU sessions (\d+) and (\d+) as (not re-established|re-established)$`,
		func(a, b int, state string) error {
			in, err := w.acceptInner(nas.MsgTypeRegistrationAccept)
			if err != nil {
				return err
			}
			// IE 0x26 is the trailing TLV when the error cause IE 0x72 is absent.
			var want []byte
			if state == "not re-established" {
				want = append([]byte{nas.IEIPDUSessionReactivationResult, 0x02}, nas.NewPDUSessionReactivationResult(uint8(a), uint8(b))...)
			} else {
				want = append([]byte{nas.IEIPDUSessionReactivationResult, 0x02}, nas.NewPDUSessionReactivationResult()...)
			}
			if !bytes.HasSuffix(in, want) {
				return fmt.Errorf("Registration Accept %x does not end with IE 0x26 %x (%s)", in, want, state)
			}
			acc, err := nas.DecodeRegistrationAccept(in[3:])
			if err != nil {
				return err
			}
			if len(acc.PDUSessionReactivationResultErrorCause) != 0 {
				return fmt.Errorf("PDU session reactivation result error cause IE (0x72) %v present, want absent",
					acc.PDUSessionReactivationResultErrorCause)
			}
			return nil
		})
	sc.Step(`^the AMF asks the SMF to activate the user plane of PDU sessions (\d+) and (\d+)$`,
		func(a, b int) error {
			want := fmt.Sprintf("sm-ctx-%d,sm-ctx-%d", a, b)
			if got := strings.Join(w.sender.activations, ","); got != want {
				return fmt.Errorf("Nsmf activations %q, want %q", got, want)
			}
			return nil
		})
	sc.Step(`^the AMF sends a PDU SESSION RESOURCE SETUP REQUEST for PDU sessions (\d+) and (\d+)$`,
		func(a, b int) error {
			if fmt.Sprint(w.sender.setups) != fmt.Sprint([]uint8{uint8(a), uint8(b)}) {
				return fmt.Errorf("PDU SESSION RESOURCE SETUP REQUEST for %v, want [%d %d]", w.sender.setups, a, b)
			}
			return nil
		})

	// Service Request
	sc.Step(`^the UE answers the paging with a Service Request$`,
		func() error { return w.deliver(nas.MsgTypeServiceRequest, a42ServiceRequestBody(), true) })
	sc.Step(`^the UE sends a later Service Request$`,
		func() error { return w.deliver(nas.MsgTypeServiceRequest, a42ServiceRequestBody(), true) })
	sc.Step(`^the AMF sends no INITIAL CONTEXT SETUP REQUEST$`, func() error {
		if w.sender.ics != 0 || len(w.sender.activations) != 0 || len(w.sender.setups) != 0 {
			return fmt.Errorf("ics=%d activations=%v setups=%v, want none", w.sender.ics, w.sender.activations, w.sender.setups)
		}
		return nil
	})
	sc.Step(`^the paged PDU sessions of the UE are drained$`, func() error {
		if p := w.ue.PagedPDUSessions(); len(p) != 0 {
			return fmt.Errorf("paged PDU sessions after the Service Request = %v, want none", p)
		}
		return nil
	})
	sc.Step(`^the paged PDU sessions (\d+) and (\d+) are logged as not re-activated$`, func(a, b int) error {
		if _, err := w.acceptInner(nas.MsgTypeServiceAccept); err != nil {
			return err
		}
		recs, err := w.pagedDropRecords()
		if err != nil {
			return err
		}
		if len(recs) != 1 || fmt.Sprint(recs[0]) != fmt.Sprint([]int{a, b}) {
			return fmt.Errorf("paged drop log records %v, want one with [%d %d]", recs, a, b)
		}
		return nil
	})
	sc.Step(`^the later Service Request sees no paged PDU sessions$`, func() error {
		if _, err := w.acceptInner(nas.MsgTypeServiceAccept); err != nil {
			return err
		}
		recs, err := w.pagedDropRecords()
		if err != nil {
			return err
		}
		if len(recs) != 1 { // only the first Service Request logged a drop
			return fmt.Errorf("%d paged drop log records after the later Service Request, want 1 (the first)", len(recs))
		}
		if p := w.ue.PagedPDUSessions(); len(p) != 0 {
			return fmt.Errorf("paged PDU sessions %v leaked into the later Service Request", p)
		}
		if w.sender.ics != 0 || len(w.sender.setups) != 0 {
			return fmt.Errorf("later Service Request sent ics=%d setups=%v, want none", w.sender.ics, w.sender.setups)
		}
		return nil
	})

	// ICS Response log procedure
	sc.Step(`^the gNB answers with an INITIAL CONTEXT SETUP RESPONSE carrying no PDU sessions$`, func() error {
		if !icsW.haveKind {
			return fmt.Errorf("no pending ICS kind was set")
		}
		if err := icsFailW.setup("imsi-001010000000001", icsW.pendKind, amfctx.GMMRegistered, nil); err != nil {
			return err
		}
		pdu, err := buildICSResponseNoSessions(icsFailW.ue.AMFUENGAPId, 7)
		if err != nil {
			return err
		}
		icsFailW.srv.DispatchNGAPForTest(context.Background(), icsFailW.gnb, pdu)
		icsFailW.srv.WaitUESerialForTest(icsFailW.ue.AMFUENGAPId)
		return nil
	})
	sc.Step(`^the ICS response log carries procedure "([^"]+)"$`, func(proc string) error {
		rec, err := icsResponseRecord()
		if err != nil {
			return err
		}
		if rec["procedure"] != proc {
			return fmt.Errorf("ICS response log procedure=%v, want %s", rec["procedure"], proc)
		}
		if got := icsFailW.ue.PendingICS(); got != amfctx.ICSNone {
			return fmt.Errorf("pending ICS after the response = %v, want ICSNone", got)
		}
		return nil
	})
}
