//go:build functional

// ngap_error_handling_steps_test.go — in-process godog steps for ngap_error_handling.feature
// (NGAP error handling: transfer syntax, abstract syntax, AP ID errors; TS 38.413 §10.2,
// §10.3.4.2, §10.3.5, §10.5, §10.6, §8.7.5). A real ngap.Server is driven through
// DispatchNGAPForTest with APER-encoded PDUs; the gNB association is a fake SCTP transport
// that captures every outbound PDU together with its PPID. Outbound ERROR INDICATIONs are
// decoded from the wire (Cause, Criticality Diagnostics, UE NGAP IDs presence).
package features_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/cucumber/godog"
	"github.com/free5gc/aper"
	"github.com/ishidawataru/sctp"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	amfngap "github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	libngap "github.com/francurieses/claudia-5gc/shared/ngap"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

// ehLink is one fake SCTP association: the gNB context plus the captured outbound PDUs.
type ehLink struct {
	gnb  *amfngap.GNBContext
	mu   sync.Mutex
	out  [][]byte
	ppid []uint32
}

func (l *ehLink) snapshot() ([][]byte, []uint32) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([][]byte{}, l.out...), append([]uint32{}, l.ppid...)
}

type ehLogBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *ehLogBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *ehLogBuf) lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Split(l.b.String(), "\n")
}

type ehWorld struct {
	srv       *amfngap.Server
	mgr       *amfctx.Manager
	logs      *ehLogBuf
	primary   *ehLink
	second    *ehLink
	fresh     *ehLink // association that has not performed NG Setup
	target    *ehLink // the association the current When step used
	nasMu     sync.Mutex
	nas       [][]byte
	ueAMFID   int64
	lastBytes int // number of outbound PDUs on target after the When step
}

var ehW ehWorld

// HandleNASMessage implements ngap.NASHandler and records every NAS PDU delivered.
func (w *ehWorld) HandleNASMessage(_ context.Context, _ *amfctx.UEContext, pdu []byte) error {
	w.nasMu.Lock()
	w.nas = append(w.nas, append([]byte{}, pdu...))
	w.nasMu.Unlock()
	return nil
}

func (w *ehWorld) nasCount() int {
	w.nasMu.Lock()
	defer w.nasMu.Unlock()
	return len(w.nas)
}

func (w *ehWorld) reset() {
	w.mgr = amfctx.NewManager(amfctx.AMFIdentity{}, nil, nil, nil)
	w.logs = &ehLogBuf{}
	w.srv = amfngap.NewServer("", w.mgr, w, amfngap.AMFConfig{Name: "5GC-AMF", MCC: "001", MNC: "01"},
		slog.New(slog.NewJSONHandler(w.logs, nil)))
	w.primary, w.second, w.fresh, w.target = nil, nil, nil, nil
	w.nas = nil
	w.ueAMFID = 0
}

func (w *ehWorld) newLink(addr string, id uint32) *ehLink {
	l := &ehLink{}
	l.gnb = &amfngap.GNBContext{
		Name:    addr,
		RANNode: amfngap.NewGlobalGNBForTest("001", "01", id, 32),
		UEs:     map[int64]*amfctx.UEContext{},
		IdleUEs: map[int64]*amfctx.UEContext{},
	}
	l.gnb.SetTransportForTest(addr, func(pdu []byte, info *sctp.SndRcvInfo) (int, error) {
		l.mu.Lock()
		l.out = append(l.out, append([]byte{}, pdu...))
		l.ppid = append(l.ppid, info.PPID)
		l.mu.Unlock()
		return len(pdu), nil
	})
	w.srv.AddGNBForTest(addr, l.gnb)
	return l
}

func (w *ehWorld) dispatch(l *ehLink, pdu []byte) {
	w.target = l
	w.srv.DispatchNGAPForTest(context.Background(), l.gnb, pdu)
	w.srv.WaitUESerialForTest(1)
}

// errorIndications decodes every outbound PDU of l, asserts PPID 60 and returns the EIs.
func (w *ehWorld) errorIndications(l *ehLink) ([]amfngap.ErrorIndicationView, error) {
	out, ppid := l.snapshot()
	var evs []amfngap.ErrorIndicationView
	for i, b := range out {
		if ppid[i] != 60 {
			return nil, fmt.Errorf("outbound PDU %d sent with SCTP PPID %d, want 60 (TS 38.412 §7)", i, ppid[i])
		}
		v, ok, err := amfngap.DecodeOutboundErrorIndicationForTest(b)
		if err != nil {
			return nil, fmt.Errorf("decode outbound PDU %d: %w", i, err)
		}
		if ok {
			evs = append(evs, v)
		}
	}
	return evs, nil
}

// theEI returns the single ERROR INDICATION sent on the target association.
func (w *ehWorld) theEI() (amfngap.ErrorIndicationView, error) {
	if w.target == nil {
		return amfngap.ErrorIndicationView{}, fmt.Errorf("no PDU was sent to the AMF yet")
	}
	evs, err := w.errorIndications(w.target)
	if err != nil {
		return amfngap.ErrorIndicationView{}, err
	}
	if len(evs) != 1 {
		return amfngap.ErrorIndicationView{}, fmt.Errorf("want exactly 1 ERROR INDICATION, got %d", len(evs))
	}
	return evs[0], nil
}

// failureMsg decodes the single outbound PDU of l as an UnsuccessfulOutcome with the given
// procedure code and returns it.
func ehFailurePDU(l *ehLink, procCode int64) (*ngapType.NGAPPDU, error) {
	out, ppid := l.snapshot()
	var found *ngapType.NGAPPDU
	for i, b := range out {
		if ppid[i] != 60 {
			return nil, fmt.Errorf("outbound PDU %d PPID %d, want 60", i, ppid[i])
		}
		p, err := libngap.Decoder(b)
		if err != nil {
			return nil, err
		}
		if p.Present == ngapType.NGAPPDUPresentUnsuccessfulOutcome && p.UnsuccessfulOutcome.ProcedureCode.Value == procCode {
			found = p
		}
	}
	if found == nil {
		return nil, fmt.Errorf("no UnsuccessfulOutcome with procedure code %d among %d outbound PDUs", procCode, len(out))
	}
	return found, nil
}

func ehCritName(v int64) string {
	switch aper.Enumerated(v) {
	case ngapType.CriticalityPresentReject:
		return "reject"
	case ngapType.CriticalityPresentIgnore:
		return "ignore"
	case ngapType.CriticalityPresentNotify:
		return "notify"
	}
	return fmt.Sprint(v)
}

func ehCritEnum(s string) (aper.Enumerated, error) {
	switch s {
	case "reject":
		return ngapType.CriticalityPresentReject, nil
	case "ignore":
		return ngapType.CriticalityPresentIgnore, nil
	case "notify":
		return ngapType.CriticalityPresentNotify, nil
	}
	return 0, fmt.Errorf("unknown criticality %q", s)
}

func ehToeName(v int64) string {
	switch aper.Enumerated(v) {
	case ngapType.TypeOfErrorPresentNotUnderstood:
		return "not-understood"
	case ngapType.TypeOfErrorPresentMissing:
		return "missing"
	}
	return fmt.Sprint(v)
}

func ehProtoCauseValue(name string) (int64, error) {
	switch name {
	case "transfer-syntax-error":
		return int64(ngapType.CauseProtocolPresentTransferSyntaxError), nil
	case "abstract-syntax-error-reject":
		return int64(ngapType.CauseProtocolPresentAbstractSyntaxErrorReject), nil
	case "abstract-syntax-error-ignore-and-notify":
		return int64(ngapType.CauseProtocolPresentAbstractSyntaxErrorIgnoreAndNotify), nil
	case "semantic-error":
		return int64(ngapType.CauseProtocolPresentSemanticError), nil
	}
	return 0, fmt.Errorf("unknown protocol cause %q", name)
}

func ehProtoCauseName(v int64) string {
	for _, n := range []string{"transfer-syntax-error", "abstract-syntax-error-reject", "abstract-syntax-error-ignore-and-notify", "semantic-error"} {
		if x, _ := ehProtoCauseValue(n); x == v {
			return n
		}
	}
	return fmt.Sprint(v)
}

// ---- PDU builders -----------------------------------------------------------

func ehEncode(pdu ngapType.NGAPPDU) ([]byte, error) { return libngap.Encoder(pdu) }

func ehUplinkNAS(amf, ran int64, withNAS bool) ([]byte, error) {
	msg := &ngapType.UplinkNASTransport{}
	add := func(id int64, v ngapType.UplinkNASTransportIEsValue) {
		msg.ProtocolIEs.List = append(msg.ProtocolIEs.List, ngapType.UplinkNASTransportIEs{
			Id: ngapType.ProtocolIEID{Value: id}, Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject}, Value: v})
	}
	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.UplinkNASTransportIEsValue{
		Present: ngapType.UplinkNASTransportIEsPresentAMFUENGAPID, AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amf}})
	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.UplinkNASTransportIEsValue{
		Present: ngapType.UplinkNASTransportIEsPresentRANUENGAPID, RANUENGAPID: &ngapType.RANUENGAPID{Value: ran}})
	if withNAS {
		add(ngapType.ProtocolIEIDNASPDU, ngapType.UplinkNASTransportIEsValue{
			Present: ngapType.UplinkNASTransportIEsPresentNASPDU, NASPDU: &ngapType.NASPDU{Value: aper.OctetString{0x7E, 0x00, 0x01}}})
	}
	return ehEncode(ngapType.NGAPPDU{Present: ngapType.NGAPPDUPresentInitiatingMessage, InitiatingMessage: &ngapType.InitiatingMessage{
		ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeUplinkNASTransport},
		Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
		Value: ngapType.InitiatingMessageValue{
			Present: ngapType.InitiatingMessagePresentUplinkNASTransport, UplinkNASTransport: msg}}})
}

func ehHandoverRequired(amf, ran int64, withTargetID bool) ([]byte, error) {
	msg := &ngapType.HandoverRequired{}
	add := func(id int64, crit aper.Enumerated, v ngapType.HandoverRequiredIEsValue) {
		msg.ProtocolIEs.List = append(msg.ProtocolIEs.List, ngapType.HandoverRequiredIEs{
			Id: ngapType.ProtocolIEID{Value: id}, Criticality: ngapType.Criticality{Value: crit}, Value: v})
	}
	rej, ign := aper.Enumerated(ngapType.CriticalityPresentReject), aper.Enumerated(ngapType.CriticalityPresentIgnore)
	add(ngapType.ProtocolIEIDAMFUENGAPID, rej, ngapType.HandoverRequiredIEsValue{Present: ngapType.HandoverRequiredIEsPresentAMFUENGAPID, AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amf}})
	add(ngapType.ProtocolIEIDRANUENGAPID, rej, ngapType.HandoverRequiredIEsValue{Present: ngapType.HandoverRequiredIEsPresentRANUENGAPID, RANUENGAPID: &ngapType.RANUENGAPID{Value: ran}})
	add(ngapType.ProtocolIEIDHandoverType, rej, ngapType.HandoverRequiredIEsValue{Present: ngapType.HandoverRequiredIEsPresentHandoverType, HandoverType: &ngapType.HandoverType{Value: ngapType.HandoverTypePresentIntra5gs}})
	cause := ngapType.Cause{Present: ngapType.CausePresentRadioNetwork, RadioNetwork: &ngapType.CauseRadioNetwork{Value: 0}}
	add(ngapType.ProtocolIEIDCause, ign, ngapType.HandoverRequiredIEsValue{Present: ngapType.HandoverRequiredIEsPresentCause, Cause: &cause})
	if withTargetID {
		gid := aper.BitString{Bytes: []byte{0x00, 0x00, 0x01, 0x00}, BitLength: 32}
		add(ngapType.ProtocolIEIDTargetID, rej, ngapType.HandoverRequiredIEsValue{Present: ngapType.HandoverRequiredIEsPresentTargetID,
			TargetID: &ngapType.TargetID{Present: ngapType.TargetIDPresentTargetRANNodeID, TargetRANNodeID: &ngapType.TargetRANNodeID{
				GlobalRANNodeID: ngapType.GlobalRANNodeID{Present: ngapType.GlobalRANNodeIDPresentGlobalGNBID, GlobalGNBID: &ngapType.GlobalGNBID{
					PLMNIdentity: ngapType.PLMNIdentity{Value: aper.OctetString{0x00, 0xF1, 0x10}},
					GNBID:        ngapType.GNBID{Present: ngapType.GNBIDPresentGNBID, GNBID: &gid}}},
				SelectedTAI: ngapType.TAI{PLMNIdentity: ngapType.PLMNIdentity{Value: aper.OctetString{0x00, 0xF1, 0x10}}, TAC: ngapType.TAC{Value: aper.OctetString{0, 0, 1}}}}}})
	}
	add(ngapType.ProtocolIEIDPDUSessionResourceListHORqd, rej, ngapType.HandoverRequiredIEsValue{Present: ngapType.HandoverRequiredIEsPresentPDUSessionResourceListHORqd,
		PDUSessionResourceListHORqd: &ngapType.PDUSessionResourceListHORqd{List: []ngapType.PDUSessionResourceItemHORqd{
			{PDUSessionID: ngapType.PDUSessionID{Value: 5}, HandoverRequiredTransfer: aper.OctetString{0x01}}}}})
	add(ngapType.ProtocolIEIDSourceToTargetTransparentContainer, rej, ngapType.HandoverRequiredIEsValue{Present: ngapType.HandoverRequiredIEsPresentSourceToTargetTransparentContainer,
		SourceToTargetTransparentContainer: &ngapType.SourceToTargetTransparentContainer{Value: aper.OctetString{0x02}}})
	return ehEncode(ngapType.NGAPPDU{Present: ngapType.NGAPPDUPresentInitiatingMessage, InitiatingMessage: &ngapType.InitiatingMessage{
		ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeHandoverPreparation},
		Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
		Value:         ngapType.InitiatingMessageValue{Present: ngapType.InitiatingMessagePresentHandoverRequired, HandoverRequired: msg}}})
}

func ehUEContextReleaseRequest(amf, ran int64) ([]byte, error) {
	msg := &ngapType.UEContextReleaseRequest{}
	add := func(id int64, crit aper.Enumerated, v ngapType.UEContextReleaseRequestIEsValue) {
		msg.ProtocolIEs.List = append(msg.ProtocolIEs.List, ngapType.UEContextReleaseRequestIEs{
			Id: ngapType.ProtocolIEID{Value: id}, Criticality: ngapType.Criticality{Value: crit}, Value: v})
	}
	rej, ign := aper.Enumerated(ngapType.CriticalityPresentReject), aper.Enumerated(ngapType.CriticalityPresentIgnore)
	add(ngapType.ProtocolIEIDAMFUENGAPID, rej, ngapType.UEContextReleaseRequestIEsValue{Present: ngapType.UEContextReleaseRequestIEsPresentAMFUENGAPID, AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amf}})
	add(ngapType.ProtocolIEIDRANUENGAPID, rej, ngapType.UEContextReleaseRequestIEsValue{Present: ngapType.UEContextReleaseRequestIEsPresentRANUENGAPID, RANUENGAPID: &ngapType.RANUENGAPID{Value: ran}})
	cause := ngapType.Cause{Present: ngapType.CausePresentRadioNetwork, RadioNetwork: &ngapType.CauseRadioNetwork{Value: ngapType.CauseRadioNetworkPresentUserInactivity}}
	add(ngapType.ProtocolIEIDCause, ign, ngapType.UEContextReleaseRequestIEsValue{Present: ngapType.UEContextReleaseRequestIEsPresentCause, Cause: &cause})
	return ehEncode(ngapType.NGAPPDU{Present: ngapType.NGAPPDUPresentInitiatingMessage, InitiatingMessage: &ngapType.InitiatingMessage{
		ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeUEContextReleaseRequest},
		Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
		Value:         ngapType.InitiatingMessageValue{Present: ngapType.InitiatingMessagePresentUEContextReleaseRequest, UEContextReleaseRequest: msg}}})
}

func ehUEContextReleaseComplete(amf, ran int64) ([]byte, error) {
	msg := &ngapType.UEContextReleaseComplete{}
	add := func(id int64, v ngapType.UEContextReleaseCompleteIEsValue) {
		msg.ProtocolIEs.List = append(msg.ProtocolIEs.List, ngapType.UEContextReleaseCompleteIEs{
			Id: ngapType.ProtocolIEID{Value: id}, Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore}, Value: v})
	}
	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.UEContextReleaseCompleteIEsValue{Present: ngapType.UEContextReleaseCompleteIEsPresentAMFUENGAPID, AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amf}})
	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.UEContextReleaseCompleteIEsValue{Present: ngapType.UEContextReleaseCompleteIEsPresentRANUENGAPID, RANUENGAPID: &ngapType.RANUENGAPID{Value: ran}})
	return ehEncode(ngapType.NGAPPDU{Present: ngapType.NGAPPDUPresentSuccessfulOutcome, SuccessfulOutcome: &ngapType.SuccessfulOutcome{
		ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeUEContextRelease},
		Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
		Value:         ngapType.SuccessfulOutcomeValue{Present: ngapType.SuccessfulOutcomePresentUEContextReleaseComplete, UEContextReleaseComplete: msg}}})
}

func ehICSResponse(amf, ran int64) ([]byte, error) {
	msg := &ngapType.InitialContextSetupResponse{}
	add := func(id int64, v ngapType.InitialContextSetupResponseIEsValue) {
		msg.ProtocolIEs.List = append(msg.ProtocolIEs.List, ngapType.InitialContextSetupResponseIEs{
			Id: ngapType.ProtocolIEID{Value: id}, Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore}, Value: v})
	}
	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.InitialContextSetupResponseIEsValue{Present: ngapType.InitialContextSetupResponseIEsPresentAMFUENGAPID, AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amf}})
	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.InitialContextSetupResponseIEsValue{Present: ngapType.InitialContextSetupResponseIEsPresentRANUENGAPID, RANUENGAPID: &ngapType.RANUENGAPID{Value: ran}})
	return ehEncode(ngapType.NGAPPDU{Present: ngapType.NGAPPDUPresentSuccessfulOutcome, SuccessfulOutcome: &ngapType.SuccessfulOutcome{
		ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeInitialContextSetup},
		Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
		Value:         ngapType.SuccessfulOutcomeValue{Present: ngapType.SuccessfulOutcomePresentInitialContextSetupResponse, InitialContextSetupResponse: msg}}})
}

func ehNGSetupRequest() ([]byte, error) {
	plmn := aper.OctetString{0x00, 0xF1, 0x10}
	msg := &ngapType.NGSetupRequest{}
	add := func(id int64, crit aper.Enumerated, v ngapType.NGSetupRequestIEsValue) {
		msg.ProtocolIEs.List = append(msg.ProtocolIEs.List, ngapType.NGSetupRequestIEs{
			Id: ngapType.ProtocolIEID{Value: id}, Criticality: ngapType.Criticality{Value: crit}, Value: v})
	}
	rej, ign := aper.Enumerated(ngapType.CriticalityPresentReject), aper.Enumerated(ngapType.CriticalityPresentIgnore)
	add(ngapType.ProtocolIEIDGlobalRANNodeID, rej, ngapType.NGSetupRequestIEsValue{Present: ngapType.NGSetupRequestIEsPresentGlobalRANNodeID,
		GlobalRANNodeID: &ngapType.GlobalRANNodeID{Present: ngapType.GlobalRANNodeIDPresentGlobalGNBID, GlobalGNBID: &ngapType.GlobalGNBID{
			PLMNIdentity: ngapType.PLMNIdentity{Value: plmn},
			GNBID:        ngapType.GNBID{Present: ngapType.GNBIDPresentGNBID, GNBID: &aper.BitString{Bytes: []byte{0x00, 0x00, 0x09, 0x00}, BitLength: 32}}}}})
	add(ngapType.ProtocolIEIDRANNodeName, ign, ngapType.NGSetupRequestIEsValue{Present: ngapType.NGSetupRequestIEsPresentRANNodeName,
		RANNodeName: &ngapType.RANNodeName{Value: "gnb-fresh"}})
	add(ngapType.ProtocolIEIDSupportedTAList, rej, ngapType.NGSetupRequestIEsValue{Present: ngapType.NGSetupRequestIEsPresentSupportedTAList,
		SupportedTAList: &ngapType.SupportedTAList{List: []ngapType.SupportedTAItem{{
			TAC: ngapType.TAC{Value: aper.OctetString{0, 0, 1}},
			BroadcastPLMNList: ngapType.BroadcastPLMNList{List: []ngapType.BroadcastPLMNItem{{
				PLMNIdentity: ngapType.PLMNIdentity{Value: plmn},
				TAISliceSupportList: ngapType.SliceSupportList{List: []ngapType.SliceSupportItem{
					{SNSSAI: ngapType.SNSSAI{SST: ngapType.SST{Value: aper.OctetString{1}}}}}}}}}}}}})
	add(ngapType.ProtocolIEIDDefaultPagingDRX, ign, ngapType.NGSetupRequestIEsValue{Present: ngapType.NGSetupRequestIEsPresentDefaultPagingDRX,
		DefaultPagingDRX: &ngapType.PagingDRX{Value: ngapType.PagingDRXPresentV128}})
	return ehEncode(ngapType.NGAPPDU{Present: ngapType.NGAPPDUPresentInitiatingMessage, InitiatingMessage: &ngapType.InitiatingMessage{
		ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeNGSetup},
		Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
		Value:         ngapType.InitiatingMessageValue{Present: ngapType.InitiatingMessagePresentNGSetupRequest, NGSetupRequest: msg}}})
}

func ehInject(pdu []byte, id uint16, crit string) ([]byte, error) {
	c, err := ehCritEnum(crit)
	if err != nil {
		return nil, err
	}
	return amfngap.InjectProtocolIEForTest(pdu, id, c, []byte{0xAA, 0xBB})
}

// ---- step implementations -----------------------------------------------------

func (w *ehWorld) sendTo(l *ehLink, pdu []byte, err error) error {
	if err != nil {
		return fmt.Errorf("build PDU: %w", err)
	}
	if l == nil {
		return fmt.Errorf("no such gNB association")
	}
	w.dispatch(l, pdu)
	return nil
}

func (w *ehWorld) logHas(substrs ...string) bool {
	for _, ln := range w.logs.lines() {
		ok := ln != ""
		for _, s := range substrs {
			if !strings.Contains(ln, s) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// ehReleaseCommandSent reports whether the AMF sent a UE CONTEXT RELEASE COMMAND on l.
func ehReleaseCommandSent(l *ehLink) (bool, error) {
	out, _ := l.snapshot()
	for _, b := range out {
		p, err := libngap.Decoder(b)
		if err != nil {
			return false, err
		}
		if p.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
			p.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeUEContextRelease {
			return true, nil
		}
	}
	return false, nil
}

func initNGAPErrorHandlingSteps(sc *godog.ScenarioContext) {
	w := &ehW
	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		w.reset()
		return ctx, nil
	})

	// ---- Background / Given ----
	sc.Step(`^the AMF NGAP server has a gNB connected over a fake SCTP association$`, func() error {
		w.primary = w.newLink("10.0.0.1:38412", 1)
		return nil
	})
	sc.Step(`^the gNB has completed NG Setup$`, func() error {
		w.srv.CompleteNGSetupForTest(w.primary.gnb)
		return nil
	})
	sc.Step(`^a UE is registered with AMF UE NGAP ID (\d+) and RAN UE NGAP ID (\d+) on that gNB$`, func(amf, ran int) error {
		ue := w.mgr.AllocateUEContext(int64(ran))
		if ue.AMFUENGAPId != int64(amf) {
			return fmt.Errorf("allocated AMF UE NGAP ID %d, want %d", ue.AMFUENGAPId, amf)
		}
		w.ueAMFID = ue.AMFUENGAPId
		w.primary.gnb.UEs[int64(ran)] = ue
		return nil
	})
	sc.Step(`^a second gNB has completed NG Setup$`, func() error {
		w.second = w.newLink("10.0.0.2:38412", 2)
		w.srv.CompleteNGSetupForTest(w.second.gnb)
		return nil
	})
	sc.Step(`^a new gNB association that has not yet performed NG Setup$`, func() error {
		w.fresh = w.newLink("10.0.0.3:38412", 9)
		return nil
	})
	sc.Step(`^the AMF has sent an INITIAL CONTEXT SETUP REQUEST for AMF UE NGAP ID (\d+)$`, func(amf int) error {
		ue, ok := w.mgr.GetByNGAPId(int64(amf))
		if !ok {
			return fmt.Errorf("UE %d not found", amf)
		}
		ue.CMState = amfctx.CMConnected
		return nil
	})

	// ---- When ----
	sc.Step(`^the gNB sends a PDU of (\d+) random bytes that is not valid APER$`, func(n int) error {
		pdu := []byte{0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}[:n]
		if _, err := libngap.Decoder(pdu); err == nil {
			return fmt.Errorf("test PDU unexpectedly decodes as APER")
		}
		return w.sendTo(w.primary, pdu, nil)
	})
	sc.Step(`^the gNB sends an UPLINK NAS TRANSPORT for AMF UE NGAP ID (\d+) and RAN UE NGAP ID (\d+) carrying an unknown IE id (\d+) with criticality "([^"]+)"$`,
		func(amf, ran, id int, crit string) error {
			b, err := ehUplinkNAS(int64(amf), int64(ran), true)
			if err == nil {
				b, err = ehInject(b, uint16(id), crit)
			}
			return w.sendTo(w.primary, b, err)
		})
	sc.Step(`^the gNB sends a HANDOVER REQUIRED for AMF UE NGAP ID (\d+) carrying an unknown IE id (\d+) with criticality "([^"]+)"$`,
		func(amf, id int, crit string) error {
			b, err := ehHandoverRequired(int64(amf), 101, true)
			if err == nil {
				b, err = ehInject(b, uint16(id), crit)
			}
			return w.sendTo(w.primary, b, err)
		})
	sc.Step(`^that gNB sends an NG SETUP REQUEST carrying an unknown IE id (\d+) with criticality "([^"]+)"$`,
		func(id int, crit string) error {
			b, err := ehNGSetupRequest()
			if err == nil {
				b, err = ehInject(b, uint16(id), crit)
			}
			return w.sendTo(w.fresh, b, err)
		})
	sc.Step(`^the gNB sends a UE CONTEXT RELEASE REQUEST for AMF UE NGAP ID (\d+) and RAN UE NGAP ID (\d+) carrying an unknown IE id (\d+) with criticality "([^"]+)"$`,
		func(amf, ran, id int, crit string) error {
			b, err := ehUEContextReleaseRequest(int64(amf), int64(ran))
			if err == nil {
				b, err = ehInject(b, uint16(id), crit)
			}
			return w.sendTo(w.primary, b, err)
		})
	sc.Step(`^the gNB sends an INITIAL CONTEXT SETUP RESPONSE for AMF UE NGAP ID (\d+) and RAN UE NGAP ID (\d+) carrying an unknown IE id (\d+) with criticality "([^"]+)"$`,
		func(amf, ran, id int, crit string) error {
			b, err := ehICSResponse(int64(amf), int64(ran))
			if err == nil {
				b, err = ehInject(b, uint16(id), crit)
			}
			return w.sendTo(w.primary, b, err)
		})
	sc.Step(`^the gNB sends an UPLINK NAS TRANSPORT for AMF UE NGAP ID (\d+) and RAN UE NGAP ID (\d+) lacking the mandatory NAS-PDU IE id (\d+)$`,
		func(amf, ran, id int) error {
			if int64(id) != ngapType.ProtocolIEIDNASPDU {
				return fmt.Errorf("IE id %d is not NAS-PDU", id)
			}
			b, err := ehUplinkNAS(int64(amf), int64(ran), false)
			return w.sendTo(w.primary, b, err)
		})
	sc.Step(`^the gNB sends a HANDOVER REQUIRED for AMF UE NGAP ID (\d+) lacking the mandatory Target ID IE id (\d+)$`,
		func(amf, id int) error {
			if int64(id) != ngapType.ProtocolIEIDTargetID {
				return fmt.Errorf("IE id %d is not Target ID", id)
			}
			b, err := ehHandoverRequired(int64(amf), 101, false)
			return w.sendTo(w.primary, b, err)
		})
	sc.Step(`^the gNB sends an ERROR INDICATION with Cause protocol "([^"]+)" carrying an unknown IE id (\d+) with criticality "([^"]+)"$`,
		func(cause string, id int, crit string) error {
			cv, err := ehProtoCauseValue(cause)
			if err != nil {
				return err
			}
			b, err := amfngap.BuildErrorIndication(amfngap.ErrorIndicationParams{CausePresent: ngapType.CausePresentProtocol, CauseValue: cv})
			if err == nil {
				b, err = ehInject(b, uint16(id), crit)
			}
			return w.sendTo(w.primary, b, err)
		})
	sc.Step(`^the gNB sends a truncated ERROR INDICATION PDU that fails APER decoding but has procedure code (\d+)$`,
		func(proc int) error {
			ei, err := amfngap.BuildErrorIndication(amfngap.ErrorIndicationParams{CausePresent: ngapType.CausePresentProtocol, CauseValue: 0})
			if err != nil {
				return err
			}
			// Keep the NGAP-PDU header (choice + procedure code) so the PDU stays identifiable.
			for n := len(ei) - 1; n >= 3; n-- {
				if _, derr := libngap.Decoder(ei[:n]); derr != nil {
					if int(ei[1]) != proc {
						return fmt.Errorf("ERROR INDICATION procedure code octet is %d, want %d", ei[1], proc)
					}
					return w.sendTo(w.primary, ei[:n], nil)
				}
			}
			return fmt.Errorf("no truncation of the ERROR INDICATION fails APER decoding")
		})
	sc.Step(`^the gNB sends an UPLINK NAS TRANSPORT for AMF UE NGAP ID (\d+) and RAN UE NGAP ID (\d+)$`,
		func(amf, ran int) error {
			b, err := ehUplinkNAS(int64(amf), int64(ran), true)
			return w.sendTo(w.primary, b, err)
		})
	sc.Step(`^the gNB sends a well-formed UPLINK NAS TRANSPORT for AMF UE NGAP ID (\d+) and RAN UE NGAP ID (\d+)$`,
		func(amf, ran int) error {
			b, err := ehUplinkNAS(int64(amf), int64(ran), true)
			return w.sendTo(w.primary, b, err)
		})
	sc.Step(`^the gNB sends a UE CONTEXT RELEASE COMPLETE for AMF UE NGAP ID (\d+) and RAN UE NGAP ID (\d+)$`,
		func(amf, ran int) error {
			b, err := ehUEContextReleaseComplete(int64(amf), int64(ran))
			return w.sendTo(w.primary, b, err)
		})

	// ---- Then: ERROR INDICATION presence / content ----
	sc.Step(`^the AMF sends an ERROR INDICATION to the gNB$`, func() error {
		_, err := w.theEI()
		return err
	})
	sc.Step(`^the AMF sends an ERROR INDICATION on that association$`, func() error {
		if w.fresh == nil {
			return fmt.Errorf("no fresh association")
		}
		w.target = w.fresh
		_, err := w.theEI()
		return err
	})
	sc.Step(`^the AMF sends no ERROR INDICATION to the gNB$`, func() error {
		evs, err := w.errorIndications(w.primary)
		if err != nil {
			return err
		}
		if len(evs) != 0 {
			return fmt.Errorf("AMF sent %d ERROR INDICATION(s), want none", len(evs))
		}
		return nil
	})
	sc.Step(`^the AMF sends an ERROR INDICATION "(yes|no)"$`, func(want string) error {
		evs, err := w.errorIndications(w.primary)
		if err != nil {
			return err
		}
		if (len(evs) == 1) != (want == "yes") || len(evs) > 1 {
			return fmt.Errorf("ERROR INDICATION count = %d, want %q", len(evs), want)
		}
		return nil
	})
	sc.Step(`^the ERROR INDICATION has Cause protocol "([^"]+)"$`, func(name string) error {
		ev, err := w.theEI()
		if err != nil {
			return err
		}
		want, err := ehProtoCauseValue(name)
		if err != nil {
			return err
		}
		if ev.CausePresent != ngapType.CausePresentProtocol || ev.CauseValue != want {
			return fmt.Errorf("Cause = group %d value %d (%s), want protocol %q", ev.CausePresent, ev.CauseValue, ehProtoCauseName(ev.CauseValue), name)
		}
		return nil
	})
	sc.Step(`^the ERROR INDICATION has Cause radio network "unknown-local-UE-NGAP-ID"$`, func() error {
		ev, err := w.theEI()
		if err != nil {
			return err
		}
		if ev.CausePresent != ngapType.CausePresentRadioNetwork || ev.CauseValue != int64(ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID) {
			return fmt.Errorf("Cause = group %d value %d, want radioNetwork unknown-local-UE-NGAP-ID", ev.CausePresent, ev.CauseValue)
		}
		return nil
	})
	sc.Step(`^the ERROR INDICATION contains neither AMF UE NGAP ID nor RAN UE NGAP ID$`, func() error {
		ev, err := w.theEI()
		if err != nil {
			return err
		}
		if ev.HasAMFUENGAPID || ev.HasRANUENGAPID {
			return fmt.Errorf("non-UE-associated ERROR INDICATION carries IDs: %+v", ev)
		}
		return nil
	})
	sc.Step(`^the ERROR INDICATION contains AMF UE NGAP ID (\d+) and RAN UE NGAP ID (\d+)$`, func(amf, ran int) error {
		ev, err := w.theEI()
		if err != nil {
			return err
		}
		if !ev.HasAMFUENGAPID || !ev.HasRANUENGAPID || ev.AMFUENGAPID != int64(amf) || ev.RANUENGAPID != int64(ran) {
			return fmt.Errorf("UE IDs = AMF %v/%d RAN %v/%d, want %d/%d", ev.HasAMFUENGAPID, ev.AMFUENGAPID, ev.HasRANUENGAPID, ev.RANUENGAPID, amf, ran)
		}
		return nil
	})
	sc.Step(`^the ERROR INDICATION Criticality Diagnostics has Procedure Code (\d+), Triggering Message "initiating message" and Procedure Criticality "ignore"$`,
		func(pc int) error {
			ev, err := w.theEI()
			if err != nil {
				return err
			}
			if !ev.HasCD || ev.CDProcedureCode != int64(pc) || ev.CDTriggeringMessage != int64(ngapType.TriggeringMessagePresentInitiatingMessage) ||
				ev.CDProcedureCriticality != int64(ngapType.CriticalityPresentIgnore) {
				return fmt.Errorf("CD header = proc %d trig %d crit %d, want %d/initiating/ignore", ev.CDProcedureCode, ev.CDTriggeringMessage, ev.CDProcedureCriticality, pc)
			}
			return nil
		})
	sc.Step(`^the ERROR INDICATION Criticality Diagnostics has Procedure Code (\d+) and Triggering Message "initiating message"$`,
		func(pc int) error {
			ev, err := w.theEI()
			if err != nil {
				return err
			}
			if !ev.HasCD || ev.CDProcedureCode != int64(pc) || ev.CDTriggeringMessage != int64(ngapType.TriggeringMessagePresentInitiatingMessage) {
				return fmt.Errorf("CD header = proc %d trig %d, want %d/initiating", ev.CDProcedureCode, ev.CDTriggeringMessage, pc)
			}
			return nil
		})
	sc.Step(`^the ERROR INDICATION Criticality Diagnostics has Procedure Criticality "ignore"$`, func() error {
		ev, err := w.theEI()
		if err != nil {
			return err
		}
		if !ev.HasCD || ev.CDProcedureCriticality != int64(ngapType.CriticalityPresentIgnore) {
			return fmt.Errorf("Procedure Criticality = %d, want ignore", ev.CDProcedureCriticality)
		}
		return nil
	})
	sc.Step(`^the Criticality Diagnostics lists IE id (\d+) with IE Criticality "([^"]+)" and Type of Error "([^"]+)"$`,
		func(id int, crit, toe string) error {
			ev, err := w.theEI()
			if err != nil {
				return err
			}
			if len(ev.CDIEs) != 1 {
				return fmt.Errorf("CD lists %d IEs, want 1: %+v", len(ev.CDIEs), ev.CDIEs)
			}
			it := ev.CDIEs[0]
			if it.IEID != int64(id) || ehCritName(it.IECriticality) != crit || ehToeName(it.TypeOfError) != toe {
				return fmt.Errorf("CD item = id %d crit %s toe %s, want %d/%s/%s", it.IEID, ehCritName(it.IECriticality), ehToeName(it.TypeOfError), id, crit, toe)
			}
			return nil
		})

	// ---- Then: failure messages with Criticality Diagnostics ----
	sc.Step(`^the AMF sends a HANDOVER PREPARATION FAILURE to the gNB$`, func() error {
		_, err := ehFailurePDU(w.primary, ngapType.ProcedureCodeHandoverPreparation)
		return err
	})
	sc.Step(`^the HANDOVER PREPARATION FAILURE Criticality Diagnostics lists IE id (\d+) with IE Criticality "([^"]+)" and Type of Error "([^"]+)"$`,
		func(id int, crit, toe string) error {
			p, err := ehFailurePDU(w.primary, ngapType.ProcedureCodeHandoverPreparation)
			if err != nil {
				return err
			}
			var cd *ngapType.CriticalityDiagnostics
			for _, ie := range p.UnsuccessfulOutcome.Value.HandoverPreparationFailure.ProtocolIEs.List {
				if ie.Value.CriticalityDiagnostics != nil {
					cd = ie.Value.CriticalityDiagnostics
				}
			}
			if cd == nil || cd.IEsCriticalityDiagnostics == nil || len(cd.IEsCriticalityDiagnostics.List) != 1 {
				return fmt.Errorf("HANDOVER PREPARATION FAILURE lacks a Criticality Diagnostics with one IE item: %+v", cd)
			}
			it := cd.IEsCriticalityDiagnostics.List[0]
			if it.IEID.Value != int64(id) || ehCritName(int64(it.IECriticality.Value)) != crit || ehToeName(int64(it.TypeOfError.Value)) != toe {
				return fmt.Errorf("CD item = id %d crit %s toe %s, want %d/%s/%s", it.IEID.Value,
					ehCritName(int64(it.IECriticality.Value)), ehToeName(int64(it.TypeOfError.Value)), id, crit, toe)
			}
			return nil
		})
	sc.Step(`^the AMF sends an NG SETUP FAILURE on that association$`, func() error {
		if w.fresh == nil {
			return fmt.Errorf("no fresh association")
		}
		w.target = w.fresh
		_, err := ehFailurePDU(w.fresh, ngapType.ProcedureCodeNGSetup)
		return err
	})
	sc.Step(`^the NG SETUP FAILURE has Cause protocol "([^"]+)"$`, func(name string) error {
		p, err := ehFailurePDU(w.fresh, ngapType.ProcedureCodeNGSetup)
		if err != nil {
			return err
		}
		for _, ie := range p.UnsuccessfulOutcome.Value.NGSetupFailure.ProtocolIEs.List {
			if ie.Value.Cause != nil {
				present, val, _ := amfngap.CauseFromNGAPForTest(*ie.Value.Cause)
				if present == ngapType.CausePresentProtocol && name == "abstract-syntax-error-reject" &&
					val == int64(ngapType.CauseProtocolPresentAbstractSyntaxErrorReject) {
					return nil
				}
				return fmt.Errorf("NG SETUP FAILURE cause = %d/%d, want protocol %s", present, val, name)
			}
		}
		return fmt.Errorf("NG SETUP FAILURE has no Cause IE")
	})
	sc.Step(`^the NG SETUP FAILURE Criticality Diagnostics lists IE id (\d+) with IE Criticality "([^"]+)" and Type of Error "([^"]+)"$`,
		func(id int, crit, toe string) error {
			p, err := ehFailurePDU(w.fresh, ngapType.ProcedureCodeNGSetup)
			if err != nil {
				return err
			}
			var cd *ngapType.CriticalityDiagnostics
			for _, ie := range p.UnsuccessfulOutcome.Value.NGSetupFailure.ProtocolIEs.List {
				if ie.Value.CriticalityDiagnostics != nil {
					cd = ie.Value.CriticalityDiagnostics
				}
			}
			if cd == nil || cd.IEsCriticalityDiagnostics == nil || len(cd.IEsCriticalityDiagnostics.List) != 1 {
				return fmt.Errorf("NG SETUP FAILURE lacks a Criticality Diagnostics with one IE item: %+v", cd)
			}
			it := cd.IEsCriticalityDiagnostics.List[0]
			if it.IEID.Value != int64(id) || ehCritName(int64(it.IECriticality.Value)) != crit || ehToeName(int64(it.TypeOfError.Value)) != toe {
				return fmt.Errorf("CD item = id %d crit %s toe %s, want %d/%s/%s", it.IEID.Value,
					ehCritName(int64(it.IECriticality.Value)), ehToeName(int64(it.TypeOfError.Value)), id, crit, toe)
			}
			return nil
		})
	sc.Step(`^the AMF sends no ERROR INDICATION on that association$`, func() error {
		if w.fresh == nil {
			return fmt.Errorf("no fresh association")
		}
		evs, err := w.errorIndications(w.fresh)
		if err != nil {
			return err
		}
		if len(evs) != 0 {
			return fmt.Errorf("AMF sent %d ERROR INDICATION(s), want none", len(evs))
		}
		return nil
	})
	sc.Step(`^the AMF sends no HANDOVER REQUEST to the second gNB$`, func() error {
		if w.second == nil {
			return fmt.Errorf("no second gNB")
		}
		out, _ := w.second.snapshot()
		if len(out) != 0 {
			return fmt.Errorf("second gNB received %d PDU(s), want 0", len(out))
		}
		return nil
	})

	// ---- Then: NAS delivery / processing ----
	sc.Step(`^the NAS PDU of the UPLINK NAS TRANSPORT was delivered to the NAS layer$`, func() error {
		if n := w.nasCount(); n != 1 {
			return fmt.Errorf("%d NAS PDU(s) delivered, want 1", n)
		}
		return nil
	})
	sc.Step(`^the NAS PDU of the UPLINK NAS TRANSPORT was not delivered to the NAS layer$`, func() error {
		if n := w.nasCount(); n != 0 {
			return fmt.Errorf("%d NAS PDU(s) delivered, want 0", n)
		}
		return nil
	})
	sc.Step(`^no NAS PDU is delivered to the NAS layer$`, func() error {
		if n := w.nasCount(); n != 0 {
			return fmt.Errorf("%d NAS PDU(s) delivered, want 0", n)
		}
		return nil
	})
	sc.Step(`^the message is processed with its understood IEs "(yes|no)"$`, func(want string) error {
		sent, err := ehReleaseCommandSent(w.primary)
		if err != nil {
			return err
		}
		if sent != (want == "yes") {
			return fmt.Errorf("UE CONTEXT RELEASE COMMAND sent = %v, want processed=%q", sent, want)
		}
		return nil
	})

	// ---- Then: counts, state, logs ----
	sc.Step(`^the AMF sends exactly (\d+) NGAP messages? to the gNB$`, func(n int) error {
		out, _ := w.primary.snapshot()
		if len(out) != n {
			return fmt.Errorf("AMF sent %d NGAP message(s), want %d", len(out), n)
		}
		return nil
	})
	sc.Step(`^the AMF sends (\d+) NGAP messages to the gNB$`, func(n int) error {
		out, _ := w.primary.snapshot()
		if len(out) != n {
			return fmt.Errorf("AMF sent %d NGAP message(s), want %d", len(out), n)
		}
		return nil
	})
	sc.Step(`^the gNB is not listed as "([^"]+)"$`, func(state string) error {
		if w.fresh == nil {
			return fmt.Errorf("no fresh association")
		}
		for _, s := range w.srv.GNBSnapshots() {
			if s.SCTP.RemoteAddrs != nil && string(s.State) == state && s.RANNodeName == "gnb-fresh" {
				return fmt.Errorf("gNB listed as %s although NG Setup was rejected", state)
			}
		}
		if string(w.fresh.gnb.State) == state {
			return fmt.Errorf("gNB state = %s", w.fresh.gnb.State)
		}
		return nil
	})
	sc.Step(`^the Initial Context Setup procedure is marked as unsuccessfully terminated in the AMF log$`, func() error {
		if !w.logHas("unsuccessfully terminated", `"result":"FAILURE"`, "TS 38.413 §10.3.4.2") {
			return fmt.Errorf("no 'unsuccessfully terminated' FAILURE log with spec_ref TS 38.413 §10.3.4.2")
		}
		return nil
	})
	sc.Step(`^the AMF logs the received ERROR INDICATION without taking recovery action$`, func() error {
		if !w.logHas("Error Indication received from gNB", `"direction":"IN"`) {
			return fmt.Errorf("received ERROR INDICATION not logged")
		}
		if out, _ := w.primary.snapshot(); len(out) != 0 {
			return fmt.Errorf("AMF sent %d PDU(s) after a received ERROR INDICATION, want 0", len(out))
		}
		if _, ok := w.mgr.GetByNGAPId(w.ueAMFID); !ok {
			return fmt.Errorf("UE context removed after a received ERROR INDICATION")
		}
		return nil
	})
	sc.Step(`^the AMF logs the transfer syntax error with spec_ref "([^"]+)"$`, func(ref string) error {
		if !w.logHas("not answered", `"result":"FAILURE"`, ref) {
			return fmt.Errorf("no transfer-syntax-error log line with spec_ref %q", ref)
		}
		return nil
	})
	sc.Step(`^the UE with AMF UE NGAP ID (\d+) is still registered$`, func(amf int) error {
		if _, ok := w.mgr.GetByNGAPId(int64(amf)); !ok {
			return fmt.Errorf("UE %d no longer in the AMF UE context manager", amf)
		}
		return nil
	})
}
