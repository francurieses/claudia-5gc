package ngap

// error_handling.go — NGAP error handling of received PDUs: transfer syntax errors
// (TS 38.413 §10.2), not comprehended / missing IEs (§10.3.4.2, §10.3.5), unknown procedure
// codes (§10.3.4.1), the ERROR INDICATION procedure (§8.7.5) and unknown local AP IDs (§10.6).
// Design and decision table: docs/procedures/ngap-error-handling.md.

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/free5gc/aper"

	"github.com/francurieses/claudia-5gc/shared/logging"
	libngap "github.com/francurieses/claudia-5gc/shared/ngap"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

const (
	// procErrorIndication is the log / metric name of the ERROR INDICATION procedure.
	procErrorIndication = "ErrorIndication"

	refTransferSyntax   = "TS 38.413 §10.2"
	refAbstractSyntax   = "TS 38.413 §10.3.4.2"
	refMissingIE        = "TS 38.413 §10.3.5"
	refProcedureCode    = "TS 38.413 §10.3.4.1"
	refErrorIndication  = "TS 38.413 §8.7.5.2"
	refErrorIndRecvd    = "TS 38.413 §10.5"
	refUnknownLocalAPID = "TS 38.413 §10.6, §8.7.5.2"
)

// ieFinding is one erroneous IE found by the abstract-syntax scan.
type ieFinding struct {
	id   int64
	crit aper.Enumerated // criticality of the IE (as received, or as assigned for a missing IE)
	typ  aper.Enumerated // ngapType.TypeOfErrorPresent*
}

// rawIE is the part of a decoded ProtocolIE the scan needs.
type rawIE struct {
	id      int64
	crit    aper.Enumerated
	present int // IEsValue.Present; 0 = the decoder did not recognise the IE id
	amf     *int64
	ran     *int64
}

// notifyPost is the deferred ERROR INDICATION of the "ignore and notify" case for a message
// without a response message. amf is the AMF UE NGAP ID of a UE-associated message (nil
// otherwise), used to run fn behind the UE's queued work.
type notifyPost struct {
	amf *int64
	fn  func()
}

// mandatoryRejectIEs lists, per (message type, procedure code), the mandatory IEs whose
// assigned criticality is reject (TS 38.413 §9.2). Absent ones are reported per §10.3.5.
// Mandatory IEs with criticality ignore are deliberately not checked: a missing one is
// silently ignored (§10.3.5). Only messages the AMF consumes are listed.
var mandatoryRejectIEs = map[[2]int][]int64{
	{0, int(ProcUplinkNASTransport)}: {
		ngapType.ProtocolIEIDAMFUENGAPID, ngapType.ProtocolIEIDRANUENGAPID, ngapType.ProtocolIEIDNASPDU,
	},
	{0, int(ProcInitialUEMessage)}: { // INITIAL UE MESSAGE, §9.2.5.1
		ngapType.ProtocolIEIDRANUENGAPID, ngapType.ProtocolIEIDNASPDU, ngapType.ProtocolIEIDUserLocationInformation,
	},
	{0, int(ProcHandoverPreparation)}: { // HANDOVER REQUIRED, §9.2.3.1
		ngapType.ProtocolIEIDAMFUENGAPID, ngapType.ProtocolIEIDRANUENGAPID, ngapType.ProtocolIEIDHandoverType,
		ngapType.ProtocolIEIDTargetID, ngapType.ProtocolIEIDPDUSessionResourceListHORqd,
		ngapType.ProtocolIEIDSourceToTargetTransparentContainer,
	},
}

// hasResponseMessage reports whether the AMF answers the initiating message of this
// procedure code with a response message it builds (NG SETUP, HANDOVER PREPARATION, PATH
// SWITCH REQUEST): the Criticality Diagnostics of an "ignore and notify" IE then travel in
// that response (§10.3.4.2) instead of an ERROR INDICATION. NG RESET has a response but the
// AMF sends none (observe-only), so it keeps the ERROR INDICATION.
func hasResponseMessage(pc ProcedureCode) bool {
	switch pc {
	case ProcNGSetup, ProcHandoverPreparation, ProcPathSwitchRequest:
		return true
	}
	return false
}

var errScanReflect = errors.New("ngap: abstract syntax scan: unexpected PDU structure")

// reflectInt reads a signed or unsigned integer field (ProtocolIEID.Value is int64,
// Criticality.Value is the unsigned aper.Enumerated).
func reflectInt(v reflect.Value) (int64, error) {
	if !v.IsValid() {
		return 0, fmt.Errorf("%w: missing integer field", errScanReflect)
	}
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int64(v.Uint()), nil
	}
	return 0, fmt.Errorf("%w: field kind %s is not an integer", errScanReflect, v.Kind())
}

// structField returns the named field of the struct v, or an error when v is not a valid
// struct or has no such field (FieldByName would panic on a non-struct).
func structField(v reflect.Value, name string) (reflect.Value, error) {
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return reflect.Value{}, fmt.Errorf("%w: %q looked up on a non-struct", errScanReflect, name)
	}
	f := v.FieldByName(name)
	if !f.IsValid() {
		return reflect.Value{}, fmt.Errorf("%w: no field %q", errScanReflect, name)
	}
	return f, nil
}

// intField reads the integer v.<name1>.<name2>.
func intField(v reflect.Value, name1, name2 string) (int64, error) {
	f, err := structField(v, name1)
	if err != nil {
		return 0, err
	}
	g, err := structField(f, name2)
	if err != nil {
		return 0, err
	}
	return reflectInt(g)
}

// walkProtocolIEs returns the protocol IEs of the message carried by pdu (any procedure),
// using reflection over the generated ngapType structs: every message struct has a
// ProtocolIEs.List whose items have Id, Criticality and a Value with Present. A PDU whose
// structure does not match returns an error (never panics, never a silent nil).
func walkProtocolIEs(pdu *ngapType.NGAPPDU) ([]rawIE, error) {
	if pdu == nil {
		return nil, fmt.Errorf("%w: nil PDU", errScanReflect)
	}
	var val reflect.Value
	switch pdu.Present {
	case ngapType.NGAPPDUPresentInitiatingMessage:
		if pdu.InitiatingMessage == nil {
			return nil, fmt.Errorf("%w: nil InitiatingMessage", errScanReflect)
		}
		val = reflect.ValueOf(pdu.InitiatingMessage.Value)
	case ngapType.NGAPPDUPresentSuccessfulOutcome:
		if pdu.SuccessfulOutcome == nil {
			return nil, fmt.Errorf("%w: nil SuccessfulOutcome", errScanReflect)
		}
		val = reflect.ValueOf(pdu.SuccessfulOutcome.Value)
	case ngapType.NGAPPDUPresentUnsuccessfulOutcome:
		if pdu.UnsuccessfulOutcome == nil {
			return nil, fmt.Errorf("%w: nil UnsuccessfulOutcome", errScanReflect)
		}
		val = reflect.ValueOf(pdu.UnsuccessfulOutcome.Value)
	default:
		return nil, fmt.Errorf("%w: PDU choice %d", errScanReflect, pdu.Present)
	}
	if val.Kind() != reflect.Struct {
		return nil, fmt.Errorf("%w: message value is not a struct", errScanReflect)
	}
	var msg reflect.Value
	for i := 0; i < val.NumField(); i++ {
		if f := val.Field(i); f.Kind() == reflect.Pointer && !f.IsNil() {
			msg = f.Elem()
			break
		}
	}
	if !msg.IsValid() {
		return nil, fmt.Errorf("%w: no message populated", errScanReflect)
	}
	ps, err := structField(msg, "ProtocolIEs")
	if err != nil {
		return nil, err
	}
	list, err := structField(ps, "List")
	if err != nil {
		return nil, err
	}
	if list.Kind() != reflect.Slice {
		return nil, fmt.Errorf("%w: ProtocolIEs.List is not a slice", errScanReflect)
	}
	out := make([]rawIE, 0, list.Len())
	for i := 0; i < list.Len(); i++ {
		it := list.Index(i)
		var r rawIE
		if r.id, err = intField(it, "Id", "Value"); err != nil {
			return nil, err
		}
		c, err := intField(it, "Criticality", "Value")
		if err != nil {
			return nil, err
		}
		r.crit = aper.Enumerated(c)
		v, err := structField(it, "Value")
		if err != nil {
			return nil, err
		}
		pf, err := structField(v, "Present")
		if err != nil {
			return nil, err
		}
		pr, err := reflectInt(pf)
		if err != nil {
			return nil, err
		}
		r.present = int(pr)
		for _, n := range []string{"AMFUENGAPID", "SourceAMFUENGAPID"} {
			if x, err := ptrValue(v, n); err != nil {
				return nil, err
			} else if x != nil {
				r.amf = x
			}
		}
		if x, err := ptrValue(v, "RANUENGAPID"); err != nil {
			return nil, err
		} else if x != nil {
			r.ran = x
		}
		out = append(out, r)
	}
	return out, nil
}

// ptrValue reads <v.name>.Value for an optional pointer field of a decoded IE value struct;
// nil when the field is absent or unset.
func ptrValue(v reflect.Value, name string) (*int64, error) {
	f := v.FieldByName(name)
	if !f.IsValid() || f.Kind() != reflect.Pointer || f.IsNil() {
		return nil, nil
	}
	vf, err := structField(f.Elem(), "Value")
	if err != nil {
		return nil, err
	}
	x, err := reflectInt(vf)
	if err != nil {
		return nil, err
	}
	return &x, nil
}

// scanAbstractSyntax collects the not comprehended IEs (Present == 0: the decoder keeps
// Id and Criticality of an unknown IE but leaves its value unpopulated) and the absent
// mandatory reject IEs of msg. amf/ran are the UE NGAP IDs when both were decoded. It
// recovers from any panic of the reflection walk and returns it as an error.
func scanAbstractSyntax(msg *Message, pdu *ngapType.NGAPPDU) (findings []ieFinding, amf, ran *int64, err error) {
	defer func() {
		if r := recover(); r != nil {
			findings, amf, ran, err = nil, nil, nil, fmt.Errorf("%w: panic: %v", errScanReflect, r)
		}
	}()
	ies, err := walkProtocolIEs(pdu)
	if err != nil {
		return nil, nil, nil, err
	}
	seen := map[int64]bool{}
	var a, r *int64
	for _, ie := range ies {
		if ie.present == 0 {
			findings = append(findings, ieFinding{id: ie.id, crit: ie.crit, typ: ngapType.TypeOfErrorPresentNotUnderstood})
			continue
		}
		seen[ie.id] = true
		if ie.amf != nil {
			a = ie.amf
		}
		if ie.ran != nil {
			r = ie.ran
		}
	}
	for _, id := range mandatoryRejectIEs[[2]int{int(msg.Type), int(msg.ProcedureCode)}] {
		if !seen[id] {
			findings = append(findings, ieFinding{id: id, crit: ngapType.CriticalityPresentReject, typ: ngapType.TypeOfErrorPresentMissing})
		}
	}
	if a != nil && r != nil {
		amf, ran = a, r
	}
	return findings, amf, ran, nil
}

// cdFor builds the Criticality Diagnostics for the erroneous IEs items of msg. With
// withProcedure the Procedure Code, Triggering Message and Procedure Criticality are
// included (ERROR INDICATION, §10.3.4.2); in a response message of the procedure only the
// IE items are (§9.3.1.3).
func cdFor(msg *Message, items []ieFinding, withProcedure bool) ngapType.CriticalityDiagnostics {
	p := CriticalityDiagnosticsParams{}
	if withProcedure {
		pc := int64(msg.ProcedureCode)
		tm := aper.Enumerated(msg.Type) // initiating 0 / successful 1 / unsuccessful 2 match TriggeringMessage
		pcrit := aper.Enumerated(msg.Criticality)
		p.ProcedureCode, p.TriggeringMessage, p.ProcedureCriticality = &pc, &tm, &pcrit
	}
	for _, f := range items {
		p.IEs = append(p.IEs, CDIEItem{IECriticality: f.crit, IEID: f.id, TypeOfError: f.typ})
	}
	return BuildCriticalityDiagnostics(p)
}

// unknownProcedure reports whether the decoder left the message value unpopulated
// (open-type Present == 0): the Procedure Code (or its combination with the message type)
// is not comprehended. aper leaves this without a decode error.
func unknownProcedure(pdu *ngapType.NGAPPDU) bool {
	if pdu == nil {
		return false
	}
	switch pdu.Present {
	case ngapType.NGAPPDUPresentInitiatingMessage:
		return pdu.InitiatingMessage != nil && pdu.InitiatingMessage.Value.Present == 0
	case ngapType.NGAPPDUPresentSuccessfulOutcome:
		return pdu.SuccessfulOutcome != nil && pdu.SuccessfulOutcome.Value.Present == 0
	case ngapType.NGAPPDUPresentUnsuccessfulOutcome:
		return pdu.UnsuccessfulOutcome != nil && pdu.UnsuccessfulOutcome.Value.Present == 0
	}
	return false
}

// attachNotifyCD stores the Criticality Diagnostics of "ignore and notify" IEs on the
// decoded message so the handler puts it into the response message it builds (§10.3.4.2).
func attachNotifyCD(msg *Message, cd *ngapType.CriticalityDiagnostics) {
	switch v := msg.Value.(type) {
	case *NGSetupRequest:
		v.NotifyCD = cd
	case *HandoverRequiredMsg:
		v.NotifyCD = cd
	case *PathSwitchRequestMsg:
		v.NotifyCD = cd
	}
}

// checkAbstractSyntax applies TS 38.413 §10.3.4 / §10.3.5 to a decoded PDU before it is
// routed (decision table: docs/procedures/ngap-error-handling.md §5). It returns whether
// the message is to be processed and an optional action to run after processing (the
// ERROR INDICATION of the "notify" case for a message without a response message). A
// received ERROR INDICATION is never scanned (§10.5).
func (s *Server) checkAbstractSyntax(ctx context.Context, gnb *GNBContext, msg *Message, pdu *ngapType.NGAPPDU) (process bool, post *notifyPost) {
	if msg.ProcedureCode == ProcErrorIndication {
		return true, nil
	}
	log := logging.NewProcedureLogger(ctx, s.logger, procErrorIndication).With("nf", "AMF", "interface", "N2", "direction", "IN")

	// Unknown Procedure Code (§10.3.4.1): the decoder leaves the value unpopulated.
	if unknownProcedure(pdu) {
		return s.handleUnknownProcedure(ctx, log, gnb, msg)
	}

	findings, amf, ran, err := scanAbstractSyntax(msg, pdu)
	if err != nil {
		log.Error("NGAP abstract syntax scan failed — PDU dropped",
			"procedure_code", msg.ProcedureCode, "error", err, "result", "FAILURE",
			"gnb_addr", gnb.remoteAddrString(), "spec_ref", refAbstractSyntax)
		metrics.ProcedureTotal.WithLabelValues("AMF", procErrorIndication, "FAILURE").Inc()
		return false, nil
	}
	var rejects, notifies []ieFinding
	for _, f := range findings {
		switch f.crit {
		case ngapType.CriticalityPresentReject:
			rejects = append(rejects, f)
		case ngapType.CriticalityPresentNotify:
			notifies = append(notifies, f)
		default:
			log.Debug("not comprehended IE with criticality ignore — ignored",
				"procedure_code", msg.ProcedureCode, "ie_id", f.id, "gnb_addr", gnb.remoteAddrString(),
				"spec_ref", refAbstractSyntax)
		}
	}
	spec := refAbstractSyntax
	for _, f := range findings {
		if f.typ == ngapType.TypeOfErrorPresentMissing {
			spec = refMissingIE
			break
		}
	}

	switch {
	case len(rejects) > 0:
		s.rejectAbstractSyntax(ctx, gnb, msg, rejects, notifies, amf, ran, spec)
		return false, nil
	case len(notifies) > 0:
		// Notify (§10.3.4.2 / §10.3.5): process with the understood IEs, then report.
		if msg.Type == 0 && hasResponseMessage(msg.ProcedureCode) {
			// The initiating message has a response message: the diagnostics (IE items only)
			// go into the response the handler builds, no ERROR INDICATION.
			cd := cdFor(msg, notifies, false)
			attachNotifyCD(msg, &cd)
			return true, nil
		}
		return true, &notifyPost{amf: amf, fn: func() {
			p := ErrorIndicationParams{
				CausePresent: ngapType.CausePresentProtocol,
				CauseValue:   int64(ngapType.CauseProtocolPresentAbstractSyntaxErrorIgnoreAndNotify),
			}
			cd := cdFor(msg, notifies, true)
			p.CD = &cd
			if amf != nil {
				p.AMFUENGAPID, p.RANUENGAPID = amf, ran
			}
			s.sendErrorIndication(ctx, gnb, p, spec)
		}}
	}
	return true, nil
}

// handleUnknownProcedure applies TS 38.413 §10.3.4.1 to a PDU whose Procedure Code is not
// comprehended, by the Procedure Criticality in the PDU header: reject -> ERROR INDICATION
// (abstract-syntax-error-reject); notify -> ERROR INDICATION (…-ignore-and-notify), the
// procedure ignored; ignore -> dropped silently. The Criticality Diagnostics carry the
// Procedure Code, Triggering Message and Procedure Criticality.
func (s *Server) handleUnknownProcedure(ctx context.Context, log interface {
	Debug(msg string, args ...any)
}, gnb *GNBContext, msg *Message) (bool, *notifyPost) {
	var cause aper.Enumerated
	switch aper.Enumerated(msg.Criticality) {
	case ngapType.CriticalityPresentReject:
		cause = ngapType.CauseProtocolPresentAbstractSyntaxErrorReject
	case ngapType.CriticalityPresentNotify:
		cause = ngapType.CauseProtocolPresentAbstractSyntaxErrorIgnoreAndNotify
	default:
		log.Debug("NGAP PDU with a not comprehended Procedure Code (criticality ignore) — ignored",
			"procedure_code", msg.ProcedureCode, "gnb_addr", gnb.remoteAddrString(), "spec_ref", refProcedureCode)
		return false, nil
	}
	cd := cdFor(msg, nil, true)
	s.sendErrorIndication(ctx, gnb, ErrorIndicationParams{
		CausePresent: ngapType.CausePresentProtocol,
		CauseValue:   int64(cause),
		CD:           &cd,
	}, refProcedureCode)
	return false, nil
}

// runPost runs the notify action of a message. For a UE-associated message whose UE is
// known it is queued on the UE's serial queue, behind the NAS/NGAP work the handler
// enqueued, so the ERROR INDICATION follows the processing (§10.3.4.2). Otherwise (no UE
// yet, e.g. InitialUEMessage, or non-UE-associated) it runs immediately.
func (s *Server) runPost(_ context.Context, post *notifyPost) {
	if post == nil || post.fn == nil {
		return
	}
	if post.amf != nil {
		if ue, ok := s.mgr.GetByNGAPId(*post.amf); ok {
			ue.EnqueueSerial(post.fn)
			return
		}
	}
	post.fn()
}

// rejectAbstractSyntax handles an erroneous message with criticality reject: nothing of the
// message is executed; the answer is the procedure's failure message with Criticality
// Diagnostics where one exists and its IEs can be determined, else an ERROR INDICATION;
// for a response message only local error handling applies (§10.3.4.2, §10.3.5).
func (s *Server) rejectAbstractSyntax(ctx context.Context, gnb *GNBContext, msg *Message,
	rejects, notifies []ieFinding, amf, ran *int64, spec string) {
	items := append(append([]ieFinding{}, rejects...), notifies...)
	log := logging.NewProcedureLogger(ctx, s.logger, procErrorIndication).With("nf", "AMF", "interface", "N2")

	if msg.Type != 0 { // SuccessfulOutcome / UnsuccessfulOutcome
		log.Warn("NGAP response message with a reject IE error — procedure unsuccessfully terminated, no ERROR INDICATION",
			"direction", "IN", "procedure_code", msg.ProcedureCode, "message_type", fmt.Sprintf("outcome-%d", msg.Type),
			"ie_id", items[0].id, "result", "FAILURE", "gnb_addr", gnb.remoteAddrString(), "spec_ref", spec)
		metrics.ProcedureTotal.WithLabelValues("AMF", procErrorIndication, "FAILURE").Inc()
		return
	}

	reject := ngapType.CauseProtocolPresentAbstractSyntaxErrorReject
	cause := int64(reject)
	failName := func(name string) {
		log.Error(name+" builder returned nil — falling back to ERROR INDICATION",
			"direction", "OUT", "procedure_code", msg.ProcedureCode, "result", "FAILURE",
			"gnb_addr", gnb.remoteAddrString(), "spec_ref", spec)
	}
	switch {
	case msg.ProcedureCode == ProcNGSetup:
		// NG SETUP REQUEST -> NG SETUP FAILURE (Cause + Criticality Diagnostics), §8.7.1.3.
		cd := cdFor(msg, items, false)
		if pdu := BuildNGSetupFailureWithDiagnostics(ngapType.CausePresentProtocol, cause, &cd); pdu != nil {
			s.writeFailure(log, gnb, pdu, "NGSetupFailure", msg, items, spec, "TS 38.413 §8.7.1.3")
			return
		}
		failName("NGSetupFailure")
	case msg.ProcedureCode == ProcHandoverPreparation && amf != nil:
		// HANDOVER REQUIRED -> HANDOVER PREPARATION FAILURE with Criticality Diagnostics.
		cd := cdFor(msg, items, false)
		pdu := BuildHandoverPreparationFailureWithDiagnostics(*amf, *ran, ngapType.CausePresentProtocol, cause, &cd)
		if pdu != nil {
			s.writeFailure(log, gnb, pdu, "HandoverPreparationFailure", msg, items, spec, "TS 38.413 §8.4.1.3")
			return
		}
		failName("HandoverPreparationFailure")
	case msg.ProcedureCode == ProcPathSwitchRequest && amf != nil:
		// PATH SWITCH REQUEST -> PATH SWITCH REQUEST FAILURE with Criticality Diagnostics
		// (needs the requested PDU sessions for the mandatory Released List).
		if req, ok := msg.Value.(*PathSwitchRequestMsg); ok {
			var released []PDUSessionReleasedItem
			for _, it := range req.PDUSessions {
				released = append(released, PDUSessionReleasedItem{PDUSessionID: it.PDUSessionID,
					CausePresent: ngapType.CausePresentProtocol, CauseValue: cause})
			}
			cd := cdFor(msg, items, false)
			if pdu := BuildPathSwitchRequestFailureWithDiagnostics(*amf, *ran, released, &cd); pdu != nil {
				s.writeFailure(log, gnb, pdu, "PathSwitchRequestFailure", msg, items, spec, "TS 38.413 §8.4.4.3")
				return
			}
			failName("PathSwitchRequestFailure")
		}
	}
	// Class 2 initiating message or failure message not determinable: ERROR INDICATION.
	p := ErrorIndicationParams{CausePresent: ngapType.CausePresentProtocol, CauseValue: cause}
	cd := cdFor(msg, items, true)
	p.CD = &cd
	if amf != nil {
		p.AMFUENGAPID, p.RANUENGAPID = amf, ran
	}
	s.sendErrorIndication(ctx, gnb, p, spec)
}

// writeFailure sends a failure message built by rejectAbstractSyntax and logs it.
func (s *Server) writeFailure(log interface {
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}, gnb *GNBContext, pdu []byte, name string, msg *Message, items []ieFinding, spec, clause string) {
	fields := []any{"direction", "OUT", "message_type", name, "procedure_code", msg.ProcedureCode,
		"ie_id", items[0].id, "spec_ref", spec + "; " + clause, "gnb_addr", gnb.remoteAddrString()}
	if gnb.Conn == nil && gnb.sctpWrite == nil {
		log.Error(name+" not sent: no N2 association", append(fields, "result", "FAILURE")...)
		metrics.ProcedureTotal.WithLabelValues("AMF", procErrorIndication, "FAILURE").Inc()
		return
	}
	if _, err := gnb.writeNGAP(pdu); err != nil {
		log.Error(name+" send failed", append(fields, "result", "FAILURE", "error", err)...)
		metrics.ProcedureTotal.WithLabelValues("AMF", procErrorIndication, "FAILURE").Inc()
		return
	}
	log.Warn(name+" sent for erroneous request", append(fields, "result", "REJECT")...)
	metrics.ProcedureTotal.WithLabelValues("AMF", procErrorIndication, "REJECT").Inc()
}

// sendErrorIndication encodes and sends an ERROR INDICATION on gnb's association (SCTP PPID
// 60) and logs / counts it. spec is the clause that triggered it. Ref: TS 38.413 §8.7.5.
func (s *Server) sendErrorIndication(ctx context.Context, gnb *GNBContext, p ErrorIndicationParams, spec string) {
	log := logging.NewProcedureLogger(ctx, s.logger, procErrorIndication).With(
		"nf", "AMF", "interface", "N2", "direction", "OUT", "message_type", "ErrorIndication",
		"gnb_addr", gnb.remoteAddrString())
	fields := []any{"spec_ref", spec + "; " + refErrorIndication, "cause", causeName(p.CausePresent, p.CauseValue)}
	if p.AMFUENGAPID != nil && p.RANUENGAPID != nil {
		fields = append(fields, "amf_ue_ngap_id", *p.AMFUENGAPID, "ran_ue_ngap_id", *p.RANUENGAPID)
	}
	if gnb.Conn == nil && gnb.sctpWrite == nil {
		log.Error("ErrorIndication not sent: no N2 association", append(fields, "result", "FAILURE")...)
		metrics.ProcedureTotal.WithLabelValues("AMF", procErrorIndication, "FAILURE").Inc()
		return
	}
	pdu, err := BuildErrorIndication(p)
	if err != nil {
		log.Error("ErrorIndication build failed", append(fields, "result", "FAILURE", "error", err)...)
		metrics.ProcedureTotal.WithLabelValues("AMF", procErrorIndication, "FAILURE").Inc()
		return
	}
	if _, err := gnb.writeNGAP(pdu); err != nil {
		log.Error("ErrorIndication send failed", append(fields, "result", "FAILURE", "error", err)...)
		metrics.ProcedureTotal.WithLabelValues("AMF", procErrorIndication, "FAILURE").Inc()
		return
	}
	log.Warn("ErrorIndication sent", append(fields, "result", "OK")...)
	metrics.ProcedureTotal.WithLabelValues("AMF", procErrorIndication, "OK").Inc()
}

// causeName renders an NGAP Cause for logs.
func causeName(present int, value int64) string {
	group := map[int]string{
		ngapType.CausePresentRadioNetwork: "radioNetwork", ngapType.CausePresentTransport: "transport",
		ngapType.CausePresentNas: "nas", ngapType.CausePresentProtocol: "protocol", ngapType.CausePresentMisc: "misc",
	}[present]
	if group == "" {
		return "none"
	}
	if present == ngapType.CausePresentProtocol {
		switch aper.Enumerated(value) {
		case ngapType.CauseProtocolPresentTransferSyntaxError:
			return "protocol/transfer-syntax-error"
		case ngapType.CauseProtocolPresentAbstractSyntaxErrorReject:
			return "protocol/abstract-syntax-error-reject"
		case ngapType.CauseProtocolPresentAbstractSyntaxErrorIgnoreAndNotify:
			return "protocol/abstract-syntax-error-ignore-and-notify"
		}
	}
	if present == ngapType.CausePresentRadioNetwork && aper.Enumerated(value) == ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID {
		return "radioNetwork/unknown-local-UE-NGAP-ID"
	}
	return fmt.Sprintf("%s/%d", group, value)
}

// peekErrorIndication reports whether the raw PDU is identifiable as an ERROR INDICATION
// (InitiatingMessage, procedure code 9) without a full decode: the NGAP-PDU header is an
// extension bit, a 2-bit CHOICE index (0 = initiatingMessage) and padding, followed by the
// procedure code octet (TS 38.413 §9.4.1; X.691 aligned PER).
func peekErrorIndication(data []byte) bool {
	return len(data) >= 2 && data[0]&0xE0 == 0 && data[1] == byte(ngapType.ProcedureCodeErrorIndication)
}

// handleTransferSyntaxError answers a PDU the APER decoder rejected (TS 38.413 §10.2): a
// non-UE-associated ERROR INDICATION with Cause protocol transfer-syntax-error, unless the
// PDU is identifiable as an ERROR INDICATION itself (§10.5: never answered; log + metric).
func (s *Server) handleTransferSyntaxError(ctx context.Context, gnb *GNBContext, data []byte, decErr error) {
	if peekErrorIndication(data) {
		s.logger.Warn("NGAP decode error in a received ERROR INDICATION — not answered",
			"nf", "AMF", "procedure", procErrorIndication, "interface", "N2", "direction", "IN",
			"error", decErr, "pdu_len", len(data), "result", "FAILURE", "gnb_addr", gnb.remoteAddrString(),
			"spec_ref", refTransferSyntax+"; "+refErrorIndRecvd)
		metrics.ProcedureTotal.WithLabelValues("AMF", procErrorIndication, "FAILURE").Inc()
		return
	}
	s.logger.Error("NGAP decode error",
		"nf", "AMF", "procedure", procErrorIndication, "interface", "N2", "direction", "IN",
		"error", decErr, "pdu_len", len(data), "result", "FAILURE", "gnb_addr", gnb.remoteAddrString(),
		"spec_ref", refTransferSyntax)
	s.sendErrorIndication(ctx, gnb, ErrorIndicationParams{
		CausePresent: ngapType.CausePresentProtocol,
		CauseValue:   int64(ngapType.CauseProtocolPresentTransferSyntaxError),
	}, refTransferSyntax)
}

// decodeNGAPPDUWithRaw is DecodeNGAPPDU that also returns the decoded ngapType PDU for the
// abstract-syntax scan.
func decodeNGAPPDUWithRaw(data []byte) (*Message, *ngapType.NGAPPDU, error) {
	pdu, err := libngap.Decoder(data)
	if err != nil {
		return nil, nil, fmt.Errorf("ngap: aper decode: %w", err)
	}
	return buildMessage(pdu), pdu, nil
}

// sendUnknownLocalUENGAPID answers a non-last UE-associated message whose AMF UE NGAP ID
// is unknown with an ERROR INDICATION carrying the received IDs and Cause radioNetwork
// unknown-local-UE-NGAP-ID. Ref: TS 38.413 §10.6, §8.7.5.2.
func (s *Server) sendUnknownLocalUENGAPID(ctx context.Context, gnb *GNBContext, amfID, ranID int64) {
	s.sendErrorIndication(ctx, gnb, ErrorIndicationParams{
		AMFUENGAPID: &amfID, RANUENGAPID: &ranID,
		CausePresent: ngapType.CausePresentRadioNetwork,
		CauseValue:   int64(ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID),
	}, refUnknownLocalAPID)
}

// localReleaseByRANUENGAPID performs the local release of TS 38.413 §10.6: when a message
// carries an unknown AMF UE NGAP ID, any UE context of that gNB whose RAN UE NGAP ID equals
// the received one is released locally (PDU sessions released, context removed) since the
// signalling connection it stood for is gone from the peer's point of view.
func (s *Server) localReleaseByRANUENGAPID(ctx context.Context, gnb *GNBContext, ranID, rcvdAMFID int64) {
	gnb.mu.Lock()
	ue := gnb.UEs[ranID]
	if ue != nil {
		delete(gnb.UEs, ranID)
	}
	gnb.mu.Unlock()
	if ue == nil || ue.AMFUENGAPId == rcvdAMFID {
		return
	}
	logging.NewProcedureLogger(ctx, s.logger, procErrorIndication).Warn("local release of UE context with matching RAN UE NGAP ID",
		"nf", "AMF", "interface", "N2", "direction", "IN", "ran_ue_ngap_id", ranID,
		"amf_ue_ngap_id", ue.AMFUENGAPId, "received_amf_ue_ngap_id", rcvdAMFID, "supi", ue.SUPI,
		"gnb_addr", gnb.remoteAddrString(), "result", "OK", "spec_ref", "TS 38.413 §10.6")
	if s.onGNBDisconnect != nil {
		s.onGNBDisconnect(context.WithoutCancel(ctx), ue)
	}
}
