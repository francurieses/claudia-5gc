package ngap

// error_handling_seams.go — test seams for NGAP error handling (TS 38.413 §10, §8.7.5).
// Production code must not call anything in this file.

import (
	"errors"
	"fmt"

	libngap "github.com/francurieses/claudia-5gc/shared/ngap"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
	"github.com/free5gc/aper"
)

// InjectProtocolIEForTest appends one extra protocol IE (id, criticality, raw open-type
// value bytes) to the ProtocolIE-Container of an APER-encoded NGAP PDU and returns the new
// PDU. It exists to build PDUs carrying an IE the AMF does not comprehend (TS 38.413
// §10.3.4.2): the PDU header (choice, procedure code, criticality, length determinant),
// the message preamble and the 16-bit IE count are all octet-aligned in the NGAP-PDU
// encoding, so the IE is spliced in byte-wise. crit is the ASN.1 Criticality value
// (0 reject, 1 ignore, 2 notify). value must be shorter than 128 octets.
func InjectProtocolIEForTest(pdu []byte, id uint16, crit aper.Enumerated, value []byte) ([]byte, error) {
	if len(pdu) < 6 {
		return nil, errors.New("ngap: inject ie: pdu too short")
	}
	if len(value) >= 128 {
		return nil, errors.New("ngap: inject ie: value too long")
	}
	// byte0 choice, byte1 procedure code, byte2 criticality (2 bits + pad), then the
	// open-type length determinant of the message.
	lenOff := 3
	var msgLen, lenSize int
	if pdu[lenOff]&0x80 == 0 {
		msgLen, lenSize = int(pdu[lenOff]), 1
	} else {
		msgLen, lenSize = int(pdu[lenOff]&0x3F)<<8|int(pdu[lenOff+1]), 2
	}
	body := pdu[lenOff+lenSize:]
	if len(body) != msgLen || len(body) < 3 {
		return nil, fmt.Errorf("ngap: inject ie: unexpected length determinant (%d vs %d)", msgLen, len(body))
	}
	// body: preamble (1 octet: extension bit + padding), IE count (2 octets), IEs.
	count := int(body[1])<<8 | int(body[2])
	count++
	ie := []byte{byte(id >> 8), byte(id), byte(crit) << 6, byte(len(value))}
	ie = append(ie, value...)
	newBody := append([]byte{body[0], byte(count >> 8), byte(count)}, body[3:]...)
	newBody = append(newBody, ie...)

	out := append([]byte{}, pdu[:lenOff]...)
	if n := len(newBody); n < 128 {
		out = append(out, byte(n))
	} else {
		out = append(out, 0x80|byte(n>>8), byte(n))
	}
	return append(out, newBody...), nil
}

// ErrorIndicationView is a flattened decoded ERROR INDICATION (TS 38.413 §9.2.6.13) for
// godog steps.
type ErrorIndicationView struct {
	HasAMFUENGAPID, HasRANUENGAPID bool
	AMFUENGAPID, RANUENGAPID       int64
	// CausePresent / CauseValue: ngapType.CausePresent* group and enumerated value; 0 = no Cause IE.
	CausePresent int
	CauseValue   int64
	HasCD        bool
	// CDProcedureCode etc. are -1 when the optional CD member is absent.
	CDProcedureCode, CDTriggeringMessage, CDProcedureCriticality int64
	CDIEs                                                        []CDIEView
}

// CDIEView is one Criticality Diagnostics IE item (TS 38.413 §9.3.1.3).
type CDIEView struct {
	IECriticality int64 // 0 reject, 1 ignore, 2 notify
	IEID          int64
	TypeOfError   int64 // 0 not-understood, 1 missing
}

// DecodeOutboundErrorIndicationForTest decodes an AMF-originated NGAP PDU as an ERROR
// INDICATION. ok is false when the PDU is not an ERROR INDICATION.
func DecodeOutboundErrorIndicationForTest(pdu []byte) (v ErrorIndicationView, ok bool, err error) {
	p, err := libngap.Decoder(pdu)
	if err != nil {
		return v, false, err
	}
	if p.Present != ngapType.NGAPPDUPresentInitiatingMessage ||
		p.InitiatingMessage.ProcedureCode.Value != ngapType.ProcedureCodeErrorIndication ||
		p.InitiatingMessage.Value.ErrorIndication == nil {
		return v, false, nil
	}
	v.CDProcedureCode, v.CDTriggeringMessage, v.CDProcedureCriticality = -1, -1, -1
	for _, ie := range p.InitiatingMessage.Value.ErrorIndication.ProtocolIEs.List {
		switch {
		case ie.Value.AMFUENGAPID != nil:
			v.HasAMFUENGAPID, v.AMFUENGAPID = true, ie.Value.AMFUENGAPID.Value
		case ie.Value.RANUENGAPID != nil:
			v.HasRANUENGAPID, v.RANUENGAPID = true, ie.Value.RANUENGAPID.Value
		case ie.Value.Cause != nil:
			v.CausePresent, v.CauseValue, _ = causeFromNGAP(*ie.Value.Cause)
		case ie.Value.CriticalityDiagnostics != nil:
			v.HasCD = true
			cd := ie.Value.CriticalityDiagnostics
			if cd.ProcedureCode != nil {
				v.CDProcedureCode = cd.ProcedureCode.Value
			}
			if cd.TriggeringMessage != nil {
				v.CDTriggeringMessage = int64(cd.TriggeringMessage.Value)
			}
			if cd.ProcedureCriticality != nil {
				v.CDProcedureCriticality = int64(cd.ProcedureCriticality.Value)
			}
			if cd.IEsCriticalityDiagnostics != nil {
				for _, it := range cd.IEsCriticalityDiagnostics.List {
					v.CDIEs = append(v.CDIEs, CDIEView{
						IECriticality: int64(it.IECriticality.Value),
						IEID:          it.IEID.Value,
						TypeOfError:   int64(it.TypeOfError.Value),
					})
				}
			}
		}
	}
	return v, true, nil
}

// CauseFromNGAPForTest decodes an NGAP Cause into (group, value) for godog steps.
func CauseFromNGAPForTest(c ngapType.Cause) (present int, value int64, ok bool) {
	return causeFromNGAP(c)
}
