package ngap

// strict_check.go — conditional-presence verification of encoded NGAP PDUs, mirroring
// the strict decoder checks of free5gc/ngap v1.2.0 (observed with PacketRusher). Used by
// unit and BDD tests; not on the production path.
// Ref: TS 38.413 §10.3 (Abstract Syntax Error), Table 9.2.2.1-1

import (
	"fmt"

	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

// CheckICSConditionalPresence decodes an INITIAL CONTEXT SETUP REQUEST and returns
// one message per violated conditional-presence rule (empty when conformant):
// UE-AMBR (id 110) is present if and only if the PDU Session Resource Setup Request
// List (id 71) is present. Ref: TS 38.413 Table 9.2.2.1-1 (C-ifPDUsessionResourceSetup).
func CheckICSConditionalPresence(raw []byte) ([]string, error) {
	pdu, err := libngap.Decoder(raw)
	if err != nil {
		return nil, fmt.Errorf("amf: strict check: decode: %w", err)
	}
	if pdu.InitiatingMessage == nil || pdu.InitiatingMessage.Value.InitialContextSetupRequest == nil {
		return nil, fmt.Errorf("amf: strict check: not an InitialContextSetupRequest")
	}
	var hasAMBR, hasList bool
	for _, ie := range pdu.InitiatingMessage.Value.InitialContextSetupRequest.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDUEAggregateMaximumBitRate:
			hasAMBR = true
		case ngapType.ProtocolIEIDPDUSessionResourceSetupListCxtReq:
			hasList = true
		}
	}
	var v []string
	if hasAMBR && !hasList {
		v = append(v, "UEAggregateMaximumBitRate must not be present if PDUSessionResourceSetupListCxtReq is not present")
	}
	if hasList && !hasAMBR {
		v = append(v, "UEAggregateMaximumBitRate must be present if PDUSessionResourceSetupListCxtReq is present")
	}
	return v, nil
}
