package ngap

// codec.go — NGAP ASN.1 PER aligned codec using free5GC aper library.
// Decodes incoming NGAP PDUs and builds outgoing ones for UERANSIM interop.
// Ref: 3GPP TS 38.413, free5GC ngap (Apache-2.0)

import (
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/free5gc/aper"
	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

// ---- Decoder -------------------------------------------------------------

// DecodeNGAPPDU decodes a raw NGAP PDU (ASN.1 PER aligned) into our Message type.
func DecodeNGAPPDU(data []byte) (*Message, error) {
	pdu, err := libngap.Decoder(data)
	if err != nil {
		return nil, fmt.Errorf("ngap: aper decode: %w", err)
	}
	return buildMessage(pdu), nil
}

// buildMessage converts a free5gc NGAPPDU into our internal Message.
func buildMessage(pdu *ngapType.NGAPPDU) *Message {
	msg := &Message{}
	switch pdu.Present {
	case ngapType.NGAPPDUPresentInitiatingMessage:
		im := pdu.InitiatingMessage
		msg.Type = 0
		msg.ProcedureCode = ProcedureCode(im.ProcedureCode.Value)
		msg.Criticality = Criticality(im.Criticality.Value)
		switch im.ProcedureCode.Value {
		case ngapType.ProcedureCodeNGSetup:
			if im.Value.NGSetupRequest != nil {
				msg.Value = extractNGSetupRequest(im.Value.NGSetupRequest)
			}
		case ngapType.ProcedureCodeInitialUEMessage:
			if im.Value.InitialUEMessage != nil {
				msg.Value = extractInitialUEMessage(im.Value.InitialUEMessage)
			}
		case ngapType.ProcedureCodeUplinkNASTransport:
			if im.Value.UplinkNASTransport != nil {
				msg.Value = extractUplinkNASTransport(im.Value.UplinkNASTransport)
			}
		case ngapType.ProcedureCodeUEContextReleaseRequest: // gNB-initiated (proc=42)
			if im.Value.UEContextReleaseRequest != nil {
				msg.Value = extractUEContextReleaseRequest(im.Value.UEContextReleaseRequest)
			}
		case ngapType.ProcedureCodePathSwitchRequest: // Xn Handover (proc=25)
			if im.Value.PathSwitchRequest != nil {
				msg.Value = extractPathSwitchRequest(im.Value.PathSwitchRequest)
			}
		case ngapType.ProcedureCodeHandoverPreparation: // N2 HO step 1: HandoverRequired (proc=12)
			if im.Value.HandoverRequired != nil {
				msg.Value = extractHandoverRequired(im.Value.HandoverRequired)
			}
		case ngapType.ProcedureCodeHandoverNotification: // N2 HO step 5: HandoverNotify (proc=11)
			if im.Value.HandoverNotify != nil {
				msg.Value = extractHandoverNotify(im.Value.HandoverNotify)
			}
		case ngapType.ProcedureCodeErrorIndication: // proc=9
			if im.Value.ErrorIndication != nil {
				msg.Value = extractErrorIndication(im.Value.ErrorIndication)
			}
		case ngapType.ProcedureCodeLocationReport: // proc=18 (gNB→AMF)
			// Ref: TS 38.413 §8.17.1 (Location Report, Cell-ID positioning)
			if im.Value.LocationReport != nil {
				msg.Value = extractLocationReport(im.Value.LocationReport)
			}
		case ngapType.ProcedureCodeUplinkUEAssociatedNRPPaTransport: // proc=50 (gNB→AMF)
			// Ref: TS 38.413 §8.17.3 (UE-associated NRPPa relay)
			if im.Value.UplinkUEAssociatedNRPPaTransport != nil {
				msg.Value = extractUplinkUEAssociatedNRPPaTransport(im.Value.UplinkUEAssociatedNRPPaTransport)
			}
		case ngapType.ProcedureCodeUplinkNonUEAssociatedNRPPaTransport: // proc=47 (gNB→AMF)
			// Ref: TS 38.413 §8.17.4 (Non-UE-associated NRPPa relay)
			if im.Value.UplinkNonUEAssociatedNRPPaTransport != nil {
				msg.Value = extractUplinkNonUEAssociatedNRPPaTransport(im.Value.UplinkNonUEAssociatedNRPPaTransport)
			}
		case ngapType.ProcedureCodeUERadioCapabilityInfoIndication: // proc=44 (gNB→AMF)
			// Ref: TS 38.413 §8.7.6 (UE Radio Capability Info Indication)
			if im.Value.UERadioCapabilityInfoIndication != nil {
				msg.Value = extractUERadioCapabilityInfoIndication(im.Value.UERadioCapabilityInfoIndication)
			}
		}
	case ngapType.NGAPPDUPresentSuccessfulOutcome:
		so := pdu.SuccessfulOutcome
		msg.Type = 1
		msg.ProcedureCode = ProcedureCode(so.ProcedureCode.Value)
		msg.Criticality = Criticality(so.Criticality.Value)
		switch so.ProcedureCode.Value {
		case ngapType.ProcedureCodePDUSessionResourceSetup:
			if so.Value.PDUSessionResourceSetupResponse != nil {
				msg.Value = extractPDUSessionResourceSetupResponse(so.Value.PDUSessionResourceSetupResponse)
			}
		case ngapType.ProcedureCodePDUSessionResourceRelease:
			if so.Value.PDUSessionResourceReleaseResponse != nil {
				msg.Value = extractPDUSessionResourceReleaseResponse(so.Value.PDUSessionResourceReleaseResponse)
			}
		case ngapType.ProcedureCodePDUSessionResourceModify:
			if so.Value.PDUSessionResourceModifyResponse != nil {
				msg.Value = extractPDUSessionResourceModifyResponse(so.Value.PDUSessionResourceModifyResponse)
			}
		case ngapType.ProcedureCodeInitialContextSetup: // gNB's ICS Response (proc=14)
			if so.Value.InitialContextSetupResponse != nil {
				msg.Value = extractInitialContextSetupResponse(so.Value.InitialContextSetupResponse)
			}
		case ngapType.ProcedureCodeUEContextRelease: // gNB's Complete (proc=41)
			if so.Value.UEContextReleaseComplete != nil {
				msg.Value = extractUEContextReleaseComplete(so.Value.UEContextReleaseComplete)
			}
		case ngapType.ProcedureCodeHandoverResourceAllocation: // N2 HO step 3: HandoverRequestAck (proc=13)
			if so.Value.HandoverRequestAcknowledge != nil {
				msg.Value = extractHandoverRequestAcknowledge(so.Value.HandoverRequestAcknowledge)
			}
		case ngapType.ProcedureCodeWriteReplaceWarning: // PWS broadcast confirm (proc=51)
			if so.Value.WriteReplaceWarningResponse != nil {
				msg.Value = extractWriteReplaceWarningResponse(so.Value.WriteReplaceWarningResponse)
			}
		case ngapType.ProcedureCodePWSCancel: // PWS cancel confirm (proc=32)
			if so.Value.PWSCancelResponse != nil {
				msg.Value = extractPWSCancelResponse(so.Value.PWSCancelResponse)
			}
		}
	case ngapType.NGAPPDUPresentUnsuccessfulOutcome:
		uo := pdu.UnsuccessfulOutcome
		msg.Type = 2
		msg.ProcedureCode = ProcedureCode(uo.ProcedureCode.Value)
		msg.Criticality = Criticality(uo.Criticality.Value)
		switch uo.ProcedureCode.Value {
		case ngapType.ProcedureCodeInitialContextSetup: // gNB rejected the ICS Request (proc=14)
			if uo.Value.InitialContextSetupFailure != nil {
				msg.Value = extractInitialContextSetupFailure(uo.Value.InitialContextSetupFailure)
			}
		}
	}
	return msg
}

// ---- Extractors ----------------------------------------------------------

func extractNGSetupRequest(req *ngapType.NGSetupRequest) *NGSetupRequest {
	out := &NGSetupRequest{}
	for _, ie := range req.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDGlobalRANNodeID: // 27
			if ie.Value.GlobalRANNodeID != nil {
				out.GlobalRANNodeID = extractGlobalRANNodeIDBytes(ie.Value.GlobalRANNodeID)
				out.RANNode = extractGlobalRANNode(ie.Value.GlobalRANNodeID)
				out.RANNodeName = "" // populated below if present
			}
		case ngapType.ProtocolIEIDRANNodeName: // 82
			if ie.Value.RANNodeName != nil {
				out.RANNodeName = string(ie.Value.RANNodeName.Value)
			}
		case ngapType.ProtocolIEIDSupportedTAList: // 102
			if ie.Value.SupportedTAList != nil {
				out.SupportedTAList = extractSupportedTAList(ie.Value.SupportedTAList)
			}
		}
	}
	return out
}

func extractGlobalRANNodeIDBytes(id *ngapType.GlobalRANNodeID) []byte {
	switch id.Present {
	case ngapType.GlobalRANNodeIDPresentGlobalGNBID:
		if id.GlobalGNBID != nil {
			plmn := id.GlobalGNBID.PLMNIdentity.Value
			gnbID := id.GlobalGNBID.GNBID.GNBID.Bytes
			result := make([]byte, 0, len(plmn)+len(gnbID))
			result = append(result, plmn...)
			result = append(result, gnbID...)
			return result
		}
	}
	return nil
}

// extractGlobalRANNode decodes the Global RAN Node ID into its structured form,
// keeping the gNB ID bit length (22..32) that the flat byte form loses.
// Ref: TS 38.413 §9.3.1.5, §9.3.1.6.
func extractGlobalRANNode(id *ngapType.GlobalRANNodeID) GlobalRANNode {
	switch id.Present {
	case ngapType.GlobalRANNodeIDPresentGlobalGNBID:
		n := GlobalRANNode{Type: RANNodeTypeGNB}
		if g := id.GlobalGNBID; g != nil {
			n.MCC = plmnToMCC(g.PLMNIdentity.Value)
			n.MNC = plmnToMNC(g.PLMNIdentity.Value)
			if bs := g.GNBID.GNBID; bs != nil {
				n.GNBIDBitLen = uint8(bs.BitLength)
				var v uint64
				for _, b := range bs.Bytes {
					v = v<<8 | uint64(b)
				}
				// The BIT STRING is left-aligned in its octets; drop the padding bits.
				if pad := uint(len(bs.Bytes))*8 - uint(bs.BitLength); pad < 64 {
					v >>= pad
				}
				n.GNBID = uint32(v)
			}
		}
		return n
	case ngapType.GlobalRANNodeIDPresentGlobalNgENBID:
		return GlobalRANNode{Type: RANNodeTypeNgENB}
	case ngapType.GlobalRANNodeIDPresentGlobalN3IWFID:
		return GlobalRANNode{Type: RANNodeTypeN3IWF}
	}
	return GlobalRANNode{}
}

// extractTAISliceSupport decodes a TAI Slice Support List into S-NSSAIs.
// Ref: TS 38.413 §9.3.1.x (Slice Support List).
func extractTAISliceSupport(list ngapType.SliceSupportList) []amfctx.SNSSAISubscribed {
	var out []amfctx.SNSSAISubscribed
	for _, item := range list.List {
		var sn amfctx.SNSSAISubscribed
		if len(item.SNSSAI.SST.Value) > 0 {
			sn.SST = item.SNSSAI.SST.Value[0]
		}
		if item.SNSSAI.SD != nil && len(item.SNSSAI.SD.Value) > 0 {
			sn.SD = hex.EncodeToString(item.SNSSAI.SD.Value)
		}
		out = append(out, sn)
	}
	return out
}

func extractSupportedTAList(list *ngapType.SupportedTAList) []SupportedTA {
	var result []SupportedTA
	for _, item := range list.List {
		ta := SupportedTA{
			TAC: tacToUint32(item.TAC.Value),
		}
		for _, bplmn := range item.BroadcastPLMNList.List {
			ps := PLMNSlice{
				MCC:          plmnToMCC(bplmn.PLMNIdentity.Value),
				MNC:          plmnToMNC(bplmn.PLMNIdentity.Value),
				SliceSupport: extractTAISliceSupport(bplmn.TAISliceSupportList),
			}
			ta.BroadcastPLMNs = append(ta.BroadcastPLMNs, ps)
		}
		result = append(result, ta)
	}
	return result
}

func extractInitialUEMessage(msg *ngapType.InitialUEMessage) *InitialUEMessage {
	out := &InitialUEMessage{}
	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDRANUENGAPID: // 85
			if ie.Value.RANUENGAPID != nil {
				out.RANUENGAPId = ie.Value.RANUENGAPID.Value
			}
		case ngapType.ProtocolIEIDNASPDU: // 38
			if ie.Value.NASPDU != nil {
				out.NASPdu = []byte(ie.Value.NASPDU.Value)
			}
		case ngapType.ProtocolIEIDUserLocationInformation: // 121
			if ie.Value.UserLocationInformation != nil {
				out.TAI = extractTAIFromULI(ie.Value.UserLocationInformation)
			}
		case ngapType.ProtocolIEIDRRCEstablishmentCause: // 90
			// Log only — no field stored
		case ngapType.ProtocolIEIDFiveGSTMSI: // 26 — present for Service Request
			if ie.Value.FiveGSTMSI != nil {
				tmsiBytes := []byte(ie.Value.FiveGSTMSI.FiveGTMSI.Value)
				if len(tmsiBytes) == 4 {
					tmsi := uint32(tmsiBytes[0])<<24 | uint32(tmsiBytes[1])<<16 |
						uint32(tmsiBytes[2])<<8 | uint32(tmsiBytes[3])
					out.FiveGSTMSI = &tmsi
				}
			}
		}
	}
	return out
}

func extractTAIFromULI(uli *ngapType.UserLocationInformation) *TAI {
	if uli.Present == ngapType.UserLocationInformationPresentUserLocationInformationNR {
		nr := uli.UserLocationInformationNR
		if nr != nil {
			return &TAI{
				MCC: plmnToMCC(nr.TAI.PLMNIdentity.Value),
				MNC: plmnToMNC(nr.TAI.PLMNIdentity.Value),
				TAC: tacToUint32(nr.TAI.TAC.Value),
			}
		}
	}
	return nil
}

func extractUplinkNASTransport(msg *ngapType.UplinkNASTransport) *UplinkNASTransport {
	out := &UplinkNASTransport{}
	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID: // 10
			if ie.Value.AMFUENGAPID != nil {
				out.AMFUENGAPId = ie.Value.AMFUENGAPID.Value
			}
		case ngapType.ProtocolIEIDRANUENGAPID: // 85
			if ie.Value.RANUENGAPID != nil {
				out.RANUENGAPId = ie.Value.RANUENGAPID.Value
			}
		case ngapType.ProtocolIEIDNASPDU: // 38
			if ie.Value.NASPDU != nil {
				out.NASPdu = []byte(ie.Value.NASPDU.Value)
			}
		}
	}
	return out
}

// ---- Error Indication (gNB→AMF, InitiatingMessage, ProcCode=9) --------------
// Ref: TS 38.413 §8.1

// ErrorIndicationMsg holds decoded fields from an NGAP ErrorIndication.
type ErrorIndicationMsg struct {
	AMFUENGAPId int64
	RANUENGAPId int64
	// CausePresent: 1=RadioNetwork 2=Transport 3=NAS 4=Protocol 5=Misc; 0=absent
	CausePresent int
	CauseValue   int64
}

func extractErrorIndication(msg *ngapType.ErrorIndication) *ErrorIndicationMsg {
	out := &ErrorIndicationMsg{}
	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				out.AMFUENGAPId = ie.Value.AMFUENGAPID.Value
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				out.RANUENGAPId = ie.Value.RANUENGAPID.Value
			}
		case ngapType.ProtocolIEIDCause:
			if ie.Value.Cause != nil {
				out.CausePresent = ie.Value.Cause.Present
				switch ie.Value.Cause.Present {
				case ngapType.CausePresentRadioNetwork:
					if ie.Value.Cause.RadioNetwork != nil {
						out.CauseValue = int64(ie.Value.Cause.RadioNetwork.Value)
					}
				case ngapType.CausePresentTransport:
					if ie.Value.Cause.Transport != nil {
						out.CauseValue = int64(ie.Value.Cause.Transport.Value)
					}
				case ngapType.CausePresentNas:
					if ie.Value.Cause.Nas != nil {
						out.CauseValue = int64(ie.Value.Cause.Nas.Value)
					}
				case ngapType.CausePresentProtocol:
					if ie.Value.Cause.Protocol != nil {
						out.CauseValue = int64(ie.Value.Cause.Protocol.Value)
					}
				case ngapType.CausePresentMisc:
					if ie.Value.Cause.Misc != nil {
						out.CauseValue = int64(ie.Value.Cause.Misc.Value)
					}
				}
			}
		}
	}
	return out
}

// InitialContextSetupFailureMsg is the decoded gNB rejection of an Initial
// Context Setup Request (TS 38.413 §8.3.1, UnsuccessfulOutcome).
type InitialContextSetupFailureMsg struct {
	AMFUENGAPId int64
	RANUENGAPId int64
	// CausePresent: 1=RadioNetwork 2=Transport 3=NAS 4=Protocol 5=Misc; 0=absent
	CausePresent int
	CauseValue   int64
}

func extractInitialContextSetupFailure(msg *ngapType.InitialContextSetupFailure) *InitialContextSetupFailureMsg {
	out := &InitialContextSetupFailureMsg{}
	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				out.AMFUENGAPId = ie.Value.AMFUENGAPID.Value
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				out.RANUENGAPId = ie.Value.RANUENGAPID.Value
			}
		case ngapType.ProtocolIEIDCause:
			if ie.Value.Cause != nil {
				out.CausePresent = ie.Value.Cause.Present
				switch ie.Value.Cause.Present {
				case ngapType.CausePresentRadioNetwork:
					if ie.Value.Cause.RadioNetwork != nil {
						out.CauseValue = int64(ie.Value.Cause.RadioNetwork.Value)
					}
				case ngapType.CausePresentTransport:
					if ie.Value.Cause.Transport != nil {
						out.CauseValue = int64(ie.Value.Cause.Transport.Value)
					}
				case ngapType.CausePresentNas:
					if ie.Value.Cause.Nas != nil {
						out.CauseValue = int64(ie.Value.Cause.Nas.Value)
					}
				case ngapType.CausePresentProtocol:
					if ie.Value.Cause.Protocol != nil {
						out.CauseValue = int64(ie.Value.Cause.Protocol.Value)
					}
				case ngapType.CausePresentMisc:
					if ie.Value.Cause.Misc != nil {
						out.CauseValue = int64(ie.Value.Cause.Misc.Value)
					}
				}
			}
		}
	}
	return out
}

// ---- Encoders ------------------------------------------------------------

// BuildNGSetupResponse builds a real NG Setup Response PDU (ASN.1 PER).
// snssais is the list of slices this AMF/PLMN serves; uses SST=1/SD=000001 if empty.
func BuildNGSetupResponse(amfName, mcc, mnc string, regionID byte, setID uint16, amfID byte, snssais []amfctx.SNSSAISubscribed) []byte {
	plmn := plmnFromMCCMNC(mcc, mnc)

	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentSuccessfulOutcome,
		SuccessfulOutcome: &ngapType.SuccessfulOutcome{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeNGSetup},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.SuccessfulOutcomeValue{
				Present: ngapType.SuccessfulOutcomePresentNGSetupResponse,
				NGSetupResponse: &ngapType.NGSetupResponse{
					ProtocolIEs: ngapType.ProtocolIEContainerNGSetupResponseIEs{
						List: []ngapType.NGSetupResponseIEs{
							// IE: AMFName (id=1)
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFName},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.NGSetupResponseIEsValue{
									Present: ngapType.NGSetupResponseIEsPresentAMFName,
									AMFName: &ngapType.AMFName{Value: amfName},
								},
							},
							// IE: ServedGUAMIList (id=96)
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDServedGUAMIList},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.NGSetupResponseIEsValue{
									Present:         ngapType.NGSetupResponseIEsPresentServedGUAMIList,
									ServedGUAMIList: buildServedGUAMIList(plmn, regionID, setID, amfID),
								},
							},
							// IE: RelativeAMFCapacity (id=86)
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRelativeAMFCapacity},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.NGSetupResponseIEsValue{
									Present:             ngapType.NGSetupResponseIEsPresentRelativeAMFCapacity,
									RelativeAMFCapacity: &ngapType.RelativeAMFCapacity{Value: 100},
								},
							},
							// IE: PLMNSupportList (id=80)
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPLMNSupportList},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.NGSetupResponseIEsValue{
									Present:         ngapType.NGSetupResponseIEsPresentPLMNSupportList,
									PLMNSupportList: buildPLMNSupportList(plmn, snssais),
								},
							},
						},
					},
				},
			},
		},
	}

	b, err := libngap.Encoder(pdu)
	if err != nil {
		// Should never happen with valid structs; log and return empty
		return nil
	}
	return b
}

// BuildDownlinkNASTransport builds a Downlink NAS Transport PDU (ASN.1 PER).
// Ref: TS 38.413 §8.6.2
func BuildDownlinkNASTransport(amfID, ranID int64, nasPDU []byte) []byte {
	nasPduVal := ngapType.NASPDU{Value: aper.OctetString(nasPDU)}
	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeDownlinkNASTransport},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.InitiatingMessageValue{
				Present: ngapType.InitiatingMessagePresentDownlinkNASTransport,
				DownlinkNASTransport: &ngapType.DownlinkNASTransport{
					ProtocolIEs: ngapType.ProtocolIEContainerDownlinkNASTransportIEs{
						List: []ngapType.DownlinkNASTransportIEs{
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.DownlinkNASTransportIEsValue{
									Present:     ngapType.DownlinkNASTransportIEsPresentAMFUENGAPID,
									AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfID},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.DownlinkNASTransportIEsValue{
									Present:     ngapType.DownlinkNASTransportIEsPresentRANUENGAPID,
									RANUENGAPID: &ngapType.RANUENGAPID{Value: ranID},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDNASPDU},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.DownlinkNASTransportIEsValue{
									Present: ngapType.DownlinkNASTransportIEsPresentNASPDU,
									NASPDU:  &nasPduVal,
								},
							},
						},
					},
				},
			},
		},
	}

	b, err := libngap.Encoder(pdu)
	if err != nil {
		return nil
	}
	return b
}

// PDUSessionSetupItemCxtReq is one PDU session to (re-)establish inside an
// Initial Context Setup Request (PDUSessionResourceSetupListCxtReq, IE id=71).
// Transfer carries the raw APER-encoded PDUSessionResourceSetupRequestTransfer
// produced by the SMF (UL GTP-U TEID + QoS profile).
// Ref: TS 38.413 §9.2.2.1, TS 23.502 §4.2.3.2 step 12 (Service Request)
type PDUSessionSetupItemCxtReq struct {
	PDUSessionID uint8
	SST          uint8
	SD           []byte // 3 bytes, nil to omit
	Transfer     []byte
}

// DefaultUEAMBRBps is the operator-default UE Aggregate Maximum Bit Rate (1 Gbps,
// bit/s) used per direction when the subscription (UDM am-data) carries no
// subscribedUeAmbr. Ref: TS 38.413 §9.3.1.58 (Bit Rate, bit/s), TS 23.501 §5.7.2.6.
const DefaultUEAMBRBps int64 = 1_000_000_000

// UEAMBR is a UE Aggregate Maximum Bit Rate to encode, in bit/s. A value <= 0 in
// either direction falls back to DefaultUEAMBRBps. Ref: TS 38.413 §9.3.1.58.
type UEAMBR struct {
	ULBps, DLBps int64
}

// NewUEAMBRFromKbps converts the subscribed UE-AMBR stored on the UE context
// (kbit/s, from UDM am-data) to a UEAMBR in bit/s. Zero keeps the default.
// Ref: TS 38.413 §9.3.1.58, TS 29.571 BitRate
func NewUEAMBRFromKbps(ulKbps, dlKbps uint64) *UEAMBR {
	return &UEAMBR{ULBps: int64(ulKbps) * 1000, DLBps: int64(dlKbps) * 1000}
}

// buildUEAMBR builds the NGAP UE Aggregate Maximum Bit Rate IE value, applying
// the operator default for non-positive inputs. Ref: TS 38.413 §9.3.1.58.
func buildUEAMBR(ulBps, dlBps int64) *ngapType.UEAggregateMaximumBitRate {
	if ulBps <= 0 {
		ulBps = DefaultUEAMBRBps
	}
	if dlBps <= 0 {
		dlBps = DefaultUEAMBRBps
	}
	return &ngapType.UEAggregateMaximumBitRate{
		UEAggregateMaximumBitRateUL: ngapType.BitRate{Value: ulBps},
		UEAggregateMaximumBitRateDL: ngapType.BitRate{Value: dlBps},
	}
}

// BuildInitialContextSetupRequest builds an Initial Context Setup Request PDU.
// encAlgsBitmap and intAlgsBitmap are the UE's advertised capability bitmasks
// (bit 15=NEA1/NIA1, 14=NEA2/NIA2, 13=NEA3/NIA3) per TS 38.413 §9.3.1.86.
// ambrULBps/ambrDLBps is the subscribed UE Aggregate Maximum Bit Rate in bit/s
// (TS 38.413 §9.3.1.58); pass 0 to fall back to the 1 Gbps operator default. It
// is only encoded when pduSessions is non-empty (C-ifPDUsessionResourceSetup,
// Table 9.2.2.1-1); with no PDU session list the IE is omitted and the values ignored.
// rfsp is the Radio Frequency Selection Priority index (1-256) from PCF; 0 means omit.
// pduSessions, when non-empty, is encoded as PDUSessionResourceSetupListCxtReq
// (IE id=71) so the gNB re-establishes user-plane resources during Service
// Request without a separate PDU Session Resource Setup procedure.
// Ref: TS 38.413 §8.3.1, §9.3.1.27 (IndexToRFSP, IE id=31)
func BuildInitialContextSetupRequest(
	amfUEID, ranUEID int64,
	nasPDU []byte,
	secKey [32]byte,
	encAlgsBitmap, intAlgsBitmap uint16,
	mcc, mnc string,
	regionID byte, setID uint16, amfIDByte byte,
	allowedNSSAI []amfctx.SNSSAISubscribed,
	ambrULBps, ambrDLBps int64,
	rfsp int,
	pduSessions []PDUSessionSetupItemCxtReq,
) []byte {
	plmn := plmnFromMCCMNC(mcc, mnc)

	// IEs in the exact order specified by TS 38.413 Table 9.2.2.1-1.
	// TS 38.413 §8.1: "Protocol IEs shall be contained in the order specified in the
	// corresponding IE table." Out-of-order IEs may be rejected by strict ASN.1 decoders.
	ieList := []ngapType.InitialContextSetupRequestIEs{
		// (1) AMF-UE-NGAP-ID (id=10) — Mandatory
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitialContextSetupRequestIEsValue{
				Present:     ngapType.InitialContextSetupRequestIEsPresentAMFUENGAPID,
				AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfUEID},
			},
		},
		// (2) RAN-UE-NGAP-ID (id=85) — Mandatory
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitialContextSetupRequestIEsValue{
				Present:     ngapType.InitialContextSetupRequestIEsPresentRANUENGAPID,
				RANUENGAPID: &ngapType.RANUENGAPID{Value: ranUEID},
			},
		},
	}

	// (4) UEAggregateMaximumBitRate (id=110) — C-ifPDUsessionResourceSetup: "shall be
	// present if the PDU Session Resource Setup Request List IE is present", and MUST
	// NOT be included otherwise (strict gNBs reject it with an Abstract Syntax Error,
	// TS 38.413 §10.3). Position 4: after RAN UE NGAP ID, before GUAMI. Value: the
	// subscribed UE-AMBR or the 1 Gbps operator default.
	// Ref: TS 38.413 Table 9.2.2.1-1, §9.3.1.58, TS 23.502 §4.2.3.2 step 12
	if len(pduSessions) > 0 {
		ieList = append(ieList, ngapType.InitialContextSetupRequestIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDUEAggregateMaximumBitRate},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitialContextSetupRequestIEsValue{
				Present:                   ngapType.InitialContextSetupRequestIEsPresentUEAggregateMaximumBitRate,
				UEAggregateMaximumBitRate: buildUEAMBR(ambrULBps, ambrDLBps),
			},
		})
	}

	// (6) GUAMI (id=28) — Mandatory
	ieList = append(ieList, ngapType.InitialContextSetupRequestIEs{
		Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDGUAMI},
		Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
		Value: ngapType.InitialContextSetupRequestIEsValue{
			Present: ngapType.InitialContextSetupRequestIEsPresentGUAMI,
			GUAMI:   buildGUAMI(plmn, regionID, setID, amfIDByte),
		},
	})

	// (7) PDUSessionResourceSetupListCxtReq (id=71) — position 7 in the spec
	// table, between GUAMI and AllowedNSSAI. Carries the SMF-built
	// PDUSessionResourceSetupRequestTransfer per PDU session to activate.
	// Ref: TS 38.413 §9.2.2.1, TS 23.502 §4.2.3.2 step 12
	if len(pduSessions) > 0 {
		var items []ngapType.PDUSessionResourceSetupItemCxtReq
		for _, ps := range pduSessions {
			items = append(items, ngapType.PDUSessionResourceSetupItemCxtReq{
				PDUSessionID:                           ngapType.PDUSessionID{Value: int64(ps.PDUSessionID)},
				SNSSAI:                                 buildNGAPSNSSAI(ps.SST, ps.SD),
				PDUSessionResourceSetupRequestTransfer: aper.OctetString(ps.Transfer),
			})
		}
		list := ngapType.PDUSessionResourceSetupListCxtReq{List: items}
		ieList = append(ieList, ngapType.InitialContextSetupRequestIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPDUSessionResourceSetupListCxtReq},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitialContextSetupRequestIEsValue{
				Present:                           ngapType.InitialContextSetupRequestIEsPresentPDUSessionResourceSetupListCxtReq,
				PDUSessionResourceSetupListCxtReq: &list,
			},
		})
	}

	// (8) AllowedNSSAI (id=0) — position 8 in the spec table, before UESecurityCapabilities.
	// Informs gNB which slices are permitted for this UE.
	// Ref: TS 38.413 §9.2.2.1, §9.3.1.52
	if len(allowedNSSAI) > 0 {
		var items []ngapType.AllowedNSSAIItem
		for _, s := range allowedNSSAI {
			items = append(items, ngapType.AllowedNSSAIItem{
				SNSSAI: buildNGAPSNSSAI(s.SST, snssaiSDBytes(s.SD)),
			})
		}
		nssai := ngapType.AllowedNSSAI{List: items}
		ieList = append(ieList, ngapType.InitialContextSetupRequestIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAllowedNSSAI},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitialContextSetupRequestIEsValue{
				Present:      ngapType.InitialContextSetupRequestIEsPresentAllowedNSSAI,
				AllowedNSSAI: &nssai,
			},
		})
	}

	// (9) UESecurityCapabilities (id=119) — Mandatory
	ieList = append(ieList, ngapType.InitialContextSetupRequestIEs{
		Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDUESecurityCapabilities},
		Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
		Value: ngapType.InitialContextSetupRequestIEsValue{
			Present:                ngapType.InitialContextSetupRequestIEsPresentUESecurityCapabilities,
			UESecurityCapabilities: buildUESecurityCapabilities(encAlgsBitmap, intAlgsBitmap),
		},
	})

	// (10) SecurityKey (id=94) — Mandatory
	ieList = append(ieList, ngapType.InitialContextSetupRequestIEs{
		Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDSecurityKey},
		Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
		Value: ngapType.InitialContextSetupRequestIEsValue{
			Present: ngapType.InitialContextSetupRequestIEsPresentSecurityKey,
			SecurityKey: &ngapType.SecurityKey{
				Value: aper.BitString{
					Bytes:     secKey[:],
					BitLength: 256,
				},
			},
		},
	})

	// (15) IndexToRFSP (id=31) — Optional, position 15 in the spec table.
	// Must precede NAS-PDU (id=38, position 17): TS 38.413 Table 9.2.2.1-1 lists
	// Index to RAT/Frequency Selection Priority before NAS-PDU. A strict decoder
	// (real Nokia RAN) rejects the whole PDU with abstract-syntax-error-reject if
	// these are out of tabular order.
	// Radio Frequency Selection Priority index: 1=lowest priority, 256=highest.
	// Operator default (1) guarantees this IE is always on the wire.
	// Ref: TS 38.413 §9.3.1.27, TS 23.501 §5.3.4.2, TS 29.507 §4.2.2.2
	if rfsp > 0 {
		rfspVal := ngapType.IndexToRFSP{Value: int64(rfsp)}
		ieList = append(ieList, ngapType.InitialContextSetupRequestIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDIndexToRFSP},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.InitialContextSetupRequestIEsValue{
				Present:     ngapType.InitialContextSetupRequestIEsPresentIndexToRFSP,
				IndexToRFSP: &rfspVal,
			},
		})
	}

	// (17) NAS-PDU (id=38) — Optional, position 17 in the spec table (after IndexToRFSP).
	if len(nasPDU) > 0 {
		nasPduVal := ngapType.NASPDU{Value: aper.OctetString(nasPDU)}
		ieList = append(ieList, ngapType.InitialContextSetupRequestIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDNASPDU},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.InitialContextSetupRequestIEsValue{
				Present: ngapType.InitialContextSetupRequestIEsPresentNASPDU,
				NASPDU:  &nasPduVal,
			},
		})
	}

	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeInitialContextSetup},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitiatingMessageValue{
				Present: ngapType.InitiatingMessagePresentInitialContextSetupRequest,
				InitialContextSetupRequest: &ngapType.InitialContextSetupRequest{
					ProtocolIEs: ngapType.ProtocolIEContainerInitialContextSetupRequestIEs{
						List: ieList,
					},
				},
			},
		},
	}

	b, err := libngap.Encoder(pdu)
	if err != nil {
		return nil
	}
	return b
}

// ---- Builder helpers -----------------------------------------------------

func buildServedGUAMIList(plmn []byte, regionID byte, setID uint16, amfID byte) *ngapType.ServedGUAMIList {
	return &ngapType.ServedGUAMIList{
		List: []ngapType.ServedGUAMIItem{
			{
				GUAMI: *buildGUAMI(plmn, regionID, setID, amfID),
			},
		},
	}
}

func buildGUAMI(plmn []byte, regionID byte, setID uint16, amfID byte) *ngapType.GUAMI {
	// AMFRegionID: 8-bit → 1 byte
	// AMFSetID: 10-bit → 2 bytes, top 10 bits used
	// AMFPointer: 6-bit → 1 byte, top 6 bits used
	setIDBytes := []byte{byte(setID >> 2), byte(setID<<6) | (amfID >> 2)}
	pointerBytes := []byte{amfID << 2}

	return &ngapType.GUAMI{
		PLMNIdentity: ngapType.PLMNIdentity{Value: plmn},
		AMFRegionID: ngapType.AMFRegionID{
			Value: aper.BitString{Bytes: []byte{regionID}, BitLength: 8},
		},
		AMFSetID: ngapType.AMFSetID{
			Value: aper.BitString{Bytes: setIDBytes, BitLength: 10},
		},
		AMFPointer: ngapType.AMFPointer{
			Value: aper.BitString{Bytes: pointerBytes, BitLength: 6},
		},
	}
}

// buildPLMNSupportList builds the PLMNSupportList for the NG Setup Response.
// snssais is the set of slices this AMF advertises; falls back to SST=1 if empty.
func buildPLMNSupportList(plmn []byte, snssais []amfctx.SNSSAISubscribed) *ngapType.PLMNSupportList {
	if len(snssais) == 0 {
		snssais = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}}
	}
	var items []ngapType.SliceSupportItem
	for _, s := range snssais {
		sdBytes := snssaiSDBytes(s.SD)
		items = append(items, ngapType.SliceSupportItem{SNSSAI: buildNGAPSNSSAI(s.SST, sdBytes)})
	}
	return &ngapType.PLMNSupportList{
		List: []ngapType.PLMNSupportItem{
			{
				PLMNIdentity:     ngapType.PLMNIdentity{Value: plmn},
				SliceSupportList: ngapType.SliceSupportList{List: items},
			},
		},
	}
}

// snssaiSDBytes decodes a 6-char hex SD string to 3 bytes.
// Returns nil if the string is empty or invalid (SD not present).
func snssaiSDBytes(sd string) []byte {
	if len(sd) != 6 {
		return nil
	}
	b := make([]byte, 3)
	for i := 0; i < 3; i++ {
		b[i] = hexNibble(sd[i*2+1]) | (hexNibble(sd[i*2]) << 4)
	}
	return b
}

// buildNGAPSNSSAI constructs an NGAP SNSSAI IE.
// sdBytes is the 3-byte SD; if nil or empty, the SD optional IE is omitted.
func buildNGAPSNSSAI(sst uint8, sdBytes []byte) ngapType.SNSSAI {
	s := ngapType.SNSSAI{
		SST: ngapType.SST{Value: aper.OctetString{sst}},
	}
	if len(sdBytes) == 3 {
		sd := ngapType.SD{Value: aper.OctetString(sdBytes)}
		s.SD = &sd
	}
	return s
}

// buildUESecurityCapabilities builds the NGAP UESecurityCapabilities IE from
// the UE's advertised bitmasks (bit 15=NEA1/NIA1, 14=NEA2/NIA2, 13=NEA3/NIA3).
// These must reflect what the UE supports, not the selected algorithm.
// Ref: TS 38.413 §9.3.1.86
func buildUESecurityCapabilities(encAlgsBitmap, intAlgsBitmap uint16) *ngapType.UESecurityCapabilities {
	encBytes := []byte{byte(encAlgsBitmap >> 8), byte(encAlgsBitmap)}
	intBytes := []byte{byte(intAlgsBitmap >> 8), byte(intAlgsBitmap)}

	return &ngapType.UESecurityCapabilities{
		NRencryptionAlgorithms: ngapType.NRencryptionAlgorithms{
			Value: aper.BitString{Bytes: encBytes, BitLength: 16},
		},
		NRintegrityProtectionAlgorithms: ngapType.NRintegrityProtectionAlgorithms{
			Value: aper.BitString{Bytes: intBytes, BitLength: 16},
		},
		EUTRAencryptionAlgorithms: ngapType.EUTRAencryptionAlgorithms{
			Value: aper.BitString{Bytes: []byte{0x00, 0x00}, BitLength: 16},
		},
		EUTRAintegrityProtectionAlgorithms: ngapType.EUTRAintegrityProtectionAlgorithms{
			Value: aper.BitString{Bytes: []byte{0x00, 0x00}, BitLength: 16},
		},
	}
}

// ---- PLMN/TAC helpers ---------------------------------------------------

// plmnFromMCCMNC encodes MCC+MNC into the 3-byte PLMN format per 3GPP TS 24.501.
// Example: MCC="001", MNC="01" → [0x00, 0xf1, 0x10]
func plmnFromMCCMNC(mcc, mnc string) []byte {
	mcc = zeroPad(mcc, 3)
	mnc = zeroPad(mnc, 2)
	if len(mnc) == 2 {
		mnc = mnc + "f"
	}
	// Nibble encoding: MCC digit 2 | MCC digit 1, MNC digit 3 | MCC digit 3, MNC digit 2 | MNC digit 1
	b := make([]byte, 3)
	b[0] = hexNibble(mcc[1])<<4 | hexNibble(mcc[0])
	b[1] = hexNibble(mnc[2])<<4 | hexNibble(mcc[2])
	b[2] = hexNibble(mnc[1])<<4 | hexNibble(mnc[0])
	return b
}

func plmnToMCC(plmn aper.OctetString) string {
	if len(plmn) < 3 {
		return ""
	}
	d1 := plmn[0] & 0x0F
	d2 := (plmn[0] >> 4) & 0x0F
	d3 := plmn[1] & 0x0F
	return fmt.Sprintf("%d%d%d", d1, d2, d3)
}

func plmnToMNC(plmn aper.OctetString) string {
	if len(plmn) < 3 {
		return ""
	}
	d1 := plmn[2] & 0x0F
	d2 := (plmn[2] >> 4) & 0x0F
	d3 := (plmn[1] >> 4) & 0x0F
	if d3 == 0x0F {
		return fmt.Sprintf("%d%d", d1, d2)
	}
	return fmt.Sprintf("%d%d%d", d1, d2, d3)
}

func tacToUint32(tac aper.OctetString) uint32 {
	var v uint32
	for _, b := range tac {
		v = (v << 8) | uint32(b)
	}
	return v
}

func hexNibble(c byte) byte {
	if c >= '0' && c <= '9' {
		return c - '0'
	}
	if c >= 'a' && c <= 'f' {
		return c - 'a' + 10
	}
	if c >= 'A' && c <= 'F' {
		return c - 'A' + 10
	}
	return 0x0F
}

func zeroPad(s string, n int) string {
	for len(s) < n {
		s = "0" + s
	}
	return s
}

// BuildPDUSessionResourceSetupRequest builds a PDU Session Resource Setup Request.
// sst is the Slice/Service Type (1 byte); sdBytes is the 3-byte SD (nil if not set).
// ueAMBR, when non-nil, appends the optional UE Aggregate Maximum Bit Rate IE
// (id=110, criticality ignore) AFTER the PDU Session Resource Setup Request List,
// as in the Rel-17 PDUSessionResourceSetupRequestIEs order; nil omits it. The AMF
// passes it when the gNB has not yet received a UE-AMBR for the current N2 context.
// Ref: TS 38.413 §8.2.1, §9.2.1.1, §9.3.1.58
func BuildPDUSessionResourceSetupRequest(
	amfUEID, ranUEID int64, pduSessionID uint8, nasPDU []byte, n2SmInfo []byte,
	sst uint8, sdBytes []byte,
	ueAMBR *UEAMBR,
) []byte {
	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodePDUSessionResourceSetup},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitiatingMessageValue{
				Present: ngapType.InitiatingMessagePresentPDUSessionResourceSetupRequest,
				PDUSessionResourceSetupRequest: &ngapType.PDUSessionResourceSetupRequest{
					ProtocolIEs: ngapType.ProtocolIEContainerPDUSessionResourceSetupRequestIEs{
						List: []ngapType.PDUSessionResourceSetupRequestIEs{
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.PDUSessionResourceSetupRequestIEsValue{
									Present:     ngapType.PDUSessionResourceSetupRequestIEsPresentAMFUENGAPID,
									AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfUEID},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.PDUSessionResourceSetupRequestIEsValue{
									Present:     ngapType.PDUSessionResourceSetupRequestIEsPresentRANUENGAPID,
									RANUENGAPID: &ngapType.RANUENGAPID{Value: ranUEID},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPDUSessionResourceSetupListSUReq},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.PDUSessionResourceSetupRequestIEsValue{
									Present: ngapType.PDUSessionResourceSetupRequestIEsPresentPDUSessionResourceSetupListSUReq,
									PDUSessionResourceSetupListSUReq: &ngapType.PDUSessionResourceSetupListSUReq{
										List: []ngapType.PDUSessionResourceSetupItemSUReq{
											{
												PDUSessionID: ngapType.PDUSessionID{Value: int64(pduSessionID)},
												PDUSessionNASPDU: &ngapType.NASPDU{
													Value: aper.OctetString(nasPDU),
												},
												SNSSAI:                                 buildNGAPSNSSAI(sst, sdBytes),
												PDUSessionResourceSetupRequestTransfer: aper.OctetString(n2SmInfo),
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	if ueAMBR != nil {
		ies := &pdu.InitiatingMessage.Value.PDUSessionResourceSetupRequest.ProtocolIEs
		ies.List = append(ies.List, ngapType.PDUSessionResourceSetupRequestIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDUEAggregateMaximumBitRate},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.PDUSessionResourceSetupRequestIEsValue{
				Present:                   ngapType.PDUSessionResourceSetupRequestIEsPresentUEAggregateMaximumBitRate,
				UEAggregateMaximumBitRate: buildUEAMBR(ueAMBR.ULBps, ueAMBR.DLBps),
			},
		})
	}

	b, err := libngap.Encoder(pdu)
	if err != nil {
		return nil
	}
	return b
}

// ---- PDU Session Resource Setup Response ------------------------------------

// PDUSessionSetupResult holds one successful PDU session setup from the gNB.
type PDUSessionSetupResult struct {
	PDUSessionID      uint8
	N2SMTransferBytes []byte // raw APER-encoded PDUSessionResourceSetupResponseTransfer
}

// PDUSessionResourceSetupResponseMsg is the decoded PDU Session Resource Setup Response.
// Carries the gNB GTP-U tunnel info for each PDU session. FailedPSIs lists the
// sessions the gNB could not set up (PDUSessionResourceFailedToSetupListSURes) —
// the AMF must inform the SMF so the session is released and its resources
// (UE IP, PFCP) are freed. Ref: TS 38.413 §8.2.1, TS 23.502 §4.3.2.2.1 step 16.
type PDUSessionResourceSetupResponseMsg struct {
	AMFUENGAPId int64
	RANUENGAPId int64
	Setups      []PDUSessionSetupResult
	FailedPSIs  []uint8
}

func extractPDUSessionResourceSetupResponse(resp *ngapType.PDUSessionResourceSetupResponse) *PDUSessionResourceSetupResponseMsg {
	out := &PDUSessionResourceSetupResponseMsg{}
	for _, ie := range resp.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				out.AMFUENGAPId = ie.Value.AMFUENGAPID.Value
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				out.RANUENGAPId = ie.Value.RANUENGAPID.Value
			}
		case ngapType.ProtocolIEIDPDUSessionResourceSetupListSURes:
			if ie.Value.PDUSessionResourceSetupListSURes != nil {
				for _, item := range ie.Value.PDUSessionResourceSetupListSURes.List {
					out.Setups = append(out.Setups, PDUSessionSetupResult{
						PDUSessionID:      uint8(item.PDUSessionID.Value),
						N2SMTransferBytes: []byte(item.PDUSessionResourceSetupResponseTransfer),
					})
				}
			}
		case ngapType.ProtocolIEIDPDUSessionResourceFailedToSetupListSURes:
			if ie.Value.PDUSessionResourceFailedToSetupListSURes != nil {
				for _, item := range ie.Value.PDUSessionResourceFailedToSetupListSURes.List {
					out.FailedPSIs = append(out.FailedPSIs, uint8(item.PDUSessionID.Value))
				}
			}
		}
	}
	return out
}

// InitialContextSetupResponseMsg is the decoded Initial Context Setup Response.
// Setups carries the gNB's PDUSessionResourceSetupResponseTransfer per PDU
// session re-established via PDUSessionResourceSetupListCxtReq (Service Request
// UP re-activation). FailedPSIs lists sessions the gNB could not set up.
// Ref: TS 38.413 §8.3.1, §9.2.2.2
type InitialContextSetupResponseMsg struct {
	AMFUENGAPId int64
	RANUENGAPId int64
	Setups      []PDUSessionSetupResult
	FailedPSIs  []uint8
}

func extractInitialContextSetupResponse(resp *ngapType.InitialContextSetupResponse) *InitialContextSetupResponseMsg {
	out := &InitialContextSetupResponseMsg{}
	for _, ie := range resp.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				out.AMFUENGAPId = ie.Value.AMFUENGAPID.Value
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				out.RANUENGAPId = ie.Value.RANUENGAPID.Value
			}
		case ngapType.ProtocolIEIDPDUSessionResourceSetupListCxtRes:
			if ie.Value.PDUSessionResourceSetupListCxtRes != nil {
				for _, item := range ie.Value.PDUSessionResourceSetupListCxtRes.List {
					out.Setups = append(out.Setups, PDUSessionSetupResult{
						PDUSessionID:      uint8(item.PDUSessionID.Value),
						N2SMTransferBytes: []byte(item.PDUSessionResourceSetupResponseTransfer),
					})
				}
			}
		case ngapType.ProtocolIEIDPDUSessionResourceFailedToSetupListCxtRes:
			if ie.Value.PDUSessionResourceFailedToSetupListCxtRes != nil {
				for _, item := range ie.Value.PDUSessionResourceFailedToSetupListCxtRes.List {
					out.FailedPSIs = append(out.FailedPSIs, uint8(item.PDUSessionID.Value))
				}
			}
		}
	}
	return out
}

// ---- PDU Session Resource Release Response ----------------------------------

// PDUSessionResourceReleaseResponseMsg is the decoded PDU Session Resource Release Response.
type PDUSessionResourceReleaseResponseMsg struct {
	AMFUENGAPId int64
	RANUENGAPId int64
}

func extractPDUSessionResourceReleaseResponse(resp *ngapType.PDUSessionResourceReleaseResponse) *PDUSessionResourceReleaseResponseMsg {
	out := &PDUSessionResourceReleaseResponseMsg{}
	for _, ie := range resp.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				out.AMFUENGAPId = ie.Value.AMFUENGAPID.Value
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				out.RANUENGAPId = ie.Value.RANUENGAPID.Value
			}
		}
	}
	return out
}

// BuildPDUSessionResourceReleaseCommand builds an NGAP PDU Session Resource Release Command.
// nasPDU carries the DL NAS Transport with 5GSM PDU Session Release Command.
// Ref: TS 38.413 §8.4.2
func BuildPDUSessionResourceReleaseCommand(amfUEID, ranUEID int64, pduSessionID uint8, nasPDU []byte) []byte {
	// Encode the N2 SM Release Command Transfer (APER SEQUENCE, extensible).
	transfer := ngapType.PDUSessionResourceReleaseCommandTransfer{
		Cause: ngapType.Cause{
			Present: ngapType.CausePresentRadioNetwork,
			RadioNetwork: &ngapType.CauseRadioNetwork{
				Value: ngapType.CauseRadioNetworkPresentReleaseDueTo5gcGeneratedReason,
			},
		},
	}
	transferBytes, err := aper.MarshalWithParams(transfer, "valueExt")
	if err != nil {
		return nil
	}

	nasPduVal := ngapType.NASPDU{Value: aper.OctetString(nasPDU)}
	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodePDUSessionResourceRelease},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitiatingMessageValue{
				Present: ngapType.InitiatingMessagePresentPDUSessionResourceReleaseCommand,
				PDUSessionResourceReleaseCommand: &ngapType.PDUSessionResourceReleaseCommand{
					ProtocolIEs: ngapType.ProtocolIEContainerPDUSessionResourceReleaseCommandIEs{
						List: []ngapType.PDUSessionResourceReleaseCommandIEs{
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.PDUSessionResourceReleaseCommandIEsValue{
									Present:     ngapType.PDUSessionResourceReleaseCommandIEsPresentAMFUENGAPID,
									AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfUEID},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.PDUSessionResourceReleaseCommandIEsValue{
									Present:     ngapType.PDUSessionResourceReleaseCommandIEsPresentRANUENGAPID,
									RANUENGAPID: &ngapType.RANUENGAPID{Value: ranUEID},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDNASPDU},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.PDUSessionResourceReleaseCommandIEsValue{
									Present: ngapType.PDUSessionResourceReleaseCommandIEsPresentNASPDU,
									NASPDU:  &nasPduVal,
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPDUSessionResourceToReleaseListRelCmd},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.PDUSessionResourceReleaseCommandIEsValue{
									Present: ngapType.PDUSessionResourceReleaseCommandIEsPresentPDUSessionResourceToReleaseListRelCmd,
									PDUSessionResourceToReleaseListRelCmd: &ngapType.PDUSessionResourceToReleaseListRelCmd{
										List: []ngapType.PDUSessionResourceToReleaseItemRelCmd{
											{
												PDUSessionID:                             ngapType.PDUSessionID{Value: int64(pduSessionID)},
												PDUSessionResourceReleaseCommandTransfer: aper.OctetString(transferBytes),
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	b, err := libngap.Encoder(pdu)
	if err != nil {
		return nil
	}
	return b
}

// ---- UE Context Release Request (gNB→AMF, InitiatingMessage, ProcCode=42) ----
// Ref: TS 38.413 §8.3.4

// UEContextReleaseRequestMsg holds decoded fields from a UE Context Release Request.
type UEContextReleaseRequestMsg struct {
	AMFUENGAPId int64
	RANUENGAPId int64
	// CausePresent: 1=RadioNetwork 2=Transport 3=NAS 4=Protocol 5=Misc
	CausePresent int
	CauseValue   int64
}

func extractUEContextReleaseRequest(req *ngapType.UEContextReleaseRequest) *UEContextReleaseRequestMsg {
	out := &UEContextReleaseRequestMsg{}
	for _, ie := range req.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				out.AMFUENGAPId = ie.Value.AMFUENGAPID.Value
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				out.RANUENGAPId = ie.Value.RANUENGAPID.Value
			}
		case ngapType.ProtocolIEIDCause:
			if ie.Value.Cause != nil {
				out.CausePresent = ie.Value.Cause.Present
				switch ie.Value.Cause.Present {
				case ngapType.CausePresentRadioNetwork:
					if ie.Value.Cause.RadioNetwork != nil {
						out.CauseValue = int64(ie.Value.Cause.RadioNetwork.Value)
					}
				case ngapType.CausePresentNas:
					if ie.Value.Cause.Nas != nil {
						out.CauseValue = int64(ie.Value.Cause.Nas.Value)
					}
				case ngapType.CausePresentMisc:
					if ie.Value.Cause.Misc != nil {
						out.CauseValue = int64(ie.Value.Cause.Misc.Value)
					}
				}
			}
		}
	}
	return out
}

// ---- UE Radio Capability Info Indication (gNB→AMF, InitiatingMessage, ProcCode=44) ---
// Ref: TS 38.413 §8.7.6

// UERadioCapabilityInfoIndicationMsg holds the decoded fields of a
// UE Radio Capability Info Indication. Class-2 procedure — no response.
type UERadioCapabilityInfoIndicationMsg struct {
	AMFUENGAPId       int64
	RANUENGAPId       int64
	UERadioCapability []byte // OCTET STRING, opaque to the AMF; stored for later N2 use
}

func extractUERadioCapabilityInfoIndication(m *ngapType.UERadioCapabilityInfoIndication) *UERadioCapabilityInfoIndicationMsg {
	out := &UERadioCapabilityInfoIndicationMsg{}
	for _, ie := range m.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				out.AMFUENGAPId = ie.Value.AMFUENGAPID.Value
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				out.RANUENGAPId = ie.Value.RANUENGAPID.Value
			}
		case ngapType.ProtocolIEIDUERadioCapability:
			if ie.Value.UERadioCapability != nil {
				out.UERadioCapability = append([]byte(nil), ie.Value.UERadioCapability.Value...)
			}
		}
	}
	return out
}

// ---- UE Context Release Complete (gNB→AMF, SuccessfulOutcome, ProcCode=41) ---
// Ref: TS 38.413 §8.3.3

// UEContextReleaseCompleteMsg holds decoded fields from a UE Context Release Complete.
type UEContextReleaseCompleteMsg struct {
	AMFUENGAPId int64
	RANUENGAPId int64
}

func extractUEContextReleaseComplete(msg *ngapType.UEContextReleaseComplete) *UEContextReleaseCompleteMsg {
	out := &UEContextReleaseCompleteMsg{}
	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				out.AMFUENGAPId = ie.Value.AMFUENGAPID.Value
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				out.RANUENGAPId = ie.Value.RANUENGAPID.Value
			}
		}
	}
	return out
}

// ---- UE Context Release Command (AMF→gNB, InitiatingMessage, ProcCode=41) ----
// Ref: TS 38.413 §8.3.3

// BuildUEContextReleaseCommand builds a UE Context Release Command NGAP PDU.
// cause: 1=RadioNetwork, 3=NAS; causeValue: the enumerated value within that group.
// Ref: TS 38.413 §8.3.3, Table 9.1.3.5-1
func BuildUEContextReleaseCommand(amfUEID, ranUEID int64, causePresent int, causeValue int64) []byte {
	cause := buildCause(causePresent, causeValue)

	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeUEContextRelease},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitiatingMessageValue{
				Present: ngapType.InitiatingMessagePresentUEContextReleaseCommand,
				UEContextReleaseCommand: &ngapType.UEContextReleaseCommand{
					ProtocolIEs: ngapType.ProtocolIEContainerUEContextReleaseCommandIEs{
						List: []ngapType.UEContextReleaseCommandIEs{
							// UE NGAP IDs — use pair (AMF+RAN) per §9.1.3.5
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDUENGAPIDs},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.UEContextReleaseCommandIEsValue{
									Present: ngapType.UEContextReleaseCommandIEsPresentUENGAPIDs,
									UENGAPIDs: &ngapType.UENGAPIDs{
										Present: ngapType.UENGAPIDsPresentUENGAPIDPair,
										UENGAPIDPair: &ngapType.UENGAPIDPair{
											AMFUENGAPID: ngapType.AMFUENGAPID{Value: amfUEID},
											RANUENGAPID: ngapType.RANUENGAPID{Value: ranUEID},
										},
									},
								},
							},
							// Cause
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDCause},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.UEContextReleaseCommandIEsValue{
									Present: ngapType.UEContextReleaseCommandIEsPresentCause,
									Cause:   &cause,
								},
							},
						},
					},
				},
			},
		},
	}

	b, err := libngap.Encoder(pdu)
	if err != nil {
		return nil
	}
	return b
}

// ---- Paging (AMF→gNB, InitiatingMessage, ProcedureCode=24) ------------------
// Ref: TS 38.413 §9.2.4.1 (PAGING message), §8.5.1 (Paging procedure), TS 23.502 §4.2.3.3 step 4b (Network Triggered Service Request)

// TAIForPaging is one Tracking Area Identity in the paging area.
type TAIForPaging struct {
	PLMN []byte // 3-byte nibble-encoded PLMN identity
	TAC  uint32 // 24-bit Tracking Area Code
}

// BuildPaging builds an NGAP Paging PDU (non-UE-associated) addressed at the UE
// via its 5G-S-TMSI, covering the supplied TAI list (the UE's registration area).
//
// 5G-S-TMSI = AMFSetID(10b) + AMFPointer(6b) + 5G-TMSI(32b). Ref: TS 23.003 §2.10.
func BuildPaging(setID uint16, amfID byte, tmsi uint32, tais []TAIForPaging) []byte {
	// AMFSetID is a 10-bit field: the top 10 bits of the two bytes carry setID.
	amfSetID := ngapType.AMFSetID{
		Value: aper.BitString{Bytes: []byte{byte(setID >> 2), byte(setID << 6)}, BitLength: 10},
	}
	// AMFPointer is a 6-bit field: the top 6 bits carry amfID.
	amfPointer := ngapType.AMFPointer{
		Value: aper.BitString{Bytes: []byte{amfID << 2}, BitLength: 6},
	}
	tmsiBytes := []byte{byte(tmsi >> 24), byte(tmsi >> 16), byte(tmsi >> 8), byte(tmsi)}

	var taiItems []ngapType.TAIListForPagingItem
	for _, t := range tais {
		taiItems = append(taiItems, ngapType.TAIListForPagingItem{
			TAI: ngapType.TAI{
				PLMNIdentity: ngapType.PLMNIdentity{Value: t.PLMN},
				TAC:          ngapType.TAC{Value: aper.OctetString{byte(t.TAC >> 16), byte(t.TAC >> 8), byte(t.TAC)}},
			},
		})
	}

	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodePaging},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.InitiatingMessageValue{
				Present: ngapType.InitiatingMessagePresentPaging,
				Paging: &ngapType.Paging{
					ProtocolIEs: ngapType.ProtocolIEContainerPagingIEs{
						List: []ngapType.PagingIEs{
							// UE Paging Identity (5G-S-TMSI) — mandatory
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDUEPagingIdentity},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.PagingIEsValue{
									Present: ngapType.PagingIEsPresentUEPagingIdentity,
									UEPagingIdentity: &ngapType.UEPagingIdentity{
										Present: ngapType.UEPagingIdentityPresentFiveGSTMSI,
										FiveGSTMSI: &ngapType.FiveGSTMSI{
											AMFSetID:   amfSetID,
											AMFPointer: amfPointer,
											FiveGTMSI:  ngapType.FiveGTMSI{Value: aper.OctetString(tmsiBytes)},
										},
									},
								},
							},
							// TAI List for Paging — mandatory
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDTAIListForPaging},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.PagingIEsValue{
									Present:          ngapType.PagingIEsPresentTAIListForPaging,
									TAIListForPaging: &ngapType.TAIListForPaging{List: taiItems},
								},
							},
						},
					},
				},
			},
		},
	}

	b, err := libngap.Encoder(pdu)
	if err != nil {
		return nil
	}
	return b
}

// buildCause constructs an NGAP Cause IE.
// causePresent: 1=RadioNetwork, 2=Transport, 3=NAS, 4=Protocol, 5=Misc.
func buildCause(causePresent int, causeValue int64) ngapType.Cause {
	c := ngapType.Cause{Present: causePresent}
	switch causePresent {
	case ngapType.CausePresentRadioNetwork:
		c.RadioNetwork = &ngapType.CauseRadioNetwork{Value: aper.Enumerated(causeValue)}
	case ngapType.CausePresentTransport:
		c.Transport = &ngapType.CauseTransport{Value: aper.Enumerated(causeValue)}
	case ngapType.CausePresentNas:
		c.Nas = &ngapType.CauseNas{Value: aper.Enumerated(causeValue)}
	case ngapType.CausePresentProtocol:
		c.Protocol = &ngapType.CauseProtocol{Value: aper.Enumerated(causeValue)}
	case ngapType.CausePresentMisc:
		c.Misc = &ngapType.CauseMisc{Value: aper.Enumerated(causeValue)}
	default:
		// Default to NAS normal release
		c.Present = ngapType.CausePresentNas
		c.Nas = &ngapType.CauseNas{Value: ngapType.CauseNasPresentNormalRelease}
	}
	return c
}

// causeFromNGAP flattens a decoded NGAP Cause into the (present, value) pair buildCause
// takes; ok is false when the selected group is absent.
func causeFromNGAP(c ngapType.Cause) (present int, value int64, ok bool) {
	switch c.Present {
	case ngapType.CausePresentRadioNetwork:
		if c.RadioNetwork != nil {
			return c.Present, int64(c.RadioNetwork.Value), true
		}
	case ngapType.CausePresentTransport:
		if c.Transport != nil {
			return c.Present, int64(c.Transport.Value), true
		}
	case ngapType.CausePresentNas:
		if c.Nas != nil {
			return c.Present, int64(c.Nas.Value), true
		}
	case ngapType.CausePresentProtocol:
		if c.Protocol != nil {
			return c.Present, int64(c.Protocol.Value), true
		}
	case ngapType.CausePresentMisc:
		if c.Misc != nil {
			return c.Present, int64(c.Misc.Value), true
		}
	}
	return 0, 0, false
}

// ensure hex import is used
var _ = hex.EncodeToString

// ---- Location Reporting Control (AMF→gNB, InitiatingMessage, ProcCode=16) ---
// Ref: TS 38.413 §8.17.1 (Location Reporting)

// BuildLocationReportingControl builds an NGAP LocationReportingControl PDU.
// It requests a single immediate (Direct) cell-level location report for the UE
// identified by amfUENGAPID / ranUENGAPID.
//
// IE ordering matches TS 38.413 Table 9.2.x:
//   - AMF-UE-NGAP-ID (id=10) — Mandatory
//   - RAN-UE-NGAP-ID (id=85) — Mandatory
//   - LocationReportingRequestType (id=33): EventType=Direct(0), ReportArea=Cell(0) — Mandatory
//
// Ref: TS 38.413 §8.17.1, §9.2.x; TS 23.273 §7.2 (Cell-ID positioning MVP).
func BuildLocationReportingControl(amfUENGAPID, ranUENGAPID int64) []byte {
	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeLocationReportingControl},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.InitiatingMessageValue{
				Present: ngapType.InitiatingMessagePresentLocationReportingControl,
				LocationReportingControl: &ngapType.LocationReportingControl{
					ProtocolIEs: ngapType.ProtocolIEContainerLocationReportingControlIEs{
						List: []ngapType.LocationReportingControlIEs{
							// AMF-UE-NGAP-ID (id=10) — Mandatory
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.LocationReportingControlIEsValue{
									Present:     ngapType.LocationReportingControlIEsPresentAMFUENGAPID,
									AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfUENGAPID},
								},
							},
							// RAN-UE-NGAP-ID (id=85) — Mandatory
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.LocationReportingControlIEsValue{
									Present:     ngapType.LocationReportingControlIEsPresentRANUENGAPID,
									RANUENGAPID: &ngapType.RANUENGAPID{Value: ranUENGAPID},
								},
							},
							// LocationReportingRequestType (id=33) — Mandatory
							// EventType=Direct(0): report once immediately.
							// ReportArea=Cell(0): serving cell granularity.
							// Ref: TS 38.413 §9.3.1.x, §8.17.1; TS 23.273 §7.2.
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDLocationReportingRequestType},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
								Value: ngapType.LocationReportingControlIEsValue{
									Present: ngapType.LocationReportingControlIEsPresentLocationReportingRequestType,
									LocationReportingRequestType: &ngapType.LocationReportingRequestType{
										EventType:  ngapType.EventType{Value: ngapType.EventTypePresentDirect},
										ReportArea: ngapType.ReportArea{Value: ngapType.ReportAreaPresentCell},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	b, err := libngap.Encoder(pdu)
	if err != nil {
		return nil
	}
	return b
}

// ---- Location Report (gNB→AMF, InitiatingMessage, ProcCode=18) ----------------
// Ref: TS 38.413 §8.17.1 (Location Report)

// LocationReportMsg holds the decoded fields from an NGAP LocationReport.
// The NRCGI is rendered as a hex string (36-bit cell id zero-padded to 9 hex digits).
// Ref: TS 38.413 §9.3.1.x; TS 29.572 §6.1.6.2.2 (LocationData).
type LocationReportMsg struct {
	AMFUENGAPId int64
	RANUENGAPId int64
	// NRCellID is the NR Cell Global Identifier rendered as a hex string.
	// 36 bits from aper.BitString, zero-extended to 9 hex digits (38.413 §9.3.1.x).
	NRCellID string
	TAI      *TAI
}

// extractLocationReport decodes the IEs from an NGAP LocationReport.
func extractLocationReport(msg *ngapType.LocationReport) *LocationReportMsg {
	out := &LocationReportMsg{}
	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Value.Present {
		case ngapType.LocationReportIEsPresentAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				out.AMFUENGAPId = ie.Value.AMFUENGAPID.Value
			}
		case ngapType.LocationReportIEsPresentRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				out.RANUENGAPId = ie.Value.RANUENGAPID.Value
			}
		case ngapType.LocationReportIEsPresentUserLocationInformation:
			if ie.Value.UserLocationInformation != nil {
				uli := ie.Value.UserLocationInformation
				if uli.Present == ngapType.UserLocationInformationPresentUserLocationInformationNR &&
					uli.UserLocationInformationNR != nil {
					nr := uli.UserLocationInformationNR
					// Encode NRCellIdentity (36-bit BitString) as hex string.
					// The bytes array holds ≥5 bytes (36 bits packed big-endian with
					// trailing zero-padding); render as 9-char hex for portability.
					// Ref: TS 38.413 §9.3.1.x, TS 29.572 §6.1.6.2.2 nrCellId field.
					bs := nr.NRCGI.NRCellIdentity.Value
					cellID := nrCellIdentityToHex(bs.Bytes, bs.BitLength)
					out.NRCellID = cellID
					// Decode TAI from PLMN + TAC.
					tai := &TAI{
						MCC: plmnToMCC(nr.TAI.PLMNIdentity.Value),
						MNC: plmnToMNC(nr.TAI.PLMNIdentity.Value),
						TAC: tacToUint32(nr.TAI.TAC.Value),
					}
					out.TAI = tai
				}
			}
		}
	}
	return out
}

// nrCellIdentityToHex converts a BitString (36 bits, aper big-endian) to a
// 9-character lowercase hex string. The 36-bit value occupies 5 bytes with
// the top 4 bits of the last byte unused (zero-filled by the encoder).
// Example: bytes=[0x00,0x00,0x00,0x01,0x00], bitLen=36 → "000000010"
// Ref: TS 38.413 §9.3.1.x (NRCellIdentity, 36-bit BIT STRING).
func nrCellIdentityToHex(b []byte, bitLen uint64) string {
	// Reconstruct a uint64 from up to 5 bytes, big-endian.
	// The 36-bit value is packed into the most-significant bits of the byte array.
	var v uint64
	for i, byteVal := range b {
		if i >= 5 {
			break
		}
		v = (v << 8) | uint64(byteVal)
	}
	// Shift right to remove the trailing (8*len(b) - bitLen) padding bits.
	if len(b) > 0 {
		shift := uint64(len(b))*8 - bitLen
		v >>= shift
	}
	return fmt.Sprintf("%09x", v)
}

// ---- N2 Handover — HandoverRequired (source gNB → AMF, ProcCode=12) --------
// Ref: TS 38.413 §8.4.1 (Handover Preparation), §9.2.3.1; TS 23.502 §4.9.1.3.2

// PDUSessionHORqdItem carries one PDU session that must be set up at the target gNB.
type PDUSessionHORqdItem struct {
	PDUSessionID             uint8
	HandoverRequiredTransfer []byte // opaque transfer per TS 38.413 §9.3.4.14
}

// HOTargetTAI is the Selected TAI of the Target ID of a HANDOVER REQUIRED, in the string
// form of TS 29.571 (Tai): PLMN digits and the 3-octet TAC as 6 hex digits.
type HOTargetTAI struct {
	MCC, MNC string
	TAC      string // 6 hex digits
}

// HOTargetID is the decoded Target ID (TargetRANNodeID: Global gNB ID + Selected TAI) of a
// HANDOVER REQUIRED, used to build the TS 29.571 NgRanTargetId of the PREPARING
// UpdateSMContext. Absent parts are left zero / nil and omitted from the SBI JSON.
// Ref: TS 38.413 §9.2.3.1 (Target ID IE); TS 29.571 (NgRanTargetId, GlobalRanNodeId, Tai).
type HOTargetID struct {
	// Node is the Global gNB ID (Type == RANNodeTypeGNB) of the target; zero when the
	// target is not a gNB or absent.
	Node GlobalRANNode
	// TAI is the Selected TAI, nil when absent.
	TAI *HOTargetTAI
}

// extractHOTargetID decodes the TargetRANNodeID of a Target ID IE.
func extractHOTargetID(t *ngapType.TargetID) HOTargetID {
	var out HOTargetID
	if t == nil || t.Present != ngapType.TargetIDPresentTargetRANNodeID || t.TargetRANNodeID == nil {
		return out
	}
	out.Node = extractGlobalRANNode(&t.TargetRANNodeID.GlobalRANNodeID)
	sel := t.TargetRANNodeID.SelectedTAI
	if len(sel.PLMNIdentity.Value) >= 3 && len(sel.TAC.Value) > 0 {
		out.TAI = &HOTargetTAI{
			MCC: plmnToMCC(sel.PLMNIdentity.Value),
			MNC: plmnToMNC(sel.PLMNIdentity.Value),
			TAC: hex.EncodeToString(sel.TAC.Value),
		}
	}
	return out
}

// HandoverRequiredMsg holds decoded fields from an NGAP HandoverRequired.
type HandoverRequiredMsg struct {
	AMFUENGAPId                        int64
	RANUENGAPId                        int64
	HandoverType                       int // 0=intra5GS, 1=5GS→EPS, 2=EPS→5GS
	CausePresent                       int
	CauseValue                         int64
	TargetGlobalRANNodeID              []byte // GlobalRANNodeID bytes for gNB lookup
	Target                             HOTargetID
	PDUSessions                        []PDUSessionHORqdItem
	SourceToTargetTransparentContainer []byte // opaque RRC container
}

func extractHandoverRequired(req *ngapType.HandoverRequired) *HandoverRequiredMsg {
	out := &HandoverRequiredMsg{}
	for _, ie := range req.ProtocolIEs.List {
		switch ie.Value.Present {
		case ngapType.HandoverRequiredIEsPresentAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				out.AMFUENGAPId = ie.Value.AMFUENGAPID.Value
			}
		case ngapType.HandoverRequiredIEsPresentRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				out.RANUENGAPId = ie.Value.RANUENGAPID.Value
			}
		case ngapType.HandoverRequiredIEsPresentHandoverType:
			if ie.Value.HandoverType != nil {
				out.HandoverType = int(ie.Value.HandoverType.Value)
			}
		case ngapType.HandoverRequiredIEsPresentCause:
			if ie.Value.Cause != nil {
				out.CausePresent = ie.Value.Cause.Present
				switch ie.Value.Cause.Present {
				case ngapType.CausePresentRadioNetwork:
					if ie.Value.Cause.RadioNetwork != nil {
						out.CauseValue = int64(ie.Value.Cause.RadioNetwork.Value)
					}
				case ngapType.CausePresentNas:
					if ie.Value.Cause.Nas != nil {
						out.CauseValue = int64(ie.Value.Cause.Nas.Value)
					}
				}
			}
		case ngapType.HandoverRequiredIEsPresentTargetID:
			if ie.Value.TargetID != nil &&
				ie.Value.TargetID.Present == ngapType.TargetIDPresentTargetRANNodeID &&
				ie.Value.TargetID.TargetRANNodeID != nil {
				out.TargetGlobalRANNodeID = extractGlobalRANNodeIDBytes(
					&ie.Value.TargetID.TargetRANNodeID.GlobalRANNodeID)
			}
		case ngapType.HandoverRequiredIEsPresentPDUSessionResourceListHORqd:
			if ie.Value.PDUSessionResourceListHORqd != nil {
				for _, item := range ie.Value.PDUSessionResourceListHORqd.List {
					out.PDUSessions = append(out.PDUSessions, PDUSessionHORqdItem{
						PDUSessionID:             uint8(item.PDUSessionID.Value),
						HandoverRequiredTransfer: []byte(item.HandoverRequiredTransfer),
					})
				}
			}
		case ngapType.HandoverRequiredIEsPresentSourceToTargetTransparentContainer:
			if ie.Value.SourceToTargetTransparentContainer != nil {
				out.SourceToTargetTransparentContainer = []byte(
					ie.Value.SourceToTargetTransparentContainer.Value)
			}
		}
	}
	return out
}

// ---- N2 Handover — HandoverRequestAcknowledge (target gNB → AMF, ProcCode=13) ---
// Ref: TS 38.413 §8.4.2 (Handover Resource Allocation), §9.2.3.5

// PDUSessionHOAdmittedItem carries one successfully admitted PDU session.
type PDUSessionHOAdmittedItem struct {
	PDUSessionID                       uint8
	HandoverRequestAcknowledgeTransfer []byte // opaque HandoverRequestAcknowledgeTransfer, TS 38.413 §9.3.4.11 (ngapType.HandoverRequestAcknowledgeTransfer)
}

// PDUSessionHOFailedItem is one item of the PDU Session Resource Failed to Setup List
// HOAck of a HANDOVER REQUEST ACKNOWLEDGE: a PDU session the target could not admit.
type PDUSessionHOFailedItem struct {
	PDUSessionID uint8
	// HandoverResourceAllocationUnsuccessfulTransfer is the opaque transfer, TS 38.413
	// §9.3.4 (Handover Resource Allocation Unsuccessful Transfer).
	HandoverResourceAllocationUnsuccessfulTransfer []byte
}

// HandoverRequestAckMsg holds decoded fields from an NGAP HandoverRequestAcknowledge.
type HandoverRequestAckMsg struct {
	AMFUENGAPId                        int64
	RANUENGAPId                        int64
	AdmittedSessions                   []PDUSessionHOAdmittedItem
	FailedSessions                     []PDUSessionHOFailedItem
	TargetToSourceTransparentContainer []byte
}

func extractHandoverRequestAcknowledge(ack *ngapType.HandoverRequestAcknowledge) *HandoverRequestAckMsg {
	out := &HandoverRequestAckMsg{}
	for _, ie := range ack.ProtocolIEs.List {
		switch ie.Value.Present {
		case ngapType.HandoverRequestAcknowledgeIEsPresentAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				out.AMFUENGAPId = ie.Value.AMFUENGAPID.Value
			}
		case ngapType.HandoverRequestAcknowledgeIEsPresentRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				out.RANUENGAPId = ie.Value.RANUENGAPID.Value
			}
		case ngapType.HandoverRequestAcknowledgeIEsPresentPDUSessionResourceAdmittedList:
			if ie.Value.PDUSessionResourceAdmittedList != nil {
				for _, item := range ie.Value.PDUSessionResourceAdmittedList.List {
					out.AdmittedSessions = append(out.AdmittedSessions, PDUSessionHOAdmittedItem{
						PDUSessionID:                       uint8(item.PDUSessionID.Value),
						HandoverRequestAcknowledgeTransfer: []byte(item.HandoverRequestAcknowledgeTransfer),
					})
				}
			}
		case ngapType.HandoverRequestAcknowledgeIEsPresentPDUSessionResourceFailedToSetupListHOAck:
			if ie.Value.PDUSessionResourceFailedToSetupListHOAck != nil {
				for _, item := range ie.Value.PDUSessionResourceFailedToSetupListHOAck.List {
					out.FailedSessions = append(out.FailedSessions, PDUSessionHOFailedItem{
						PDUSessionID: uint8(item.PDUSessionID.Value),
						HandoverResourceAllocationUnsuccessfulTransfer: []byte(item.HandoverResourceAllocationUnsuccessfulTransfer),
					})
				}
			}
		case ngapType.HandoverRequestAcknowledgeIEsPresentTargetToSourceTransparentContainer:
			if ie.Value.TargetToSourceTransparentContainer != nil {
				out.TargetToSourceTransparentContainer = []byte(
					ie.Value.TargetToSourceTransparentContainer.Value)
			}
		}
	}
	return out
}

// ---- N2 Handover — HandoverNotify (target gNB → AMF, ProcCode=11) ----------
// Ref: TS 38.413 §8.4.3 (Handover Notification)

// HandoverNotifyMsg holds decoded fields from an NGAP HandoverNotify.
type HandoverNotifyMsg struct {
	AMFUENGAPId             int64
	RANUENGAPId             int64
	UserLocationInformation *ngapType.UserLocationInformation
}

func extractHandoverNotify(msg *ngapType.HandoverNotify) *HandoverNotifyMsg {
	out := &HandoverNotifyMsg{}
	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Value.Present {
		case ngapType.HandoverNotifyIEsPresentAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				out.AMFUENGAPId = ie.Value.AMFUENGAPID.Value
			}
		case ngapType.HandoverNotifyIEsPresentRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				out.RANUENGAPId = ie.Value.RANUENGAPID.Value
			}
		case ngapType.HandoverNotifyIEsPresentUserLocationInformation:
			out.UserLocationInformation = ie.Value.UserLocationInformation
		}
	}
	return out
}

// ---- N2 Handover — BuildHandoverRequest (AMF → target gNB) -----------------
// Ref: TS 38.413 §8.4.2, §9.2.3.4 (Handover Resource Allocation)

// PDUSessionHOReqItem carries one PDU session setup request for the target gNB.
type PDUSessionHOReqItem struct {
	PDUSessionID            uint8
	SNSSAI                  amfctx.SNSSAISubscribed
	HandoverRequestTransfer []byte // from source gNB's HandoverRequiredTransfer
}

// HandoverRequestMissingIE returns the name of the first mandatory HANDOVER
// REQUEST IE (TS 38.413 Table 9.2.3.4-1) that cannot be populated, or "".
func HandoverRequestMissingIE(nSessions, nAllowedNSSAI, containerLen int) string {
	switch {
	case nSessions == 0:
		return "PDUSessionResourceSetupListHOReq"
	case nAllowedNSSAI == 0:
		return "AllowedNSSAI"
	case containerLen == 0:
		return "SourceToTarget-TransparentContainer"
	}
	return ""
}

// BuildHandoverRequest builds an NGAP HandoverRequest (AMF → target gNB).
// Returns nil if a mandatory IE (session list, Allowed NSSAI, container) is empty.
// ueAMBR is the subscribed UE-AMBR (nil, or a non-positive direction, falls back
// to DefaultUEAMBRBps). nhNCC/nh are the next pair of the per-UE NH chain
// (UEContext.NextNH: NCC+1 mod 8, NH = KNH(KAMF, NH_prev), TS 33.501 §6.9.2.3.3).
// srcToTgtContainer is forwarded opaquely from the HandoverRequired.
func BuildHandoverRequest(
	amfUEID int64,
	handoverType int,
	causePresent int, causeValue int64,
	ueAMBR *UEAMBR,
	nhNCC uint8, nh [32]byte,
	encAlgsBitmap, intAlgsBitmap uint16,
	sessions []PDUSessionHOReqItem,
	allowedNSSAI []amfctx.SNSSAISubscribed,
	srcToTgtContainer []byte,
	mcc, mnc string,
	regionID byte, setID uint16, amfIDByte byte,
) []byte {
	if len(sessions) == 0 || len(allowedNSSAI) == 0 || len(srcToTgtContainer) == 0 {
		return nil
	}
	plmn := plmnFromMCCMNC(mcc, mnc)

	var sessionList []ngapType.PDUSessionResourceSetupItemHOReq
	for _, s := range sessions {
		sessionList = append(sessionList, ngapType.PDUSessionResourceSetupItemHOReq{
			PDUSessionID:            ngapType.PDUSessionID{Value: int64(s.PDUSessionID)},
			SNSSAI:                  buildNGAPSNSSAI(s.SNSSAI.SST, snssaiSDBytes(s.SNSSAI.SD)),
			HandoverRequestTransfer: aper.OctetString(s.HandoverRequestTransfer),
		})
	}

	nssaiItems := allowedNSSAIItems(allowedNSSAI)

	var ambrUL, ambrDL int64
	if ueAMBR != nil {
		ambrUL, ambrDL = ueAMBR.ULBps, ueAMBR.DLBps
	}

	cause := buildCause(causePresent, causeValue)

	ieList := []ngapType.HandoverRequestIEs{
		// AMF-UE-NGAP-ID
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.HandoverRequestIEsValue{
				Present:     ngapType.HandoverRequestIEsPresentAMFUENGAPID,
				AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfUEID},
			},
		},
		// HandoverType
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDHandoverType},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.HandoverRequestIEsValue{
				Present:      ngapType.HandoverRequestIEsPresentHandoverType,
				HandoverType: &ngapType.HandoverType{Value: aper.Enumerated(handoverType)},
			},
		},
		// Cause
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDCause},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.HandoverRequestIEsValue{
				Present: ngapType.HandoverRequestIEsPresentCause,
				Cause:   &cause,
			},
		},
		// UEAggregateMaximumBitRate
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDUEAggregateMaximumBitRate},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.HandoverRequestIEsValue{
				Present:                   ngapType.HandoverRequestIEsPresentUEAggregateMaximumBitRate,
				UEAggregateMaximumBitRate: buildUEAMBR(ambrUL, ambrDL),
			},
		},
		// UESecurityCapabilities
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDUESecurityCapabilities},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.HandoverRequestIEsValue{
				Present:                ngapType.HandoverRequestIEsPresentUESecurityCapabilities,
				UESecurityCapabilities: buildUESecurityCapabilities(encAlgsBitmap, intAlgsBitmap),
			},
		},
		// SecurityContext (NH + NCC) — TS 38.413 §9.3.1.18
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDSecurityContext},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.HandoverRequestIEsValue{
				Present: ngapType.HandoverRequestIEsPresentSecurityContext,
				SecurityContext: &ngapType.SecurityContext{
					NextHopChainingCount: ngapType.NextHopChainingCount{Value: int64(nhNCC)},
					NextHopNH: ngapType.SecurityKey{
						Value: aper.BitString{Bytes: nh[:], BitLength: 256},
					},
				},
			},
		},
		// GUAMI
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDGUAMI},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.HandoverRequestIEsValue{
				Present: ngapType.HandoverRequestIEsPresentGUAMI,
				GUAMI:   buildGUAMI(plmn, regionID, setID, amfIDByte),
			},
		},
		// SourceToTargetTransparentContainer
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDSourceToTargetTransparentContainer},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.HandoverRequestIEsValue{
				Present: ngapType.HandoverRequestIEsPresentSourceToTargetTransparentContainer,
				SourceToTargetTransparentContainer: &ngapType.SourceToTargetTransparentContainer{
					Value: aper.OctetString(srcToTgtContainer),
				},
			},
		},
	}

	// PDUSessionResourceSetupListHOReq (73) and AllowedNSSAI (0) — mandatory
	// (TS 38.413 Table 9.2.3.4-1); an empty SEQUENCE (SIZE(1..max)) cannot be
	// encoded, so the caller must have checked HandoverRequestMissingIE first.
	ieList = append(ieList,
		ngapType.HandoverRequestIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPDUSessionResourceSetupListHOReq},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.HandoverRequestIEsValue{
				Present: ngapType.HandoverRequestIEsPresentPDUSessionResourceSetupListHOReq,
				PDUSessionResourceSetupListHOReq: &ngapType.PDUSessionResourceSetupListHOReq{
					List: sessionList,
				},
			},
		},
		ngapType.HandoverRequestIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAllowedNSSAI},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.HandoverRequestIEsValue{
				Present:      ngapType.HandoverRequestIEsPresentAllowedNSSAI,
				AllowedNSSAI: &ngapType.AllowedNSSAI{List: nssaiItems},
			},
		},
	)
	// aper encodes IEs in append order: sort into the ASN.1 HandoverRequestIEs
	// order (TS 38.413 Table 9.2.3.4-1) so real RANs do not reject the message.
	sort.SliceStable(ieList, func(i, j int) bool {
		return ieList[i].Value.Present < ieList[j].Value.Present
	})

	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeHandoverResourceAllocation},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitiatingMessageValue{
				Present: ngapType.InitiatingMessagePresentHandoverRequest,
				HandoverRequest: &ngapType.HandoverRequest{
					ProtocolIEs: ngapType.ProtocolIEContainerHandoverRequestIEs{List: ieList},
				},
			},
		},
	}

	b, err := libngap.Encoder(pdu)
	if err != nil {
		return nil
	}
	return b
}

// BuildHandoverPreparationFailure builds an NGAP HandoverPreparationFailure
// (UnsuccessfulOutcome of HandoverPreparation, AMF → source gNB): AMF UE NGAP ID,
// RAN UE NGAP ID, Cause. Ref: TS 38.413 §8.4.1.3, §9.2.3.3.
func BuildHandoverPreparationFailure(amfUEID, ranUEID int64, causePresent int, causeValue int64) []byte {
	cause := buildCause(causePresent, causeValue)
	fail := &ngapType.HandoverPreparationFailure{}
	add := func(id int64, crit aper.Enumerated, v ngapType.HandoverPreparationFailureIEsValue) {
		fail.ProtocolIEs.List = append(fail.ProtocolIEs.List, ngapType.HandoverPreparationFailureIEs{
			Id:          ngapType.ProtocolIEID{Value: id},
			Criticality: ngapType.Criticality{Value: crit},
			Value:       v,
		})
	}
	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.CriticalityPresentIgnore, ngapType.HandoverPreparationFailureIEsValue{
		Present:     ngapType.HandoverPreparationFailureIEsPresentAMFUENGAPID,
		AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfUEID},
	})
	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.CriticalityPresentIgnore, ngapType.HandoverPreparationFailureIEsValue{
		Present:     ngapType.HandoverPreparationFailureIEsPresentRANUENGAPID,
		RANUENGAPID: &ngapType.RANUENGAPID{Value: ranUEID},
	})
	add(ngapType.ProtocolIEIDCause, ngapType.CriticalityPresentIgnore, ngapType.HandoverPreparationFailureIEsValue{
		Present: ngapType.HandoverPreparationFailureIEsPresentCause,
		Cause:   &cause,
	})
	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentUnsuccessfulOutcome,
		UnsuccessfulOutcome: &ngapType.UnsuccessfulOutcome{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeHandoverPreparation},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.UnsuccessfulOutcomeValue{
				Present:                    ngapType.UnsuccessfulOutcomePresentHandoverPreparationFailure,
				HandoverPreparationFailure: fail,
			},
		},
	}
	b, err := libngap.Encoder(pdu)
	if err != nil {
		return nil
	}
	return b
}

// ---- N2 Handover — BuildHandoverCommand (AMF → source gNB) -----------------
// Ref: TS 38.413 §8.4.1 (SuccessfulOutcome of HandoverPreparation)

// PDUSessionHOCmdItem is one item of the PDU Session Resource Handover List (IE 59)
// of a HANDOVER COMMAND.
type PDUSessionHOCmdItem struct {
	PDUSessionID uint8
	// HandoverCommandTransfer is the APER HandoverCommandTransfer (TS 38.413 §9.3.4.10)
	// returned by the SMF (n2SmInfoType HANDOVER_CMD). Empty: the builder encodes an
	// empty transfer (all IEs optional — no data forwarding tunnels).
	HandoverCommandTransfer []byte
}

// PDUSessionHOReleaseItem is one item of the PDU Session Resource To Release List
// HOCmd (IE 78) of a HANDOVER COMMAND: an admitted PDU session that will not be handed
// over, with its HandoverPreparationUnsuccessfulTransfer.
type PDUSessionHOReleaseItem struct {
	PDUSessionID uint8
	// HandoverPreparationUnsuccessfulTransfer, when non-empty, is the SMF-supplied
	// transfer (n2SmInfoType HANDOVER_PREP_FAIL) and is used verbatim; otherwise the
	// builder encodes {Cause} from CausePresent/CauseValue.
	HandoverPreparationUnsuccessfulTransfer []byte
	CausePresent                            int
	CauseValue                              int64
}

// BuildHandoverCommand builds an NGAP HandoverCommand (successful outcome of
// HandoverPreparation). IEs are appended in TS 38.413 Table 9.2.3.2-1 order:
// AMF UE NGAP ID (10), RAN UE NGAP ID (85), Handover Type (29), [PDU Session Resource
// Handover List (59)], [PDU Session Resource To Release List HOCmd (78)], Target to
// Source Transparent Container (106). tgtToSrcContainer is the container from
// HandoverRequestAcknowledge. Returns nil when an item cannot be encoded.
// Ref: TS 38.413 §8.4.1.2, §9.2.3.2; TS 23.502 §4.9.1.3.2 steps 9-12.
func BuildHandoverCommand(
	amfUEID, ranUEID int64,
	handoverType int,
	handled []PDUSessionHOCmdItem,
	toRelease []PDUSessionHOReleaseItem,
	tgtToSrcContainer []byte,
) []byte {
	var sessionList []ngapType.PDUSessionResourceHandoverItem
	for _, s := range handled {
		cmdTransfer := s.HandoverCommandTransfer
		if len(cmdTransfer) == 0 {
			tb, err := aper.MarshalWithParams(ngapType.HandoverCommandTransfer{}, "valueExt")
			if err != nil {
				return nil
			}
			cmdTransfer = tb
		}
		sessionList = append(sessionList, ngapType.PDUSessionResourceHandoverItem{
			PDUSessionID:            ngapType.PDUSessionID{Value: int64(s.PDUSessionID)},
			HandoverCommandTransfer: aper.OctetString(cmdTransfer),
		})
	}
	var releaseList []ngapType.PDUSessionResourceToReleaseItemHOCmd
	for _, r := range toRelease {
		tr := r.HandoverPreparationUnsuccessfulTransfer
		if len(tr) == 0 {
			tb, err := aper.MarshalWithParams(ngapType.HandoverPreparationUnsuccessfulTransfer{
				Cause: buildCause(r.CausePresent, r.CauseValue),
			}, "valueExt")
			if err != nil {
				return nil
			}
			tr = tb
		}
		releaseList = append(releaseList, ngapType.PDUSessionResourceToReleaseItemHOCmd{
			PDUSessionID:                            ngapType.PDUSessionID{Value: int64(r.PDUSessionID)},
			HandoverPreparationUnsuccessfulTransfer: aper.OctetString(tr),
		})
	}

	ieList := []ngapType.HandoverCommandIEs{
		// AMF-UE-NGAP-ID
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.HandoverCommandIEsValue{
				Present:     ngapType.HandoverCommandIEsPresentAMFUENGAPID,
				AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfUEID},
			},
		},
		// RAN-UE-NGAP-ID
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.HandoverCommandIEsValue{
				Present:     ngapType.HandoverCommandIEsPresentRANUENGAPID,
				RANUENGAPID: &ngapType.RANUENGAPID{Value: ranUEID},
			},
		},
		// HandoverType
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDHandoverType},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.HandoverCommandIEsValue{
				Present:      ngapType.HandoverCommandIEsPresentHandoverType,
				HandoverType: &ngapType.HandoverType{Value: aper.Enumerated(handoverType)},
			},
		},
	}
	// PDUSessionResourceHandoverList (59) — aper keeps append order.
	if len(sessionList) > 0 {
		ieList = append(ieList, ngapType.HandoverCommandIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPDUSessionResourceHandoverList},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.HandoverCommandIEsValue{
				Present: ngapType.HandoverCommandIEsPresentPDUSessionResourceHandoverList,
				PDUSessionResourceHandoverList: &ngapType.PDUSessionResourceHandoverList{
					List: sessionList,
				},
			},
		})
	}
	// PDUSessionResourceToReleaseListHOCmd (78) — between 59 and 106.
	if len(releaseList) > 0 {
		ieList = append(ieList, ngapType.HandoverCommandIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPDUSessionResourceToReleaseListHOCmd},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.HandoverCommandIEsValue{
				Present: ngapType.HandoverCommandIEsPresentPDUSessionResourceToReleaseListHOCmd,
				PDUSessionResourceToReleaseListHOCmd: &ngapType.PDUSessionResourceToReleaseListHOCmd{
					List: releaseList,
				},
			},
		})
	}
	// TargetToSourceTransparentContainer (106, mandatory)
	ieList = append(ieList, ngapType.HandoverCommandIEs{
		Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDTargetToSourceTransparentContainer},
		Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
		Value: ngapType.HandoverCommandIEsValue{
			Present: ngapType.HandoverCommandIEsPresentTargetToSourceTransparentContainer,
			TargetToSourceTransparentContainer: &ngapType.TargetToSourceTransparentContainer{
				Value: aper.OctetString(tgtToSrcContainer),
			},
		},
	})

	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentSuccessfulOutcome,
		SuccessfulOutcome: &ngapType.SuccessfulOutcome{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeHandoverPreparation},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.SuccessfulOutcomeValue{
				Present: ngapType.SuccessfulOutcomePresentHandoverCommand,
				HandoverCommand: &ngapType.HandoverCommand{
					ProtocolIEs: ngapType.ProtocolIEContainerHandoverCommandIEs{List: ieList},
				},
			},
		},
	}

	b, err := libngap.Encoder(pdu)
	if err != nil {
		return nil
	}
	return b
}

// ---- PDU Session Resource Modify Request (AMF→gNB, InitiatingMessage, ProcCode=26) ----
// Ref: TS 38.413 §8.2.1

// BuildPDUSessionResourceModifyRequest builds an NGAP PDU Session Resource Modify Request.
// nasPDU carries the DL NAS Transport with 5GSM PDU Session Modification Command.
// n2SmInfo is the APER-encoded PDUSessionResourceModifyRequestTransfer.
// Ref: TS 38.413 §8.2.1, §9.3.4.7; ProcedureCode=26
func BuildPDUSessionResourceModifyRequest(amfUEID, ranUEID int64, pduSessionID uint8, nasPDU []byte, n2SmInfo []byte) []byte {
	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodePDUSessionResourceModify},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.InitiatingMessageValue{
				Present: ngapType.InitiatingMessagePresentPDUSessionResourceModifyRequest,
				PDUSessionResourceModifyRequest: &ngapType.PDUSessionResourceModifyRequest{
					ProtocolIEs: ngapType.ProtocolIEContainerPDUSessionResourceModifyRequestIEs{
						List: []ngapType.PDUSessionResourceModifyRequestIEs{
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.PDUSessionResourceModifyRequestIEsValue{
									Present:     ngapType.PDUSessionResourceModifyRequestIEsPresentAMFUENGAPID,
									AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfUEID},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.PDUSessionResourceModifyRequestIEsValue{
									Present:     ngapType.PDUSessionResourceModifyRequestIEsPresentRANUENGAPID,
									RANUENGAPID: &ngapType.RANUENGAPID{Value: ranUEID},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPDUSessionResourceModifyListModReq},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.PDUSessionResourceModifyRequestIEsValue{
									Present: ngapType.PDUSessionResourceModifyRequestIEsPresentPDUSessionResourceModifyListModReq,
									PDUSessionResourceModifyListModReq: &ngapType.PDUSessionResourceModifyListModReq{
										List: []ngapType.PDUSessionResourceModifyItemModReq{
											{
												PDUSessionID:                            ngapType.PDUSessionID{Value: int64(pduSessionID)},
												NASPDU:                                  &ngapType.NASPDU{Value: nasPDU},
												PDUSessionResourceModifyRequestTransfer: aper.OctetString(n2SmInfo),
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	b, err := libngap.Encoder(pdu)
	if err != nil {
		return nil
	}
	return b
}

// ---- PDU Session Resource Modify Response (gNB→AMF, SuccessfulOutcome, ProcCode=26) ----

// PDUSessionModifyResult holds one successful PDU session modification from gNB.
type PDUSessionModifyResult struct {
	PDUSessionID uint8
}

// PDUSessionResourceModifyResponseMsg is the decoded PDU Session Resource Modify Response.
type PDUSessionResourceModifyResponseMsg struct {
	AMFUENGAPId int64
	RANUENGAPId int64
	Results     []PDUSessionModifyResult
}

func extractPDUSessionResourceModifyResponse(resp *ngapType.PDUSessionResourceModifyResponse) *PDUSessionResourceModifyResponseMsg {
	out := &PDUSessionResourceModifyResponseMsg{}
	for _, ie := range resp.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				out.AMFUENGAPId = ie.Value.AMFUENGAPID.Value
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				out.RANUENGAPId = ie.Value.RANUENGAPID.Value
			}
		case ngapType.ProtocolIEIDPDUSessionResourceModifyListModRes:
			if ie.Value.PDUSessionResourceModifyListModRes != nil {
				for _, item := range ie.Value.PDUSessionResourceModifyListModRes.List {
					out.Results = append(out.Results, PDUSessionModifyResult{
						PDUSessionID: uint8(item.PDUSessionID.Value),
					})
				}
			}
		}
	}
	return out
}

// ---- Path Switch Request (Xn Handover, TS 38.413 §8.4.4) -----------------

// PDUSessionSwitchItem carries one PDU session's new DL GTP-U endpoint for Xn handover.
type PDUSessionSwitchItem struct {
	PDUSessionID              uint8
	PathSwitchRequestTransfer []byte // raw APER bytes of PathSwitchRequestTransfer
	// AckTransfer is used only when the item is placed in the PATH SWITCH REQUEST
	// ACKNOWLEDGE Switched List: the SMF-returned PathSwitchRequestAcknowledgeTransfer
	// (TS 38.413 §9.3.4.9), used verbatim. Empty: the builder encodes an empty transfer.
	AckTransfer []byte
}

// PDUSessionFailedSetupItem is one entry of the PDU Session Resource Failed to
// Setup List PSReq (TS 38.413 §9.2.3.8).
type PDUSessionFailedSetupItem struct {
	PDUSessionID                         uint8
	PathSwitchRequestSetupFailedTransfer []byte
}

// UESecCapBitmaps are the NR encryption / integrity algorithm bitmaps of a UE
// Security Capabilities IE (bit 15 = NEA1/NIA1 ... bit 13 = NEA3/NIA3).
// Ref: TS 38.413 §9.3.1.86.
type UESecCapBitmaps struct {
	Enc, Int uint16
}

// PathSwitchRequestMsg is the decoded form of an NGAP PathSwitchRequest
// (TS 38.413 Table 9.2.3.8-1).
type PathSwitchRequestMsg struct {
	SourceAMFUENGAPId int64 // AMF UE NGAP ID assigned by source AMF
	RANUENGAPId       int64 // new RAN UE NGAP ID assigned by target gNB
	PDUSessions       []PDUSessionSwitchItem
	// TAI is the TAI of the User Location Information (nil when absent / not NR).
	TAI *TAI
	// UESecCap is the UE Security Capabilities received from the target (nil if absent).
	UESecCap *UESecCapBitmaps
	// FailedToSetup lists PDU Session Resource Failed to Setup List PSReq items.
	FailedToSetup []PDUSessionFailedSetupItem
}

func extractPathSwitchRequest(req *ngapType.PathSwitchRequest) *PathSwitchRequestMsg {
	out := &PathSwitchRequestMsg{}
	for _, ie := range req.ProtocolIEs.List {
		switch ie.Value.Present {
		case ngapType.PathSwitchRequestIEsPresentSourceAMFUENGAPID:
			if ie.Value.SourceAMFUENGAPID != nil {
				out.SourceAMFUENGAPId = ie.Value.SourceAMFUENGAPID.Value
			}
		case ngapType.PathSwitchRequestIEsPresentRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				out.RANUENGAPId = ie.Value.RANUENGAPID.Value
			}
		case ngapType.PathSwitchRequestIEsPresentUserLocationInformation:
			if ie.Value.UserLocationInformation != nil {
				out.TAI = extractTAIFromULI(ie.Value.UserLocationInformation)
			}
		case ngapType.PathSwitchRequestIEsPresentUESecurityCapabilities:
			if c := ie.Value.UESecurityCapabilities; c != nil {
				out.UESecCap = &UESecCapBitmaps{
					Enc: bitmap16(c.NRencryptionAlgorithms.Value.Bytes),
					Int: bitmap16(c.NRintegrityProtectionAlgorithms.Value.Bytes),
				}
			}
		case ngapType.PathSwitchRequestIEsPresentPDUSessionResourceToBeSwitchedDLList:
			if ie.Value.PDUSessionResourceToBeSwitchedDLList != nil {
				for _, item := range ie.Value.PDUSessionResourceToBeSwitchedDLList.List {
					out.PDUSessions = append(out.PDUSessions, PDUSessionSwitchItem{
						PDUSessionID:              uint8(item.PDUSessionID.Value),
						PathSwitchRequestTransfer: []byte(item.PathSwitchRequestTransfer),
					})
				}
			}
		case ngapType.PathSwitchRequestIEsPresentPDUSessionResourceFailedToSetupListPSReq:
			if ie.Value.PDUSessionResourceFailedToSetupListPSReq != nil {
				for _, item := range ie.Value.PDUSessionResourceFailedToSetupListPSReq.List {
					out.FailedToSetup = append(out.FailedToSetup, PDUSessionFailedSetupItem{
						PDUSessionID:                         uint8(item.PDUSessionID.Value),
						PathSwitchRequestSetupFailedTransfer: []byte(item.PathSwitchRequestSetupFailedTransfer),
					})
				}
			}
		}
	}
	return out
}

// bitmap16 reads the first two bytes of a 16-bit NGAP bit string as a big-endian bitmap.
func bitmap16(b []byte) uint16 {
	var v uint16
	if len(b) > 0 {
		v = uint16(b[0]) << 8
	}
	if len(b) > 1 {
		v |= uint16(b[1])
	}
	return v
}

// maxAllowedNSSAI is maxnoofAllowedS-NSSAIs. Ref: TS 38.413 §9.4.5.
const maxAllowedNSSAI = 8

// allowedNSSAIItems converts subscribed S-NSSAIs to NGAP Allowed NSSAI items,
// de-duplicated on (SST, SD) — the subscription type also carries a per-slice DNN,
// so the same slice can appear twice — and capped at maxnoofAllowedS-NSSAIs.
// Returns nil for an empty input. Ref: TS 38.413 §9.3.1.31.
func allowedNSSAIItems(in []amfctx.SNSSAISubscribed) []ngapType.AllowedNSSAIItem {
	type key struct {
		sst uint8
		sd  string
	}
	seen := make(map[key]struct{}, len(in))
	var items []ngapType.AllowedNSSAIItem
	for _, s := range in {
		k := key{s.SST, s.SD}
		if _, dup := seen[k]; dup || len(items) >= maxAllowedNSSAI {
			continue
		}
		seen[k] = struct{}{}
		items = append(items, ngapType.AllowedNSSAIItem{
			SNSSAI: buildNGAPSNSSAI(s.SST, snssaiSDBytes(s.SD)),
		})
	}
	return items
}

// PDUSessionReleasedItem is one PDU session of a PDU Session Resource Released List
// PSAck (Path Switch Request Acknowledge) or PSFail (Path Switch Request Failure),
// with the cause carried in its PathSwitchRequestUnsuccessfulTransfer
// (TS 38.413 §9.3.4 "Path Switch Request Unsuccessful Transfer"). CausePresent is an ngapType.CausePresent* value.
type PDUSessionReleasedItem struct {
	PDUSessionID uint8
	CausePresent int
	CauseValue   int64
	// Transfer, when non-empty, is the SMF-supplied PathSwitchRequestUnsuccessfulTransfer
	// (n2SmInfoType PATH_SWITCH_REQ_FAIL), already decode-checked, used verbatim instead
	// of {Cause} built from CausePresent/CauseValue.
	Transfer []byte
}

// buildUnsuccessfulTransfer encodes a PathSwitchRequestUnsuccessfulTransfer{Cause}.
func buildUnsuccessfulTransfer(causePresent int, causeValue int64) ([]byte, error) {
	return aper.MarshalWithParams(ngapType.PathSwitchRequestUnsuccessfulTransfer{
		Cause: buildCause(causePresent, causeValue),
	}, "valueExt")
}

// releasedTransfer returns the PathSwitchRequestUnsuccessfulTransfer bytes of a
// released item: the SMF bytes when present, else {Cause} built by the AMF.
func releasedTransfer(r PDUSessionReleasedItem) ([]byte, error) {
	if len(r.Transfer) > 0 {
		return r.Transfer, nil
	}
	return buildUnsuccessfulTransfer(r.CausePresent, r.CauseValue)
}

// PathSwitchAckParams are the inputs of BuildPathSwitchRequestAcknowledge.
type PathSwitchAckParams struct {
	AMFUENGAPId, RANUENGAPId int64
	// UESecCap, when non-nil, is echoed as UE Security Capabilities (IE 119): only
	// set when the capabilities received from the target differ from the stored ones.
	UESecCap *UESecCapBitmaps
	// NCC / NH is the Security Context (IE 93), the next pair of the per-UE chain.
	NCC uint8
	NH  [32]byte
	// Switched are the sessions in the PDU Session Resource Switched List (IE 77, M).
	Switched []PDUSessionSwitchItem
	// Released are sessions not switched (IE 68, omitted when empty).
	Released []PDUSessionReleasedItem
	// AllowedNSSAI is IE 0 (M); must be non-empty.
	AllowedNSSAI []amfctx.SNSSAISubscribed
}

// BuildPathSwitchRequestAcknowledge builds an NGAP PathSwitchRequestAcknowledge.
// IEs are appended in TS 38.413 Table 9.2.3.9-1 order: AMF UE NGAP ID (10),
// RAN UE NGAP ID (85), [UE Security Capabilities (119)], Security Context (93),
// PDU Session Resource Switched List (77), [Released List PSAck (68)], Allowed NSSAI (0).
// Returns nil when a mandatory IE cannot be built (empty Switched or AllowedNSSAI).
// Ref: TS 38.413 §8.4.4.2, §9.2.3.9, §9.3.1.18.
func BuildPathSwitchRequestAcknowledge(p PathSwitchAckParams) []byte {
	nssaiItems := allowedNSSAIItems(p.AllowedNSSAI)
	if len(p.Switched) == 0 || len(nssaiItems) == 0 {
		return nil
	}
	pdu := ngapType.NGAPPDU{Present: ngapType.NGAPPDUPresentSuccessfulOutcome}
	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)
	pdu.SuccessfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodePathSwitchRequest
	pdu.SuccessfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject
	pdu.SuccessfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentPathSwitchRequestAcknowledge
	ack := new(ngapType.PathSwitchRequestAcknowledge)
	pdu.SuccessfulOutcome.Value.PathSwitchRequestAcknowledge = ack

	add := func(id int64, crit aper.Enumerated, v ngapType.PathSwitchRequestAcknowledgeIEsValue) {
		ack.ProtocolIEs.List = append(ack.ProtocolIEs.List, ngapType.PathSwitchRequestAcknowledgeIEs{
			Id:          ngapType.ProtocolIEID{Value: id},
			Criticality: ngapType.Criticality{Value: crit},
			Value:       v,
		})
	}

	// (1) AMF UE NGAP ID — M, ignore
	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.CriticalityPresentIgnore,
		ngapType.PathSwitchRequestAcknowledgeIEsValue{
			Present:     ngapType.PathSwitchRequestAcknowledgeIEsPresentAMFUENGAPID,
			AMFUENGAPID: &ngapType.AMFUENGAPID{Value: p.AMFUENGAPId},
		})
	// (2) RAN UE NGAP ID — M, ignore
	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.CriticalityPresentIgnore,
		ngapType.PathSwitchRequestAcknowledgeIEsValue{
			Present:     ngapType.PathSwitchRequestAcknowledgeIEsPresentRANUENGAPID,
			RANUENGAPID: &ngapType.RANUENGAPID{Value: p.RANUENGAPId},
		})
	// (3) UE Security Capabilities — O, reject (only on mismatch)
	if p.UESecCap != nil {
		add(ngapType.ProtocolIEIDUESecurityCapabilities, ngapType.CriticalityPresentReject,
			ngapType.PathSwitchRequestAcknowledgeIEsValue{
				Present:                ngapType.PathSwitchRequestAcknowledgeIEsPresentUESecurityCapabilities,
				UESecurityCapabilities: buildUESecurityCapabilities(p.UESecCap.Enc, p.UESecCap.Int),
			})
	}
	// (4) Security Context {NCC, NH} — M, reject (TS 38.413 §9.3.1.18)
	nh := p.NH
	add(ngapType.ProtocolIEIDSecurityContext, ngapType.CriticalityPresentReject,
		ngapType.PathSwitchRequestAcknowledgeIEsValue{
			Present: ngapType.PathSwitchRequestAcknowledgeIEsPresentSecurityContext,
			SecurityContext: &ngapType.SecurityContext{
				NextHopChainingCount: ngapType.NextHopChainingCount{Value: int64(p.NCC)},
				NextHopNH: ngapType.SecurityKey{
					Value: aper.BitString{Bytes: nh[:], BitLength: 256},
				},
			},
		})
	// (6) PDU Session Resource Switched List — M, ignore
	// Per-PSI transfer: the SMF-returned PathSwitchRequestAcknowledgeTransfer
	// (TS 23.502 §4.9.1.2.2 step 7), or an empty one (all IEs optional) when the SMF
	// supplied none — docs/procedures/XnHandover.md §7.4.2.
	switchedList := &ngapType.PDUSessionResourceSwitchedList{}
	for _, sess := range p.Switched {
		ackTransfer := sess.AckTransfer
		if len(ackTransfer) == 0 {
			var err error
			ackTransfer, err = aper.MarshalWithParams(ngapType.PathSwitchRequestAcknowledgeTransfer{}, "valueExt")
			if err != nil {
				return nil
			}
		}
		switchedList.List = append(switchedList.List, ngapType.PDUSessionResourceSwitchedItem{
			PDUSessionID:                         ngapType.PDUSessionID{Value: int64(sess.PDUSessionID)},
			PathSwitchRequestAcknowledgeTransfer: aper.OctetString(ackTransfer),
		})
	}
	add(ngapType.ProtocolIEIDPDUSessionResourceSwitchedList, ngapType.CriticalityPresentIgnore,
		ngapType.PathSwitchRequestAcknowledgeIEsValue{
			Present:                        ngapType.PathSwitchRequestAcknowledgeIEsPresentPDUSessionResourceSwitchedList,
			PDUSessionResourceSwitchedList: switchedList,
		})
	// (7) PDU Session Resource Released List PSAck — O, ignore
	if len(p.Released) > 0 {
		rel := &ngapType.PDUSessionResourceReleasedListPSAck{}
		for _, r := range p.Released {
			tr, err := releasedTransfer(r)
			if err != nil {
				return nil
			}
			rel.List = append(rel.List, ngapType.PDUSessionResourceReleasedItemPSAck{
				PDUSessionID:                          ngapType.PDUSessionID{Value: int64(r.PDUSessionID)},
				PathSwitchRequestUnsuccessfulTransfer: aper.OctetString(tr),
			})
		}
		add(ngapType.ProtocolIEIDPDUSessionResourceReleasedListPSAck, ngapType.CriticalityPresentIgnore,
			ngapType.PathSwitchRequestAcknowledgeIEsValue{
				Present:                             ngapType.PathSwitchRequestAcknowledgeIEsPresentPDUSessionResourceReleasedListPSAck,
				PDUSessionResourceReleasedListPSAck: rel,
			})
	}
	// (8) Allowed NSSAI — M, reject
	add(ngapType.ProtocolIEIDAllowedNSSAI, ngapType.CriticalityPresentReject,
		ngapType.PathSwitchRequestAcknowledgeIEsValue{
			Present:      ngapType.PathSwitchRequestAcknowledgeIEsPresentAllowedNSSAI,
			AllowedNSSAI: &ngapType.AllowedNSSAI{List: nssaiItems},
		})

	b, err := libngap.Encoder(pdu)
	if err != nil {
		return nil
	}
	return b
}

// BuildPathSwitchRequestFailure builds an NGAP PathSwitchRequestFailure
// (UnsuccessfulOutcome, procedure code 25): AMF UE NGAP ID (10), RAN UE NGAP ID (85),
// PDU Session Resource Released List PSFail (69, M, SIZE 1..). The cause travels per
// session in PathSwitchRequestUnsuccessfulTransfer — there is no message-level Cause.
// Returns nil when released is empty. Ref: TS 38.413 §8.4.4.3, §9.2.3.10.
func BuildPathSwitchRequestFailure(amfUENGAPId, ranUENGAPId int64, released []PDUSessionReleasedItem) []byte {
	if len(released) == 0 {
		return nil
	}
	list := &ngapType.PDUSessionResourceReleasedListPSFail{}
	for _, r := range released {
		tr, err := releasedTransfer(r)
		if err != nil {
			return nil
		}
		list.List = append(list.List, ngapType.PDUSessionResourceReleasedItemPSFail{
			PDUSessionID:                          ngapType.PDUSessionID{Value: int64(r.PDUSessionID)},
			PathSwitchRequestUnsuccessfulTransfer: aper.OctetString(tr),
		})
	}
	fail := &ngapType.PathSwitchRequestFailure{}
	add := func(id int64, v ngapType.PathSwitchRequestFailureIEsValue) {
		fail.ProtocolIEs.List = append(fail.ProtocolIEs.List, ngapType.PathSwitchRequestFailureIEs{
			Id:          ngapType.ProtocolIEID{Value: id},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value:       v,
		})
	}
	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.PathSwitchRequestFailureIEsValue{
		Present:     ngapType.PathSwitchRequestFailureIEsPresentAMFUENGAPID,
		AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfUENGAPId},
	})
	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.PathSwitchRequestFailureIEsValue{
		Present:     ngapType.PathSwitchRequestFailureIEsPresentRANUENGAPID,
		RANUENGAPID: &ngapType.RANUENGAPID{Value: ranUENGAPId},
	})
	add(ngapType.ProtocolIEIDPDUSessionResourceReleasedListPSFail, ngapType.PathSwitchRequestFailureIEsValue{
		Present:                              ngapType.PathSwitchRequestFailureIEsPresentPDUSessionResourceReleasedListPSFail,
		PDUSessionResourceReleasedListPSFail: list,
	})

	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentUnsuccessfulOutcome,
		UnsuccessfulOutcome: &ngapType.UnsuccessfulOutcome{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodePathSwitchRequest},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.UnsuccessfulOutcomeValue{
				Present:                  ngapType.UnsuccessfulOutcomePresentPathSwitchRequestFailure,
				PathSwitchRequestFailure: fail,
			},
		},
	}
	b, err := libngap.Encoder(pdu)
	if err != nil {
		return nil
	}
	return b
}

// ---- NRPPa Transport (TS 38.413 §8.17.3 / §8.17.4) -------------------------

// UplinkUEAssociatedNRPPaTransportMsg holds the decoded fields from an NGAP
// UplinkUEAssociatedNRPPaTransport message (gNB→AMF InitiatingMessage, ProcCode=50).
// The AMF treats NRPPaPDU as an opaque byte string and relays it to the LMF.
// Ref: TS 38.413 §8.17.3; TS 38.413 §9.3.x (NRPPa-PDU IE id=46, RoutingID IE id=89).
type UplinkUEAssociatedNRPPaTransportMsg struct {
	// AMFUENGAPId is the AMF-side UE NGAP ID used to correlate the pending request.
	AMFUENGAPId int64
	// RANUENGAPId is the RAN-side UE NGAP ID (informational).
	RANUENGAPId int64
	// RoutingID is the LMF routing identity from IE id=89. May be nil if absent.
	RoutingID []byte
	// NRPPaPDU is the opaque NRPPa PDU payload from IE id=46.
	NRPPaPDU []byte
}

// UplinkNonUEAssociatedNRPPaTransportMsg holds the decoded fields from an NGAP
// UplinkNonUEAssociatedNRPPaTransport message (gNB→AMF InitiatingMessage, ProcCode=47).
// Ref: TS 38.413 §8.17.4.
type UplinkNonUEAssociatedNRPPaTransportMsg struct {
	// RoutingID is the LMF routing identity from IE id=89. May be nil if absent.
	RoutingID []byte
	// NRPPaPDU is the opaque NRPPa PDU payload from IE id=46.
	NRPPaPDU []byte
}

// extractUplinkUEAssociatedNRPPaTransport converts a free5gc UplinkUEAssociatedNRPPaTransport
// into our internal UplinkUEAssociatedNRPPaTransportMsg.
// Ref: TS 38.413 §8.17.3 (Uplink UE Associated NRPPa Transport).
func extractUplinkUEAssociatedNRPPaTransport(msg *ngapType.UplinkUEAssociatedNRPPaTransport) *UplinkUEAssociatedNRPPaTransportMsg {
	out := &UplinkUEAssociatedNRPPaTransportMsg{}
	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Value.Present {
		case ngapType.UplinkUEAssociatedNRPPaTransportIEsPresentAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				out.AMFUENGAPId = ie.Value.AMFUENGAPID.Value
			}
		case ngapType.UplinkUEAssociatedNRPPaTransportIEsPresentRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				out.RANUENGAPId = ie.Value.RANUENGAPID.Value
			}
		case ngapType.UplinkUEAssociatedNRPPaTransportIEsPresentRoutingID:
			if ie.Value.RoutingID != nil {
				out.RoutingID = []byte(ie.Value.RoutingID.Value)
			}
		case ngapType.UplinkUEAssociatedNRPPaTransportIEsPresentNRPPaPDU:
			if ie.Value.NRPPaPDU != nil {
				out.NRPPaPDU = []byte(ie.Value.NRPPaPDU.Value)
			}
		}
	}
	return out
}

// extractUplinkNonUEAssociatedNRPPaTransport converts a free5gc
// UplinkNonUEAssociatedNRPPaTransport into our internal
// UplinkNonUEAssociatedNRPPaTransportMsg.
// Ref: TS 38.413 §8.17.4 (Uplink Non UE Associated NRPPa Transport).
func extractUplinkNonUEAssociatedNRPPaTransport(msg *ngapType.UplinkNonUEAssociatedNRPPaTransport) *UplinkNonUEAssociatedNRPPaTransportMsg {
	out := &UplinkNonUEAssociatedNRPPaTransportMsg{}
	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Value.Present {
		case ngapType.UplinkNonUEAssociatedNRPPaTransportIEsPresentRoutingID:
			if ie.Value.RoutingID != nil {
				out.RoutingID = []byte(ie.Value.RoutingID.Value)
			}
		case ngapType.UplinkNonUEAssociatedNRPPaTransportIEsPresentNRPPaPDU:
			if ie.Value.NRPPaPDU != nil {
				out.NRPPaPDU = []byte(ie.Value.NRPPaPDU.Value)
			}
		}
	}
	return out
}

// BuildDownlinkUEAssociatedNRPPaTransport builds the NGAP
// DownlinkUEAssociatedNRPPaTransport PDU (AMF→gNB, InitiatingMessage, ProcCode=8).
//
// The nrppaPDU bytes are inserted as IE id=46 (NRPPa-PDU) without modification.
// routingID may be nil; if non-empty it is inserted as IE id=89 (RoutingID).
//
// Criticality for all IEs is "reject" per TS 38.413 §9.3.x.
// Ref: TS 38.413 §8.17.3.
func BuildDownlinkUEAssociatedNRPPaTransport(amfUENGAPId, ranUENGAPId int64, nrppaPDU []byte, routingID []byte) []byte {
	msg := &ngapType.DownlinkUEAssociatedNRPPaTransport{}

	// IE: AMF-UE-NGAP-ID (id=10, criticality=reject, mandatory)
	amfIDIE := ngapType.DownlinkUEAssociatedNRPPaTransportIEs{
		Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
		Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
		Value: ngapType.DownlinkUEAssociatedNRPPaTransportIEsValue{
			Present:     ngapType.DownlinkUEAssociatedNRPPaTransportIEsPresentAMFUENGAPID,
			AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfUENGAPId},
		},
	}
	msg.ProtocolIEs.List = append(msg.ProtocolIEs.List, amfIDIE)

	// IE: RAN-UE-NGAP-ID (id=85, criticality=reject, mandatory)
	ranIDIE := ngapType.DownlinkUEAssociatedNRPPaTransportIEs{
		Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
		Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
		Value: ngapType.DownlinkUEAssociatedNRPPaTransportIEsValue{
			Present:     ngapType.DownlinkUEAssociatedNRPPaTransportIEsPresentRANUENGAPID,
			RANUENGAPID: &ngapType.RANUENGAPID{Value: ranUENGAPId},
		},
	}
	msg.ProtocolIEs.List = append(msg.ProtocolIEs.List, ranIDIE)

	// IE: RoutingID (id=89, criticality=reject, optional)
	if len(routingID) > 0 {
		ridIE := ngapType.DownlinkUEAssociatedNRPPaTransportIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRoutingID},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.DownlinkUEAssociatedNRPPaTransportIEsValue{
				Present:   ngapType.DownlinkUEAssociatedNRPPaTransportIEsPresentRoutingID,
				RoutingID: &ngapType.RoutingID{Value: aper.OctetString(routingID)},
			},
		}
		msg.ProtocolIEs.List = append(msg.ProtocolIEs.List, ridIE)
	}

	// IE: NRPPa-PDU (id=46, criticality=reject, mandatory)
	nrppaIE := ngapType.DownlinkUEAssociatedNRPPaTransportIEs{
		Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDNRPPaPDU},
		Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
		Value: ngapType.DownlinkUEAssociatedNRPPaTransportIEsValue{
			Present:  ngapType.DownlinkUEAssociatedNRPPaTransportIEsPresentNRPPaPDU,
			NRPPaPDU: &ngapType.NRPPaPDU{Value: aper.OctetString(nrppaPDU)},
		},
	}
	msg.ProtocolIEs.List = append(msg.ProtocolIEs.List, nrppaIE)

	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeDownlinkUEAssociatedNRPPaTransport},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.InitiatingMessageValue{
				Present:                            ngapType.InitiatingMessagePresentDownlinkUEAssociatedNRPPaTransport,
				DownlinkUEAssociatedNRPPaTransport: msg,
			},
		},
	}
	encodedDL, errDL := libngap.Encoder(pdu)
	if errDL != nil {
		return nil
	}
	return encodedDL
}

// BuildDownlinkNonUEAssociatedNRPPaTransport builds the NGAP
// DownlinkNonUEAssociatedNRPPaTransport PDU (AMF→gNB, InitiatingMessage, ProcCode=5).
//
// Used for cell-level NRPPa signalling not tied to a specific UE context.
// Ref: TS 38.413 §8.17.4.
func BuildDownlinkNonUEAssociatedNRPPaTransport(nrppaPDU []byte, routingID []byte) []byte {
	msg := &ngapType.DownlinkNonUEAssociatedNRPPaTransport{}

	// IE: RoutingID (id=89, criticality=reject, optional)
	if len(routingID) > 0 {
		ridIE := ngapType.DownlinkNonUEAssociatedNRPPaTransportIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRoutingID},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.DownlinkNonUEAssociatedNRPPaTransportIEsValue{
				Present:   ngapType.DownlinkNonUEAssociatedNRPPaTransportIEsPresentRoutingID,
				RoutingID: &ngapType.RoutingID{Value: aper.OctetString(routingID)},
			},
		}
		msg.ProtocolIEs.List = append(msg.ProtocolIEs.List, ridIE)
	}

	// IE: NRPPa-PDU (id=46, criticality=reject, mandatory)
	nrppaIE := ngapType.DownlinkNonUEAssociatedNRPPaTransportIEs{
		Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDNRPPaPDU},
		Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
		Value: ngapType.DownlinkNonUEAssociatedNRPPaTransportIEsValue{
			Present:  ngapType.DownlinkNonUEAssociatedNRPPaTransportIEsPresentNRPPaPDU,
			NRPPaPDU: &ngapType.NRPPaPDU{Value: aper.OctetString(nrppaPDU)},
		},
	}
	msg.ProtocolIEs.List = append(msg.ProtocolIEs.List, nrppaIE)

	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeDownlinkNonUEAssociatedNRPPaTransport},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.InitiatingMessageValue{
				Present:                               ngapType.InitiatingMessagePresentDownlinkNonUEAssociatedNRPPaTransport,
				DownlinkNonUEAssociatedNRPPaTransport: msg,
			},
		},
	}
	encodedNonUE, errNonUE := libngap.Encoder(pdu)
	if errNonUE != nil {
		return nil
	}
	return encodedNonUE
}
