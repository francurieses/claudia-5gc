//go:build functional

// initial_context_setup_steps_test.go — in-process godog steps for
// initial_context_setup.feature (UE-AMBR conditional presence in the INITIAL
// CONTEXT SETUP REQUEST and its delivery in the PDU SESSION RESOURCE SETUP
// REQUEST, TS 38.413 §8.3.1, §9.2.2.1, §8.2.1, §9.2.1.1, §9.3.1.58).
//
// The real NGAP builders are called and their output is decoded with
// github.com/free5gc/ngap. Server.SendInitialContextSetupRequest and
// Server.SendPDUSessionResourceSetupRequest need a live *sctp.SCTPConn (no
// seam, no SCTP on all dev hosts), so the per-UE UEAMBRSentToRAN flag logic is
// mirrored here exactly as ngap.go applies it; those scenarios are therefore
// "builder + flag model" scenarios. The INITIAL CONTEXT SETUP FAILURE scenario
// needs the real server handler and is reported pending.
package features_test

import (
	"context"
	"fmt"
	"regexp"
	"strconv"

	"github.com/cucumber/godog"
	"github.com/free5gc/aper"
	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	amfngap "github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
)

type icsIE struct {
	id   int64
	crit aper.Enumerated
}

type icsWorld struct {
	ue       *amfctx.UEContext
	kbpsUL   uint64
	kbpsDL   uint64
	sessions []amfngap.PDUSessionSetupItemCxtReq
	allowed  []amfctx.SNSSAISubscribed
	rfsp     int
	region   byte
	setID    uint16
	ptr      byte

	psID  uint8
	psSST uint8
	psSD  []byte

	raw      []byte
	pdu      *ngapType.NGAPPDU
	ies      []icsIE
	ambrUL   int64
	ambrDL   int64
	hasAMBR  bool
	icsItems []int64 // PDU session ids in IE 71
	suItems  []int64 // PDU session ids in IE 74
}

var icsW icsWorld

func (w *icsWorld) reset() {
	*w = icsWorld{ue: &amfctx.UEContext{}}
}

var nasStub = []byte{0x7E, 0x02, 0x01, 0x02, 0x03}

func (w *icsWorld) buildICS() error {
	var k [32]byte
	for i := range k {
		k[i] = byte(i)
	}
	// Mirrors Server.SendInitialContextSetupRequest.
	w.raw = amfngap.BuildInitialContextSetupRequest(
		1, 1, nasStub, k, 0xE000, 0xE000, "001", "01",
		w.region, w.setID, w.ptr, w.allowed,
		int64(w.kbpsUL)*1000, int64(w.kbpsDL)*1000, w.rfsp, w.sessions)
	if len(w.raw) == 0 {
		return fmt.Errorf("BuildInitialContextSetupRequest returned empty PDU")
	}
	w.ue.UEAMBRSentToRAN = len(w.sessions) > 0
	return w.decode()
}

// buildPDUSessionSetup mirrors Server.SendPDUSessionResourceSetupRequest.
func (w *icsWorld) buildPDUSessionSetup() error {
	var ambr *amfngap.UEAMBR
	if !w.ue.UEAMBRSentToRAN {
		ambr = amfngap.NewUEAMBRFromKbps(w.kbpsUL, w.kbpsDL)
	}
	w.raw = amfngap.BuildPDUSessionResourceSetupRequest(
		1, 1, w.psID, nasStub, []byte{0xAA, 0xBB}, w.psSST, w.psSD, ambr)
	if len(w.raw) == 0 {
		return fmt.Errorf("BuildPDUSessionResourceSetupRequest returned empty PDU")
	}
	if ambr != nil {
		w.ue.UEAMBRSentToRAN = true
	}
	return w.decode()
}

func (w *icsWorld) decode() error {
	pdu, err := libngap.Decoder(w.raw)
	if err != nil {
		return fmt.Errorf("free5gc/ngap decode: %w", err)
	}
	w.pdu = pdu
	w.ies, w.hasAMBR, w.icsItems, w.suItems = nil, false, nil, nil
	im := pdu.InitiatingMessage
	if im == nil {
		return fmt.Errorf("not an initiatingMessage")
	}
	switch {
	case im.Value.InitialContextSetupRequest != nil:
		for _, ie := range im.Value.InitialContextSetupRequest.ProtocolIEs.List {
			w.ies = append(w.ies, icsIE{ie.Id.Value, ie.Criticality.Value})
			switch ie.Id.Value {
			case ngapType.ProtocolIEIDUEAggregateMaximumBitRate:
				w.hasAMBR = true
				w.ambrUL = ie.Value.UEAggregateMaximumBitRate.UEAggregateMaximumBitRateUL.Value
				w.ambrDL = ie.Value.UEAggregateMaximumBitRate.UEAggregateMaximumBitRateDL.Value
			case ngapType.ProtocolIEIDPDUSessionResourceSetupListCxtReq:
				for _, it := range ie.Value.PDUSessionResourceSetupListCxtReq.List {
					w.icsItems = append(w.icsItems, it.PDUSessionID.Value)
				}
			}
		}
	case im.Value.PDUSessionResourceSetupRequest != nil:
		for _, ie := range im.Value.PDUSessionResourceSetupRequest.ProtocolIEs.List {
			w.ies = append(w.ies, icsIE{ie.Id.Value, ie.Criticality.Value})
			switch ie.Id.Value {
			case ngapType.ProtocolIEIDUEAggregateMaximumBitRate:
				w.hasAMBR = true
				w.ambrUL = ie.Value.UEAggregateMaximumBitRate.UEAggregateMaximumBitRateUL.Value
				w.ambrDL = ie.Value.UEAggregateMaximumBitRate.UEAggregateMaximumBitRateDL.Value
			case ngapType.ProtocolIEIDPDUSessionResourceSetupListSUReq:
				for _, it := range ie.Value.PDUSessionResourceSetupListSUReq.List {
					w.suItems = append(w.suItems, it.PDUSessionID.Value)
				}
			}
		}
	default:
		return fmt.Errorf("unexpected NGAP message")
	}
	return nil
}

func (w *icsWorld) find(id int64) (icsIE, bool) {
	for _, ie := range w.ies {
		if ie.id == id {
			return ie, true
		}
	}
	return icsIE{}, false
}

var ieIDs = map[string]int64{
	"AMFUENGAPID":                       ngapType.ProtocolIEIDAMFUENGAPID,
	"RANUENGAPID":                       ngapType.ProtocolIEIDRANUENGAPID,
	"GUAMI":                             ngapType.ProtocolIEIDGUAMI,
	"UESecurityCapabilities":            ngapType.ProtocolIEIDUESecurityCapabilities,
	"SecurityKey":                       ngapType.ProtocolIEIDSecurityKey,
	"NASPDU":                            ngapType.ProtocolIEIDNASPDU,
	"UEAggregateMaximumBitRate":         ngapType.ProtocolIEIDUEAggregateMaximumBitRate,
	"PDUSessionResourceSetupListCxtReq": ngapType.ProtocolIEIDPDUSessionResourceSetupListCxtReq,
	"PDUSessionResourceSetupListSUReq":  ngapType.ProtocolIEIDPDUSessionResourceSetupListSUReq,
	"AllowedNSSAI":                      ngapType.ProtocolIEIDAllowedNSSAI,
	"IndexToRFSP":                       ngapType.ProtocolIEIDIndexToRFSP,
}

func critName(c aper.Enumerated) string {
	switch c {
	case ngapType.CriticalityPresentReject:
		return "reject"
	case ngapType.CriticalityPresentIgnore:
		return "ignore"
	}
	return "notify"
}

func initICSSteps(sc *godog.ScenarioContext) {
	w := &icsW
	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		w.reset()
		return ctx, nil
	})

	// Background
	sc.Step(`^the AMF NGAP builders are available$`, func() error { return nil })
	sc.Step(`^UE with SUPI "([^"]+)" has AMF UE NGAP ID (\d+) and RAN UE NGAP ID (\d+)$`,
		func(supi string, a, r int) error { w.ue.SUPI = supi; return nil })
	sc.Step(`^the UE has Security Capabilities, a KgNB of 256 bits and GUAMI "(\d+)/(\d+)/([0-9a-f]{6})"$`,
		func(mcc, mnc, hex string) error {
			v, err := strconv.ParseUint(hex, 16, 32)
			if err != nil {
				return err
			}
			w.region, w.setID, w.ptr = byte(v>>16), uint16(byte(v>>8)), byte(v)
			return nil
		})

	// Givens
	sc.Step(`^the subscribed UE-AMBR is (\d+) kbit/s uplink and (\d+) kbit/s downlink$`,
		func(ul, dl int64) error {
			if xnActive() {
				return xnSubscribedAMBR(ul, dl)
			}
			w.kbpsUL, w.kbpsDL = uint64(ul), uint64(dl)
			return nil
		})
	sc.Step(`^the subscription has no subscribedUeAmbr$`,
		func() error {
			if xnActive() {
				return xnSubscribedAMBR(0, 0)
			}
			w.kbpsUL, w.kbpsDL = 0, 0
			return nil
		})
	sc.Step(`^no PDU sessions are to be activated$`,
		func() error { w.sessions = nil; return nil })
	sc.Step(`^the registration case is "([^"]+)"$`, func(string) error { return nil })
	sc.Step(`^the UE sent a Service Request whose Uplink Data Status is empty$`,
		func() error { w.sessions = nil; return nil })
	sc.Step(`^the UE sent a Service Request whose Uplink Data Status flags PDU session ids (\d+) and (\d+)$`,
		func(a, b int) error { return nil })
	sc.Step(`^the SMF fails the activation of PDU session ids (\d+) and (\d+)$`,
		func(a, b int) error { w.sessions = nil; return nil })
	sc.Step(`^the UE has PDU session id (\d+) on S-NSSAI SST (\d+) SD "([0-9a-f]{6})" to be activated with a PDUSessionResourceSetupRequestTransfer$`,
		func(id, sst int, sd string) error {
			b, err := hexBytes(sd)
			if err != nil {
				return err
			}
			w.sessions = append(w.sessions, amfngap.PDUSessionSetupItemCxtReq{
				PDUSessionID: uint8(id), SST: uint8(sst), SD: b, Transfer: []byte{0x01, 0x02, 0x03},
			})
			return nil
		})
	sc.Step(`^the UE has an Allowed NSSAI and an Index to RFSP of (\d+)$`,
		func(r int) error {
			w.allowed = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}}
			w.rfsp = r
			return nil
		})
	sc.Step(`^the SMF returns a PDUSessionResourceSetupRequestTransfer for PDU session id (\d+) on S-NSSAI SST (\d+) SD "([0-9a-f]{6})"$`,
		func(id, sst int, sd string) error {
			b, err := hexBytes(sd)
			if err != nil {
				return err
			}
			w.psID, w.psSST, w.psSD = uint8(id), uint8(sst), b
			return nil
		})
	sc.Step(`^the gNB has not yet received a UE-AMBR for this UE in the current N2 context$`,
		func() error { w.ue.UEAMBRSentToRAN = false; return nil })
	sc.Step(`^the gNB already received a UE-AMBR for this UE in an INITIAL CONTEXT SETUP REQUEST with PDU sessions$`,
		func() error {
			w.sessions = []amfngap.PDUSessionSetupItemCxtReq{{PDUSessionID: 1, SST: 1, SD: []byte{0, 0, 1}, Transfer: []byte{1}}}
			if err := w.buildICS(); err != nil {
				return err
			}
			if !w.ue.UEAMBRSentToRAN {
				return fmt.Errorf("UEAMBRSentToRAN not set after ICS Request with PDU sessions")
			}
			return nil
		})
	sc.Step(`^the gNB already received a UE-AMBR for this UE in a PDU SESSION RESOURCE SETUP REQUEST$`,
		func() error {
			w.ue.UEAMBRSentToRAN = false
			w.psID, w.psSST, w.psSD = 1, 1, []byte{0, 0, 1}
			if err := w.buildPDUSessionSetup(); err != nil {
				return err
			}
			if !w.hasAMBR || !w.ue.UEAMBRSentToRAN {
				return fmt.Errorf("first PDU SESSION RESOURCE SETUP REQUEST did not deliver UE-AMBR / set flag")
			}
			return nil
		})
	// Mirrors handleUEContextReleaseComplete (ue.UEAMBRSentToRAN = false).
	sc.Step(`^the UE Context Release Complete was received for the UE$`,
		func() error { w.ue.UEAMBRSentToRAN = false; return nil })
	sc.Step(`^a new Initial Registration ICS Request without UE-AMBR was sent$`,
		func() error {
			w.sessions = nil
			if err := w.buildICS(); err != nil {
				return err
			}
			if w.hasAMBR {
				return fmt.Errorf("registration ICS Request unexpectedly carried UE-AMBR")
			}
			return nil
		})

	// Whens
	sc.Step(`^the AMF builds the INITIAL CONTEXT SETUP REQUEST with the (?:Registration|Service) Accept NAS-PDU$`,
		w.buildICS)
	sc.Step(`^the AMF builds the PDU SESSION RESOURCE SETUP REQUEST$`, w.buildPDUSessionSetup)

	// Thens
	sc.Step(`^the encoded PDU decodes cleanly with free5gc/ngap$`, func() error {
		if xnActive() {
			return xnDecodesCleanly()
		}
		if w.pdu == nil {
			return fmt.Errorf("no decoded PDU")
		}
		return nil
	})
	sc.Step(`^the message is an initiatingMessage of procedure code (\d+) with criticality reject$`,
		func(code int) error { return w.checkProc(code, true) })
	sc.Step(`^the message is an initiatingMessage of procedure code (\d+)$`,
		func(code int) error { return w.checkProc(code, false) })
	sc.Step(`^the message does not contain the "([^"]+)" IE \(id (\d+)\)$`,
		func(name string, id int) error {
			if xnActive() {
				return xnNotContain(name, id)
			}
			if ieIDs[name] != int64(id) {
				return fmt.Errorf("feature maps %q to id %d, builders know %d", name, id, ieIDs[name])
			}
			if _, ok := w.find(int64(id)); ok {
				return fmt.Errorf("IE %s (id %d) is present but must be absent", name, id)
			}
			return nil
		})
	sc.Step(`^the message contains the "([^"]+)" IE \(id (\d+)\) with criticality (reject|ignore)$`,
		func(name string, id int, crit string) error {
			if xnActive() {
				return xnContains(name, id, crit)
			}
			if ieIDs[name] != int64(id) {
				return fmt.Errorf("feature maps %q to id %d, builders know %d", name, id, ieIDs[name])
			}
			ie, ok := w.find(int64(id))
			if !ok {
				return fmt.Errorf("IE %s (id %d) missing", name, id)
			}
			if got := critName(ie.crit); got != crit {
				return fmt.Errorf("IE %s criticality %s, want %s", name, got, crit)
			}
			return nil
		})
	sc.Step(`^the message contains the "([^"]+)" IE \(id (\d+)\) with 1 item for PDU session id (\d+)$`,
		func(name string, id, psi int) error {
			if ieIDs[name] != int64(id) {
				return fmt.Errorf("feature maps %q to id %d, builders know %d", name, id, ieIDs[name])
			}
			var items []int64
			switch int64(id) {
			case ngapType.ProtocolIEIDPDUSessionResourceSetupListCxtReq:
				items = w.icsItems
			case ngapType.ProtocolIEIDPDUSessionResourceSetupListSUReq:
				items = w.suItems
			default:
				return fmt.Errorf("IE id %d is not a PDU session list", id)
			}
			if len(items) != 1 || items[0] != int64(psi) {
				return fmt.Errorf("IE %s items = %v, want [%d]", name, items, psi)
			}
			return nil
		})
	sc.Step(`^the message contains the mandatory IEs (.+)$`, func(list string) error {
		for _, m := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(list, -1) {
			id, ok := ieIDs[m[1]]
			if !ok {
				return fmt.Errorf("unknown IE name %q", m[1])
			}
			if _, present := w.find(id); !present {
				return fmt.Errorf("mandatory IE %s (id %d) missing", m[1], id)
			}
		}
		return nil
	})
	sc.Step(`^the UE-AMBR uplink is (\d+) bit/s and downlink is (\d+) bit/s$`, func(ul, dl int64) error {
		if xnActive() {
			return xnAMBR(ul, dl)
		}
		if !w.hasAMBR {
			return fmt.Errorf("no UE-AMBR in message")
		}
		if w.ambrUL != ul || w.ambrDL != dl {
			return fmt.Errorf("UE-AMBR UL/DL = %d/%d bit/s, want %d/%d", w.ambrUL, w.ambrDL, ul, dl)
		}
		return nil
	})
	sc.Step(`^the IEs appear in this order:$`, func(t *godog.Table) error {
		if xnActive() {
			return xnIEOrder(t)
		}
		var wantIDs []int64
		for _, row := range t.Rows[1:] {
			id, err := strconv.ParseInt(row.Cells[1].Value, 10, 64)
			if err != nil {
				return err
			}
			if n := row.Cells[0].Value; ieIDs[n] != id {
				return fmt.Errorf("table maps %q to id %d, builders know %d", n, id, ieIDs[n])
			}
			wantIDs = append(wantIDs, id)
		}
		var got []int64
		for _, ie := range w.ies {
			got = append(got, ie.id)
		}
		if fmt.Sprint(got) != fmt.Sprint(wantIDs) {
			return fmt.Errorf("IE order = %v, want %v", got, wantIDs)
		}
		return nil
	})
	sc.Step(`^a strict conditional-presence check reports no Abstract Syntax Error$`, func() error {
		v, err := amfngap.CheckICSConditionalPresence(w.raw)
		if err != nil {
			return err
		}
		if len(v) != 0 {
			return fmt.Errorf("strict check violations: %v", v)
		}
		return nil
	})
	sc.Step(`^the check "([^"]+)" passes$`, func(rule string) error {
		v, err := amfngap.CheckICSConditionalPresence(w.raw)
		if err != nil {
			return err
		}
		for _, m := range v {
			if m == rule {
				return fmt.Errorf("check failed: %s", rule)
			}
		}
		return nil
	})

	// ICS Failure scenario: needs the real Server handler (gNB SCTP conn for the
	// UE Context Release Command, no test seam) — pending, never a false pass.
	sc.Step(`^UE "([^"]+)" is in 5GMM-REGISTERED state after an ICS Request was sent$`, icsPending1)
	sc.Step(`^the gNB answers with INITIAL CONTEXT SETUP FAILURE with protocol cause "([^"]+)"$`, icsPending1)
	sc.Step(`^the UE transitions to 5GMM-DEREGISTERED and is flagged for removal$`, icsPending0)
	sc.Step(`^the AMF sends a UE CONTEXT RELEASE COMMAND with radioNetwork cause "([^"]+)"$`, icsPending1)
	sc.Step(`^the failure is logged with result "([^"]+)" and spec_ref "([^"]+)"$`, icsPending2)
}

func icsPending0() error       { return godog.ErrPending }
func icsPending1(string) error { return godog.ErrPending }
func icsPending2(result, specRef string) error {
	if xnActive() {
		return xnFailureLogged(result, specRef)
	}
	return godog.ErrPending
}

func (w *icsWorld) checkProc(code int, wantReject bool) error {
	im := w.pdu.InitiatingMessage
	if im == nil {
		return fmt.Errorf("not an initiatingMessage")
	}
	if im.ProcedureCode.Value != int64(code) {
		return fmt.Errorf("procedure code %d, want %d", im.ProcedureCode.Value, code)
	}
	if wantReject && im.Criticality.Value != ngapType.CriticalityPresentReject {
		return fmt.Errorf("message criticality %s, want reject", critName(im.Criticality.Value))
	}
	return nil
}

func hexBytes(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := range out {
		v, err := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
		if err != nil {
			return nil, err
		}
		out[i] = byte(v)
	}
	return out, nil
}
