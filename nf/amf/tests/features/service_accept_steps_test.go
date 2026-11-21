//go:build functional

// service_accept_steps_test.go -- in-process godog steps for
// service_accept_ies.feature: Service Accept PDU session status (IEI 0x50) /
// PDU session reactivation result (IEI 0x26) and the local release of PDU
// sessions the UE reports inactive (TS 24.501 §5.6.1.4.1, §8.2.17).
//
// Reuses the network-triggered SR world (ntsrW): the real nasmsg.Handler, the
// httptest SMF (UpdateSMContext ACTIVATING + DELETE sm-contexts/{ref}) and the
// fake N2 sender that records the InitialContextSetupRequest NAS-PDU.
package features_test

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"

	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nea"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// smReleaseWait bounds how long the steps wait for the AMF's asynchronous
// SM context release towards the SMF.
const smReleaseWait = 2 * time.Second

// parsePSIs parses a comma-separated PSI list ("" = empty).
func parsePSIs(list string) ([]uint8, error) {
	var out []uint8
	for _, f := range strings.Split(list, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		n, err := strconv.Atoi(f)
		if err != nil || n < 1 || n > 15 {
			return nil, fmt.Errorf("invalid PSI %q", f)
		}
		out = append(out, uint8(n))
	}
	return out, nil
}

// buildServiceRequestIEs encodes a plain Service Request (TS 24.501 §8.2.16)
// with optional Uplink data status (0x40) and PDU session status (0x50);
// a nil list omits the IE.
func buildServiceRequestIEs(svcType byte, tmsi uint32, ulds, status []uint8, withULDS, withStatus bool) []byte {
	pdu := []byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeServiceRequest), svcType << 4}
	pdu = append(pdu, 0x00, 0x07, 0xF4, 0x00, 0x41,
		byte(tmsi>>24), byte(tmsi>>16), byte(tmsi>>8), byte(tmsi))
	if withULDS {
		m := nas.PSIMask(ulds...)
		pdu = append(pdu, 0x40, 0x02, byte(m>>8), byte(m))
	}
	if withStatus {
		m := nas.PSIMask(status...)
		pdu = append(pdu, 0x50, 0x02, byte(m>>8), byte(m))
	}
	return pdu
}

// srWithIEs: an empty quoted list means "IE absent".
func srWithIEs(svcName, uldsList, statusList string) error {
	st, ok := ntsrServiceTypes[svcName]
	if !ok {
		return fmt.Errorf("unknown service type %q", svcName)
	}
	ue := sbiW.ue
	if ue == nil || ue.GUTI == nil {
		return fmt.Errorf("UE not seeded with a GUTI")
	}
	ulds, err := parsePSIs(uldsList)
	if err != nil {
		return err
	}
	status, err := parsePSIs(statusList)
	if err != nil {
		return err
	}
	plain := buildServiceRequestIEs(st, ue.GUTI.TMSI, ulds, status,
		strings.TrimSpace(uldsList) != "", strings.TrimSpace(statusList) != "")
	return ntsrW.sendRawServiceRequest(plain)
}

// decodedServiceAccept deciphers the Service Accept carried in the ICS
// Request (NEA2, DL COUNT = value before the SR) and decodes its IEs.
func decodedServiceAccept() (*nas.ServiceAccept, error) {
	raw, err := rawServiceAcceptIEs()
	if err != nil {
		return nil, err
	}
	return nas.DecodeServiceAccept(raw)
}

// rawServiceAcceptIEs returns the Service Accept IE bytes (after the 3-octet
// EPD/SHT/message type header) of the NAS PDU sent to the gNB.
func rawServiceAcceptIEs() ([]byte, error) {
	w := ntsrW
	if err := w.serviceAccept(); err != nil { // also verifies SHT and MAC
		return nil, err
	}
	inner, err := nea.NEA2(sbiW.ue.SecurityCtx.KNASenc, w.preDL, 0x01, 0x01, w.icsNAS[7:])
	if err != nil {
		return nil, err
	}
	if len(inner) < 3 {
		return nil, fmt.Errorf("Service Accept too short (%d octets)", len(inner))
	}
	return inner[3:], nil
}

func (w *ntsrWorld) smfFailsWith(psi, status int, cause string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.failSpec[ntsrRef(psi)] = ntsrFailSpec{status: status, cause: cause}
	return nil
}

func smfFailsWithCause(psi, status int, cause string) error {
	return ntsrW.smfFailsWith(psi, status, cause)
}

func smfFailsNoBody(psi, status int) error { return ntsrW.smfFailsWith(psi, status, "") }

func errCauseString(l []nas.PDUSessionErrorCause) string {
	var out []string
	for _, e := range l {
		out = append(out, fmt.Sprintf("%d:%d", e.PDUSessionID, e.Cause5GMM))
	}
	return strings.Join(out, ",")
}

func saCarriesErrorCause(entries string) error {
	sa, err := decodedServiceAccept()
	if err != nil {
		return err
	}
	if sa.PDUSessionReactivationResultErrorCause == nil {
		return fmt.Errorf("Service Accept has no PDU session reactivation result error cause IE (0x72)")
	}
	if got := errCauseString(sa.PDUSessionReactivationResultErrorCause); got != entries {
		return fmt.Errorf("PDU session reactivation result error cause entries = %q, want %q", got, entries)
	}
	return nil
}

func saNoErrorCause() error {
	sa, err := decodedServiceAccept()
	if err != nil {
		return err
	}
	if sa.PDUSessionReactivationResultErrorCause != nil {
		return fmt.Errorf("unexpected PDU session reactivation result error cause IE: %s",
			errCauseString(sa.PDUSessionReactivationResultErrorCause))
	}
	return nil
}

// saIEOrder walks the raw Service Accept IEs: 0x50 / 0x26 are TLV (1-octet
// length), 0x72 is TLV-E (2-octet length) per TS 24.501 §8.2.17.
func saIEOrder(want string) error {
	raw, err := rawServiceAcceptIEs()
	if err != nil {
		return err
	}
	var got []string
	for i := 0; i < len(raw); {
		iei := raw[i]
		var l, hdr int
		switch iei {
		case 0x72:
			if i+3 > len(raw) {
				return fmt.Errorf("truncated TLV-E IE 0x72 at offset %d", i)
			}
			hdr, l = 3, int(raw[i+1])<<8|int(raw[i+2])
		case 0x50, 0x26:
			if i+2 > len(raw) {
				return fmt.Errorf("truncated IE 0x%02X at offset %d", iei, i)
			}
			hdr, l = 2, int(raw[i+1])
		default:
			return fmt.Errorf("unexpected IEI 0x%02X at offset %d in Service Accept %x", iei, i, raw)
		}
		if i+hdr+l > len(raw) {
			return fmt.Errorf("IE 0x%02X overruns the Service Accept %x", iei, raw)
		}
		got = append(got, fmt.Sprintf("0x%02x", iei))
		i += hdr + l
	}
	var wantList []string
	for _, f := range strings.Split(want, ",") {
		n, err := strconv.ParseUint(strings.TrimSpace(f), 0, 8)
		if err != nil {
			return fmt.Errorf("bad IEI %q", f)
		}
		wantList = append(wantList, fmt.Sprintf("0x%02x", n))
	}
	if g, w := strings.Join(got, ","), strings.Join(wantList, ","); g != w {
		return fmt.Errorf("Service Accept IE order = %s, want %s", g, w)
	}
	return nil
}

func maskString(m uint16) string {
	var psis []string
	for psi := uint8(1); psi <= 15; psi++ {
		if nas.PSIInStatus(m, psi) {
			psis = append(psis, strconv.Itoa(int(psi)))
		}
	}
	return "[" + strings.Join(psis, ",") + "]"
}

func saCarriesStatus(list string) error {
	sa, err := decodedServiceAccept()
	if err != nil {
		return err
	}
	psis, err := parsePSIs(list)
	if err != nil {
		return err
	}
	if sa.PDUSessionStatus == nil {
		return fmt.Errorf("Service Accept has no PDU session status IE (0x50)")
	}
	if want := nas.PSIMask(psis...); *sa.PDUSessionStatus != want {
		return fmt.Errorf("Service Accept PDU session status = %s, want %s",
			maskString(*sa.PDUSessionStatus), maskString(want))
	}
	return nil
}

func saNoStatus() error {
	sa, err := decodedServiceAccept()
	if err != nil {
		return err
	}
	if sa.PDUSessionStatus != nil {
		return fmt.Errorf("unexpected PDU session status IE %s", maskString(*sa.PDUSessionStatus))
	}
	return nil
}

func saCarriesResult(list string) error {
	sa, err := decodedServiceAccept()
	if err != nil {
		return err
	}
	psis, err := parsePSIs(list)
	if err != nil {
		return err
	}
	if sa.PDUSessionReactivationResult == nil {
		return fmt.Errorf("Service Accept has no PDU session reactivation result IE (0x26)")
	}
	if want := nas.PSIMask(psis...); *sa.PDUSessionReactivationResult != want {
		return fmt.Errorf("Service Accept PDU session reactivation result = %s, want %s",
			maskString(*sa.PDUSessionReactivationResult), maskString(want))
	}
	return nil
}

func saNoResult() error {
	sa, err := decodedServiceAccept()
	if err != nil {
		return err
	}
	if sa.PDUSessionReactivationResult != nil {
		return fmt.Errorf("unexpected PDU session reactivation result IE %s",
			maskString(*sa.PDUSessionReactivationResult))
	}
	return nil
}

func amfReleasesSMContext(psi int) error {
	w := ntsrW
	if err := w.requireSR(); err != nil {
		return err
	}
	want := ntsrRef(psi)
	deadline := time.After(smReleaseWait)
	for {
		w.mu.Lock()
		for _, r := range w.released {
			if r == want {
				w.mu.Unlock()
				return nil
			}
		}
		got := append([]string(nil), w.released...)
		w.mu.Unlock()
		select {
		case <-w.relCh:
		case <-deadline:
			return fmt.Errorf("SMF did not receive a release for %s within %s (released: %v)", want, smReleaseWait, got)
		}
	}
}

func amfReleasesNoSMContext() error {
	w := ntsrW
	if err := w.requireSR(); err != nil {
		return err
	}
	select {
	case ref := <-w.relCh:
		return fmt.Errorf("unexpected SM context release %s", ref)
	case <-time.After(150 * time.Millisecond):
		return nil
	}
}

func sessionGone(psi int) error {
	ue := sbiW.ue
	ue.Lock()
	defer ue.Unlock()
	if _, ok := ue.PDUSessions[uint8(psi)]; ok {
		var left []int
		for p := range ue.PDUSessions {
			left = append(left, int(p))
		}
		sort.Ints(left)
		return fmt.Errorf("PDU session %d still in UE context (sessions: %v)", psi, left)
	}
	return nil
}

func sessionStill(psi int) error {
	ue := sbiW.ue
	ue.Lock()
	defer ue.Unlock()
	if _, ok := ue.PDUSessions[uint8(psi)]; !ok {
		return fmt.Errorf("PDU session %d missing from UE context", psi)
	}
	return nil
}

func initServiceAcceptSteps(sc *godog.ScenarioContext) {
	sc.Step(`^the SMF will fail the activation of PDU session (\d+) with status (\d+) and cause "([^"]+)"$`, smfFailsWithCause)
	sc.Step(`^the SMF will fail the activation of PDU session (\d+) with status (\d+) and no body$`, smfFailsNoBody)
	sc.Step(`^the Service Accept carries a PDU session reactivation result error cause IE with entries "([^"]*)"$`, saCarriesErrorCause)
	sc.Step(`^the Service Accept carries no PDU session reactivation result error cause IE$`, saNoErrorCause)
	sc.Step(`^the Service Accept IEs are in the order "([^"]+)"$`, saIEOrder)
	sc.Step(`^the UE sends a Service Request with service type "([^"]+)", Uplink Data Status "([^"]*)" and PDU session status "([^"]*)"$`, srWithIEs)
	sc.Step(`^the Service Accept carries a PDU session status IE flagging PDU sessions "([^"]*)"$`, saCarriesStatus)
	sc.Step(`^the Service Accept carries no PDU session status IE$`, saNoStatus)
	sc.Step(`^the Service Accept carries a PDU session reactivation result IE flagging PDU sessions "([^"]*)"$`, saCarriesResult)
	sc.Step(`^the Service Accept carries no PDU session reactivation result IE$`, saNoResult)
	sc.Step(`^the AMF releases the SM context of PDU session (\d+) at the SMF$`, amfReleasesSMContext)
	sc.Step(`^the AMF releases no SM context at the SMF$`, amfReleasesNoSMContext)
	sc.Step(`^PDU session (\d+) is no longer in the UE context$`, sessionGone)
	sc.Step(`^PDU session (\d+) is still in the UE context$`, sessionStill)
}
