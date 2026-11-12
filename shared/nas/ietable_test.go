package nas

// ietable_test.go — tests for the per-message IE tables and the generic
// unknown-IE skipper. Ref: TS 24.007 §11.2.4, TS 24.501 §7.6.1.

import (
	"errors"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

// regReqPrefix is a Registration Request body up to the end of the mandatory
// part: ngKSI/reg-type octet + 5GS mobile identity LV-E (No Identity).
var regReqPrefix = []byte{0x11, 0x00, 0x01, 0x00}

// requestedNSSAI is a Requested NSSAI IE (0x2F) carrying SST 0x42.
var requestedNSSAI = []byte{0x2F, 0x02, 0x01, 0x42}

// decodeRegReq decodes prefix + injected + Requested NSSAI and checks the
// NSSAI after the injected IE is still found.
func decodeRegReqWithInjected(t *testing.T, injected []byte) error {
	t.Helper()
	body := append(append(append([]byte{}, regReqPrefix...), injected...), requestedNSSAI...)
	rr, err := DecodeRegistrationRequest(body)
	if err != nil {
		return err
	}
	if rr.RequestedNSSAI == nil || len(rr.RequestedNSSAI.SNSSAIs) != 1 || rr.RequestedNSSAI.SNSSAIs[0].SST != 0x42 {
		t.Fatalf("Requested NSSAI after injected IE % X not decoded: parser desynchronised", injected)
	}
	return nil
}

// decodePDUReqWithInjected decodes mandatory part + injected + SSC mode (0xA2)
// and checks the SSC mode after the injected IE is still found.
func decodePDUReqWithInjected(t *testing.T, injected []byte) error {
	t.Helper()
	body := append(append([]byte{0x00, 0x00}, injected...), 0xA2)
	msg, err := DecodePDUSessionEstablishmentRequest(body)
	if err != nil {
		return err
	}
	if msg.SSCMode == nil || *msg.SSCMode != 2 {
		t.Fatalf("SSC mode after injected IE % X not decoded: parser desynchronised", injected)
	}
	return nil
}

// TestSkipUnknownTLVE: IEI 0x70-0x7F unknown to the message is TLV-E with a
// 2-octet length; a 1-octet-length skip would desynchronise the rest.
func TestSkipUnknownTLVE(t *testing.T) {
	// 0x7F and 0x7D are not in the Registration Request / PDU Session
	// Establishment Request tables; a length of 0x0102 spans a 0x01 length
	// byte that a TLV skip would misread.
	val := make([]byte, 0x0102)
	for _, iei := range []byte{0x7F, 0x7D} {
		inj := append([]byte{iei, 0x01, 0x02}, val...)
		if err := decodeRegReqWithInjected(t, inj); err != nil {
			t.Errorf("RegistrationRequest IEI 0x%02X: %v", iei, err)
		}
		if err := decodePDUReqWithInjected(t, inj); err != nil {
			t.Errorf("PDUSessionEstablishmentRequest IEI 0x%02X: %v", iei, err)
		}
	}
	// Known TLV-E IE with no dedicated case (Additional GUTI 0x77, LADN 0x74).
	for _, iei := range []byte{0x77, 0x74, 0x71} {
		if err := decodeRegReqWithInjected(t, []byte{iei, 0x00, 0x02, 0xAA, 0xBB}); err != nil {
			t.Errorf("known TLV-E 0x%02X: %v", iei, err)
		}
	}
	if end, err := skipUnknownIE([]byte{0x7F, 0x00, 0x02, 1, 2, 9}, 0); err != nil || end != 5 {
		t.Errorf("skipUnknownIE TLV-E = (%d, %v), want (5, nil)", end, err)
	}
	// Truncation.
	for name, b := range map[string][]byte{
		"no length":      {0x7F},
		"one length oct": {0x7F, 0x00},
		"value overrun":  {0x7F, 0x00, 0x05, 1, 2},
	} {
		if _, err := skipUnknownIE(b, 0); !errors.Is(err, ErrIETruncated) {
			t.Errorf("%s: err = %v, want ErrIETruncated", name, err)
		}
	}
	assertTruncatedOptionalIEIgnored(t, []byte{0x7F, 0x00, 0x09, 1})
}

// TestSkipUnknownTLV: IEI 0x00-0x6F unknown to the message is TLV with a
// 1-octet length.
func TestSkipUnknownTLV(t *testing.T) {
	for _, iei := range []byte{0x03, 0x4E, 0x6F} {
		inj := []byte{iei, 0x03, 0xAA, 0xBB, 0xCC}
		if err := decodeRegReqWithInjected(t, inj); err != nil {
			t.Errorf("RegistrationRequest IEI 0x%02X: %v", iei, err)
		}
		if err := decodePDUReqWithInjected(t, inj); err != nil {
			t.Errorf("PDUSessionEstablishmentRequest IEI 0x%02X: %v", iei, err)
		}
	}
	// Zero-length value.
	if err := decodeRegReqWithInjected(t, []byte{0x03, 0x00}); err != nil {
		t.Errorf("empty TLV: %v", err)
	}
	// Known type 3 TV IE (Last visited registered TAI, 0x52, 7 octets in
	// total): the table, not the TLV rule, must decide its length.
	tai := []byte{0x52, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	if err := decodeRegReqWithInjected(t, tai); err != nil {
		t.Errorf("known TV 0x52: %v", err)
	}
	// Known TV 0x55 in PDU Session Establishment Request (3 octets).
	if err := decodePDUReqWithInjected(t, []byte{0x55, 0x00, 0x10}); err != nil {
		t.Errorf("known TV 0x55: %v", err)
	}
	for name, b := range map[string][]byte{
		"no length":     {0x03},
		"value overrun": {0x03, 0x04, 1, 2},
	} {
		if _, err := skipUnknownIE(b, 0); !errors.Is(err, ErrIETruncated) {
			t.Errorf("%s: err = %v, want ErrIETruncated", name, err)
		}
	}
	// Truncated optional IE: treated as not present, message decoded so far
	// is returned without error (TS 24.501 §7.7.1).
	msg, err := DecodePDUSessionEstablishmentRequest([]byte{0x00, 0x00, 0xA2, 0x03, 0x09, 1})
	if err != nil || msg == nil || msg.SSCMode == nil || *msg.SSCMode != 2 {
		t.Errorf("truncated TLV in PDU Session Establishment Request = (%+v, %v), want SSC mode 2 and nil error", msg, err)
	}
	if _, err := skipIE(IEMsgRegistrationRequest, []byte{0x52, 1, 2}, 0); !errors.Is(err, ErrIETruncated) {
		t.Errorf("truncated known TV: err = %v, want ErrIETruncated", err)
	}
}

// TestSkipUnknownTV1: IEI with bit 8 set is a one-octet type 1 (TV, half
// octet value) or type 2 (T) IE.
func TestSkipUnknownTV1(t *testing.T) {
	// 0xC5 / 0xD3 / 0xF0 are not in the Registration Request or PDU Session
	// Establishment Request tables (0xF0 is a type 2 shape).
	for _, inj := range [][]byte{{0xC5}, {0xD3}, {0xF0}, {0xC5, 0xD3}} {
		if err := decodeRegReqWithInjected(t, inj); err != nil {
			t.Errorf("RegistrationRequest % X: %v", inj, err)
		}
		if err := decodePDUReqWithInjected(t, inj); err != nil {
			t.Errorf("PDUSessionEstablishmentRequest % X: %v", inj, err)
		}
	}
	// Known TV1 IEs without a dedicated case: MICO indication (0xB-) and
	// N5GC indication (0xA-) in a Registration Request.
	if err := decodeRegReqWithInjected(t, []byte{0xB1, 0xA1}); err != nil {
		t.Errorf("known TV1: %v", err)
	}
	if end, err := skipUnknownIE([]byte{0xC5, 0x01}, 0); err != nil || end != 1 {
		t.Errorf("skipUnknownIE TV1 = (%d, %v), want (1, nil)", end, err)
	}
	if _, err := skipUnknownIE(nil, 0); err == nil {
		t.Error("skipUnknownIE on empty buffer: want error")
	}
	if _, err := skipUnknownIE([]byte{0xC5}, 1); err == nil {
		t.Error("skipUnknownIE past end: want error")
	}
}

// TestRegistrationAcceptSkipsUnknownIEs checks the Registration Accept
// decoder with unknown TLV-E / TLV / TV1 IEs before a known IE.
func TestRegistrationAcceptSkipsUnknownIEs(t *testing.T) {
	// 5GS registration result LV, then unknown IEs, then T3512 (0x5E).
	for _, inj := range [][]byte{
		{0x7F, 0x00, 0x02, 0x01, 0x5E},
		{0x03, 0x02, 0x5E, 0x5E},
		{0xC5},
	} {
		b := append([]byte{0x01, 0x01}, inj...)
		b = append(b, 0x5E, 0x01, 0x21)
		ra, err := DecodeRegistrationAccept(b)
		if err != nil {
			t.Fatalf("% X: %v", inj, err)
		}
		if ra.T3512Value == nil || *ra.T3512Value != 0x21 {
			t.Errorf("% X: T3512 after unknown IE not decoded", inj)
		}
	}
	ra, err := DecodeRegistrationAccept([]byte{0x01, 0x01, 0x5E, 0x01, 0x21, 0x7F, 0x00, 0x09})
	if err != nil || ra == nil || ra.T3512Value == nil || *ra.T3512Value != 0x21 {
		t.Errorf("truncated TLV-E in Registration Accept = (%+v, %v), want T3512 kept and nil error", ra, err)
	}
	// Truncation in the imperative part still errors.
	if _, err := DecodeRegistrationAccept(nil); err == nil {
		t.Error("empty Registration Accept decoded without error")
	}
}

// TestIETableSanity checks every registered table: unique IEIs and format
// consistent with the TS 24.007 §11.2.4 IEI ranges for 5GMM/5GSM.
func TestIETableSanity(t *testing.T) {
	for msg, defs := range ieTables {
		if len(defs) == 0 {
			t.Errorf("%s: empty table", msg)
		}
		seen := map[byte]string{}
		for _, d := range defs {
			key := d.IEI
			if d.Format == IEFormatTV1 || d.Format == IEFormatT {
				key &= 0xF0
			}
			if prev, dup := seen[key]; dup {
				t.Errorf("%s: duplicate IEI 0x%02X (%q and %q)", msg, d.IEI, prev, d.Name)
			}
			seen[key] = d.Name
			if d.Name == "" || d.Ref == "" {
				t.Errorf("%s: IEI 0x%02X missing name/ref", msg, d.IEI)
			}
			if d.Introduced < capability.Rel15 || d.Introduced > capability.Rel19 {
				t.Errorf("%s: %q introducedIn %v out of range", msg, d.Name, d.Introduced)
			}
			switch d.Format {
			case IEFormatTV1:
				if d.IEI&0x0F != 0 || d.IEI&0x80 == 0 {
					t.Errorf("%s: %q TV1 IEI 0x%02X must be a high nibble >= 0x80", msg, d.Name, d.IEI)
				}
			case IEFormatT:
				if d.IEI&0x80 == 0 {
					t.Errorf("%s: %q type 2 IEI 0x%02X must have bit 8 set", msg, d.Name, d.IEI)
				}
			case IEFormatTLVE:
				if d.IEI&0xF0 != 0x70 {
					t.Errorf("%s: %q TLV-E IEI 0x%02X outside 0x70-0x7F", msg, d.Name, d.IEI)
				}
			case IEFormatTLV:
				if d.IEI >= 0x70 {
					t.Errorf("%s: %q TLV IEI 0x%02X not in 0x00-0x6F", msg, d.Name, d.IEI)
				}
			case IEFormatTV:
				if d.IEI >= 0x70 || d.Len < 2 {
					t.Errorf("%s: %q TV IEI 0x%02X len %d invalid", msg, d.Name, d.IEI, d.Len)
				}
			default:
				t.Errorf("%s: %q unknown format %v", msg, d.Name, d.Format)
			}
			if d.Format != IEFormatTV && d.Len != 0 {
				t.Errorf("%s: %q Len set for non-TV format", msg, d.Name)
			}
		}
	}
	// Spot checks against the transcribed tables.
	for _, c := range []struct {
		msg  IEMessage
		iei  byte
		want IEFormat
	}{
		{IEMsgRegistrationRequest, 0x52, IEFormatTV},
		{IEMsgRegistrationRequest, 0x71, IEFormatTLVE},
		{IEMsgRegistrationRequest, 0xB3, IEFormatTV1},
		{IEMsgRegistrationAccept, 0x68, IEFormatTLV},
		{IEMsgRegistrationAccept, 0x7B, IEFormatTLVE},
		{IEMsgPDUSessionEstablishmentRequest, 0x7B, IEFormatTLVE},
		{IEMsgPDUSessionEstablishmentRequest, 0x55, IEFormatTV},
	} {
		d, ok := LookupIE(c.msg, c.iei)
		if !ok || d.Format != c.want {
			t.Errorf("LookupIE(%s, 0x%02X) = %+v ok=%v, want format %v", c.msg, c.iei, d, ok, c.want)
		}
	}
	if _, ok := LookupIE(IEMsgRegistrationRequest, 0x7F); ok {
		t.Error("0x7F must be unknown in Registration Request")
	}
}

// assertTruncatedOptionalIEIgnored checks that a truncated optional IE placed
// after the Requested NSSAI stops optional-IE parsing without an error and
// keeps what was decoded before it (TS 24.501 §7.7.1), while truncation in
// the imperative part still errors.
func assertTruncatedOptionalIEIgnored(t *testing.T, injected []byte) {
	t.Helper()
	body := append(append(append([]byte{}, regReqPrefix...), requestedNSSAI...), injected...)
	rr, err := DecodeRegistrationRequest(body)
	if err != nil {
		t.Fatalf("truncated optional IE % X: err = %v, want nil", injected, err)
	}
	if rr.RequestedNSSAI == nil || rr.RequestedNSSAI.SNSSAIs[0].SST != 0x42 {
		t.Errorf("IEs before truncated IE % X lost", injected)
	}
	if _, err := DecodeRegistrationRequest(regReqPrefix[:2]); err == nil {
		t.Error("truncated mandatory part decoded without error")
	}
}

// TestSkipIETablePathVsRulePath distinguishes the table path from the TS
// 24.007 §11.2.4 rule path by asserting exact offsets.
func TestSkipIETablePathVsRulePath(t *testing.T) {
	// Known TV 0x52 (7 octets). First value octet 0x00 read as a TLV length
	// would end the IE at offset 2 and desynchronise.
	tai := []byte{0x52, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xB1}
	if end, err := skipIE(IEMsgRegistrationRequest, tai, 0); err != nil || end != 7 {
		t.Errorf("table TV skip = (%d, %v), want (7, nil)", end, err)
	}
	if end, err := skipUnknownIE(tai, 0); err != nil || end != 2 {
		t.Errorf("rule skip of the same bytes = (%d, %v), want (2, nil): rule must differ from table", end, err)
	}
	// Known TV 0x55 (3 octets) in the PDU Session Establishment Request.
	if end, err := skipIE(IEMsgPDUSessionEstablishmentRequest, []byte{0x55, 0x00, 0x10, 0xA2}, 0); err != nil || end != 3 {
		t.Errorf("table TV 0x55 skip = (%d, %v), want (3, nil)", end, err)
	}

	// Synthetic message whose table disagrees with the rule for TV1, TLV and
	// TLV-E, so only the table path yields the asserted offsets.
	const synth IEMessage = "synthetic-test"
	ieTables[synth] = []IEDef{
		{IEI: 0x20, Name: "t1", Format: IEFormatTV1, Introduced: capability.Rel15},
		{IEI: 0x7E, Name: "tlv", Format: IEFormatTLV, Introduced: capability.Rel15},
		{IEI: 0x30, Name: "tlve", Format: IEFormatTLVE, Introduced: capability.Rel15},
	}
	t.Cleanup(func() { delete(ieTables, synth) })
	cases := []struct {
		name string
		buf  []byte
		want int
		rule int // offset the rule path would give
	}{
		{"TV1 (rule: TLV, len 0x7F overruns)", []byte{0x25, 0x7F}, 1, -1},
		{"TLV at 0x7E (rule: TLV-E, 2-octet length 0x0203)", []byte{0x7E, 0x02, 0x03, 0xAA, 0xBB}, 4, 0},
		{"TLV-E at 0x30 (rule: TLV, length 0x00)", []byte{0x30, 0x00, 0x02, 0xAA, 0xBB, 0xCC}, 5, 2},
	}
	for _, c := range cases {
		end, err := skipIE(synth, c.buf, 0)
		if err != nil || end != c.want {
			t.Errorf("%s: table skip = (%d, %v), want (%d, nil)", c.name, end, err, c.want)
		}
		rend, rerr := skipUnknownIE(c.buf, 0)
		if c.rule >= 0 && c.rule > 0 && (rerr != nil || rend != c.rule) {
			t.Errorf("%s: rule skip = (%d, %v), want (%d, nil)", c.name, rend, rerr, c.rule)
		}
		if rend == end && rerr == nil {
			t.Errorf("%s: rule and table agree; case does not discriminate", c.name)
		}
	}
}

// TestIETableReturnsCopy checks that mutating the result of IETable does not
// change the registered table.
func TestIETableReturnsCopy(t *testing.T) {
	got := IETable(IEMsgRegistrationRequest)
	if len(got) == 0 {
		t.Fatal("empty Registration Request table")
	}
	got[0].Name = "mutated"
	if IETable(IEMsgRegistrationRequest)[0].Name == "mutated" {
		t.Error("IETable exposes the live table")
	}
}
