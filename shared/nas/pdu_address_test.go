package nas

import (
	"bytes"
	"net"
	"testing"
)

// TestBuildPDUAddressIE checks the PDU Address IE value encoding for each
// granted PDU session type. For IPv6/IPv4v6 the IE carries only the 64-bit
// interface identifier — never the /64 prefix. Ref: TS 24.501 §9.11.4.10.
func TestBuildPDUAddressIE(t *testing.T) {
	iid := []byte{0, 0, 0, 0, 0, 0, 0, 1}
	v4 := net.ParseIP("192.0.2.10")

	tests := []struct {
		name string
		in   PDUAddressInfo
		want []byte
	}{
		{
			name: "IPv4",
			in:   PDUAddressInfo{SessionType: PDUSessionTypeIPv4, IPv4: v4},
			want: []byte{0x01, 192, 0, 2, 10},
		},
		{
			name: "IPv6 carries the interface identifier",
			in:   PDUAddressInfo{SessionType: PDUSessionTypeIPv6, IPv6IID: iid},
			want: []byte{0x02, 0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			name: "IPv4v6 carries IID then IPv4",
			in:   PDUAddressInfo{SessionType: PDUSessionTypeIPv4v6, IPv4: v4, IPv6IID: iid},
			want: []byte{0x03, 0, 0, 0, 0, 0, 0, 0, 1, 192, 0, 2, 10},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildPDUAddressIE(tc.in)
			if !bytes.Equal(got, tc.want) {
				t.Errorf("buildPDUAddressIE = % X, want % X", got, tc.want)
			}
		})
	}
}

// TestBuildPDUAddressIENilIPv4 verifies an IPv4 type without an address yields
// no IE (the caller must omit the optional IE entirely).
func TestBuildPDUAddressIENilIPv4(t *testing.T) {
	if got := buildPDUAddressIE(PDUAddressInfo{SessionType: PDUSessionTypeIPv4}); got != nil {
		t.Errorf("expected nil IE for IPv4 with no address, got % X", got)
	}
}

// TestEncodeAcceptBodyIPv4Unchanged guards against a regression: the legacy
// IPv4 encoder and the new address-aware encoder must emit identical bytes for
// an IPv4 session.
func TestEncodeAcceptBodyIPv4Unchanged(t *testing.T) {
	ip := net.ParseIP("10.60.0.5")
	snssai := SNSSAI{SST: 1, SD: SDFromString("000001")}

	legacy, err := EncodePDUSessionEstablishmentAcceptBodyWithQoS(
		PDUSessionTypeIPv4, SSCMode1, ip, "internet", 1, 9, 100, 50, snssai)
	if err != nil {
		t.Fatalf("legacy encode: %v", err)
	}
	typed, err := EncodePDUSessionEstablishmentAcceptBodyWithQoSAddr(
		PDUAddressInfo{SessionType: PDUSessionTypeIPv4, IPv4: ip}, SSCMode1, "internet", 1, 9, 100, 50, snssai)
	if err != nil {
		t.Fatalf("typed encode: %v", err)
	}
	if !bytes.Equal(legacy, typed) {
		t.Errorf("IPv4 encoding diverged:\n legacy=% X\n typed =% X", legacy, typed)
	}
}

// TestEncodeAcceptBodyV6TypeOctet verifies the granted type lands in octet 1
// (low nibble) and the PDU Address IE follows the SSC/type + QoS rules + AMBR.
func TestEncodeAcceptBodyV6TypeOctet(t *testing.T) {
	body, err := EncodePDUSessionEstablishmentAcceptBodyWithQoSAddr(
		PDUAddressInfo{SessionType: PDUSessionTypeIPv4v6, IPv4: net.ParseIP("10.61.0.7"),
			IPv6IID: []byte{0, 0, 0, 0, 0, 0, 0, 1}}, SSCMode1, "ims", 1, 9, 100, 50)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Octet 1: SSC mode (1) high nibble | PDU session type (3) low nibble = 0x13.
	if body[0] != ((SSCMode1&0x0F)<<4)|(PDUSessionTypeIPv4v6&0x0F) {
		t.Fatalf("octet 1 = 0x%02X, want 0x%02X", body[0], ((SSCMode1&0x0F)<<4)|(PDUSessionTypeIPv4v6&0x0F))
	}
	// Compute the PDU Address IE offset deterministically:
	// octet0 (1) + [2-byte len + QoS rules] + [1-byte len + AMBR].
	qosRules := BuildDefaultQoSRules(1)
	ambr := buildSessionAMBR(100, 50)
	idx := 1 + 2 + len(qosRules) + 1 + len(ambr)
	if body[idx] != IEIPDUAddress {
		t.Fatalf("expected PDU Address IE (0x29) at offset %d, got 0x%02X", idx, body[idx])
	}
	if body[idx+1] != 13 {
		t.Errorf("PDU Address IE length = %d, want 13 (type + 8 IID + 4 IPv4)", body[idx+1])
	}
	if body[idx+2] != 0x03 {
		t.Errorf("PDU Address type octet = 0x%02X, want 0x03 (IPv4v6)", body[idx+2])
	}
}
