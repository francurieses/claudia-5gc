// Golden bytes for the UERANSIM patch 0080 (opt-in 5GMM/5GSM capability bits,
// tools/ueransim/patches/0080-nas-capability-ie-optin.patch): the octets the
// modded UE puts on the wire must decode to exactly the configured bits.

package nas_test

import (
	"bytes"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

// TestUERANSIMCapabilityBitsGolden decodes the value octets captured from a UE
// configured with mmCapabilityBits [8.3 8.4 9.3 11.5 12.7 13.4] and
// smCapabilityBits [4.6 4.7 4.8 5.2] (TS 24.501 §9.11.3.1, §9.11.4.1), and
// checks the stock default (one zero octet) decodes to no bits.
func TestUERANSIMCapabilityBitsGolden(t *testing.T) {
	mmWire := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x04, 0x00, 0x10, 0x40, 0x08}
	mm, err := nas.Decode5GMMCapability(mmWire)
	if err != nil {
		t.Fatal(err)
	}
	if !mm.ESI || !mm.ECI || !mm.UNPER || !mm.RSLPVU || !mm.EF5L || !mm.LCSCDL {
		t.Errorf("5GMM configured bits not all decoded: %+v", mm)
	}
	if mm.S1Mode || mm.LPP || mm.NSSAA || mm.A2XUu || mm.ATUC {
		t.Errorf("5GMM unexpected extra bits: %+v", mm)
	}
	enc, err := nas.Encode5GMMCapability(&nas.FiveGMMCapability{ESI: true, ECI: true, UNPER: true, RSLPVU: true, EF5L: true, LCSCDL: true})
	if err != nil || !bytes.Equal(enc, mmWire) {
		t.Errorf("5GMM re-encode = %x (%v), want %x", enc, err, mmWire)
	}

	smWire := []byte{0x00, 0xe0, 0x02}
	sm, err := nas.Decode5GSMCapability(smWire)
	if err != nil {
		t.Fatal(err)
	}
	if !sm.MPTCP || !sm.MPQUICUDP || !sm.MPQUICIP || !sm.E8PCPDEI {
		t.Errorf("5GSM configured bits not all decoded: %+v", sm)
	}
	if sm.RQoS || sm.MH6PDU || sm.ATSSSST != 0 || sm.ATSSSLL != 0 || sm.MPQUICE {
		t.Errorf("5GSM unexpected extra bits: %+v", sm)
	}
	enc, err = nas.Encode5GSMCapability(&nas.FiveGSMCapability{MPTCP: true, MPQUICUDP: true, MPQUICIP: true, E8PCPDEI: true})
	if err != nil || !bytes.Equal(enc, smWire) {
		t.Errorf("5GSM re-encode = %x (%v), want %x", enc, err, smWire)
	}

	// Default config: stock UERANSIM sends a single zero octet in both IEs.
	for _, b := range [][]byte{{0x00}} {
		m, err := nas.Decode5GMMCapability(b)
		if err != nil || m.ESI || m.S1Mode {
			t.Errorf("default 5GMM capability decoded with bits: %+v %v", m, err)
		}
		s, err := nas.Decode5GSMCapability(b)
		if err != nil || s.MPTCP || s.RQoS {
			t.Errorf("default 5GSM capability decoded with bits: %+v %v", s, err)
		}
	}
}

// TestCapabilitySetBitNames pins the observability helpers used by the
// capability_5gmm / capability_5gsm(_bits) log fields.
func TestCapabilitySetBitNames(t *testing.T) {
	mm, _ := nas.Decode5GMMCapability([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x04, 0x00, 0x10, 0x40, 0x08})
	want := []string{"ESI", "ECI", "UNPER", "RSLPVU", "EF5L", "LCSCDL"}
	got := mm.SetBitNames()
	if len(got) != len(want) {
		t.Fatalf("5GMM bits = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("5GMM bit %d = %s, want %s", i, got[i], want[i])
		}
	}
	if mm.RawHex() != "00000000000c0400104008" {
		t.Errorf("RawHex = %s", mm.RawHex())
	}
	sm, _ := nas.Decode5GSMCapability([]byte{0x10, 0xe8, 0x02})
	if g := sm.SetBitNames(); len(g) != 6 || g[len(g)-2] != "ATSSS-ST=2" || g[len(g)-1] != "ATSSS-LL=1" {
		t.Errorf("5GSM bits = %v", g)
	}
	var nilMM *nas.FiveGMMCapability
	if nilMM.SetBitNames() != nil || nilMM.RawHex() != "" {
		t.Error("nil receiver must be safe")
	}
}
