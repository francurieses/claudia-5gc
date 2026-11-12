package context

// capability_5gmm_test.go - the decoded 5GMM capability survives the
// UEContext -> UERecord -> JSON -> UEContext round trip (REL19-5.4).
// Ref: TS 24.501 §9.11.3.1

import (
	"encoding/json"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/amf/internal/store"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

func TestUERecordRoundTrip5GMMCapability(t *testing.T) {
	raw := []byte{0x81, 0x80, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xF0}
	c, err := nas.Decode5GMMCapability(raw)
	if err != nil {
		t.Fatal(err)
	}
	rec := ueContextToRecord(&UEContext{SUPI: "imsi-001010000000001", Capability5GMM: c})
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var back store.UERecord
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	ue := recordToUEContext(&back)
	got := ue.Capability5GMM
	if got == nil || !got.S1Mode || !got.SGC || !got.RACS || !got.ERNSSAI || !got.LCSCDL || string(got.Raw) != string(raw) {
		t.Fatalf("capability lost in round trip: %+v", got)
	}
}

func TestUERecordNo5GMMCapabilityOmitted(t *testing.T) {
	rec := ueContextToRecord(&UEContext{SUPI: "imsi-001010000000001"})
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["capability_5gmm"]; ok {
		t.Fatalf("capability_5gmm must be omitted when absent: %s", b)
	}
	if recordToUEContext(rec).Capability5GMM != nil {
		t.Error("absent capability must restore as nil")
	}
}

// TestDecode5GMMCapabilityCopiesInput proves mutating the caller's buffer
// after decode does not change the stored capability.
func TestDecode5GMMCapabilityCopiesInput(t *testing.T) {
	buf := []byte{0x81, 0x80, 0x10}
	c, err := nas.Decode5GMMCapability(buf)
	if err != nil {
		t.Fatal(err)
	}
	for i := range buf {
		buf[i] = 0xFF
	}
	if string(c.Raw) != string([]byte{0x81, 0x80, 0x10}) || !c.S1Mode || c.LCSCDL {
		t.Fatalf("stored capability aliases caller buffer: %+v", c)
	}
}
