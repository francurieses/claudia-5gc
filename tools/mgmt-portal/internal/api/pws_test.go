package api

import (
	"encoding/json"
	"testing"

	"github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/store"
)

// TestMergePWS_LiveOverlay: a stored warning the AMF still knows gets its live
// per-gNB status overlaid and live:true.
func TestMergePWS_LiveOverlay(t *testing.T) {
	stored := []store.PWSBroadcast{{
		MessageIdentifier: 7001, SerialNumber: 1, DataCodingScheme: 0x04,
		Language: "es", MessageText: "hola", WarningType: "0000",
	}}
	amf := []amfPWSStatus{{
		MessageIdentifier: 7001, SerialNumber: 1, GNBsTargeted: 2, GNBsCompleted: 2,
		PerGNB: json.RawMessage(`[{"gnb_name":"g1"}]`),
	}}
	got := mergePWS(stored, amf)
	if len(got) != 1 {
		t.Fatalf("want 1 merged, got %d", len(got))
	}
	m := got[0]
	if !m.Live || !m.Stored {
		t.Errorf("want live+stored, got live=%v stored=%v", m.Live, m.Stored)
	}
	if m.GNBsCompleted != 2 || m.GNBsTargeted != 2 {
		t.Errorf("live status not overlaid: %d/%d", m.GNBsCompleted, m.GNBsTargeted)
	}
	if m.MessageText != "hola" || m.Language != "es" || m.DataCodingScheme == nil || *m.DataCodingScheme != 0x04 {
		t.Errorf("stored content missing: %+v", m)
	}
	if string(m.PerGNB) != `[{"gnb_name":"g1"}]` {
		t.Errorf("per_gnb not carried through: %s", m.PerGNB)
	}
}

// TestMergePWS_StoredOnly: a stored warning the AMF no longer has (post-restart)
// is live:false with its content intact — the whole point of CBC persistence.
func TestMergePWS_StoredOnly(t *testing.T) {
	stored := []store.PWSBroadcast{{
		MessageIdentifier: 7001, SerialNumber: 1, MessageText: "survived", DataCodingScheme: 0x0F,
	}}
	got := mergePWS(stored, nil)
	if len(got) != 1 || got[0].Live || !got[0].Stored {
		t.Fatalf("want 1 stored-only live:false, got %+v", got)
	}
	if got[0].MessageText != "survived" {
		t.Errorf("content lost: %+v", got[0])
	}
}

// TestMergePWS_AMFOnly: a warning the AMF knows but the store doesn't (sent
// directly to the AMF API) is appended with stored:false.
func TestMergePWS_AMFOnly(t *testing.T) {
	amf := []amfPWSStatus{{MessageIdentifier: 42, SerialNumber: 1, GNBsTargeted: 1, GNBsCompleted: 1}}
	got := mergePWS(nil, amf)
	if len(got) != 1 || got[0].Stored || !got[0].Live {
		t.Fatalf("want 1 amf-only stored:false live:true, got %+v", got)
	}
}

// TestMergePWS_NewestFirst verifies ordering by created_at descending.
func TestMergePWS_NewestFirst(t *testing.T) {
	stored := []store.PWSBroadcast{}
	amf := []amfPWSStatus{
		{MessageIdentifier: 1, SerialNumber: 1, CreatedAt: "2026-07-28T09:00:00Z"},
		{MessageIdentifier: 2, SerialNumber: 1, CreatedAt: "2026-07-28T10:00:00Z"},
	}
	got := mergePWS(stored, amf)
	if got[0].MessageIdentifier != 2 {
		t.Errorf("want newest (msgId 2) first, got %d", got[0].MessageIdentifier)
	}
}

// TestRequestStoreRoundTrip verifies a broadcast request → stored record →
// reconstructed request preserves the fields needed to re-drive, and that
// toStore applies the AMF defaults for omitted values.
func TestRequestStoreRoundTrip(t *testing.T) {
	mid, sn, dcs := 4370, 2, 0x11
	req := pwsBroadcastRequest{
		MessageIdentifier: &mid, SerialNumber: &sn, DataCodingScheme: &dcs,
		Language: "ja", MessageText: "keihou", WarningType: "0003",
		WarningAreaTACs: []int{1, 7},
	}
	rec := req.toStore()
	if rec.MessageIdentifier != 4370 || rec.SerialNumber != 2 || rec.DataCodingScheme != 0x11 ||
		rec.Language != "ja" || rec.MessageText != "keihou" || rec.WarningType != "0003" {
		t.Fatalf("toStore lost fields: %+v", rec)
	}
	if len(rec.WarningAreaTACs) != 2 || rec.WarningAreaTACs[1] != 7 {
		t.Errorf("TACs not preserved: %v", rec.WarningAreaTACs)
	}
	back := storeToRequest(&rec)
	if *back.MessageIdentifier != 4370 || *back.DataCodingScheme != 0x11 || back.Language != "ja" {
		t.Errorf("storeToRequest round-trip lost fields: %+v", back)
	}

	// Omitted numeric fields fall back to the AMF defaults.
	def := pwsBroadcastRequest{MessageText: "x"}.toStore()
	if def.MessageIdentifier != 0x1112 || def.SerialNumber != 1 || def.DataCodingScheme != 0x0F ||
		def.RepetitionPeriod != 4096 || def.NumberOfBroadcasts != 1 || def.WarningType != "1000" {
		t.Errorf("toStore defaults wrong: %+v", def)
	}
}
