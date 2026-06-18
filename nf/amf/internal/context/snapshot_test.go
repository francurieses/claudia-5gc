package context

import (
	"testing"
	"time"
)

func TestUEContextSnapshot(t *testing.T) {
	ue := &UEContext{
		SUPI:             "imsi-001010000000001",
		SUCI:             "suci-0-001-01-0000-0-0-0000000001",
		GUTI:             &GUTI5G{MCC: "001", MNC: "01", AMFRegionID: 1, AMFSetID: 1, AMFID: 1, TMSI: 0x12345678},
		State:            GMMRegistered,
		CMState:          CMConnected,
		RegistrationTime: time.Unix(1000, 0),
		LastActivity:     time.Unix(2000, 0),
		PDUSessions: map[uint8]*PDUSession{
			5: {PDUSessionID: 5},
			1: {PDUSessionID: 1},
		},
	}
	snap := ue.Snapshot()
	if snap.SUPI != ue.SUPI {
		t.Errorf("SUPI: got %q", snap.SUPI)
	}
	if snap.GMMState != GMMRegistered.String() {
		t.Errorf("GMMState: got %q", snap.GMMState)
	}
	if snap.CMState != CMConnected.String() {
		t.Errorf("CMState: got %q", snap.CMState)
	}
	if snap.GUTI == "" {
		t.Error("GUTI should be rendered")
	}
	// PDU session ids must be sorted ascending.
	if len(snap.PDUSessionIDs) != 2 || snap.PDUSessionIDs[0] != 1 || snap.PDUSessionIDs[1] != 5 {
		t.Errorf("PDUSessionIDs: got %v, want [1 5]", snap.PDUSessionIDs)
	}
}

func TestUEContextSnapshotNoGUTI(t *testing.T) {
	ue := &UEContext{SUPI: "imsi-x", State: GMMDeregistered, CMState: CMIdle}
	snap := ue.Snapshot()
	if snap.GUTI != "" {
		t.Errorf("GUTI should be empty, got %q", snap.GUTI)
	}
	if len(snap.PDUSessionIDs) != 0 {
		t.Errorf("PDUSessionIDs should be empty, got %v", snap.PDUSessionIDs)
	}
}

func TestManagerListContexts(t *testing.T) {
	m := NewManager(AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
	a := m.AllocateUEContext(1)
	a.SUPI = "imsi-a"
	b := m.AllocateUEContext(2)
	b.SUPI = "imsi-b"

	got := m.ListContexts()
	if len(got) != 2 {
		t.Fatalf("ListContexts: got %d, want 2", len(got))
	}
}
