package ngap

// ue_ambr_presence_test.go — UE-AMBR conditional presence in ICS Request and
// optional presence in PDU Session Resource Setup Request.
// Ref: TS 38.413 §8.3.1, §9.2.2.1, §8.2.1, §9.2.1.1, §9.3.1.58; TS 23.501 §5.7.2.6

import (
	"testing"

	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

var oneSession = []PDUSessionSetupItemCxtReq{
	{PDUSessionID: 5, SST: 1, SD: []byte{0, 0, 1}, Transfer: []byte{0xAA}},
}

func icsIEIDs(t *testing.T, raw []byte) []int64 {
	t.Helper()
	pdu, err := libngap.Decoder(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var ids []int64
	for _, ie := range pdu.InitiatingMessage.Value.InitialContextSetupRequest.ProtocolIEs.List {
		ids = append(ids, ie.Id.Value)
	}
	return ids
}

func contains(ids []int64, id int64) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

func TestICS_UEAMBRConditionalPresence(t *testing.T) {
	tests := []struct {
		name     string
		sessions []PDUSessionSetupItemCxtReq
		wantAMBR bool
	}{
		{"registration, nil sessions", nil, false},
		{"service request, empty sessions", []PDUSessionSetupItemCxtReq{}, false},
		{"service request, one session", oneSession, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildTestICSRWithSessions(1, tc.sessions)
			ids := icsIEIDs(t, raw)
			if got := contains(ids, ngapType.ProtocolIEIDUEAggregateMaximumBitRate); got != tc.wantAMBR {
				t.Fatalf("UE-AMBR present = %v, want %v (ids %v)", got, tc.wantAMBR, ids)
			}
			if got := contains(ids, ngapType.ProtocolIEIDPDUSessionResourceSetupListCxtReq); got != tc.wantAMBR {
				t.Fatalf("IE 71 present = %v, want %v", got, tc.wantAMBR)
			}
			for _, m := range []int64{ngapType.ProtocolIEIDAMFUENGAPID, ngapType.ProtocolIEIDRANUENGAPID,
				ngapType.ProtocolIEIDGUAMI, ngapType.ProtocolIEIDUESecurityCapabilities,
				ngapType.ProtocolIEIDSecurityKey, ngapType.ProtocolIEIDNASPDU} {
				if !contains(ids, m) {
					t.Errorf("mandatory IE %d missing", m)
				}
			}
			v, err := CheckICSConditionalPresence(raw)
			if err != nil || len(v) != 0 {
				t.Fatalf("strict check: violations=%v err=%v", v, err)
			}
		})
	}
}

func TestICS_WithSessionsIEOrderAndDefaultAMBR(t *testing.T) {
	raw := buildTestICSRWithSessions(10, oneSession) // subscribed AMBR 0 → default
	want := []int64{
		ngapType.ProtocolIEIDAMFUENGAPID, ngapType.ProtocolIEIDRANUENGAPID,
		ngapType.ProtocolIEIDUEAggregateMaximumBitRate, ngapType.ProtocolIEIDGUAMI,
		ngapType.ProtocolIEIDPDUSessionResourceSetupListCxtReq, ngapType.ProtocolIEIDAllowedNSSAI,
		ngapType.ProtocolIEIDUESecurityCapabilities, ngapType.ProtocolIEIDSecurityKey,
		ngapType.ProtocolIEIDIndexToRFSP, ngapType.ProtocolIEIDNASPDU,
	}
	got := icsIEIDs(t, raw)
	if len(got) != len(want) {
		t.Fatalf("ids = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ids = %v, want %v", got, want)
		}
	}
	pdu, _ := libngap.Decoder(raw)
	a := pdu.InitiatingMessage.Value.InitialContextSetupRequest.ProtocolIEs.List[2]
	if a.Criticality.Value != ngapType.CriticalityPresentReject {
		t.Errorf("criticality = %d, want reject", a.Criticality.Value)
	}
	ambr := a.Value.UEAggregateMaximumBitRate
	if ambr.UEAggregateMaximumBitRateUL.Value != DefaultUEAMBRBps || ambr.UEAggregateMaximumBitRateDL.Value != DefaultUEAMBRBps {
		t.Errorf("default AMBR = %d/%d, want %d", ambr.UEAggregateMaximumBitRateUL.Value, ambr.UEAggregateMaximumBitRateDL.Value, DefaultUEAMBRBps)
	}
}

func TestCheckICSConditionalPresence_DetectsViolation(t *testing.T) {
	// Hand-build the pre-fix shape: UE-AMBR without IE 71.
	raw := buildTestICSRWithSessions(1, oneSession)
	pdu, _ := libngap.Decoder(raw)
	req := pdu.InitiatingMessage.Value.InitialContextSetupRequest
	var kept []ngapType.InitialContextSetupRequestIEs
	for _, ie := range req.ProtocolIEs.List {
		if ie.Id.Value != ngapType.ProtocolIEIDPDUSessionResourceSetupListCxtReq {
			kept = append(kept, ie)
		}
	}
	req.ProtocolIEs.List = kept
	bad, err := libngap.Encoder(*pdu)
	if err != nil {
		t.Fatal(err)
	}
	v, err := CheckICSConditionalPresence(bad)
	if err != nil || len(v) != 1 {
		t.Fatalf("violations=%v err=%v, want exactly one", v, err)
	}
}

func decodePSRSetup(t *testing.T, raw []byte) []ngapType.PDUSessionResourceSetupRequestIEs {
	t.Helper()
	if raw == nil {
		t.Fatal("encoder returned nil")
	}
	pdu, err := libngap.Decoder(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if pdu.InitiatingMessage.ProcedureCode.Value != ngapType.ProcedureCodePDUSessionResourceSetup {
		t.Fatalf("procedure code = %d", pdu.InitiatingMessage.ProcedureCode.Value)
	}
	return pdu.InitiatingMessage.Value.PDUSessionResourceSetupRequest.ProtocolIEs.List
}

func TestPDUSessionResourceSetupRequest_UEAMBR(t *testing.T) {
	sd := []byte{0, 0, 1}
	t.Run("with UE-AMBR after list, criticality ignore", func(t *testing.T) {
		ies := decodePSRSetup(t, BuildPDUSessionResourceSetupRequest(1, 2, 1, []byte{0x01}, []byte{0xBB}, 1, sd,
			NewUEAMBRFromKbps(2_000_000, 4_000_000)))
		want := []int64{ngapType.ProtocolIEIDAMFUENGAPID, ngapType.ProtocolIEIDRANUENGAPID,
			ngapType.ProtocolIEIDPDUSessionResourceSetupListSUReq, ngapType.ProtocolIEIDUEAggregateMaximumBitRate}
		if len(ies) != len(want) {
			t.Fatalf("got %d IEs, want %d", len(ies), len(want))
		}
		for i := range want {
			if ies[i].Id.Value != want[i] {
				t.Fatalf("IE %d id = %d, want %d", i, ies[i].Id.Value, want[i])
			}
		}
		last := ies[3]
		if last.Criticality.Value != ngapType.CriticalityPresentIgnore {
			t.Errorf("criticality = %d, want ignore", last.Criticality.Value)
		}
		a := last.Value.UEAggregateMaximumBitRate
		if a.UEAggregateMaximumBitRateUL.Value != 2_000_000_000 || a.UEAggregateMaximumBitRateDL.Value != 4_000_000_000 {
			t.Errorf("AMBR UL/DL = %d/%d", a.UEAggregateMaximumBitRateUL.Value, a.UEAggregateMaximumBitRateDL.Value)
		}
	})
	t.Run("default 1 Gbps when subscription lacks UE-AMBR", func(t *testing.T) {
		ies := decodePSRSetup(t, BuildPDUSessionResourceSetupRequest(1, 2, 1, []byte{0x01}, []byte{0xBB}, 1, sd,
			NewUEAMBRFromKbps(0, 0)))
		a := ies[3].Value.UEAggregateMaximumBitRate
		if a.UEAggregateMaximumBitRateUL.Value != DefaultUEAMBRBps || a.UEAggregateMaximumBitRateDL.Value != DefaultUEAMBRBps {
			t.Errorf("AMBR = %d/%d", a.UEAggregateMaximumBitRateUL.Value, a.UEAggregateMaximumBitRateDL.Value)
		}
	})
	t.Run("omitted when nil (already delivered)", func(t *testing.T) {
		ies := decodePSRSetup(t, BuildPDUSessionResourceSetupRequest(1, 2, 2, []byte{0x01}, []byte{0xBB}, 1, sd, nil))
		if len(ies) != 3 {
			t.Fatalf("got %d IEs, want 3", len(ies))
		}
		for _, ie := range ies {
			if ie.Id.Value == ngapType.ProtocolIEIDUEAggregateMaximumBitRate {
				t.Fatal("UE-AMBR must be absent")
			}
		}
	})
}
