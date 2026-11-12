package sbi

// golden_transfer_test.go - REL19-3.5 slice 2 byte-identity golden for the
// Namf_Communication UEContextTransfer 200 body under rel17 / no profile. The
// golden under testdata/ was captured at the pre-change HEAD (git worktree,
// UPDATE_GOLDEN=1); never regenerate it on a changed tree.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

func checkTransferGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s changed\n got: %q\nwant: %q", name, got, want)
	}
}

// transferBody runs one UEContextTransfer and returns the raw 200 body.
func transferBody(t *testing.T, p *capability.Profile) []byte {
	t.Helper()
	srv, mgr := newTestServer(t)
	if p != nil {
		srv.SetProfile(p)
	}
	seedRegisteredUE(mgr, "imsi-001010000000001")
	body, _ := json.Marshal(UeContextTransferReqData{Reason: ReasonMobiReg, AccessType: "3GPP_ACCESS"})
	resp, raw := post(t, srv, "imsi-001010000000001", body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, raw)
	}
	return raw
}

func TestGolden_UEContextTransfer_Legacy(t *testing.T) {
	t.Run("no profile", func(t *testing.T) {
		checkTransferGolden(t, "ue_context_transfer_rel17_200.json", transferBody(t, nil))
	})
	t.Run("rel17", func(t *testing.T) {
		checkTransferGolden(t, "ue_context_transfer_rel17_200.json", transferBody(t, profileNamed(t, "rel17")))
	})
}

// TestUEContextTransfer_Rel19SpecShape: rel19 carries the key as
// ueContext.seafData.keyAmf (hex); the project members kamf / smfInstanceId are
// absent. PDUSession.SMFInstanceID is the SM context reference (even when it is
// a UUID, as the project SMF allocates), never the H-SMF NfInstanceId, so it is
// not sent as hsmfId (drift-amf, TS 29.518 Table 6.1.6.2.37-1). Both shapes decode.
func TestUEContextTransfer_Rel19SpecShape(t *testing.T) {
	const smContextRef = "0f3c2a6e-8a1b-4c11-9d0e-5a2b7c9d1e44"
	srv, mgr := newTestServer(t)
	srv.SetProfile(profileNamed(t, "rel19"))
	ue := seedRegisteredUE(mgr, "imsi-001010000000001")
	ue.PDUSessions[1].SMFInstanceID = smContextRef
	ue.SecurityCtx.NGKSI = 2
	body, _ := json.Marshal(UeContextTransferReqData{Reason: ReasonMobiReg, AccessType: "3GPP_ACCESS"})
	resp, raw := post(t, srv, "imsi-001010000000001", body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, raw)
	}
	for _, bad := range []string{`"kamf"`, `"smfInstanceId"`} {
		if strings.Contains(string(raw), bad) {
			t.Errorf("rel19 body carries %s: %s", bad, raw)
		}
	}
	var rsp UeContextTransferRspData
	if err := json.Unmarshal(raw, &rsp); err != nil {
		t.Fatal(err)
	}
	sd := rsp.UeContext.SeafData
	if sd == nil || sd.NgKsi != (NgKsi{Tsc: "NATIVE", Ksi: 2}) || sd.KeyAmf.KeyType != "KAMF" ||
		sd.KeyAmf.KeyVal != strings.Repeat("ab", 32) {
		t.Errorf("seafData = %+v", sd)
	}
	if got := rsp.UeContext.SessionContextList[0]; got.HsmfID != "" || got.SmContextRef != smContextRef {
		t.Errorf("hsmfId = %q (want absent), smContextRef = %q", got.HsmfID, got.SmContextRef)
	}
	if rsp.UeContext.MmContextList[0].KAmf != "" {
		t.Error("KAmf must stay empty under rel19")
	}

	// A non-UUID SMF id and an unusable ngKSI are omitted, never sent malformed.
	srv2, mgr2 := newTestServer(t)
	srv2.SetProfile(profileNamed(t, "rel19"))
	ue2 := seedRegisteredUE(mgr2, "imsi-001010000000001")
	ue2.SecurityCtx.NGKSI = 7
	_, raw2 := post(t, srv2, "imsi-001010000000001", body)
	if strings.Contains(string(raw2), "seafData") || strings.Contains(string(raw2), "hsmfId") {
		t.Errorf("malformed values must be omitted: %s", raw2)
	}

	// The legacy shape still decodes into the same fields.
	var legacy UeContextTransferRspData
	if err := json.Unmarshal(transferBody(t, nil), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.UeContext.MmContextList[0].KAmf == "" || legacy.UeContext.SessionContextList[0].SmfInstanceID != "smf-ctx-ref-1" {
		t.Errorf("legacy decode lost kamf/smfInstanceId: %+v", legacy.UeContext)
	}
}
