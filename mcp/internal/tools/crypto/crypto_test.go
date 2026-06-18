package crypto_test

import (
	"context"
	"encoding/json"
	"testing"

	cryptotools "github.com/francurieses/claudia-5gc/mcp/internal/tools/crypto"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// ---- helpers ---------------------------------------------------------------

func invoke(t *testing.T, tool registry.Tool, input string) map[string]any {
	t.Helper()
	res, err := tool.Invoke(context.Background(), json.RawMessage(input))
	if err != nil {
		t.Fatalf("%s.Invoke error: %v", tool.Name(), err)
	}
	b, _ := json.Marshal(res)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	return m
}

func invokeErr(t *testing.T, tool registry.Tool, input string) error {
	t.Helper()
	_, err := tool.Invoke(context.Background(), json.RawMessage(input))
	if err == nil {
		t.Fatalf("%s.Invoke: expected error but got nil", tool.Name())
	}
	return err
}

func str(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

// ---- milenage_run ----------------------------------------------------------

// TestMilenageRunSet1 uses the normative test vectors from TS 35.207 §6 Set 1.
func TestMilenageRunSet1(t *testing.T) {
	tool := cryptotools.All()[0] // milenage_run

	m := invoke(t, tool, `{
		"k":    "465b5ce8b199b49faa5f0a2ee238a6bc",
		"opc":  "cd63cb71954a9f4e48a5994e37a02baf",
		"rand": "23553cbe9637a89d218ae64dae47bf35",
		"sqn":  "ff9bb4d0b607",
		"amf":  "b9b9"
	}`)

	// TS 35.207 §6 Set 1 expected values
	// f1: MAC-A = 4A9FFAC354DFAFB3, f2: RES, f3: CK, f4: IK, f5: AK
	want := map[string]string{
		"res":   "a54211d5e3ba50bf",
		"ck":    "b40ba9a3c58b2a05bbf0d987b21bf8cb",
		"ik":    "f769bcd751044604127672711c6d3441",
		"ak":    "aa689c648370",
		"mac_a": "4a9ffac354dfafb3",
	}
	for k, wantV := range want {
		if got := str(m, k); got != wantV {
			t.Errorf("%s: got %s, want %s", k, got, wantV)
		}
	}
}

func TestMilenageRunBadHex(t *testing.T) {
	tool := cryptotools.All()[0]
	invokeErr(t, tool, `{"k":"zzzz","opc":"cd63cb71954a9f4e48a5994e37a02baf","rand":"23553cbe9637a89d218ae64dae47bf35","sqn":"ff9bb4d0b607","amf":"b9b9"}`)
}

func TestMilenageRunWrongLength(t *testing.T) {
	tool := cryptotools.All()[0]
	// k only 8 bytes
	invokeErr(t, tool, `{"k":"465b5ce8b199b49f","opc":"cd63cb71954a9f4e48a5994e37a02baf","rand":"23553cbe9637a89d218ae64dae47bf35","sqn":"ff9bb4d0b607","amf":"b9b9"}`)
}

func TestMilenageRunEmptyInput(t *testing.T) {
	tool := cryptotools.All()[0]
	invokeErr(t, tool, `{"k":"","opc":"cd63cb71954a9f4e48a5994e37a02baf","rand":"23553cbe9637a89d218ae64dae47bf35","sqn":"ff9bb4d0b607","amf":"b9b9"}`)
}

// ---- kdf_compute -----------------------------------------------------------

func TestKDFComputeKSEAF(t *testing.T) {
	// TS 33.501 Annex C §C.1 — derive KSEAF from KAUSF
	tool := findTool(t, "kdf_compute")
	kausf := "15c9d99a2034c0c6d10ecfb494f0ddbbb9bf48da1d4530209508a0304cc9e0e5"
	snName := "35472D6E6D6335352E6D636332313033676770706E6574776F726B2E6F7267"
	// For KSEAF: FC=0x6C, P0=SN name (UTF-8 bytes)
	// We pass the SN name as hex of its UTF-8 encoding
	snBytes := hexEncodeStr("5G:mnc093.mcc208.3gppnetwork.org")
	_ = snName

	m := invoke(t, tool, `{
		"key": "`+kausf+`",
		"fc":  "0x6c",
		"params": [{"value":"`+snBytes+`"}]
	}`)
	got := str(m, "derived_key")
	want := "16596ba9a4a26db2cf12c887acdafa270efa89e2e85ba99c9d4e0288c83d6ce1"
	if got != want {
		t.Errorf("KSEAF: got %s, want %s", got, want)
	}
}

func TestKDFComputeBadFC(t *testing.T) {
	tool := findTool(t, "kdf_compute")
	invokeErr(t, tool, `{"key":"deadbeef","fc":"notabyte","params":[]}`)
}

func TestKDFComputeParamLengthMismatch(t *testing.T) {
	tool := findTool(t, "kdf_compute")
	invokeErr(t, tool, `{"key":"deadbeef","fc":"0x6c","params":[{"value":"aabb","length":3}]}`)
}

// ---- xres_star_compute + res_star_verify -----------------------------------

func TestXResStarRoundTrip(t *testing.T) {
	xresTool := findTool(t, "xres_star_compute")
	verTool := findTool(t, "res_star_verify")

	m := invoke(t, xresTool, `{
		"ck":   "b40ba9a3c58b2a05bbf0d987b21bf8cb",
		"ik":   "f769bcd751044604127672711c6d3441",
		"rand": "23553cbe9637a89d218ae64dae47bf35",
		"xres": "a54211d5e3ba50bf",
		"serving_network_name": "5G:mnc001.mcc001.3gppnetwork.org"
	}`)
	xresStar := str(m, "xres_star")
	if xresStar == "" {
		t.Fatal("xres_star is empty")
	}

	// Verify correct RES*
	mv := invoke(t, verTool, `{"xres_star":"`+xresStar+`","res_star":"`+xresStar+`"}`)
	if mv["verified"] != true {
		t.Errorf("verify: expected true, got %v", mv["verified"])
	}

	// Verify wrong RES* (flip one byte)
	bad := "ff" + xresStar[2:]
	mv2 := invoke(t, verTool, `{"xres_star":"`+xresStar+`","res_star":"`+bad+`"}`)
	if mv2["verified"] != false {
		t.Errorf("verify bad: expected false, got %v", mv2["verified"])
	}
}

// ---- aka_full_run ----------------------------------------------------------

func TestAKAFullRunNonempty(t *testing.T) {
	tool := findTool(t, "aka_full_run")
	m := invoke(t, tool, `{
		"supi":                 "imsi-001010000000001",
		"k":                    "465b5ce8b199b49faa5f0a2ee238a6bc",
		"opc":                  "cd63cb71954a9f4e48a5994e37a02baf",
		"serving_network_name": "5G:mnc001.mcc001.3gppnetwork.org",
		"sqn":                  "ff9bb4d0b607"
	}`)
	for _, key := range []string{"rand", "autn", "xres_star", "hxres_star", "kausf", "kseaf", "kamf"} {
		if str(m, key) == "" {
			t.Errorf("aka_full_run: %s is empty", key)
		}
	}
	// RAND is 32 hex chars (16 bytes)
	if len(str(m, "rand")) != 32 {
		t.Errorf("rand length: want 32, got %d", len(str(m, "rand")))
	}
}

func TestAKAFullRunBadOPc(t *testing.T) {
	tool := findTool(t, "aka_full_run")
	invokeErr(t, tool, `{
		"supi":                 "imsi-001010000000001",
		"k":                    "465b5ce8b199b49faa5f0a2ee238a6bc",
		"opc":                  "zz",
		"serving_network_name": "5G:mnc001.mcc001.3gppnetwork.org",
		"sqn":                  "ff9bb4d0b607"
	}`)
}

func TestAKAFullRunEmptyKey(t *testing.T) {
	tool := findTool(t, "aka_full_run")
	invokeErr(t, tool, `{
		"supi": "imsi-001010000000001",
		"k": "",
		"opc": "cd63cb71954a9f4e48a5994e37a02baf",
		"serving_network_name": "5G:mnc001.mcc001.3gppnetwork.org",
		"sqn": "ff9bb4d0b607"
	}`)
}

// ---- suci_derive -----------------------------------------------------------

func TestSUCIDeriveProfileA(t *testing.T) {
	tool := findTool(t, "suci_derive")
	// Use known dev test public key (X25519)
	pubKey := "61cdb319f72eddfbac55c06c3ec38d15828880a259cbc11cc03ca92abb60fb5e"
	m := invoke(t, tool, `{
		"supi": "imsi-001010000000001",
		"home_network_public_key": "`+pubKey+`",
		"protection_scheme": "ProfileA"
	}`)
	suciStr, _ := m["suci"].(string)
	if suciStr == "" {
		t.Fatal("suci is empty")
	}
	if !startsWith(suciStr, "suci-00101-") {
		t.Errorf("unexpected SUCI prefix: %s", suciStr)
	}
	if str(m, "scheme_output") == "" {
		t.Error("scheme_output is empty")
	}
}

func TestSUCIDeriveBadSUPI(t *testing.T) {
	tool := findTool(t, "suci_derive")
	invokeErr(t, tool, `{"supi":"bad","home_network_public_key":"61cdb319f72eddfbac55c06c3ec38d15828880a259cbc11cc03ca92abb60fb5e","protection_scheme":"ProfileA"}`)
}

// ---- helpers ---------------------------------------------------------------

func findTool(t *testing.T, name string) registry.Tool {
	t.Helper()
	for _, tool := range cryptotools.All() {
		if tool.Name() == name {
			return tool
		}
	}
	t.Fatalf("tool %q not found", name)
	return nil
}

func hexEncodeStr(s string) string {
	b := []byte(s)
	out := make([]byte, len(b)*2)
	const hextable = "0123456789abcdef"
	for i, c := range b {
		out[i*2] = hextable[c>>4]
		out[i*2+1] = hextable[c&0x0f]
	}
	return string(out)
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
