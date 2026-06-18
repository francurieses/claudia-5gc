// Package crypto implements MCP Group E tools: 5G-AKA cryptographic step helpers
// wrapping shared/crypto. All tools accept hex-encoded inputs, return hex-encoded
// outputs, and never panic on malformed input — every failure is a structured
// *mcperr.Error with diagnostic context.
// References: 3GPP TS 33.501, TS 35.206, TS 35.207, TS 33.220.
package crypto

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	"github.com/francurieses/claudia-5gc/shared/crypto/kdf"
	"github.com/francurieses/claudia-5gc/shared/crypto/milenage"
	"github.com/francurieses/claudia-5gc/shared/crypto/suci"
)

// All returns the six Group E tools ready for registration.
func All() []registry.Tool {
	return []registry.Tool{
		milenageRunTool{},
		suciDeriveTool{},
		xresStarComputeTool{},
		resStarVerifyTool{},
		kdfComputeTool{},
		akaFullRunTool{},
	}
}

// ---- helpers ---------------------------------------------------------------

func schema(s string) json.RawMessage { return json.RawMessage(s) }

func parseHex16(s, field string) ([16]byte, *mcperr.Error) {
	b, err := hexDecode(s)
	if err != nil {
		return [16]byte{}, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"field": field, "input": s}, "%s: %v", field, err)
	}
	if len(b) != 16 {
		return [16]byte{}, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"field": field, "length": len(b)}, "%s must be 16 bytes (32 hex chars), got %d", field, len(b))
	}
	return [16]byte(b), nil
}

func parseHex6(s, field string) ([6]byte, *mcperr.Error) {
	b, err := hexDecode(s)
	if err != nil {
		return [6]byte{}, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"field": field}, "%s: %v", field, err)
	}
	if len(b) != 6 {
		return [6]byte{}, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"field": field, "length": len(b)}, "%s must be 6 bytes (12 hex chars), got %d", field, len(b))
	}
	return [6]byte(b), nil
}

func parseHex2(s, field string) ([2]byte, *mcperr.Error) {
	b, err := hexDecode(s)
	if err != nil {
		return [2]byte{}, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"field": field}, "%s: %v", field, err)
	}
	if len(b) != 2 {
		return [2]byte{}, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"field": field, "length": len(b)}, "%s must be 2 bytes (4 hex chars), got %d", field, len(b))
	}
	return [2]byte(b), nil
}

func parseHexVar(s, field string) ([]byte, *mcperr.Error) {
	if s == "" {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"field": field}, "%s is required", field)
	}
	b, err := hexDecode(s)
	if err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"field": field}, "%s: %v", field, err)
	}
	return b, nil
}

func hexDecode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	s = strings.NewReplacer(" ", "", ":", "", "-", "").Replace(s)
	if s == "" {
		return nil, fmt.Errorf("empty hex input")
	}
	return hex.DecodeString(s)
}

func h(b []byte) string { return hex.EncodeToString(b) }

// parseSUPI splits "imsi-{mcc}{mnc}{msin}" into (mcc, mnc, msin).
// MCC is always 3 digits. MNC is assumed 2 digits (standard for most operators).
func parseSUPI(s string) (mcc, mnc, msin string, err error) {
	if !strings.HasPrefix(s, "imsi-") {
		return "", "", "", fmt.Errorf("SUPI must start with 'imsi-', got %q", s)
	}
	digits := strings.TrimPrefix(s, "imsi-")
	if len(digits) < 6 {
		return "", "", "", fmt.Errorf("SUPI digits too short: %q", digits)
	}
	return digits[:3], digits[3:5], digits[5:], nil
}

func logInvoke(ctx context.Context, toolName string, start time.Time, err error) {
	attrs := []any{
		"tool_name", toolName,
		"latency_ms", time.Since(start).Milliseconds(),
	}
	if err != nil {
		attrs = append(attrs, "error", err.Error())
		slog.InfoContext(ctx, "tool invoked", attrs...)
		return
	}
	slog.InfoContext(ctx, "tool invoked", attrs...)
}

// ---- milenage_run ----------------------------------------------------------

type milenageRunTool struct{}

func (milenageRunTool) Name() string { return "milenage_run" }
func (milenageRunTool) Description() string {
	return "Compute the Milenage AKA functions (f1–f5) for a given subscriber key, " +
		"OPc, RAND, SQN, and AMF. Returns XRES, CK, IK, AK, and MAC-A. " +
		"All values are hex-encoded. Spec: 3GPP TS 35.206 §4; test vectors: TS 35.207 Set 1."
}
func (milenageRunTool) InputSchema() json.RawMessage {
	return schema(`{
"type":"object",
"properties":{
  "k":   {"type":"string","description":"128-bit subscriber key K (32 hex chars)"},
  "opc": {"type":"string","description":"128-bit OPc (32 hex chars). Derive from OP with ComputeOPc."},
  "rand":{"type":"string","description":"128-bit random challenge (32 hex chars)"},
  "sqn": {"type":"string","description":"48-bit sequence number (12 hex chars)"},
  "amf": {"type":"string","description":"16-bit AMF field (4 hex chars)"}
},
"required":["k","opc","rand","sqn","amf"]}`)
}
func (milenageRunTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"res":{},"ck":{},"ik":{},"ak":{},"mac_a":{},"autn":{}}}`)
}
func (t milenageRunTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		K    string `json:"k"`
		OPc  string `json:"opc"`
		RAND string `json:"rand"`
		SQN  string `json:"sqn"`
		AMF  string `json:"amf"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "milenage_run args: %v", err)
	}
	k, merr := parseHex16(a.K, "k")
	if merr != nil {
		return nil, merr
	}
	opc, merr := parseHex16(a.OPc, "opc")
	if merr != nil {
		return nil, merr
	}
	randBytes, merr := parseHex16(a.RAND, "rand")
	if merr != nil {
		return nil, merr
	}
	sqn, merr := parseHex6(a.SQN, "sqn")
	if merr != nil {
		return nil, merr
	}
	amf, merr := parseHex2(a.AMF, "amf")
	if merr != nil {
		return nil, merr
	}

	av, ak, err := milenage.GenerateAV(k, opc, randBytes, sqn, amf)
	logInvoke(ctx, t.Name(), start, err)
	if err != nil {
		return nil, mcperr.Newf(mcperr.CodeInternal, map[string]any{"op": "GenerateAV"}, "milenage: %v", err)
	}

	return map[string]any{
		"res":   h(av.XRES[:]),
		"ck":    h(av.CK[:]),
		"ik":    h(av.IK[:]),
		"ak":    h(ak[:]),
		"mac_a": h(av.AUTN[8:16]),
		"autn":  h(av.AUTN[:]),
	}, nil
}

// ---- suci_derive -----------------------------------------------------------

type suciDeriveTool struct{}

func (suciDeriveTool) Name() string { return "suci_derive" }
func (suciDeriveTool) Description() string {
	return "Derive a SUCI (Subscription Concealed Identifier) from a SUPI using ECIES. " +
		"Profile A uses X25519 + AES-128-CTR + HMAC-SHA-256. " +
		"SUPI format: 'imsi-{mcc}{mnc}{msin}' (e.g. 'imsi-001010000000001'). " +
		"Spec: 3GPP TS 33.501 §C.3 (Profile A), §C.4 (Profile B); TS 23.003 §2.7B."
}
func (suciDeriveTool) InputSchema() json.RawMessage {
	return schema(`{
"type":"object",
"properties":{
  "supi":                    {"type":"string","description":"e.g. 'imsi-001010000000001'"},
  "home_network_public_key": {"type":"string","description":"32-byte X25519 public key (64 hex chars) for Profile A"},
  "protection_scheme":       {"type":"string","enum":["ProfileA","ProfileB"],"description":"ECIES profile"},
  "key_id":                  {"type":"integer","description":"HomeNetworkPublicKeyIdentifier (0-255, default 1)"}
},
"required":["supi","home_network_public_key","protection_scheme"]}`)
}
func (suciDeriveTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"suci":{"type":"string"},"scheme_output":{"type":"string"}}}`)
}
func (t suciDeriveTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		SUPI                  string `json:"supi"`
		HomeNetworkPublicKey  string `json:"home_network_public_key"`
		ProtectionScheme      string `json:"protection_scheme"`
		KeyID                 *int   `json:"key_id"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "suci_derive args: %v", err)
	}

	mcc, mnc, msin, err := parseSUPI(a.SUPI)
	if err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"supi": a.SUPI}, "%v", err)
	}

	keyID := byte(1)
	if a.KeyID != nil {
		if *a.KeyID < 0 || *a.KeyID > 255 {
			return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "key_id out of range: %d", *a.KeyID)
		}
		keyID = byte(*a.KeyID)
	}

	switch a.ProtectionScheme {
	case "ProfileA":
		pkBytes, merr := parseHexVar(a.HomeNetworkPublicKey, "home_network_public_key")
		if merr != nil {
			return nil, merr
		}
		if len(pkBytes) != 32 {
			return nil, mcperr.Newf(mcperr.CodeInvalidParams,
				map[string]any{"length": len(pkBytes)},
				"Profile A public key must be 32 bytes (64 hex chars)")
		}
		var pubKey [32]byte
		copy(pubKey[:], pkBytes)

		s, err := suci.EncryptProfileA(msin, pubKey, keyID)
		logInvoke(ctx, t.Name(), start, err)
		if err != nil {
			return nil, mcperr.Newf(mcperr.CodeInternal, nil, "suci EncryptProfileA: %v", err)
		}
		s.SUPIFormat = 0
		s.MCC = mcc
		s.MNC = mnc
		s.RoutingIndicator = "0000"

		suciStr := fmt.Sprintf("suci-%s%s-%s-0-%d-%s",
			mcc, mnc,
			s.RoutingIndicator,
			int(s.ProtectionScheme),
			hex.EncodeToString(s.SchemeOutput),
		)
		return map[string]any{
			"suci":          suciStr,
			"scheme_output": hex.EncodeToString(s.SchemeOutput),
		}, nil

	case "ProfileB":
		logInvoke(ctx, t.Name(), start, fmt.Errorf("ProfileB not implemented"))
		return nil, mcperr.New(mcperr.CodeInternal, "Profile B (secp256r1) encryption not yet implemented on server side", nil)

	default:
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "protection_scheme must be ProfileA or ProfileB, got %q", a.ProtectionScheme)
	}
}

// ---- xres_star_compute -----------------------------------------------------

type xresStarComputeTool struct{}

func (xresStarComputeTool) Name() string { return "xres_star_compute" }
func (xresStarComputeTool) Description() string {
	return "Compute XRES* and HXRES* from CK, IK, RAND, XRES, and Serving Network Name. " +
		"XRES* is stored in the AUSF; HXRES* is compared against RES* from the UE. " +
		"Spec: 3GPP TS 33.501 §A.4 (XRES*), §A.5 (HXRES*)."
}
func (xresStarComputeTool) InputSchema() json.RawMessage {
	return schema(`{
"type":"object",
"properties":{
  "ck":                   {"type":"string","description":"CK from Milenage f3 (32 hex chars)"},
  "ik":                   {"type":"string","description":"IK from Milenage f4 (32 hex chars)"},
  "rand":                 {"type":"string","description":"RAND from auth vector (32 hex chars)"},
  "xres":                 {"type":"string","description":"XRES from Milenage f2 (16 hex chars)"},
  "serving_network_name": {"type":"string","description":"e.g. '5G:mnc093.mcc208.3gppnetwork.org'"}
},
"required":["ck","ik","rand","xres","serving_network_name"]}`)
}
func (xresStarComputeTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"xres_star":{"type":"string"},"hxres_star":{"type":"string"}}}`)
}
func (t xresStarComputeTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		CK                 string `json:"ck"`
		IK                 string `json:"ik"`
		RAND               string `json:"rand"`
		XRES               string `json:"xres"`
		ServingNetworkName string `json:"serving_network_name"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "xres_star_compute args: %v", err)
	}
	ck, merr := parseHex16(a.CK, "ck")
	if merr != nil {
		return nil, merr
	}
	ik, merr := parseHex16(a.IK, "ik")
	if merr != nil {
		return nil, merr
	}
	randBytes, merr := parseHex16(a.RAND, "rand")
	if merr != nil {
		return nil, merr
	}
	xresBytes, merr := parseHexVar(a.XRES, "xres")
	if merr != nil {
		return nil, merr
	}
	if a.ServingNetworkName == "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "serving_network_name is required", nil)
	}

	xresStar := kdf.XRESStar(ck, ik, a.ServingNetworkName, randBytes, xresBytes)
	hxresStar := kdf.HRESStar(randBytes, xresStar)
	logInvoke(ctx, t.Name(), start, nil)
	return map[string]any{
		"xres_star":  h(xresStar),
		"hxres_star": h(hxresStar),
	}, nil
}

// ---- res_star_verify -------------------------------------------------------

type resStarVerifyTool struct{}

func (resStarVerifyTool) Name() string { return "res_star_verify" }
func (resStarVerifyTool) Description() string {
	return "Compare RES* received from the UE against the stored XRES*. Returns verified: true " +
		"on match, false with mismatch_detail on failure. Uses constant-time comparison. " +
		"Spec: 3GPP TS 33.501 §6.1.3.2 step 8."
}
func (resStarVerifyTool) InputSchema() json.RawMessage {
	return schema(`{
"type":"object",
"properties":{
  "xres_star":{"type":"string","description":"Expected RES* stored in AUSF (hex)"},
  "res_star": {"type":"string","description":"RES* received from UE in AuthenticationResponse (hex)"}
},
"required":["xres_star","res_star"]}`)
}
func (resStarVerifyTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"verified":{"type":"boolean"},"mismatch_detail":{}}}`)
}
func (t resStarVerifyTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		XRESStar string `json:"xres_star"`
		RESStar  string `json:"res_star"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "res_star_verify args: %v", err)
	}
	xres, merr := parseHexVar(a.XRESStar, "xres_star")
	if merr != nil {
		return nil, merr
	}
	res, merr := parseHexVar(a.RESStar, "res_star")
	if merr != nil {
		return nil, merr
	}
	logInvoke(ctx, t.Name(), start, nil)
	if len(xres) != len(res) {
		return map[string]any{
			"verified":        false,
			"mismatch_detail": fmt.Sprintf("length mismatch: xres_star %d bytes, res_star %d bytes", len(xres), len(res)),
		}, nil
	}
	// constant-time compare
	diff := byte(0)
	for i := range xres {
		diff |= xres[i] ^ res[i]
	}
	if diff != 0 {
		return map[string]any{
			"verified":        false,
			"mismatch_detail": fmt.Sprintf("value mismatch: xres_star=%s res_star=%s", h(xres), h(res)),
		}, nil
	}
	return map[string]any{"verified": true, "mismatch_detail": nil}, nil
}

// ---- kdf_compute -----------------------------------------------------------

type kdfComputeTool struct{}

func (kdfComputeTool) Name() string { return "kdf_compute" }
func (kdfComputeTool) Description() string {
	return "Compute KDF(key, FC || P0 || L0 || ...) = HMAC-SHA-256 per TS 33.220 §B.2. " +
		"FC codes (TS 33.501 Annex A): 0x6A=KAUSF, 0x6B=XRES*, 0x6C=KSEAF, 0x6D=KAMF, " +
		"0x69=KNASint/KNASenc, 0x6E=KgNB, 0x73=KRRCint/KRRCenc/KUPint/KUPenc. " +
		"Each param: {value: hex, length: int (bytes)}. length is validated against value length."
}
func (kdfComputeTool) InputSchema() json.RawMessage {
	return schema(`{
"type":"object",
"properties":{
  "key":    {"type":"string","description":"KDF input key (hex, any length)"},
  "fc":     {"type":"string","description":"Function code byte as hex (e.g. '0x6C') or decimal"},
  "params": {
    "type":"array",
    "items":{
      "type":"object",
      "properties":{
        "value": {"type":"string","description":"Parameter value (hex)"},
        "length":{"type":"integer","description":"Expected byte length (validated against value)"}
      },
      "required":["value"]
    }
  }
},
"required":["key","fc","params"]}`)
}
func (kdfComputeTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"derived_key":{"type":"string"}}}`)
}
func (t kdfComputeTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		Key    string `json:"key"`
		FC     string `json:"fc"`
		Params []struct {
			Value  string `json:"value"`
			Length *int   `json:"length"`
		} `json:"params"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "kdf_compute args: %v", err)
	}

	keyBytes, merr := parseHexVar(a.Key, "key")
	if merr != nil {
		return nil, merr
	}

	// parse FC: accept "0x6C", "6c", or decimal "108"
	fcStr := strings.TrimSpace(a.FC)
	base := 10
	if strings.HasPrefix(fcStr, "0x") || strings.HasPrefix(fcStr, "0X") {
		fcStr = fcStr[2:]
		base = 16
	}
	fcVal, err := strconv.ParseUint(fcStr, base, 8)
	if err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"fc": a.FC}, "fc is not a valid byte: %v", err)
	}
	fc := byte(fcVal)

	params := make([][]byte, 0, len(a.Params))
	for i, p := range a.Params {
		b, merr := parseHexVar(p.Value, fmt.Sprintf("params[%d].value", i))
		if merr != nil {
			return nil, merr
		}
		if p.Length != nil && len(b) != *p.Length {
			return nil, mcperr.Newf(mcperr.CodeInvalidParams,
				map[string]any{"param_index": i, "got": len(b), "expected": *p.Length},
				"params[%d]: value length %d does not match declared length %d", i, len(b), *p.Length)
		}
		params = append(params, b)
	}

	derived := kdf.DeriveRaw(keyBytes, fc, params)
	logInvoke(ctx, t.Name(), start, nil)
	return map[string]any{"derived_key": h(derived)}, nil
}

// ---- aka_full_run ----------------------------------------------------------

type akaFullRunTool struct{}

func (akaFullRunTool) Name() string { return "aka_full_run" }
func (akaFullRunTool) Description() string {
	return "Run the complete 5G-AKA authentication vector generation in one call: Milenage → " +
		"KAUSF → KSEAF → KAMF, deriving all keys needed by the AUSF and AMF. Returns the " +
		"Authentication Request parameters (RAND, AUTN), AUSF-stored values (XRES*, HXRES*), " +
		"and the 5G key hierarchy (KAUSF, KSEAF, KAMF). " +
		"Spec: 3GPP TS 33.501 §6.1.3.2; key hierarchy §A.2, §A.4, §A.5, §A.6, §A.7."
}
func (akaFullRunTool) InputSchema() json.RawMessage {
	return schema(`{
"type":"object",
"properties":{
  "supi":                 {"type":"string","description":"e.g. 'imsi-001010000000001'"},
  "k":                    {"type":"string","description":"128-bit subscriber key K (32 hex chars)"},
  "opc":                  {"type":"string","description":"128-bit OPc (32 hex chars)"},
  "serving_network_name": {"type":"string","description":"e.g. '5G:mnc001.mcc001.3gppnetwork.org'"},
  "sqn":                  {"type":"string","description":"48-bit SQN (12 hex chars)"},
  "amf":                  {"type":"string","description":"16-bit AMF field (4 hex chars), default 8000"}
},
"required":["supi","k","opc","serving_network_name","sqn"]}`)
}
func (akaFullRunTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"rand":{},"autn":{},"xres_star":{},"hxres_star":{},"kausf":{},"kseaf":{},"kamf":{}}}`)
}
func (t akaFullRunTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		SUPI               string `json:"supi"`
		K                  string `json:"k"`
		OPc                string `json:"opc"`
		ServingNetworkName string `json:"serving_network_name"`
		SQN                string `json:"sqn"`
		AMF                string `json:"amf"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "aka_full_run args: %v", err)
	}
	if a.SUPI == "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "supi is required", nil)
	}
	if a.ServingNetworkName == "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "serving_network_name is required", nil)
	}
	k, merr := parseHex16(a.K, "k")
	if merr != nil {
		return nil, merr
	}
	opc, merr := parseHex16(a.OPc, "opc")
	if merr != nil {
		return nil, merr
	}
	sqn, merr := parseHex6(a.SQN, "sqn")
	if merr != nil {
		return nil, merr
	}
	amfField := [2]byte{0x80, 0x00}
	if a.AMF != "" {
		amfField, merr = parseHex2(a.AMF, "amf")
		if merr != nil {
			return nil, merr
		}
	}

	// Generate fresh RAND
	var randBytes [16]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInternal, nil, "rand.Read: %v", err)
	}

	// Step 1: Milenage — XRES, CK, IK, AK, AUTN
	av, ak, err := milenage.GenerateAV(k, opc, randBytes, sqn, amfField)
	if err != nil {
		logInvoke(ctx, t.Name(), start, err)
		return nil, mcperr.Newf(mcperr.CodeInternal, map[string]any{"op": "GenerateAV"}, "milenage: %v", err)
	}

	// Step 2: SQN ⊕ AK (carried in AUTN[0:6], also needed for KAUSF)
	var sqnXorAK [6]byte
	copy(sqnXorAK[:], av.AUTN[0:6])

	// Step 3: Key hierarchy per TS 33.501 §A.2, §A.6, §A.7
	kausf := kdf.KAUSF(av.CK, av.IK, a.ServingNetworkName, sqnXorAK)
	kseaf := kdf.KSEAF(kausf, a.ServingNetworkName)
	kamf := kdf.KAMF(kseaf, a.SUPI, [2]byte{0x00, 0x00}) // ABBA = 0x0000 for initial reg

	// Step 4: XRES* and HXRES*
	xresStar := kdf.XRESStar(av.CK, av.IK, a.ServingNetworkName, randBytes, av.XRES[:])
	hxresStar := kdf.HRESStar(randBytes, xresStar)

	logInvoke(ctx, t.Name(), start, nil)
	slog.InfoContext(ctx, "aka_full_run complete",
		"tool_name", t.Name(),
		"supi", a.SUPI,
		"crypto_operation", "5G-AKA",
		"key_length_bits", 256,
	)
	return map[string]any{
		"rand":       h(randBytes[:]),
		"autn":       h(av.AUTN[:]),
		"xres_star":  h(xresStar),
		"hxres_star": h(hxresStar),
		"kausf":      h(kausf),
		"kseaf":      h(kseaf),
		"kamf":       h(kamf),
		"_ak":        h(ak[:]),
		"_xres":      h(av.XRES[:]),
	}, nil
}
