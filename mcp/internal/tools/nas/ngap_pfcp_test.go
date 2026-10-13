package nas

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"
)

// ngSetupRequestHex is an NG Setup procedure (code 21) from free5gc/ngap's own
// decoder test vector (Apache-2.0). It is a real encoded PDU: the leading 0x20 is
// a successful outcome, so the message is the NGSetupResponse.
const ngSetupRequestHex = "20150039000004000100060180616d663100600017004002f839cafe00060031302e3130302e3230302e313900" +
	"564001ff005000080002f83900000008"

func TestNGAPDecodeNGSetupRequest(t *testing.T) {
	out, err := ngapDecodeTool{}.Invoke(context.Background(), json.RawMessage(`{"hex":"`+ngSetupRequestHex+`"}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	m := out.(map[string]any)
	if m["pdu_type"] != "successfulOutcome" {
		t.Errorf("pdu_type: %v, want successfulOutcome", m["pdu_type"])
	}
	if m["procedure_code"] != int64(21) {
		t.Errorf("procedure_code: %v, want 21 (NGSetup)", m["procedure_code"])
	}
	if m["message"] != "NGSetupResponse" {
		t.Errorf("message: %v", m["message"])
	}
	ies := m["ies"].([]map[string]any)
	if len(ies) < 2 {
		t.Fatalf("expected several IEs, got %d", len(ies))
	}
	// Wire order is preserved: the first IE of the vector is AMF-Name (1).
	if ies[0]["id"] != int64(1) || ies[0]["name"] != "AMF-Name" {
		t.Errorf("first IE: %+v, want AMF-Name in wire order", ies[0])
	}
}

func TestNGAPDecodeAcceptsSpacedHex(t *testing.T) {
	spaced := strings.Join(strings.Split(ngSetupRequestHex, ""), " ")
	if _, err := (ngapDecodeTool{}).Invoke(context.Background(), json.RawMessage(`{"hex":"`+spaced+`"}`)); err != nil {
		t.Errorf("spaced hex: %v", err)
	}
}

func TestNGAPDecodeRejectsGarbageWithoutPanic(t *testing.T) {
	for _, h := range []string{"00", "ff00ff00", "2015"} {
		_, err := (ngapDecodeTool{}).Invoke(context.Background(), json.RawMessage(`{"hex":"`+h+`"}`))
		if err == nil {
			t.Errorf("%s: want a structured error", h)
		}
	}
}

func TestNGAPDecodeRejectsBadHex(t *testing.T) {
	if _, err := (ngapDecodeTool{}).Invoke(context.Background(), json.RawMessage(`{"hex":"zz"}`)); err == nil {
		t.Error("non-hex input must be rejected")
	}
}

// FuzzNGAPDecode checks that no byte string makes the decoder panic.
func FuzzNGAPDecode(f *testing.F) {
	f.Add(ngSetupRequestHex)
	f.Fuzz(func(t *testing.T, h string) {
		_, _ = (ngapDecodeTool{}).Invoke(context.Background(), json.RawMessage(`{"hex":"`+h+`"}`))
	})
}

func TestPFCPDecodeSessionEstablishmentRequest(t *testing.T) {
	msg := pfcpmsg.NewSessionEstablishmentRequest(0, 0, 0x1122334455667788, 42, 0,
		pfcpie.NewCreatePDR(pfcpie.NewPDRID(1), pfcpie.NewPrecedence(100)))
	raw, err := msg.Marshal()
	if err != nil {
		t.Fatalf("build fixture: %v", err)
	}
	out, err := pfcpDecodeTool{}.Invoke(context.Background(), json.RawMessage(
		`{"hex":"`+hexOf(raw)+`"}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	m := out.(map[string]any)
	if m["message_type_name"] != "Session Establishment Request" {
		t.Errorf("message_type_name: %v", m["message_type_name"])
	}
	if m["seid"] != uint64(0x1122334455667788) || m["sequence"] != uint32(42) {
		t.Errorf("header: seid=%v seq=%v", m["seid"], m["sequence"])
	}
	ies := m["ies"].([]ieNode)
	if len(ies) != 1 || ies[0].Type != pfcpie.CreatePDR || ies[0].Name != "CreatePDR" {
		t.Fatalf("IE tree: %+v, want one CreatePDR", ies)
	}
	if len(ies[0].Children) != 2 {
		t.Errorf("CreatePDR children: %+v, want PDR ID and Precedence", ies[0].Children)
	}
}

func TestPFCPDecodeRejectsGarbage(t *testing.T) {
	if _, err := (pfcpDecodeTool{}).Invoke(context.Background(), json.RawMessage(`{"hex":"2001"}`)); err == nil {
		t.Error("truncated PFCP must be an error")
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
