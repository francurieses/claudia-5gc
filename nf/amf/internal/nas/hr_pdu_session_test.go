package nasmsg

// hr_pdu_session_test.go - ROAM-002 AMF side of the home-routed PDU session:
// the HR descriptor handed to the SMF sender (hSmfUri, hplmnSnssai, full DNN),
// the HSMFURI stored on the PDU session, and the home_routing_unconfigured
// reject (fail closed). Ref: TS 23.502 §4.3.2.2.2 step 3a; TS 29.502 Table 6.1.6.2.2-1.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/roaming"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// hrSender records the home-routing descriptor in the CallSMF context.
type hrSender struct {
	recSender
	calls  int
	hr     roaming.HomeRouting
	hasHR  bool
	dnn    string
	snssai amfctx.SNSSAISubscribed
}

func (s *hrSender) CallSMF(ctx context.Context, _ string, dnn string, _ uint8, _ []byte, sn amfctx.SNSSAISubscribed) (string, []byte, []byte, features.Set, error) {
	s.calls++
	s.hr, s.hasHR = roaming.HomeRoutingFrom(ctx)
	s.dnn, s.snssai = dnn, sn
	return "sm-ref-5", []byte{0x01}, []byte{0x02}, features.Set{}, nil
}

func establishWithRoute(t *testing.T, route *roaming.Route) (*hrSender, *amfctx.UEContext, []map[string]any) {
	t.Helper()
	s, ue, raw := establishWithRouteRaw(t, route)
	var logs []map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		var m map[string]any
		if err := dec.Decode(&m); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("log decode: %v", err)
		}
		logs = append(logs, m)
	}
	return s, ue, logs
}

// establishWithRouteRaw returns the raw JSON log bytes (duplicate keys visible).
func establishWithRouteRaw(t *testing.T, route *roaming.Route) (*hrSender, *amfctx.UEContext, []byte) {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
	reg := procedures.NewRegistrationHandler(mgr, nil, nil, nil, "test-amf", "001", "01", logger)
	s := &hrSender{}
	h := NewHandler(s, reg, logger)
	ue := newTestUE(t)
	ue.SetHomeRoute(route)
	psi := uint8(5)
	payload := []byte{0x2E, psi, 0x01, byte(nas.MsgTypePDUSessionEstablishmentRequest), 0xFF, 0xFF}
	msg := &nas.Message{Body: &nas.ULNASTransport{
		PayloadContainerType: nas.PayloadContainerTypeN1SM,
		PayloadContainer:     payload,
		PDUSessionID:         &psi,
	}}
	if err := h.handleULNASTransport(context.Background(), ue, msg); err != nil {
		t.Fatalf("handleULNASTransport: %v", err)
	}
	return s, ue, buf.Bytes()
}

func findLog(logs []map[string]any, event string) map[string]any {
	for _, m := range logs {
		if m["event"] == event {
			return m
		}
	}
	return nil
}

func TestPDUSessionEstablishment_HomeRouting(t *testing.T) {
	home := roaming.PLMN{MCC: "001", MNC: "02"}

	t.Run("roaming UE with smf_api_root gets the HR descriptor", func(t *testing.T) {
		route := &roaming.Route{HomePLMN: home, SMFAPIRoot: "https://smf.h.example:8004"}
		s, ue, _ := establishWithRoute(t, route)
		if !s.hasHR {
			t.Fatal("no HR descriptor reached the SMF sender")
		}
		if want := "https://smf.h.example:8004/nsmf-pdusession/v1"; s.hr.HSMFURI != want {
			t.Errorf("hSmfUri = %q, want %q", s.hr.HSMFURI, want)
		}
		if want := roaming.FullDNN(s.dnn, home); s.hr.FullDNN != want || s.hr.FullDNN == s.dnn {
			t.Errorf("full DNN = %q, want %q", s.hr.FullDNN, want)
		}
		if s.hr.HPLMNSST != s.snssai.SST || s.hr.HPLMNSD != s.snssai.SD {
			t.Errorf("hplmnSnssai = %d/%q, want identity %d/%q", s.hr.HPLMNSST, s.hr.HPLMNSD, s.snssai.SST, s.snssai.SD)
		}
		ue.Lock()
		ps := ue.PDUSessions[5]
		ue.Unlock()
		if ps == nil || ps.HSMFURI != s.hr.HSMFURI {
			t.Fatalf("PDUSession.HSMFURI not stored: %+v", ps)
		}
	})

	t.Run("roaming UE without smf_api_root is rejected with 5GMM cause #90", func(t *testing.T) {
		s, ue, logs := establishWithRoute(t, &roaming.Route{HomePLMN: home})
		if s.calls != 0 || s.hasHR {
			t.Errorf("CreateSMContext called (%d) although the partner has no smf_api_root", s.calls)
		}
		ue.Lock()
		ps := ue.PDUSessions[5]
		ue.Unlock()
		if ps != nil {
			t.Fatalf("no session may be stored, got %+v", ps)
		}
		msgs := s.msgs(t, ue)
		if len(msgs) != 1 || msgs[0].typ != nas.MsgTypeDLNASTransport {
			t.Fatalf("want exactly one DL NAS TRANSPORT, got %+v", msgs)
		}
		body := msgs[0].body
		if len(body) < 2 || !bytes.HasSuffix(body, []byte{0x58, uint8(nas.CausePayloadNotForwarded)}) {
			t.Errorf("5GMM cause #90 missing: % x", body)
		}
		if !bytes.Contains(body, []byte{0x2E, 5, 0x01, byte(nas.MsgTypePDUSessionEstablishmentRequest)}) {
			t.Errorf("payload container not echoed: % x", body)
		}
		w := findLog(logs, "home_routing_unconfigured")
		if w == nil {
			t.Fatal("home_routing_unconfigured log missing")
		}
		if w["level"] != "WARN" || w["supi"] != "imsi-001010000000001" || w["result"] != "REJECT" ||
			w["cause"] != float64(nas.CausePayloadNotForwarded) || w["spec_ref"] == nil {
			t.Errorf("log fields: %v", w)
		}
	})

	t.Run("non-roaming UE gets no HR descriptor", func(t *testing.T) {
		s, ue, logs := establishWithRoute(t, nil)
		if s.hasHR {
			t.Error("HR descriptor sent for a non-roaming UE")
		}
		if findLog(logs, "home_routing_unconfigured") != nil {
			t.Error("unexpected home_routing_unconfigured WARN")
		}
		ue.Lock()
		ps := ue.PDUSessions[5]
		ue.Unlock()
		if ps == nil || ps.HSMFURI != "" {
			t.Fatalf("local session expected, got %+v", ps)
		}
	})
}

// TestHomeRouting_LogKeysUnique: no ROAM-002 log line repeats a JSON key
// (slog does not de-duplicate); the H-SMF line is interface Nsmf / OUT.
func TestHomeRouting_LogKeysUnique(t *testing.T) {
	home := roaming.PLMN{MCC: "001", MNC: "02"}
	for name, route := range map[string]*roaming.Route{
		"routed":       {HomePLMN: home, SMFAPIRoot: "https://smf.h.example:8004"},
		"unconfigured": {HomePLMN: home},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, raw := establishWithRouteRaw(t, route)
			seenHR := false
			for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
				dec := json.NewDecoder(bytes.NewReader(line))
				if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
					t.Fatalf("not a JSON object: %s", line)
				}
				keys := map[string]int{}
				vals := map[string]any{}
				for dec.More() {
					kt, _ := dec.Token()
					var v any
					if err := dec.Decode(&v); err != nil {
						t.Fatalf("decode %s: %v", line, err)
					}
					k := kt.(string)
					keys[k]++
					vals[k] = v
				}
				for k, n := range keys {
					if n != 1 {
						t.Errorf("key %q appears %d times: %s", k, n, line)
					}
				}
				if vals["msg"] == "home-routed PDU session: V-SMF + H-SMF" {
					seenHR = true
					if vals["interface"] != "Nsmf" || vals["direction"] != "OUT" {
						t.Errorf("HR line interface/direction = %v/%v", vals["interface"], vals["direction"])
					}
				}
			}
			if name == "routed" && !seenHR {
				t.Error("HR log line missing")
			}
		})
	}
}
