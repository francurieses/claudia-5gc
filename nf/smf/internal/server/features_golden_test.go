package server

// features_golden_test.go - byte-identity goldens for the SMF's SBI wire
// output (REL19-2.7). They were captured BEFORE the supportedFeatures change
// and must keep passing unchanged under the rel17 / no-profile configuration
// (decisions D1/D2, dev/REL19_PROGRAM.md section 2).

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
)

// goldenSMContextRef is the placeholder substituted for the (random UUID)
// smContextRef in the golden bodies. It is the ONLY normalized value.
const goldenSMContextRef = "<SMCONTEXTREF>"

var uuidRE = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// readGolden returns testdata/<name> verbatim.
func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return b
}

// newGoldenServer builds a deterministic SMF server (one "internet" pool, no
// peers) with the given options applied before use.
func newGoldenServer(t *testing.T, opts ...func(*Server)) *Server {
	t.Helper()
	cfg := &config.Config{
		UEIPPool:  "10.60.0.0/24",
		UPFN3Addr: "192.0.2.10",
		DNNs:      []config.DNNConfig{{Name: "internet", UEIPPool: "10.60.0.0/24"}},
	}
	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// postCreateSMContext drives handleCreateSMContext with a fixed request plus
// the extra top-level attributes in extra, returning the recorder.
func postCreateSMContext(t *testing.T, s *Server, extra map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	req := map[string]any{
		"supi":         "imsi-001010000000001",
		"dnn":          "internet",
		"pduSessionId": float64(1),
		"n1SmMsg":      base64.StdEncoding.EncodeToString(buildEstablishmentRequest(1, 5)),
		"snssai":       map[string]any{"sst": float64(1), "sd": "000001"},
	}
	for k, v := range extra {
		req[k] = v
	}
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/sm-contexts", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	w := httptest.NewRecorder()
	s.handleCreateSMContext(w, r)
	return w
}

// TestGolden_CreateSMContext201 pins the 201 SmContextCreatedData body for a
// request without supportedFeatures. Only smContextRef (random UUID) is
// normalized; everything else (n1SmMsg, n2SmInfo, n2SmInfoType) compares
// byte-for-byte.
func TestGolden_CreateSMContext201(t *testing.T) {
	s := newGoldenServer(t)
	w := postCreateSMContext(t, s, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	got := uuidRE.ReplaceAllString(w.Body.String(), goldenSMContextRef)
	if want := string(readGolden(t, "golden_create_sm_context_201.json")); got != want {
		t.Fatalf("201 body changed\n got: %q\nwant: %q", got, want)
	}
}

// amfCapture starts a TLS server standing in for the AMF namf-comm endpoint and
// returns it with a channel receiving each request body. The answer is the
// JSON in rsp (cause only by default).
func amfCapture(t *testing.T, rsp string) (*httptest.Server, <-chan []byte) {
	t.Helper()
	ch := make(chan []byte, 4)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- b
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, rsp)
	}))
	t.Cleanup(ts.Close)
	return ts, ch
}

// pointAtAMF wires s to talk to the fake AMF.
func pointAtAMF(s *Server, ts *httptest.Server) {
	s.cfg.Peers.AMF = strings.TrimPrefix(ts.URL, "https://")
	s.httpClient = ts.Client()
}

// TestGolden_N1N2PagingBody pins the N1N2MessageTransfer request body of the
// DL-data-notification path (paging.go).
func TestGolden_N1N2PagingBody(t *testing.T) {
	ts, ch := amfCapture(t, `{"cause":"ATTEMPTING_TO_REACH_UE"}`)
	s := newGoldenServer(t)
	pointAtAMF(s, ts)
	cause, err := s.triggerN1N2MessageTransfer(context.Background(), "imsi-001010000000001", 1)
	if err != nil || cause != "ATTEMPTING_TO_REACH_UE" {
		t.Fatalf("cause=%q err=%v", cause, err)
	}
	got := string(<-ch)
	if want := string(readGolden(t, "golden_n1n2_paging_body.json")); got != want {
		t.Fatalf("paging body changed\n got: %q\nwant: %q", got, want)
	}
}

// TestGolden_N1N2PushBody pins the N1N2MessageTransfer request body of the
// secondary-authentication push (secondary_auth.go pushN1N2Message).
func TestGolden_N1N2PushBody(t *testing.T) {
	ts, ch := amfCapture(t, `{"cause":"N1_N2_TRANSFER_INITIATED"}`)
	s := newGoldenServer(t)
	pointAtAMF(s, ts)
	_, err := s.pushN1N2Message(context.Background(), "imsi-001010000000001", 1,
		[]byte{0x2e, 0x01, 0x05, 0xc5}, []byte{0x01, 0x02}, "PDU_RES_SETUP_REQ")
	if err != nil {
		t.Fatal(err)
	}
	got := string(<-ch)
	if want := string(readGolden(t, "golden_n1n2_push_body.json")); got != want {
		t.Fatalf("push body changed\n got: %q\nwant: %q", got, want)
	}
}

// TestGolden_NFProfile pins the NFProfile JSON the SMF sends in NFRegister.
func TestGolden_NFProfile(t *testing.T) {
	cfg := &config.Config{
		NFInstanceID: "11111111-2222-3333-4444-555555555555",
		SNSSAIs: []struct {
			SST int    `yaml:"sst"`
			SD  string `yaml:"sd"`
		}{{SST: 1, SD: "000001"}, {SST: 2, SD: "000002"}},
		DNNs: []config.DNNConfig{{Name: "internet"}, {Name: "ims"}},
	}
	got, err := json.Marshal(BuildNFProfile(cfg, nil))
	if err != nil {
		t.Fatal(err)
	}
	if want := string(readGolden(t, "golden_nf_profile.json")); string(got) != want {
		t.Fatalf("NF profile changed\n got: %s\nwant: %s", got, want)
	}
}
