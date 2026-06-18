package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"log/slog"
	"os"

	"github.com/francurieses/claudia-5gc/nf/nssf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/nssf/internal/slice"
)

func newTestServer() *Server {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	allowed := []slice.SliceID{{SST: 1, SD: "000001"}}
	cfg := &config.Config{}
	cfg.SBI.Address = "0.0.0.0:0"
	return &Server{
		cfg:    cfg,
		logger: logger,
		policy: slice.New(allowed),
	}
}

func TestHandleNSSelection_MissingParams(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest("GET", "/nnssf-nsselection/v2/network-slice-information", nil)
	w := httptest.NewRecorder()
	s.handleNSSelection(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleNSSelection_AllAllowedWhenNoRequested(t *testing.T) {
	s := newTestServer()
	q := url.Values{"nf-type": {"AMF"}, "nf-id": {"amf-001"}}
	req := httptest.NewRequest("GET", "/nnssf-nsselection/v2/network-slice-information?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	s.handleNSSelection(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		AllowedNssaiList []struct {
			AllowedSnssaiList []struct {
				SST int    `json:"sst"`
				SD  string `json:"sd,omitempty"`
			} `json:"allowedSnssaiList"`
		} `json:"allowedNssaiList"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.AllowedNssaiList) == 0 || len(resp.AllowedNssaiList[0].AllowedSnssaiList) != 1 {
		t.Fatalf("expected 1 allowed slice, got %+v", resp.AllowedNssaiList)
	}
}

func TestHandleNSSelection_IntersectsRequested(t *testing.T) {
	s := newTestServer()
	// request SST=2 which is not in allowed — expect empty list
	requestedJSON := `[{"sst":2,"sd":"000002"}]`
	q := url.Values{
		"nf-type": {"AMF"},
		"nf-id":   {"amf-001"},
		"slice-info-request-for-registration.requestedNssai": {requestedJSON},
	}
	req := httptest.NewRequest("GET", "/nnssf-nsselection/v2/network-slice-information?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	s.handleNSSelection(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		AllowedNssaiList []struct {
			AllowedSnssaiList []struct {
				SST int `json:"sst"`
			} `json:"allowedSnssaiList"`
		} `json:"allowedNssaiList"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if len(resp.AllowedNssaiList) > 0 && len(resp.AllowedNssaiList[0].AllowedSnssaiList) > 0 {
		t.Fatalf("expected empty allowed list, got %+v", resp)
	}
}

func TestHandleNSSelection_MatchingRequested(t *testing.T) {
	s := newTestServer()
	requestedJSON := `[{"sst":1,"sd":"000001"}]`
	q := url.Values{
		"nf-type": {"AMF"},
		"nf-id":   {"amf-001"},
		"slice-info-request-for-registration.requestedNssai": {requestedJSON},
	}
	req := httptest.NewRequest("GET", "/nnssf-nsselection/v2/network-slice-information?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	s.handleNSSelection(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		AllowedNssaiList []struct {
			AllowedSnssaiList []struct {
				SST int    `json:"sst"`
				SD  string `json:"sd"`
			} `json:"allowedSnssaiList"`
		} `json:"allowedNssaiList"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.AllowedNssaiList) == 0 || len(resp.AllowedNssaiList[0].AllowedSnssaiList) != 1 {
		t.Fatalf("expected 1 slice, got %+v", resp.AllowedNssaiList)
	}
	got := resp.AllowedNssaiList[0].AllowedSnssaiList[0]
	if got.SST != 1 || got.SD != "000001" {
		t.Fatalf("unexpected slice %+v", got)
	}
}
