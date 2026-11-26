package server

import (
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/aka"
)

// TestServingNetworkAuthorization covers the TS 33.501 §6.1.2 allow-list.
func TestServingNetworkAuthorization(t *testing.T) {
	const own = "5G:mnc002.mcc001.3gppnetwork.org"
	const partner = "5G:mnc001.mcc001.3gppnetwork.org"
	const other = "5G:mnc009.mcc999.3gppnetwork.org"
	tests := []struct {
		name     string
		list     []string
		snn      string
		wantCode int
		wantUDM  int
	}{
		{"absent list, foreign SNN unchecked", nil, other, http.StatusCreated, 1},
		{"list, own SNN", []string{partner}, own, http.StatusCreated, 1},
		{"list, listed SNN", []string{partner}, partner, http.StatusCreated, 1},
		{"list, unlisted SNN", []string{partner}, other, http.StatusForbidden, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs := &syncBuf{}
			udm := &recUDM{}
			srv, err := New(Config{NFInstanceID: "11111111-2222-3333-4444-555555555555",
				ServingNetworkName: own, AuthorizedServingNetworks: tc.list},
				udm, aka.NewStore(), slog.New(slog.NewJSONHandler(logs, nil)))
			if err != nil {
				t.Fatal(err)
			}
			e := featureEnv{srv: srv, udm: udm, logs: logs}
			body := `{"supiOrSuci":"suci-0-001-02-0000-0-0-0000000001","servingNetworkName":"` + tc.snn + `"}`
			resp, raw := e.post(t, body)
			if resp.StatusCode != tc.wantCode {
				t.Fatalf("status %d, want %d: %s", resp.StatusCode, tc.wantCode, raw)
			}
			if udm.calls != tc.wantUDM {
				t.Errorf("udm calls %d, want %d", udm.calls, tc.wantUDM)
			}
			if tc.wantCode == http.StatusForbidden {
				if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
					t.Errorf("content-type %q", ct)
				}
				if !strings.Contains(string(raw), `"cause":"SERVING_NETWORK_NOT_AUTHORIZED"`) {
					t.Errorf("body %s", raw)
				}
				if !strings.Contains(string(logs.bytes()), `"result":"REJECT"`) {
					t.Errorf("no REJECT log: %s", string(logs.bytes()))
				}
			}
		})
	}
}
