package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseBitRateKbps(t *testing.T) {
	tests := []struct {
		in   string
		want uint64
		ok   bool
	}{
		{"1500 bps", 2, true},
		{"1000 bps", 1, true},
		{"100000 Kbps", 100000, true},
		{"  5 Mbps ", 5000, true},
		{"2 Gbps", 2000000, true},
		{"1 Tbps", 1000000000, true},
		{"0.1 Gbps", 100000, true},
		{"1.0001 Kbps", 2, true},
		{"1000000000000 Kbps", 1000000000000, true},
		{"1000 Tbps", 1000000000000, true},
		{"1000000000001 Kbps", 0, false},
		{"1001 Tbps", 0, false},
		{"99999999999999999999999 Tbps", 0, false},
		{"100Mbps", 0, false},
		{"10 kbps", 0, false},
		{"1e3 Kbps", 0, false},
		{"0 Kbps", 0, false},
		{"0.0 Gbps", 0, false},
		{"0.0004 Kbps", 1, true},
		{"", 0, false},
	}
	for _, tc := range tests {
		got, err := parseBitRateKbps(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("parseBitRateKbps(%q) = %d, %v; want %d ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
	}
}

func TestGetAMData_SubscribedUeAmbr(t *testing.T) {
	const nssai = `"nssai":{"defaultSingleNssais":[{"sst":1}]}`
	tests := []struct {
		name, body string
		ul, dl     uint64
	}{
		{"provisioned", `{` + nssai + `,"subscribedUeAmbr":{"uplink":"50 Mbps","downlink":"1.5 Gbps"}}`, 50000, 1500000},
		{"absent", `{` + nssai + `}`, 100000, 100000},
		{"null", `{` + nssai + `,"subscribedUeAmbr":null}`, 100000, 100000},
		{"malformed uplink only", `{` + nssai + `,"subscribedUeAmbr":{"uplink":"100Mbps","downlink":"2 Mbps"}}`, 100000, 2000},
		{"non-string downlink", `{` + nssai + `,"subscribedUeAmbr":{"uplink":"2 Mbps","downlink":5}}`, 2000, 100000},
		{"missing downlink", `{` + nssai + `,"subscribedUeAmbr":{"uplink":"2 Mbps"}}`, 2000, 100000},
		{"zero", `{` + nssai + `,"subscribedUeAmbr":{"uplink":"0 Kbps","downlink":"3 Kbps"}}`, 100000, 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := newUDRStub(t, map[string]string{"am": tc.body})
			c := newTestUDRClient(st.address(), st.srv.Client(), nil)
			got, err := c.GetAMData(context.Background(), goldenUDRSupi)
			if err != nil {
				t.Fatalf("GetAMData: %v", err)
			}
			if got.AMBRUplink != tc.ul || got.AMBRDownlink != tc.dl {
				t.Errorf("AMBR = %d/%d, want %d/%d", got.AMBRUplink, got.AMBRDownlink, tc.ul, tc.dl)
			}
		})
	}
}

func TestGetAMData_UDRNon2xx(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"status":404,"cause":"USER_NOT_FOUND"}`)
	}))
	defer srv.Close()
	c := newTestUDRClient(strings.TrimPrefix(srv.URL, "https://"), srv.Client(), nil)
	if got, err := c.GetAMData(context.Background(), goldenUDRSupi); err == nil || got != nil {
		t.Fatalf("GetAMData on UDR 404 = %v, %v; want nil, error", got, err)
	}
}

func TestAmbrDirection_Warn(t *testing.T) {
	tests := []struct {
		name, raw, cause string
		want             uint64
		warn             bool
	}{
		{"null", `null`, "MANDATORY_IE_INCORRECT", defaultUEAMBRKbps, true},
		{"over cap after ceil", `"1000000000000.5 Kbps"`, "MANDATORY_IE_INCORRECT", defaultUEAMBRKbps, true},
		{"long input", `"` + strings.Repeat("9", 100) + ` Kbps"`, "MANDATORY_IE_INCORRECT", defaultUEAMBRKbps, true},
		{"trailing newline trimmed", `"5 Mbps\n"`, "", 5000, false},
		{"missing", ``, "MANDATORY_IE_MISSING", defaultUEAMBRKbps, true},
		{"valid", `"5 Mbps"`, "", 5000, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			l := slog.New(slog.NewJSONHandler(&buf, nil))
			got := ambrDirection(l, "corr-1", "imsi-1", "uplink", json.RawMessage(tc.raw))
			if got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
			if !tc.warn {
				if buf.Len() != 0 {
					t.Fatalf("unexpected log: %s", buf.String())
				}
				return
			}
			var rec map[string]any
			if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
				t.Fatalf("log: %v (%s)", err, buf.String())
			}
			if rec["level"] != "WARN" || rec["cause"] != tc.cause || rec["correlation_id"] != "corr-1" {
				t.Errorf("record = %v", rec)
			}
			if rv, _ := rec["raw_value"].(string); len(rv) > maxLoggedRawBytes {
				t.Errorf("raw_value len %d > %d", len(rv), maxLoggedRawBytes)
			}
		})
	}
}
