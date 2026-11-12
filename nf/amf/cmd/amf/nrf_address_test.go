package main

// nrf_address_test.go - the AMF NRF discovery client must reach the NRF however
// its peer address is spelled, and an SMF discovery that yields no address must
// fail uncached and be logged by cause (Debug for a 200 answer without address,
// Warn for an NRF fault). Regression for the "https://https://" URL:
// main.go handed the client a base URL ("https://nrf:8000") where it expects
// host:port and prepends "https://" itself, so the request host was "https" and
// every SMF selection (once per PDU Session Establishment) stalled on a DNS
// lookup before CallSMF silently fell back to the static SMF peer. The rel17
// request bytes are pinned by golden_nrf_test.go and are not repeated here.
// Ref: TS 29.510 §5.3.2.2 (Nnrf_NFDiscovery); TS 23.501 §6.3.2.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/logging"
)

// nrfAddrCallTimeout bounds every discovery call in this file, so a regression
// to the unresolvable host "https" fails the test within seconds instead of
// waiting for the resolver (8 s in the AMF container). Test-only value, not a
// 3GPP timer.
const nrfAddrCallTimeout = 5 * time.Second

// TestNRFClientAddressForms: every spelling of the NRF address ends in a
// request that reaches the NRF and is answered. "https://host:port" is the form
// main.go used to pass (nrfBase).
func TestNRFClientAddressForms(t *testing.T) {
	sl := []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}}
	forms := []struct {
		name  string
		spell func(hostPort string) string
	}{
		{"host:port", func(hp string) string { return hp }},
		{"https://host:port", func(hp string) string { return "https://" + hp }},
		{"https://host:port/", func(hp string) string { return "https://" + hp + "/" }},
		{"http://host:port", func(hp string) string { return "http://" + hp }},
	}
	for _, tc := range forms {
		t.Run(tc.name, func(t *testing.T) {
			s := newNRFStub(t, http.StatusOK, nrfGoldenAnswer)
			c := NewHTTPNRFClient(tc.spell(s.addr), s.hc)
			if c.address != s.addr {
				t.Errorf("address = %q, want %q", c.address, s.addr)
			}
			ctx, cancel := context.WithTimeout(t.Context(), nrfAddrCallTimeout)
			defer cancel()
			eps, err := c.Discover(ctx, "SMF", "AMF", sl)
			if err != nil {
				t.Fatalf("Discover must reach the NRF: %v", err)
			}
			if *s.seen == "" {
				t.Fatal("NRF stub was never reached")
			}
			if !strings.HasPrefix(*s.seen, "GET /nnrf-disc/v1/nf-instances?") {
				t.Errorf("request = %q, want GET /nnrf-disc/v1/nf-instances?...", *s.seen)
			}
			if len(eps) != 1 || eps[0].InstanceID != "smf-1" || eps[0].Address != "10.0.0.6:8000" {
				t.Errorf("endpoints = %+v, want smf-1 at 10.0.0.6:8000", eps)
			}
		})
	}
}

// TestNormalizeHostPort pins the helper behind NewHTTPNRFClient.
func TestNormalizeHostPort(t *testing.T) {
	tests := []struct{ in, want string }{
		{"nrf:8000", "nrf:8000"},
		{"10.0.0.5:8000", "10.0.0.5:8000"},
		{"[fd00::1]:8000", "[fd00::1]:8000"},
		{"https://nrf:8000", "nrf:8000"},
		{"https://nrf:8000/", "nrf:8000"},
		{"https://nrf:8000//", "nrf:8000"},
		{"http://nrf:8000", "nrf:8000"},
		{"HTTPS://nrf:8000", "nrf:8000"},
		{"Http://nrf:8000/", "nrf:8000"},
		{"https://[fd00::1]:8000/", "[fd00::1]:8000"},
		{"", ""},
		{"https://", ""},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := normalizeHostPort(tc.in); got != tc.want {
				t.Errorf("normalizeHostPort(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestNRFDiscoverSMFAddressOutcome: an address is returned and cached; every
// failure (no instance, an instance without address, a non-200 answer) is an
// error and is never cached, so the next PDU session asks the NRF again. The
// clients here have no logger: a failure must not need one.
func TestNRFDiscoverSMFAddressOutcome(t *testing.T) {
	sl := amfctx.SNSSAISubscribed{SST: 1, SD: "000001"}
	const cacheKey = "1:000001"
	tests := []struct {
		name       string
		status     int
		body       string
		wantAddr   string // "" = failure
		wantNoAddr bool   // failure cause is errNoSMFEndpoint (200 without an address)
	}{
		{"address is returned and cached", http.StatusOK, nrfGoldenAnswer, "10.0.0.6:8000", false},
		{"ipv4Addresses only", http.StatusOK,
			`{"nfInstances":[{"nfInstanceId":"smf-1","ipv4Addresses":["10.0.0.5"]}]}`, "10.0.0.5", false},
		{"no instances", http.StatusOK, `{"nfInstances":[]}`, "", true},
		{"no nfInstances attribute", http.StatusOK, `{}`, "", true},
		{"instance without address", http.StatusOK, `{"nfInstances":[{"nfInstanceId":"smf-1"}]}`, "", true},
		{"empty ipEndPoints list", http.StatusOK,
			`{"nfInstances":[{"nfInstanceId":"smf-1","nfServices":[{"ipEndPoints":[]}]}]}`, "", true},
		{"NRF answers 404", http.StatusNotFound, `{"title":"Not Found"}`, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newNRFStub(t, tc.status, tc.body)
			c := NewHTTPNRFClient(s.addr, s.hc)
			ctx, cancel := context.WithTimeout(t.Context(), nrfAddrCallTimeout)
			defer cancel()
			cached := func() map[string]string {
				c.mu.Lock()
				defer c.mu.Unlock()
				out := make(map[string]string, len(c.cache))
				for k, v := range c.cache {
					out[k] = v
				}
				return out
			}

			addr, err := c.DiscoverSMFAddress(ctx, sl)
			if *s.seen == "" {
				t.Fatal("first call must ask the NRF")
			}
			if tc.wantAddr != "" {
				if err != nil || addr != tc.wantAddr {
					t.Fatalf("addr = %q err = %v, want %q", addr, err, tc.wantAddr)
				}
				if got := cached(); len(got) != 1 || got[cacheKey] != tc.wantAddr {
					t.Errorf("cache = %v, want {%s: %s}", got, cacheKey, tc.wantAddr)
				}
				*s.seen = ""
				if again, err := c.DiscoverSMFAddress(ctx, sl); err != nil || again != tc.wantAddr {
					t.Errorf("cached call: addr = %q err = %v", again, err)
				}
				if *s.seen != "" {
					t.Errorf("cached call must not ask the NRF again, saw %q", *s.seen)
				}
				return
			}

			if err == nil {
				t.Fatalf("want an error, got addr %q", addr)
			}
			if addr != "" {
				t.Errorf("addr = %q on error, want empty", addr)
			}
			if got := errors.Is(err, errNoSMFEndpoint); got != tc.wantNoAddr {
				t.Errorf("errors.Is(err, errNoSMFEndpoint) = %v, want %v (err: %v)", got, tc.wantNoAddr, err)
			}
			// A nil cause once rendered as "%!w(<nil>)".
			if !strings.Contains(err.Error(), "SST=1 SD=000001") || strings.Contains(err.Error(), "%!") {
				t.Errorf("error text = %q", err)
			}
			if got := cached(); len(got) != 0 {
				t.Errorf("failure was cached: %v", got)
			}
			*s.seen = ""
			if _, err := c.DiscoverSMFAddress(ctx, sl); err == nil {
				t.Error("second call must still fail")
			}
			if *s.seen == "" {
				t.Error("second call must ask the NRF again (a failure is not cached)")
			}
		})
	}
}

// nfDiscoverRecords returns the procedure=NFDiscover records written to logs.
// slog's JSON handler does not de-duplicate keys, so each canonical key must
// appear exactly once on the raw line.
func nfDiscoverRecords(t *testing.T, logs *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte("\n")) {
		if !bytes.Contains(line, []byte(`"procedure":"NFDiscover"`)) {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		for _, k := range []string{"nf", "procedure", "correlation_id", "supi", "interface", "direction",
			"spec_ref", "snssai_sst", "snssai_sd", "error"} {
			if c := bytes.Count(line, []byte(`"`+k+`":`)); c != 1 {
				t.Errorf("key %q appears %d times in %s", k, c, line)
			}
		}
		out = append(out, rec)
	}
	return out
}

// closedNRFStub returns the address and client of an httptest TLS server that
// has already been closed: a connection to it is refused at once. That is a
// transport failure without any DNS lookup, so it cannot stall the test.
func closedNRFStub(t *testing.T) nrfStub {
	t.Helper()
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	s := nrfStub{addr: strings.TrimPrefix(srv.URL, "https://"), hc: srv.Client(), seen: new(string)}
	srv.Close()
	return s
}

// TestNRFDiscoverSMFAddressFallbackLog: the error CallSMF swallows is always
// logged, at a level that follows the cause. A 200 answer without any address
// is the normal case today (no NF registers an address with the NRF, so every
// PDU Session Establishment takes the static-peer fallback): Debug, so Info
// (the production default) stays silent. Every other cause (here a 404 and an
// unreachable NRF) is an NRF problem: Warn, so Info shows it.
func TestNRFDiscoverSMFAddressFallbackLog(t *testing.T) {
	const (
		corrID = "01HZZZZZZZZZZZZZZZZZZZZZZZ"
		supi   = "imsi-001010000000001"
	)
	sl := amfctx.SNSSAISubscribed{SST: 1, SD: "000001"}
	causes := []struct {
		name  string
		nrf   func(t *testing.T) nrfStub
		level string // "level" of the NFDiscover record: DEBUG or WARN
	}{
		{"200 without address", func(t *testing.T) nrfStub {
			return newNRFStub(t, http.StatusOK, `{"nfInstances":[{"nfInstanceId":"smf-1"}]}`)
		}, "DEBUG"},
		{"404 from the NRF", func(t *testing.T) nrfStub {
			return newNRFStub(t, http.StatusNotFound, `{"title":"Not Found"}`)
		}, "WARN"},
		{"NRF unreachable", closedNRFStub, "WARN"},
	}
	for _, tc := range causes {
		t.Run(tc.name, func(t *testing.T) {
			// run makes the failing discovery against a logger that emits
			// records at minLevel and above, and returns what it wrote.
			run := func(t *testing.T, minLevel slog.Level) (*bytes.Buffer, error) {
				t.Helper()
				s := tc.nrf(t)
				logs := new(bytes.Buffer)
				// nf is added once, by the process logger, as in main().
				base := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: minLevel})).With("nf", "AMF")
				c := NewHTTPNRFClient(s.addr, s.hc).WithFeatures(nil, base)
				ctx, cancel := context.WithTimeout(t.Context(), nrfAddrCallTimeout)
				defer cancel()
				ctx = logging.WithSUPI(logging.WithCorrelationID(ctx, corrID), supi)
				_, err := c.DiscoverSMFAddress(ctx, sl)
				return logs, err
			}

			t.Run("debug level: one canonical record at the cause level", func(t *testing.T) {
				logs, err := run(t, slog.LevelDebug)
				if err == nil {
					t.Fatal("discovery without an address must fail")
				}
				recs := nfDiscoverRecords(t, logs)
				if len(recs) != 1 {
					t.Fatalf("NFDiscover records = %d, want 1:\n%s", len(recs), logs)
				}
				r := recs[0]
				want := map[string]any{
					"level": tc.level, "nf": "AMF", "procedure": "NFDiscover",
					"correlation_id": corrID, "supi": supi,
					"interface": "Nnrf", "direction": "OUT", "spec_ref": "TS 23.501 §6.3.2",
					"snssai_sst": float64(1), "snssai_sd": "000001", "error": err.Error(),
				}
				for k, v := range want {
					if r[k] != v {
						t.Errorf("%s = %v, want %v", k, r[k], v)
					}
				}
			})

			t.Run("info level (production default)", func(t *testing.T) {
				logs, err := run(t, slog.LevelInfo)
				if err == nil {
					t.Fatal("discovery without an address must fail")
				}
				recs := nfDiscoverRecords(t, logs)
				if tc.level == "DEBUG" {
					if len(recs) != 0 {
						t.Fatalf("Info must not log a Debug-level cause, got %v", recs)
					}
					return
				}
				if len(recs) != 1 || recs[0]["level"] != tc.level {
					t.Fatalf("Info must show exactly one %s record, got %v", tc.level, recs)
				}
			})
		})
	}
}
