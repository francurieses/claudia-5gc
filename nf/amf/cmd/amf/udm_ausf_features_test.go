package main

// udm_ausf_features_test.go - REL19-2.7 slice 6a consumer side of Nausf_UEAuthentication
// (InitiateAuth, ResyncAuth) and Nudm_SDM / Nudm_UECM (GetAMSubscriptionData,
// RegisterAMF) supportedFeatures negotiation: decision D2 (rel17 sends
// nothing, rel19 sends the offer, "0" when nothing is implemented) and rules
// R11-R14 on the answer. The rel17 bytes are pinned by golden_udm_ausf_test.go.
// Ref: TS 29.500 §6.6.2; TS 29.509 §6.1.6.2.2; TS 29.503 §6.1.8, §6.2.8.

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	amfsbi "github.com/francurieses/claudia-5gc/nf/amf/internal/sbi"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// negRecords returns the FeatureNegotiation records written to logs.
func negRecords(t *testing.T, logs *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte("\n")) {
		if !bytes.Contains(line, []byte(`"procedure":"FeatureNegotiation"`)) {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		// slog's JSON handler does not de-duplicate keys: each canonical key once.
		for _, k := range []string{"nf", "procedure", "interface", "direction", "spec_ref", "peer_nf_type",
			"features_local", "features_peer", "features_negotiated", "result"} {
			if c := bytes.Count(line, []byte(`"`+k+`":`)); c != 1 {
				t.Errorf("key %q appears %d times in %s", k, c, line)
			}
		}
		out = append(out, rec)
	}
	return out
}

func oneRecord(t *testing.T, logs *bytes.Buffer) map[string]any {
	t.Helper()
	recs := negRecords(t, logs)
	if len(recs) != 1 {
		t.Fatalf("FeatureNegotiation records = %d, want 1:\n%s", len(recs), logs)
	}
	r := recs[0]
	if r["direction"] != "OUT" || r["spec_ref"] != "TS 29.500 §6.6.2" || r["nf"] != "AMF" {
		t.Errorf("record %v", r)
	}
	return r
}

func newLogs() (*bytes.Buffer, *slog.Logger) {
	b := new(bytes.Buffer)
	return b, slog.New(slog.NewJSONHandler(b, nil)).With("nf", "AMF")
}

// TestAUSFOfferAndLog: rel19 sends "0" in AuthenticationInfo, rel17 sends
// nothing; UEAuthenticationCtx has no supportedFeatures, so the record shows
// the peer absent and nothing negotiated (R12). Authentication succeeds.
func TestAUSFOfferAndLog(t *testing.T) {
	// A catalog implementing ES3XX (bit 1) exercises a non-empty offer.
	es3xx := features.MustCatalog(features.MustImplement(features.NausfUEAuthenticationEntries(), 1)...)
	none := features.MustCatalog(features.MustImplement(features.NausfUEAuthenticationEntries())...)
	tests := []struct {
		name, profile string
		cat           *features.Catalog
		wantOffer     string // "" = attribute absent
		wantLocal     string // features_local in the record
	}{
		// The default AMF catalog marks ES3XX (bit 1, M; TS 29.509 §6.1.9).
		{"rel17", "rel17", nil, "", "1"},
		{"rel17 with implemented bit: nothing sent, bit still local", "rel17", es3xx, "", "1"},
		{"rel19 default catalog offers ES3XX", "rel19", nil, "1", "1"},
		{"rel19 ES3XX implemented", "rel19", es3xx, "1", "1"},
		{"rel19 nothing implemented", "rel19", none, "0", "0"},
	}
	for _, call := range []string{"initiate", "resync"} {
		for _, tc := range tests {
			t.Run(call+"/"+tc.name, func(t *testing.T) {
				addr, got, hc := captureServer(t, http.StatusCreated, goldenAuthAnswer, "https://ausf/nausf-auth/v1/ue-authentications/ctx-1")
				logs, lg := newLogs()
				c := &HTTPAUSFClient{address: addr, client: hc, profile: testProfile(t, tc.profile), catalog: tc.cat, logger: lg}
				var err error
				if call == "initiate" {
					_, err = c.InitiateAuth(t.Context(), goldenSUCI, goldenSN)
				} else {
					_, err = c.ResyncAuth(t.Context(), goldenSUCI, goldenSN, [16]byte{}, []byte{1, 2})
				}
				if err != nil {
					t.Fatalf("auth must not fail on negotiation: %v", err)
				}
				var m map[string]any
				if err := json.Unmarshal([]byte(got.body), &m); err != nil {
					t.Fatal(err)
				}
				v, present := m["supportedFeatures"].(string)
				if tc.wantOffer == "" && present {
					t.Errorf("rel17 body carries supportedFeatures %q", v)
				}
				if tc.wantOffer != "" && v != tc.wantOffer {
					t.Errorf("offer = %q (present=%v), want %q", v, present, tc.wantOffer)
				}
				r := oneRecord(t, logs)
				if r["interface"] != "Nausf" || r["peer_nf_type"] != "AUSF" || r["result"] != "OK" ||
					r["features_peer"] != "absent" || r["features_negotiated"] != "0" ||
					r["supi_or_suci"] != goldenSUCI {
					t.Errorf("record %v", r)
				}
				if r["features_local"] != tc.wantLocal {
					t.Errorf("features_local = %v, want %s", r["features_local"], tc.wantLocal)
				}
			})
		}
	}
}

func amDataServer(t *testing.T, answer string) (*HTTPUDMClient, *capturedReq, *bytes.Buffer) {
	t.Helper()
	addr, got, hc := captureServer(t, http.StatusOK, answer, "")
	logs, lg := newLogs()
	return &HTTPUDMClient{address: addr, client: hc, logger: lg}, got, logs
}

const amAnswerFmt = `{"nssai":{"defaultSingleNssais":[{"sst":1,"sd":"000001"}]},"subscribedUeAmbr":{"uplink":"1 Gbps","downlink":"2 Gbps"}%s}`

// TestGetAMDataOfferAndAccept covers the query offer (rel19 only) and
// features.Accept on AccessAndMobilitySubscriptionData.supportedFeatures.
func TestGetAMDataOfferAndAccept(t *testing.T) {
	sdm := features.MustCatalog(features.MustImplement(features.NudmSDMEntries(), 1, 25)...)
	tests := []struct {
		name, profile string
		cat           *features.Catalog
		answer        string // supportedFeatures value in the body, "-" = absent
		wantQuery     string
		wantPeer      string
		wantNeg       string
		wantResult    string
	}{
		{"rel17 absent", "rel17", nil, "-", "", "absent", "0", "OK"},
		{"rel17 UDM answers anyway (R14)", "rel17", sdm, "1", "", "1", "0", "OK"},
		{"rel19 offer 0, answer 0", "rel19", nil, "0", "?supported-features=0", "0", "0", "OK"},
		{"rel19 offer 0, answer absent (R12)", "rel19", nil, "-", "?supported-features=0", "absent", "0", "OK"},
		{"rel19 offer 1000001, answer 1", "rel19", sdm, "1", "?supported-features=1000001", "1", "1", "OK"},
		{"rel19 answer has bits never offered (R11)", "rel19", sdm, "ffffffff", "?supported-features=1000001", "ffffffff", "1000001", "OK"},
		{"rel19 uppercase hex answer", "rel19", sdm, "1F", "?supported-features=1000001", "1F", "1", "OK"},
		{"rel19 malformed answer (R13)", "rel19", sdm, "zz", "?supported-features=1000001", "zz", "0", "FAILURE"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extra := ""
			if tc.answer != "-" {
				extra = `,"supportedFeatures":"` + tc.answer + `"`
			}
			c, got, logs := amDataServer(t, strings.Replace(amAnswerFmt, "%s", extra, 1))
			c.profile, c.sdmCatalog = testProfile(t, tc.profile), tc.cat
			sub, err := c.GetAMSubscriptionData(t.Context(), goldenSUPI)
			if err != nil || len(sub.AllowedNSSAI) != 1 || sub.AMBRDownlink != 2000000 {
				t.Fatalf("procedure must continue: sub=%+v err=%v", sub, err)
			}
			if want := "GET /nudm-sdm/v2/" + goldenSUPI + "/am-data" + tc.wantQuery; got.method+" "+got.uri != want {
				t.Errorf("request %s %s, want %s", got.method, got.uri, want)
			}
			r := oneRecord(t, logs)
			if r["interface"] != "Nudm" || r["peer_nf_type"] != "UDM" || r["supi"] != goldenSUPI ||
				r["features_peer"] != tc.wantPeer || r["features_negotiated"] != tc.wantNeg || r["result"] != tc.wantResult {
				t.Errorf("record %v", r)
			}
			if tc.wantResult == "FAILURE" && r["level"] != "WARN" {
				t.Errorf("FAILURE must be WARN: %v", r["level"])
			}
		})
	}
}

// TestRegisterAMFOfferAndAccept covers Amf3GppAccessRegistration.supportedFeatures
// on the request (rel19 only) and Accept on the 2xx answer.
func TestRegisterAMFOfferAndAccept(t *testing.T) {
	uecm := features.MustCatalog(features.MustImplement(features.NudmUECMEntries(), 1, 6)...)
	tests := []struct {
		name, profile string
		cat           *features.Catalog
		status        int
		answer        string
		wantOffer     string // "" = attribute absent
		wantRecords   int
		wantPeer      string
		wantNeg       string
		wantResult    string
	}{
		{"rel17 legacy UDM", "rel17", nil, 201, ``, "", 1, "absent", "0", "OK"},
		{"rel17 body is not read", "rel17", uecm, 201, `{"supportedFeatures":"21"}`, "", 1, "absent", "0", "OK"},
		{"rel19 legacy UDM, empty body (R12)", "rel19", nil, 201, ``, "0", 1, "absent", "0", "OK"},
		{"rel19 answer 0", "rel19", nil, 201, `{"supportedFeatures":"0"}`, "0", 1, "0", "0", "OK"},
		{"rel19 intersection", "rel19", uecm, 201, `{"amfInstanceId":"x","supportedFeatures":"3"}`, "21", 1, "3", "1", "OK"},
		{"rel19 answer without attribute", "rel19", uecm, 201, `{"amfInstanceId":"x"}`, "21", 1, "absent", "0", "OK"},
		{"rel19 200 OK update", "rel19", uecm, 200, `{"supportedFeatures":"21"}`, "21", 1, "21", "21", "OK"},
		{"rel19 malformed answer (R13)", "rel19", uecm, 201, `{"supportedFeatures":"zz"}`, "21", 1, "zz", "0", "FAILURE"},
		{"rel19 non-string answer", "rel19", uecm, 201, `{"supportedFeatures":7}`, "21", 1, "absent", "0", "FAILURE"},
		{"rel19 non-JSON body", "rel19", uecm, 201, `not json`, "21", 1, "absent", "0", "FAILURE"},
		{"rel19 error status: no negotiation", "rel19", uecm, 403, `{"cause":"X"}`, "21", 0, "", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, got, hc := captureServer(t, tc.status, tc.answer, "")
			logs, lg := newLogs()
			c := &HTTPUDMClient{address: addr, client: hc, profile: testProfile(t, tc.profile), uecmCatalog: tc.cat, logger: lg}
			err := c.RegisterAMF(t.Context(), goldenSUPI, "amf-test-1", goldenSN)
			if tc.status >= 300 {
				// AUD-registration-17: a refused registration is a typed error
				// (the procedure rejects), still without a negotiation record.
				var ue *procedures.UDMError
				if !errors.As(err, &ue) || ue.Status != tc.status {
					t.Fatalf("err = %v, want *UDMError status %d", err, tc.status)
				}
			} else if err != nil {
				t.Fatalf("registration must not fail on negotiation: %v", err)
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(got.body), &m); err != nil {
				t.Fatal(err)
			}
			v, present := m["supportedFeatures"].(string)
			if (tc.wantOffer == "") == present || (present && v != tc.wantOffer) {
				t.Errorf("offer = %q (present=%v), want %q", v, present, tc.wantOffer)
			}
			if tc.wantRecords == 0 {
				if n := len(negRecords(t, logs)); n != 0 {
					t.Errorf("records = %d, want 0", n)
				}
				return
			}
			r := oneRecord(t, logs)
			if r["interface"] != "Nudm" || r["peer_nf_type"] != "UDM" || r["supi"] != goldenSUPI ||
				r["features_peer"] != tc.wantPeer || r["features_negotiated"] != tc.wantNeg || r["result"] != tc.wantResult {
				t.Errorf("record %v", r)
			}
		})
	}
}

// TestConsumerCatalogsOfferZero: the AMF implements none of the Nudm bits, so
// the rel19 offers are "0" with the shipped catalogs; the Nausf catalog marks
// ES3XX (bit 1, TS 29.509 §6.1.9) and offers "1".
func TestConsumerCatalogsOfferZero(t *testing.T) {
	p := testProfile(t, "rel19")
	for name, cat := range map[string]*features.Catalog{
		"Nausf":    amfsbi.NausfUEAuthenticationCatalog(),
		"Nudm_SDM": amfsbi.NudmSDMCatalog(), "Nudm_UECM": amfsbi.NudmUECMCatalog(),
	} {
		want := "0"
		if name == "Nausf" {
			want = "1"
		}
		if got := features.Request(cat, p); got != want {
			t.Errorf("%s offer = %q, want %s", name, got, want)
		}
		if got := features.Request(cat, testProfile(t, "rel17")); got != "" {
			t.Errorf("%s rel17 offer = %q, want empty", name, got)
		}
	}
}

const confirmAnswer = `{"authResult":"AUTHENTICATION_SUCCESS","supi":"imsi-001010000000001","kausf":"000102"}`

// TestGolden_ConfirmAuthRequest pins the rel17 PUT 5g-aka-confirmation bytes
// (captured from the pre-slice HEAD tree): no supportedFeatures.
func TestGolden_ConfirmAuthRequest(t *testing.T) {
	const want = `PUT /nausf-auth/v1/ue-authentications/ctx-1/5g-aka-confirmation [application/json] {"resStar":"0a0b0c0d"}`
	for _, mode := range goldenModes(t) {
		t.Run(mode.name, func(t *testing.T) {
			addr, got, hc := captureServer(t, http.StatusOK, confirmAnswer, "")
			c := newAUSFClient(addr, hc, mode)
			if _, err := c.ConfirmAuth(t.Context(), "ctx-1", "0a0b0c0d"); err != nil {
				t.Fatal(err)
			}
			if got.String() != want {
				t.Fatalf("request changed:\n got %s\nwant %s", got, want)
			}
		})
	}
}

// TestConfirmAuthOfferRel19: ConfirmationData.supportedFeatures is offered
// under rel19 (TS 29.509 §6.1.6.2.6); ConfirmationDataResponse has no answer
// attribute (R12), so the record shows the peer absent.
func TestConfirmAuthOfferRel19(t *testing.T) {
	none := features.MustCatalog(features.MustImplement(features.NausfUEAuthenticationEntries())...)
	for _, tc := range []struct {
		name string
		cat  *features.Catalog
		want string
	}{{"default catalog", nil, "1"}, {"nothing implemented", none, "0"}} {
		t.Run(tc.name, func(t *testing.T) {
			addr, got, hc := captureServer(t, http.StatusOK, confirmAnswer, "")
			logs, lg := newLogs()
			c := &HTTPAUSFClient{address: addr, client: hc, profile: testProfile(t, "rel19"), catalog: tc.cat, logger: lg}
			if _, err := c.ConfirmAuth(t.Context(), "ctx-1", "0a0b0c0d"); err != nil {
				t.Fatal(err)
			}
			if want := `{"resStar":"0a0b0c0d","supportedFeatures":"` + tc.want + `"}`; got.body != want {
				t.Errorf("body = %s, want %s", got.body, want)
			}
			r := oneRecord(t, logs)
			if r["interface"] != "Nausf" || r["features_peer"] != "absent" || r["features_negotiated"] != "0" || r["result"] != "OK" {
				t.Errorf("record %v", r)
			}
		})
	}
}

// TestNonStringAnswerContinues: a supportedFeatures answer of the wrong JSON
// type is a FAILURE record, not a decode failure, under rel17 and rel19.
func TestNonStringAnswerContinues(t *testing.T) {
	for _, prof := range []string{"rel17", "rel19"} {
		t.Run(prof+"/am-data", func(t *testing.T) {
			c, _, logs := amDataServer(t, strings.Replace(amAnswerFmt, "%s", `,"supportedFeatures":["1"]`, 1))
			c.profile = testProfile(t, prof)
			sub, err := c.GetAMSubscriptionData(t.Context(), goldenSUPI)
			if err != nil || len(sub.AllowedNSSAI) != 1 {
				t.Fatalf("procedure must continue: sub=%+v err=%v", sub, err)
			}
			r := oneRecord(t, logs)
			if r["result"] != "FAILURE" || r["level"] != "WARN" || r["features_negotiated"] != "0" {
				t.Errorf("record %v", r)
			}
		})
		t.Run(prof+"/nrf-discover", func(t *testing.T) {
			s := newNRFStub(t, http.StatusOK, `{"nrfSupportedFeatures":3,"nfInstances":[{"nfInstanceId":"smf-1","ipv4Addresses":["10.0.0.5"]}]}`)
			logs, logger := newLogs()
			c := NewHTTPNRFClient(s.addr, s.hc).WithFeatures(testProfile(t, prof), logger)
			eps, err := c.Discover(t.Context(), "SMF", "AMF", nil)
			if err != nil || len(eps) != 1 {
				t.Fatalf("discovery must continue: eps=%+v err=%v", eps, err)
			}
			r := oneRecord(t, logs)
			if r["result"] != "FAILURE" || r["level"] != "WARN" || r["features_peer"] != "3" {
				t.Errorf("record %v", r)
			}
		})
	}
}

// TestGetAMDataNon2xx: an error status negotiates nothing and logs no record.
func TestGetAMDataNon2xx(t *testing.T) {
	addr, _, hc := captureServer(t, http.StatusNotFound, `{"cause":"USER_NOT_FOUND","supportedFeatures":"1"}`, "")
	logs, lg := newLogs()
	c := &HTTPUDMClient{address: addr, client: hc, profile: testProfile(t, "rel19"), logger: lg}
	if _, err := c.GetAMSubscriptionData(t.Context(), goldenSUPI); err != nil {
		t.Logf("non-2xx result: %v", err)
	}
	if recs := negRecords(t, logs); len(recs) != 0 {
		t.Fatalf("records = %v", recs)
	}
}

// TestRegisterAMFNon2xxWarns: a UDM refusal returns a typed *UDMError (the
// registration is rejected, AUD-registration-17) and logs a canonical Warn with
// the status, no negotiation record.
func TestRegisterAMFNon2xxWarns(t *testing.T) {
	for _, prof := range []string{"rel17", "rel19"} {
		t.Run(prof, func(t *testing.T) {
			addr, _, hc := captureServer(t, http.StatusForbidden, `{"cause":"X"}`, "")
			logs, lg := newLogs()
			c := &HTTPUDMClient{address: addr, client: hc, profile: testProfile(t, prof), logger: lg}
			err := c.RegisterAMF(t.Context(), goldenSUPI, "amf-test-1", goldenSN)
			var ue *procedures.UDMError
			if !errors.As(err, &ue) || ue.Status != 403 || ue.Cause != "X" {
				t.Fatalf("err = %v, want *UDMError 403 cause X", err)
			}
			if n := len(negRecords(t, logs)); n != 0 {
				t.Errorf("negotiation records = %d, want 0", n)
			}
			var rec map[string]any
			for _, line := range bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte("\n")) {
				var m map[string]any
				if json.Unmarshal(line, &m) == nil && m["level"] == "WARN" {
					rec = m
				}
			}
			if rec == nil || rec["interface"] != "Nudm" || rec["direction"] != "IN" || rec["result"] != "FAILURE" ||
				rec["supi"] != goldenSUPI || rec["status"] != float64(403) || rec["procedure"] != "UECMRegistration" {
				t.Fatalf("warn record = %v\n%s", rec, logs)
			}
		})
	}
}
