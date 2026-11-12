package server

// wire_rel19_test.go - REL19-3.5 slice 2: the rel19 profile answers LocationData
// with the spec attribute ncgi (TS 29.572 LocationData.ncgi) instead of the
// project nrCellId; both shapes decode. The rel17 bytes are pinned by
// wire_golden_test.go and golden_determine_location_200.txt.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestLocationData_SpecWireUsesNcgi(t *testing.T) {
	spec, err := json.Marshal(fullLocationData().wireFor(true))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(spec, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["nrCellId"]; ok {
		t.Errorf("spec shape must not carry top-level nrCellId: %s", spec)
	}
	if string(m["ncgi"]) != `{"plmnId":{"mcc":"001","mnc":"01"},"nrCellId":"000000010"}` {
		t.Errorf("ncgi = %s", m["ncgi"])
	}
	// no TAI -> no PLMN -> no ncgi (plmnId is mandatory in Ncgi)
	ld := fullLocationData()
	ld.Tai = nil
	b, _ := json.Marshal(ld.wireFor(true))
	if strings.Contains(string(b), "ncgi") || strings.Contains(string(b), "nrCellId") {
		t.Errorf("no-TAI spec shape = %s", b)
	}
}

func TestLocationData_DecodesBothShapes(t *testing.T) {
	for name, in := range map[string]string{
		"legacy":          `{"nrCellId":"000000010","ageOfLocationEstimate":1}`,
		"spec":            `{"ncgi":{"plmnId":{"mcc":"001","mnc":"01"},"nrCellId":"000000010"},"ageOfLocationEstimate":1}`,
		"both, spec wins": `{"nrCellId":"ffff","ncgi":{"plmnId":{"mcc":"001","mnc":"01"},"nrCellId":"000000010"},"ageOfLocationEstimate":1}`,
	} {
		var l LocationData
		if err := json.Unmarshal([]byte(in), &l); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if l.NRCellId != "000000010" || l.AgeOfLocationEstimate != 1 {
			t.Errorf("%s: %+v", name, l)
		}
	}
	// locationDataExt round-trips its tail in both shapes
	for _, spec := range []bool{false, true} {
		in := locationDataExt{LocationData: fullLocationData().wireFor(spec), TimestampOfLocationEstimate: "2026-01-01T00:00:00Z",
			AcceptedPeriodicEventInfo: &periodicEventInfo{ReportingAmount: 2, ReportingInterval: 1}}
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		var out locationDataExt
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		if out.NRCellId != "000000010" || out.TimestampOfLocationEstimate != in.TimestampOfLocationEstimate ||
			out.AcceptedPeriodicEventInfo == nil || out.AcceptedPeriodicEventInfo.ReportingAmount != 2 {
			t.Errorf("spec=%v: %s -> %+v", spec, b, out)
		}
	}
}

func TestDetermineLocation_Rel19AnswersNcgi(t *testing.T) {
	ts, _ := newFeatureLMF(t, profileNamed(t, "rel19"), nil)
	resp, raw := postDetermine(t, ts, `{"supi":"imsi-001010000000001"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["nrCellId"]; ok || string(m["ncgi"]) != `{"plmnId":{"mcc":"001","mnc":"01"},"nrCellId":"000000010"}` {
		t.Errorf("rel19 answer = %s", raw)
	}
}

func TestDeferred_Rel19AnswersNcgiAndKeepsTail(t *testing.T) {
	sink := newEventSink()
	ts, _ := newDeferredLMF(t, profileNamed(t, "rel19"), goldenAMF(), sink)
	resp, body := post(t, ts, detLM, periodicBody(2, false))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	m := decodeMap(t, body)
	if _, ok := m["nrCellId"]; ok || m["ncgi"] == nil || m["timestampOfLocationEstimate"] == nil {
		t.Errorf("locationDataExt = %s", body)
	}
}

func TestDecodeLcsPrivacy(t *testing.T) {
	tests := []struct {
		name, in, want string
		wantErr        bool
	}{
		{"legacy block", `{"locationPrivacy":"BLOCK_ALL"}`, "BLOCK_ALL", false},
		{"legacy allow", `{"locationPrivacy":"ALLOW_ALL"}`, "ALLOW_ALL", false},
		{"spec disallowed", `{"lpi":{"locationPrivacyInd":"LOCATION_DISALLOWED"}}`, "BLOCK_ALL", false},
		{"spec allowed", `{"lpi":{"locationPrivacyInd":"LOCATION_ALLOWED"}}`, "ALLOW_ALL", false},
		{"spec wins over legacy", `{"locationPrivacy":"ALLOW_ALL","lpi":{"locationPrivacyInd":"LOCATION_DISALLOWED"}}`, "BLOCK_ALL", false},
		{"unknown enum value ignored", `{"lpi":{"locationPrivacyInd":"FUTURE"},"unrelatedClass":{}}`, "", false},
		{"unknown attributes ignored", `{"x":1}`, "", false},
		{"not an object", `[]`, "", true},
		{"legacy type clash without spec", `{"locationPrivacy":5}`, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeLcsPrivacy([]byte(tc.in))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && got.LocationPrivacy != tc.want {
				t.Errorf("LocationPrivacy = %q want %q", got.LocationPrivacy, tc.want)
			}
		})
	}
}
