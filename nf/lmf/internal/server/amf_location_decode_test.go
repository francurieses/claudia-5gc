package server

// amf_location_decode_test.go - REL19-3.5 slice B: the Namf_Location answer
// consumer decodes both the legacy (rel17-profile) shape and the TS 29.518
// ProvideLocInfo shape, and the AMF->LMF Cell-ID path works for every
// combination of AMF and LMF release profile.
// Ref: TS 29.518 §5.5.2.4; TS 29.571 NrLocation schema; TS 29.500 §6.6.2.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/lmf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/capability"
)

func TestDecodeAMFLocation(t *testing.T) {
	tai := &TaiLoc{PlmnId: PlmnID{MCC: "001", MNC: "01"}, Tac: "000001"}
	tests := []struct {
		name     string
		body     string
		wantCell string
		wantTai  *TaiLoc
		wantAge  int
		wantPt   *LatLon
	}{
		{"legacy", `{"locationEstimate":{"shape":"POINT","point":{"lat":1,"lon":2}},"nrCellId":"000000042","tai":{"plmnId":{"mcc":"001","mnc":"01"},"tac":"000001"},"ageOfLocationEstimate":3}`,
			"000000042", tai, 3, &LatLon{Lat: 1, Lon: 2}},
		{"ProvideLocInfo", `{"currentLoc":true,"location":{"nrLocation":{"tai":{"plmnId":{"mcc":"001","mnc":"01"},"tac":"000001"},"ncgi":{"plmnId":{"mcc":"001","mnc":"01"},"nrCellId":"000000042"},"ageOfLocationInformation":5}},"geoInfo":{"shape":"POINT","point":{"lat":3,"lon":4}},"locationAge":7,"ratType":"NR"}`,
			"000000042", tai, 7, &LatLon{Lat: 3, Lon: 4}},
		{"ProvideLocInfo age from nrLocation", `{"location":{"nrLocation":{"tai":{"plmnId":{"mcc":"001","mnc":"01"},"tac":"000001"},"ncgi":{"plmnId":{"mcc":"001","mnc":"01"},"nrCellId":"000000042"},"ageOfLocationInformation":5}}}`,
			"000000042", tai, 5, nil},
		{"spec fields win over legacy", `{"nrCellId":"0000000AA","ageOfLocationEstimate":9,"location":{"nrLocation":{"tai":{"plmnId":{"mcc":"001","mnc":"01"},"tac":"000001"},"ncgi":{"plmnId":{"mcc":"001","mnc":"01"},"nrCellId":"000000042"}}},"locationAge":1}`,
			"000000042", tai, 1, nil},
		{"unknown attributes ignored", `{"location":{"nrLocation":{"tai":{"plmnId":{"mcc":"001","mnc":"01"},"tac":"000001"},"ncgi":{"plmnId":{"mcc":"001","mnc":"01"},"nrCellId":"000000042"},"ignoreNcgi":false}},"timezone":"+02:00","extra":1}`,
			"000000042", tai, 0, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeAMFLocation([]byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if got.NRCellId != tc.wantCell || got.AgeOfLocationEstimate != tc.wantAge {
				t.Errorf("cell=%q age=%d, want %q/%d", got.NRCellId, got.AgeOfLocationEstimate, tc.wantCell, tc.wantAge)
			}
			if got.Tai == nil || *got.Tai != *tc.wantTai {
				t.Errorf("tai = %+v, want %+v", got.Tai, tc.wantTai)
			}
			switch {
			case tc.wantPt == nil && got.LocationEstimate != nil:
				t.Errorf("unexpected estimate %+v", got.LocationEstimate)
			case tc.wantPt != nil && (got.LocationEstimate == nil || *got.LocationEstimate.Point != *tc.wantPt):
				t.Errorf("estimate = %+v, want %+v", got.LocationEstimate, tc.wantPt)
			}
		})
	}
	if _, err := decodeAMFLocation([]byte(`{`)); err == nil {
		t.Error("malformed body must fail")
	}
}

// TestDecodeAMFLocation_Degenerate: an answer without cell id, TAI and
// estimate is an error, and a type clash in one view does not fail the other.
func TestDecodeAMFLocation_Degenerate(t *testing.T) {
	for _, body := range []string{
		`{}`, `null`, `{"location":{}}`, `{"location":{"nrLocation":{}}}`,
		`{"geoInfo":{"shape":"POLYGON"}}`, `[]`,
	} {
		if got, err := decodeAMFLocation([]byte(body)); err == nil {
			t.Errorf("%s: want error, got %+v", body, got)
		}
	}

	t.Run("spec tai wins over legacy tai", func(t *testing.T) {
		got, err := decodeAMFLocation([]byte(`{"tai":{"plmnId":{"mcc":"999","mnc":"99"},"tac":"000009"},"location":{"nrLocation":{"tai":{"plmnId":{"mcc":"001","mnc":"01"},"tac":"000001"},"ncgi":{"plmnId":{"mcc":"001","mnc":"01"},"nrCellId":"000000042"}}}}`))
		if err != nil {
			t.Fatal(err)
		}
		if got.Tai == nil || got.Tai.Tac != "000001" || got.Tai.PlmnId.MCC != "001" {
			t.Errorf("tai = %+v, want spec tai", got.Tai)
		}
	})
	t.Run("non-POINT geoInfo ignored, cell kept", func(t *testing.T) {
		got, err := decodeAMFLocation([]byte(`{"location":{"nrLocation":{"tai":{"plmnId":{"mcc":"001","mnc":"01"},"tac":"000001"},"ncgi":{"plmnId":{"mcc":"001","mnc":"01"},"nrCellId":"000000042"}}},"geoInfo":{"shape":"POLYGON","pointList":[]}}`))
		if err != nil {
			t.Fatal(err)
		}
		if got.NRCellId != "000000042" || got.LocationEstimate != nil {
			t.Errorf("got %+v", got)
		}
	})
	t.Run("spec view clash keeps legacy view", func(t *testing.T) {
		got, err := decodeAMFLocation([]byte(`{"nrCellId":"000000042","location":"oops","geoInfo":7,"locationAge":"x"}`))
		if err != nil {
			t.Fatal(err)
		}
		if got.NRCellId != "000000042" {
			t.Errorf("got %+v", got)
		}
	})
	t.Run("legacy view clash keeps spec view", func(t *testing.T) {
		got, err := decodeAMFLocation([]byte(`{"tai":"oops","nrCellId":5,"location":{"nrLocation":{"tai":{"plmnId":{"mcc":"001","mnc":"01"},"tac":"000001"},"ncgi":{"plmnId":{"mcc":"001","mnc":"01"},"nrCellId":"000000042"}}}}`))
		if err != nil {
			t.Fatal(err)
		}
		if got.NRCellId != "000000042" || got.Tai == nil {
			t.Errorf("got %+v", got)
		}
	})
}

// amfGolden reads the AMF's own captured ProvideLocationInfo answer so the
// LMF consumer is exercised against the exact bytes the AMF handler emits
// (nf/amf/internal/sbi golden tests pin those bytes). It is a file read, not
// an import: nf/amf/internal is not importable from the LMF.
func amfGolden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "amf", "internal", "sbi", "testdata", name))
	if err != nil {
		t.Fatalf("read AMF golden: %v", err)
	}
	return b
}

// TestAMFToLMFCellIDPath: AMF answer (rel17 legacy or rel19 ProvideLocInfo)
// -> HTTPAMFLocationClient -> DetermineLocation, for every combination of AMF
// and LMF release profile.
func TestAMFToLMFCellIDPath(t *testing.T) {
	for _, amfProfile := range []string{"rel17", "rel19"} {
		body := amfGolden(t, "provide_loc_info_"+amfProfile+"_200.json")
		for _, lmfProfile := range []string{"", "rel17", "rel19"} {
			t.Run("amf="+amfProfile+" lmf="+lmfProfile, func(t *testing.T) {
				amf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/namf-loc/v1/ue-contexts/imsi-001010000000001/provide-loc-info" {
						t.Errorf("path %s", r.URL.Path)
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(body)
				}))
				defer amf.Close()
				client := &HTTPAMFLocationClient{BaseURL: amf.URL, Client: amf.Client(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

				cfg := &config.Config{}
				cfg.SBI.Address = "127.0.0.1:0"
				cfg.CellCoordinates = map[string]config.CellCoord{"000000042": {Lat: 40.5, Lon: -3.25}}
				srv := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), client, nil)
				if lmfProfile != "" {
					srv.SetProfile(profileNamed(t, lmfProfile))
				} else {
					var none *capability.Profile
					srv.SetProfile(none)
				}
				lmf := httptest.NewServer(srv.Handler())
				defer lmf.Close()

				req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
					lmf.URL+"/nlmf-loc/v1/determine-location", stringsReader(`{"supi":"imsi-001010000000001"}`))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", "application/json")
				resp, err := lmf.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				raw, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status %d: %s", resp.StatusCode, raw)
				}
				var ld LocationData
				if err := json.Unmarshal(raw, &ld); err != nil {
					t.Fatal(err)
				}
				if ld.NRCellId != "000000042" || ld.Tai == nil || ld.Tai.Tac != "000001" || ld.Tai.PlmnId.MCC != "001" {
					t.Errorf("Cell-ID path lost data: %s", raw)
				}
				if ld.LocationEstimate == nil || ld.LocationEstimate.Point == nil {
					t.Fatalf("no locationEstimate: %s", raw)
				}
				// Mobility is disabled in this config, so the estimate is the
				// configured anchor of the serving cell.
				if got := *ld.LocationEstimate.Point; got != (LatLon{Lat: 40.5, Lon: -3.25}) {
					t.Errorf("estimate = %+v, want the configured cell coordinate", got)
				}
			})
		}
	}
}

func stringsReader(s string) io.Reader { return strings.NewReader(s) }
