package api

// location.go — UE location endpoints.
//
// The portal acts as an LCS client of the LMF: it calls Nlmf_Location DetermineLocation
// (POST /nlmf-loc/v1/ue-contexts/{supi}/provide-loc-info, mTLS) which in turn drives the
// AMF Namf_Location → NGAP LocationReportingControl → gNB LocationReport flow and synthesizes
// WGS84 coordinates. The portal adds no positioning logic — it relays results for the map.
//
// Ref: TS 29.572 §5.2.2.2 (Nlmf_Location), TS 23.273 §7.2 (UE positioning).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/store"
)

// UELocation is the portal's view of a UE's location for the map + table.
type UELocation struct {
	SUPI      string    `json:"supi"`
	GMMState  int       `json:"gmm_state"`
	Reachable bool      `json:"reachable"`
	Latitude  float64   `json:"latitude,omitempty"`
	Longitude float64   `json:"longitude,omitempty"`
	AccuracyM float64   `json:"accuracy_m,omitempty"`
	NRCellID  string    `json:"nr_cell_id,omitempty"`
	TAC       string    `json:"tac,omitempty"`
	PLMN      string    `json:"plmn,omitempty"`
	Cause     string    `json:"cause,omitempty"` // 3GPP cause when unreachable (e.g. UE_NOT_REACHABLE)
	Timestamp time.Time `json:"timestamp"`
}

// lmfLocationData mirrors nf/lmf LocationData (the Nlmf_Location response body).
type lmfLocationData struct {
	LocationEstimate *struct {
		Shape string `json:"shape"`
		Point *struct {
			Lat float64 `json:"lat"`
			Lon float64 `json:"lon"`
		} `json:"point"`
		Uncertainty float64 `json:"uncertainty"`
	} `json:"locationEstimate"`
	NRCellID string `json:"nrCellId"`
	Tai      *struct {
		PlmnID struct {
			MCC string `json:"mcc"`
			MNC string `json:"mnc"`
		} `json:"plmnId"`
		Tac string `json:"tac"`
	} `json:"tai"`
	AgeOfLocationEstimate int `json:"ageOfLocationEstimate"`
}

// lmfProblem is the ProblemDetails body the LMF returns on 4xx/5xx.
type lmfProblem struct {
	Cause  string `json:"cause"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

// locateUE calls the LMF for a single SUPI and returns a fully-populated UELocation.
// Transport/decoding errors are returned as err; an LMF 4xx/5xx (UE idle, not found, gNB
// timeout) is reported as Reachable=false with the 3GPP cause — not an error.
func (d Deps) locateUE(r *http.Request, supi string) (UELocation, error) {
	loc := UELocation{SUPI: supi, Timestamp: time.Now()}

	u := strings.TrimRight(d.LMFBaseURL, "/") + "/nlmf-loc/v1/ue-contexts/" + supi + "/provide-loc-info"
	body, _ := json.Marshal(map[string]string{"supi": supi})
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return loc, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.MTLSClient.Do(req)
	if err != nil {
		return loc, fmt.Errorf("lmf unreachable: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusOK {
		var p lmfProblem
		_ = json.Unmarshal(raw, &p)
		loc.Reachable = false
		if p.Cause != "" {
			loc.Cause = p.Cause
		} else {
			loc.Cause = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return loc, nil
	}

	var data lmfLocationData
	if err := json.Unmarshal(raw, &data); err != nil {
		return loc, fmt.Errorf("decode LocationData: %w", err)
	}
	loc.Reachable = true
	loc.NRCellID = data.NRCellID
	if data.LocationEstimate != nil && data.LocationEstimate.Point != nil {
		loc.Latitude = data.LocationEstimate.Point.Lat
		loc.Longitude = data.LocationEstimate.Point.Lon
		loc.AccuracyM = data.LocationEstimate.Uncertainty
	}
	if data.Tai != nil {
		loc.TAC = data.Tai.Tac
		loc.PLMN = data.Tai.PlmnID.MCC + data.Tai.PlmnID.MNC
	}
	return loc, nil
}

// GET /api/v1/location/ue/{supi} → locate a single UE via the LMF.
func (d Deps) handleGetUELocation(w http.ResponseWriter, r *http.Request) {
	supi := chi.URLParam(r, "supi")
	loc, err := d.locateUE(r, supi)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, loc)
}

// GET /api/v1/location/summary → locate every registered UE (fan-out to the LMF).
// Returns one entry per UE; unreachable/idle UEs are included with Reachable=false.
func (d Deps) handleLocationSummary(w http.ResponseWriter, r *http.Request) {
	if d.Store == nil {
		writeJSON(w, http.StatusOK, []UELocation{})
		return
	}
	ctxs, err := d.Store.ListUEContexts(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	out := make([]UELocation, len(ctxs))
	var wg sync.WaitGroup
	for i, uc := range ctxs {
		wg.Add(1)
		go func(i int, uc store.UEContext) {
			defer wg.Done()
			loc, err := d.locateUE(r, uc.SUPI)
			loc.SUPI = uc.SUPI
			loc.GMMState = uc.GMMState
			if loc.Timestamp.IsZero() {
				loc.Timestamp = time.Now()
			}
			if err != nil && loc.Cause == "" {
				loc.Cause = err.Error()
			}
			out[i] = loc
		}(i, uc)
	}
	wg.Wait()

	writeJSON(w, http.StatusOK, out)
}
