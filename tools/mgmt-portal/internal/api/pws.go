package api

// pws.go — Public Warning System (ETWS/CMAS) control endpoints.
//
// The portal plays the Cell Broadcast Centre (CBC) role. 3GPP does not define a
// single CBC-AMF protocol for 5GC (TS 23.041 describes the functional split;
// legacy EPC reused SBc-AP), so — consistent with how this codebase simulates
// other external roles in-core — the portal drives the AMF's internal management
// API (:9002) which builds the real NGAP Write-Replace Warning Request
// (ProcCode 51) / PWS Cancel Request (ProcCode 32) and broadcasts them
// non-UE-associated to every connected gNB.
//
// The CBC is the 3GPP store of record for active warning messages (TS 23.041);
// the AMF is a stateless relay whose in-memory registry is transient and lost
// on restart. So the portal persists every broadcast in Postgres
// (store.PWSBroadcast) and reconciles it with the AMF's live per-gNB status:
//   - the list survives an AMF restart (warnings show `live:false` = the AMF no
//     longer has runtime state for them);
//   - a stored warning can be re-driven (resend) to re-establish it at the gNBs,
//     which is exactly what a real CBC does after a RAN/AMF restoration event
//     (TS 23.007 §16, TS 38.413 §8.9 PWS restart handling).
//
// Ref: TS 38.413 §8.9 (Write-Replace Warning, PWS Cancel), TS 23.041.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"

	"github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/store"
)

// ---- wire types -----------------------------------------------------------

// pwsBroadcastRequest mirrors the AMF mgmt-API POST /amf/v1/pws/broadcast body
// (and the portal /pws/broadcast body). Pointers distinguish "omitted" (AMF
// applies a default) from an explicit zero.
type pwsBroadcastRequest struct {
	MessageIdentifier  *int   `json:"messageIdentifier"`
	SerialNumber       *int   `json:"serialNumber"`
	RepetitionPeriod   *int   `json:"repetitionPeriod"`
	NumberOfBroadcasts *int   `json:"numberOfBroadcastsRequested"`
	WarningType        string `json:"warningType"`
	DataCodingScheme   *int   `json:"dataCodingScheme"`
	Language           string `json:"language"`
	MessageText        string `json:"messageText"`
	WarningAreaTACs    []int  `json:"warningAreaTacs"`
}

// pwsKeyRequest is the body for cancel/resend (identifies a broadcast).
type pwsKeyRequest struct {
	MessageIdentifier int `json:"messageIdentifier"`
	SerialNumber      int `json:"serialNumber"`
}

// amfPWSStatus is the AMF's per-broadcast live status (in-memory registry).
type amfPWSStatus struct {
	MessageIdentifier int             `json:"message_identifier"`
	SerialNumber      int             `json:"serial_number"`
	GNBsTargeted      int             `json:"gnbs_targeted"`
	GNBsCompleted     int             `json:"gnbs_completed"`
	GNBsCancelled     int             `json:"gnbs_cancelled"`
	Cancelled         bool            `json:"cancelled"`
	CreatedAt         string          `json:"created_at"`
	PerGNB            json.RawMessage `json:"per_gnb"`
}

// pwsMergedStatus is what the portal returns to the UI: the CBC's persisted
// content (text/language/DCS — which the AMF status does not carry) enriched
// with the AMF's live per-gNB completion state when available.
type pwsMergedStatus struct {
	MessageIdentifier int             `json:"message_identifier"`
	SerialNumber      int             `json:"serial_number"`
	DataCodingScheme  *int            `json:"data_coding_scheme,omitempty"`
	Language          string          `json:"language,omitempty"`
	WarningType       string          `json:"warning_type,omitempty"`
	MessageText       string          `json:"message_text,omitempty"`
	GNBsTargeted      int             `json:"gnbs_targeted"`
	GNBsCompleted     int             `json:"gnbs_completed"`
	GNBsCancelled     int             `json:"gnbs_cancelled"`
	Cancelled         bool            `json:"cancelled"`
	Live              bool            `json:"live"` // AMF currently has runtime state for this warning
	Stored            bool            `json:"stored"`
	CreatedAt         string          `json:"created_at,omitempty"`
	PerGNB            json.RawMessage `json:"per_gnb,omitempty"`
}

// ---- AMF forwarding helper ------------------------------------------------

// forwardToAMF sends a request to the AMF mgmt API and returns its status +
// body. Used by the handlers that need to inspect the outcome (to decide
// whether to persist) rather than blindly stream it back.
func (d *Deps) forwardToAMF(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	if d.AMFBaseURL == "" {
		return 0, nil, fmt.Errorf("AMF management API not configured")
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, d.AMFBaseURL+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, respBody, nil
}

// writeRawJSON relays an already-serialized JSON body (e.g. the AMF's response)
// with a chosen status, unlike the value-encoding writeJSON in helpers.go.
func writeRawJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// ---- handlers -------------------------------------------------------------

// handlePWSBroadcast triggers a Write-Replace Warning broadcast and persists it
// in the CBC store of record. POST /api/v1/pws/broadcast.
// Ref: TS 38.413 §8.9.1, TS 23.041.
func (d *Deps) handlePWSBroadcast(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, fmt.Sprintf("read request body: %v", err), http.StatusBadRequest)
		return
	}
	var req pwsBroadcastRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	status, respBody, err := d.forwardToAMF(r.Context(), http.MethodPost, "/amf/v1/pws/broadcast", raw)
	if err != nil {
		http.Error(w, fmt.Sprintf("AMF mgmt API unreachable: %v", err), http.StatusBadGateway)
		return
	}
	// Persist only on AMF acceptance (202), so the CBC store reflects what was
	// actually relayed to the RAN.
	if status >= 200 && status < 300 && d.Store != nil {
		if perr := d.Store.UpsertPWSBroadcast(r.Context(), req.toStore()); perr != nil {
			// Non-fatal: the broadcast already went out; log-and-continue.
			// (the portal has no logger dep here; surface via header for debug)
			w.Header().Set("X-PWS-Persist-Warning", perr.Error())
		}
	}
	writeRawJSON(w, status, respBody)
}

// handlePWSCancel stops an active broadcast and marks the CBC store cancelled.
// POST /api/v1/pws/cancel. Ref: TS 38.413 §8.9.2.
func (d *Deps) handlePWSCancel(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, fmt.Sprintf("read request body: %v", err), http.StatusBadRequest)
		return
	}
	var key pwsKeyRequest
	_ = json.Unmarshal(raw, &key)

	status, respBody, err := d.forwardToAMF(r.Context(), http.MethodPost, "/amf/v1/pws/cancel", raw)
	if err != nil {
		http.Error(w, fmt.Sprintf("AMF mgmt API unreachable: %v", err), http.StatusBadGateway)
		return
	}
	// Mark cancelled in the CBC store whenever the operator intended a cancel and
	// the AMF accepted it — OR when the AMF has no record (404) but we do, so a
	// post-restart cancel of a stored warning is still reflected.
	if d.Store != nil && (status == http.StatusAccepted || status == http.StatusNotFound) {
		_ = d.Store.MarkPWSCancelled(r.Context(), key.MessageIdentifier, key.SerialNumber)
	}
	writeRawJSON(w, status, respBody)
}

// handlePWSList returns every warning the CBC has broadcast, reconciled with the
// AMF's live per-gNB completion status. GET /api/v1/pws/broadcast.
func (d *Deps) handlePWSList(w http.ResponseWriter, r *http.Request) {
	// AMF live status (best-effort — may be empty after an AMF restart).
	var amfList []amfPWSStatus
	if status, body, err := d.forwardToAMF(r.Context(), http.MethodGet, "/amf/v1/pws/broadcast", nil); err == nil && status == http.StatusOK {
		_ = json.Unmarshal(body, &amfList)
	}

	// Without a store, fall back to the raw AMF view (graceful degradation).
	if d.Store == nil {
		writeJSON(w, http.StatusOK, amfListToMerged(amfList))
		return
	}

	stored, err := d.Store.ListPWSBroadcasts(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf("list PWS broadcasts: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, mergePWS(stored, amfList))
}

// handlePWSResend re-drives a stored warning to the RAN (the CBC re-broadcast
// after an AMF/gNB restoration event). POST /api/v1/pws/resend.
func (d *Deps) handlePWSResend(w http.ResponseWriter, r *http.Request) {
	if d.Store == nil {
		http.Error(w, "persistence not configured", http.StatusServiceUnavailable)
		return
	}
	var key pwsKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&key); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	rec, err := d.Store.GetPWSBroadcast(r.Context(), key.MessageIdentifier, key.SerialNumber)
	if err != nil {
		http.Error(w, fmt.Sprintf("load stored broadcast: %v", err), http.StatusInternalServerError)
		return
	}
	if rec == nil {
		http.Error(w, "no stored broadcast with that message identifier + serial number", http.StatusNotFound)
		return
	}

	body, _ := json.Marshal(storeToRequest(rec))
	status, respBody, err := d.forwardToAMF(r.Context(), http.MethodPost, "/amf/v1/pws/broadcast", body)
	if err != nil {
		http.Error(w, fmt.Sprintf("AMF mgmt API unreachable: %v", err), http.StatusBadGateway)
		return
	}
	if status >= 200 && status < 300 {
		// Re-broadcast refreshes created_at and clears the cancelled flag.
		_ = d.Store.UpsertPWSBroadcast(r.Context(), *rec)
	}
	writeRawJSON(w, status, respBody)
}

// ---- conversions + merge --------------------------------------------------

func intOr(p *int, def int) int {
	if p != nil {
		return *p
	}
	return def
}

// toStore maps a broadcast request to the persisted record, applying the same
// defaults the AMF does so the CBC store reflects the effective broadcast.
func (req pwsBroadcastRequest) toStore() store.PWSBroadcast {
	warningType := req.WarningType
	if warningType == "" {
		warningType = "1000" // AMF default (TS 23.041 §9.4.1.2.6)
	}
	tacs := make([]int32, 0, len(req.WarningAreaTACs))
	for _, t := range req.WarningAreaTACs {
		tacs = append(tacs, int32(t))
	}
	return store.PWSBroadcast{
		MessageIdentifier:  intOr(req.MessageIdentifier, 0x1112),
		SerialNumber:       intOr(req.SerialNumber, 1),
		DataCodingScheme:   intOr(req.DataCodingScheme, 0x0F),
		Language:           req.Language,
		WarningType:        warningType,
		RepetitionPeriod:   intOr(req.RepetitionPeriod, 4096),
		NumberOfBroadcasts: intOr(req.NumberOfBroadcasts, 1),
		MessageText:        req.MessageText,
		WarningAreaTACs:    tacs,
	}
}

// storeToRequest reconstructs a broadcast request from a stored record.
func storeToRequest(b *store.PWSBroadcast) pwsBroadcastRequest {
	tacs := make([]int, 0, len(b.WarningAreaTACs))
	for _, t := range b.WarningAreaTACs {
		tacs = append(tacs, int(t))
	}
	mi, sn := b.MessageIdentifier, b.SerialNumber
	rp, nb, dcs := b.RepetitionPeriod, b.NumberOfBroadcasts, b.DataCodingScheme
	return pwsBroadcastRequest{
		MessageIdentifier:  &mi,
		SerialNumber:       &sn,
		RepetitionPeriod:   &rp,
		NumberOfBroadcasts: &nb,
		WarningType:        b.WarningType,
		DataCodingScheme:   &dcs,
		Language:           b.Language,
		MessageText:        b.MessageText,
		WarningAreaTACs:    tacs,
	}
}

// mergePWS reconciles the CBC store (authoritative content + cancelled flag)
// with the AMF's live per-gNB status. Stored warnings the AMF no longer knows
// (post-restart) get live:false; AMF-only warnings (sent bypassing the portal)
// are appended with stored:false. Newest first.
func mergePWS(stored []store.PWSBroadcast, amf []amfPWSStatus) []pwsMergedStatus {
	amfByKey := make(map[[2]int]amfPWSStatus, len(amf))
	for _, a := range amf {
		amfByKey[[2]int{a.MessageIdentifier, a.SerialNumber}] = a
	}

	out := make([]pwsMergedStatus, 0, len(stored)+len(amf))
	seen := make(map[[2]int]bool)
	for _, b := range stored {
		key := [2]int{b.MessageIdentifier, b.SerialNumber}
		seen[key] = true
		dcs := b.DataCodingScheme
		m := pwsMergedStatus{
			MessageIdentifier: b.MessageIdentifier,
			SerialNumber:      b.SerialNumber,
			DataCodingScheme:  &dcs,
			Language:          b.Language,
			WarningType:       b.WarningType,
			MessageText:       b.MessageText,
			Cancelled:         b.Cancelled,
			Stored:            true,
			CreatedAt:         b.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		}
		if a, ok := amfByKey[key]; ok {
			m.Live = true
			m.GNBsTargeted = a.GNBsTargeted
			m.GNBsCompleted = a.GNBsCompleted
			m.GNBsCancelled = a.GNBsCancelled
			m.Cancelled = m.Cancelled || a.Cancelled
			m.PerGNB = a.PerGNB
		}
		out = append(out, m)
	}
	// AMF-only entries (not persisted — e.g. sent directly to the AMF API).
	for _, a := range amf {
		if seen[[2]int{a.MessageIdentifier, a.SerialNumber}] {
			continue
		}
		out = append(out, amfStatusToMerged(a))
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

func amfStatusToMerged(a amfPWSStatus) pwsMergedStatus {
	return pwsMergedStatus{
		MessageIdentifier: a.MessageIdentifier,
		SerialNumber:      a.SerialNumber,
		GNBsTargeted:      a.GNBsTargeted,
		GNBsCompleted:     a.GNBsCompleted,
		GNBsCancelled:     a.GNBsCancelled,
		Cancelled:         a.Cancelled,
		Live:              true,
		Stored:            false,
		CreatedAt:         a.CreatedAt,
		PerGNB:            a.PerGNB,
	}
}

// amfListToMerged is the no-store fallback: present the AMF list unchanged.
func amfListToMerged(amf []amfPWSStatus) []pwsMergedStatus {
	out := make([]pwsMergedStatus, 0, len(amf))
	for _, a := range amf {
		out = append(out, amfStatusToMerged(a))
	}
	return out
}
