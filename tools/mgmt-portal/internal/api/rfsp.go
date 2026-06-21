package api

// rfsp.go — per-subscriber RFSP (Radio Frequency Selection Priority) management.
//
// The portal proxies an in-memory per-subscriber override held by the PCF
// (PUT/GET/DELETE /pcf-internal/v1/subscribers/{supi}/am-policy-override). The PCF
// applies the override the next time the AMF creates the AM policy association — i.e.
// at the UE's next registration — so a PUT/DELETE also triggers a NW-initiated
// deregistration to re-apply it live.
//
// Ref: TS 38.413 §9.3.1.27 (IndexToRFSP), TS 23.501 §5.3.4.2, TS 29.507 §4.2.2.2

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// defaultRFSP mirrors the AMF operator default (operator.default_rfsp). When no PCF
// override exists, this is the value the subscriber's UE receives.
const defaultRFSP = 1

// handleGetSubscriberRFSP returns the subscriber's effective RFSP and whether it is a
// per-subscriber override or the operator default.
// GET /api/v1/subscribers/{supi}/rfsp → {"supi","rfsp","source":"override"|"default"}
func (d Deps) handleGetSubscriberRFSP(w http.ResponseWriter, r *http.Request) {
	supi := chi.URLParam(r, "supi")
	if d.PCFBaseURL == "" || d.MTLSClient == nil {
		writeJSON(w, http.StatusOK, map[string]any{"supi": supi, "rfsp": defaultRFSP, "source": "default"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	u := strings.TrimRight(d.PCFBaseURL, "/") +
		"/pcf-internal/v1/subscribers/" + url.PathEscape(supi) + "/am-policy-override"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	res, err := d.MTLSClient.Do(req)
	if err != nil {
		// PCF unreachable — report the operator default rather than failing the page.
		writeJSON(w, http.StatusOK, map[string]any{"supi": supi, "rfsp": defaultRFSP, "source": "default"})
		return
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		writeJSON(w, http.StatusOK, map[string]any{"supi": supi, "rfsp": defaultRFSP, "source": "default"})
		return
	}
	if res.StatusCode != http.StatusOK {
		writeJSON(w, http.StatusOK, map[string]any{"supi": supi, "rfsp": defaultRFSP, "source": "default"})
		return
	}
	var ov struct {
		RFSP int `json:"rfsp"`
	}
	_ = json.NewDecoder(res.Body).Decode(&ov)
	writeJSON(w, http.StatusOK, map[string]any{"supi": supi, "rfsp": ov.RFSP, "source": "override"})
}

// handleSetSubscriberRFSP stores a per-subscriber RFSP override in the PCF and triggers
// a NW-initiated deregistration so the UE re-registers and picks up the new value.
// PUT /api/v1/subscribers/{supi}/rfsp  body: {"rfsp": <1-256>}
func (d Deps) handleSetSubscriberRFSP(w http.ResponseWriter, r *http.Request) {
	supi := chi.URLParam(r, "supi")
	var body struct {
		RFSP int `json:"rfsp"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.RFSP < 1 || body.RFSP > 256 {
		writeError(w, http.StatusBadRequest, "rfsp must be in range 1-256")
		return
	}
	if d.PCFBaseURL == "" || d.MTLSClient == nil {
		writeError(w, http.StatusServiceUnavailable, "PCF not configured")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	payload, _ := json.Marshal(map[string]int{"rfsp": body.RFSP})
	u := strings.TrimRight(d.PCFBaseURL, "/") +
		"/pcf-internal/v1/subscribers/" + url.PathEscape(supi) + "/am-policy-override"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	res, err := d.MTLSClient.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "PCF unreachable: "+err.Error())
		return
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		writeError(w, http.StatusBadGateway, "PCF returned "+res.Status+": "+string(b))
		return
	}

	// Re-apply live: a registered UE keeps its current RFSP until it re-registers.
	deregistered := d.deregisterUE(ctx, supi)
	writeJSON(w, http.StatusOK, map[string]any{
		"supi":         supi,
		"rfsp":         body.RFSP,
		"source":       "override",
		"deregistered": deregistered,
	})
}

// handleDeleteSubscriberRFSP clears the per-subscriber RFSP override so the subscriber
// reverts to the operator default, and triggers a re-registration to apply it.
// DELETE /api/v1/subscribers/{supi}/rfsp
func (d Deps) handleDeleteSubscriberRFSP(w http.ResponseWriter, r *http.Request) {
	supi := chi.URLParam(r, "supi")
	if d.PCFBaseURL == "" || d.MTLSClient == nil {
		writeError(w, http.StatusServiceUnavailable, "PCF not configured")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	u := strings.TrimRight(d.PCFBaseURL, "/") +
		"/pcf-internal/v1/subscribers/" + url.PathEscape(supi) + "/am-policy-override"
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	res, err := d.MTLSClient.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "PCF unreachable: "+err.Error())
		return
	}
	defer res.Body.Close()
	// 404 means there was no override — treat as success (idempotent reset to default).
	if res.StatusCode != http.StatusNoContent && res.StatusCode != http.StatusNotFound {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		writeError(w, http.StatusBadGateway, "PCF returned "+res.Status+": "+string(b))
		return
	}

	deregistered := d.deregisterUE(ctx, supi)
	writeJSON(w, http.StatusOK, map[string]any{
		"supi":         supi,
		"rfsp":         defaultRFSP,
		"source":       "default",
		"deregistered": deregistered,
	})
}
