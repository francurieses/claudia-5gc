package api

// qos.go — QoS / PDU session management endpoints.
//
// These proxy the SMF internal management API (/nsmf-management/v1, shares the
// SBI listener → mTLS client) and the UDM Nudm_SDM sm-data resource. The portal
// adds no logic beyond pass-through + error normalisation; the SMF performs the
// NW-initiated PDU Session Modification (TS 23.502 §4.3.3.2).

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
)

// proxyJSON forwards a request to upstream and relays the JSON response with
// its status code. Body may be nil for GETs.
func (d Deps) proxyJSON(w http.ResponseWriter, r *http.Request, method, upstream string, body io.Reader) {
	req, err := http.NewRequestWithContext(r.Context(), method, upstream, body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := d.MTLSClient.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("upstream %s: %v", upstream, err))
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 8<<20))
}

// GET /api/v1/qos/sessions → SMF GET /nsmf-management/v1/sessions
func (d Deps) handleQoSListSessions(w http.ResponseWriter, r *http.Request) {
	d.proxyJSON(w, r, http.MethodGet,
		strings.TrimRight(d.SMFBaseURL, "/")+"/nsmf-management/v1/sessions", nil)
}

// GET /api/v1/qos/sessions/{psi}?supi=... → SMF GET /nsmf-management/v1/sessions/{psi}
func (d Deps) handleQoSGetSession(w http.ResponseWriter, r *http.Request) {
	psi := chi.URLParam(r, "psi")
	u := strings.TrimRight(d.SMFBaseURL, "/") + "/nsmf-management/v1/sessions/" + url.PathEscape(psi)
	if supi := r.URL.Query().Get("supi"); supi != "" {
		u += "?supi=" + url.QueryEscape(supi)
	}
	d.proxyJSON(w, r, http.MethodGet, u, nil)
}

// POST /api/v1/qos/sessions/{psi}/modify → SMF POST /nsmf-management/v1/sessions/{psi}/qos
// Body: {"5qi": <int>, "reason": "<string>", "supi": "...", "ambr_dl_mbps": n, "ambr_ul_mbps": n}
// Triggers the NW-initiated PDU Session Modification (TS 23.502 §4.3.3.2).
func (d Deps) handleQoSModifySession(w http.ResponseWriter, r *http.Request) {
	psi := chi.URLParam(r, "psi")
	u := strings.TrimRight(d.SMFBaseURL, "/") + "/nsmf-management/v1/sessions/" + url.PathEscape(psi) + "/qos"
	d.proxyJSON(w, r, http.MethodPost, u, r.Body)
}

// GET /api/v1/qos/subscription/{supi} → UDM GET /nudm-sdm/v2/{supi}/sm-data
func (d Deps) handleQoSSubscription(w http.ResponseWriter, r *http.Request) {
	supi := chi.URLParam(r, "supi")
	u := strings.TrimRight(d.UDMBaseURL, "/") + "/nudm-sdm/v2/" + url.PathEscape(supi) + "/sm-data"
	d.proxyJSON(w, r, http.MethodGet, u, nil)
}
