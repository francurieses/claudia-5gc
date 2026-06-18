package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/store"
)

// ---- Policy (URSP) CRUD handlers ----------------------------------------
// Ref: TS 24.526 (URSP encoding), TS 29.525 (Npcf_UEPolicyControl)

// GET /api/v1/policies
func (d Deps) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	if d.Store == nil {
		writeJSON(w, http.StatusOK, []store.PolicySubscription{})
		return
	}
	policies, err := d.Store.ListPolicies(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if policies == nil {
		policies = []store.PolicySubscription{}
	}
	writeJSON(w, http.StatusOK, policies)
}

// GET /api/v1/policies/{id}
func (d Deps) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if d.Store == nil {
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}
	p, err := d.Store.GetPolicy(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if p == nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// POST /api/v1/policies
func (d Deps) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	if d.Store == nil {
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}
	var p store.PolicySubscription
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p.ID = "" // ensure auto-generate
	if err := d.Store.UpsertPolicy(r.Context(), p); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// PUT /api/v1/policies/{id}
func (d Deps) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if d.Store == nil {
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}
	var p store.PolicySubscription
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p.ID = id
	if err := d.Store.UpsertPolicy(r.Context(), p); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DELETE /api/v1/policies/{id}
func (d Deps) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if d.Store == nil {
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := d.Store.DeletePolicy(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Policy Template CRUD handlers ----------------------------------------
// Templates are portal-managed (portal_policy_templates table); they are not
// per-subscriber policies but reusable rule sets for each network slice.

// GET /api/v1/policy-templates
func (d Deps) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	if d.Store == nil {
		writeJSON(w, http.StatusOK, []store.PolicyTemplate{})
		return
	}
	templates, err := d.Store.ListTemplates(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if templates == nil {
		templates = []store.PolicyTemplate{}
	}
	writeJSON(w, http.StatusOK, templates)
}

// GET /api/v1/policy-templates/{id}
func (d Deps) handleGetTemplate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if d.Store == nil {
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}
	t, err := d.Store.GetTemplate(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if t == nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// POST /api/v1/policy-templates
func (d Deps) handleCreateTemplate(w http.ResponseWriter, r *http.Request) {
	if d.Store == nil {
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}
	var t store.PolicyTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	t.ID = ""
	if err := d.Store.UpsertTemplate(r.Context(), t); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// PUT /api/v1/policy-templates/{id}
func (d Deps) handleUpdateTemplate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if d.Store == nil {
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}
	var t store.PolicyTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	t.ID = id
	if err := d.Store.UpsertTemplate(r.Context(), t); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DELETE /api/v1/policy-templates/{id}
func (d Deps) handleDeleteTemplate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if d.Store == nil {
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := d.Store.DeleteTemplate(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/v1/policy-templates/{id}/apply
// Body: {"supi":"imsi-..."}
// Writes per-subscriber policy to subscription_policy (shared with UDR),
// then triggers AMF UCU to push fresh URSP to the UE.
// Returns: {"status":"pushed"} | {"status":"stored","warning":"..."}
func (d Deps) handleApplyTemplate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if d.Store == nil {
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}

	var body struct {
		SUPI string `json:"supi"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.SUPI == "" {
		writeError(w, http.StatusBadRequest, "supi required")
		return
	}

	t, err := d.Store.GetTemplate(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if t == nil {
		http.NotFound(w, r)
		return
	}

	// Replace per-subscriber policy in subscription_policy (UDR reads this table).
	// SetSubscriberPolicy deletes any stale rows for the same SUPI before inserting,
	// so repeated "Apply to UE" calls don't accumulate duplicate rows.
	if err := d.Store.SetSubscriberPolicy(r.Context(), body.SUPI, t.Precedence, t.Rules); err != nil {
		writeError(w, http.StatusInternalServerError, "store policy: "+err.Error())
		return
	}

	// Trigger on-demand UCU push via AMF management API
	if d.AMFBaseURL == "" {
		writeJSON(w, http.StatusOK, map[string]string{"status": "stored"})
		return
	}
	url := fmt.Sprintf("%s/amf/v1/ue-contexts/%s/push-policies", d.AMFBaseURL, body.SUPI)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, url, bytes.NewReader(nil))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "stored", "warning": err.Error()})
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "stored", "warning": "AMF push failed: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		writeJSON(w, http.StatusOK, map[string]string{"status": "pushed"})
	case http.StatusConflict:
		writeJSON(w, http.StatusOK, map[string]string{
			"status":  "stored",
			"warning": "UE is CM-IDLE — policy delivery deferred until next registration",
		})
	case http.StatusNotFound:
		writeJSON(w, http.StatusOK, map[string]string{
			"status":  "stored",
			"warning": "UE not registered — policy will be delivered on next registration",
		})
	default:
		writeJSON(w, http.StatusOK, map[string]string{
			"status":  "stored",
			"warning": fmt.Sprintf("AMF returned %d", resp.StatusCode),
		})
	}
}

// POST /api/v1/policies/push/{supi}
// Triggers on-demand UCU for a registered UE by calling the AMF management API.
// Ref: TS 23.502 §4.2.4
func (d Deps) handlePushPolicies(w http.ResponseWriter, r *http.Request) {
	supi := chi.URLParam(r, "supi")
	if d.AMFBaseURL == "" {
		http.Error(w, "AMF base URL not configured", http.StatusServiceUnavailable)
		return
	}

	url := fmt.Sprintf("%s/amf/v1/ue-contexts/%s/push-policies", d.AMFBaseURL, supi)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, url, bytes.NewReader(nil))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		w.WriteHeader(http.StatusNoContent)
	case http.StatusConflict:
		http.Error(w, "UE is CM-IDLE — policy delivery deferred", http.StatusConflict)
	case http.StatusNotFound:
		http.NotFound(w, r)
	default:
		http.Error(w, fmt.Sprintf("AMF returned %d", resp.StatusCode), http.StatusBadGateway)
	}
}
