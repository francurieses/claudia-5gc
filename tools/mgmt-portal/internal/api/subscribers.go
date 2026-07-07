package api

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/store"
)

func (d Deps) handleListSubscribers(w http.ResponseWriter, r *http.Request) {
	if d.Store == nil {
		writeJSON(w, http.StatusOK, []store.Subscriber{})
		return
	}
	subs, err := d.Store.ListSubscribers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if subs == nil {
		subs = []store.Subscriber{}
	}
	writeJSON(w, http.StatusOK, subs)
}

func (d Deps) handleGetSubscriber(w http.ResponseWriter, r *http.Request) {
	if d.Store == nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	supi := chi.URLParam(r, "supi")
	sub, err := d.Store.GetSubscriber(r.Context(), supi)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if sub == nil {
		writeError(w, http.StatusNotFound, "subscriber not found")
		return
	}
	writeJSON(w, http.StatusOK, sub)
}

func (d Deps) handleCreateSubscriber(w http.ResponseWriter, r *http.Request) {
	if d.Store == nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	var sub store.Subscriber
	if err := decodeJSON(r, &sub); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if sub.SUPI == "" || sub.K == "" || sub.OPc == "" {
		writeError(w, http.StatusBadRequest, "supi, k, opc are required")
		return
	}
	if sub.AMF == "" {
		sub.AMF = "b9b9"
	}
	if sub.SQN == "" {
		sub.SQN = "000000000020"
	}
	if sub.AMBRUL == 0 {
		sub.AMBRUL = 100000
	}
	if sub.AMBRDL == 0 {
		sub.AMBRDL = 100000
	}
	if sub.Slices == nil {
		sub.Slices = []store.SNSSAI{}
	}

	if err := d.Store.UpsertSubscriber(r.Context(), sub, false); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"supi": sub.SUPI})
}

func (d Deps) handleUpdateSubscriber(w http.ResponseWriter, r *http.Request) {
	if d.Store == nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	supi := chi.URLParam(r, "supi")
	var sub store.Subscriber
	if err := decodeJSON(r, &sub); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sub.SUPI = supi
	if sub.K == "" || sub.OPc == "" {
		writeError(w, http.StatusBadRequest, "k and opc are required — an empty value would wipe the subscriber's key material")
		return
	}
	if sub.Slices == nil {
		sub.Slices = []store.SNSSAI{}
	}

	// preserveSQN: the SQN advances on every authentication; writing back the
	// value the form read would rewind it and break UERANSIM key derivation
	// (SMC integrity failure). See UpsertSubscriber.
	if err := d.Store.UpsertSubscriber(r.Context(), sub, true); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Trigger NW-initiated deregistration so the UE re-registers and AMF re-fetches
	// subscription data (AllowedNSSAI) from UDM/UDR. Without this, a registered UE
	// would keep using the stale AllowedNSSAI from its existing in-memory context.
	// Best-effort: the DB update is already committed regardless of this outcome.
	deregistered := d.deregisterUE(r.Context(), supi)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"supi":         supi,
		"deregistered": deregistered,
	})
}

// deregisterUE calls the AMF management API to initiate NW-initiated deregistration
// for the given SUPI. Returns true if the AMF accepted the request (UE was registered).
// Returns false if the UE was not registered or the AMF is unreachable.
func (d Deps) deregisterUE(ctx context.Context, supi string) bool {
	if d.AMFBaseURL == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		d.AMFBaseURL+"/amf/v1/ue-contexts/"+supi, nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusAccepted
}

func (d Deps) handleDeleteSubscriber(w http.ResponseWriter, r *http.Request) {
	if d.Store == nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	supi := chi.URLParam(r, "supi")
	if err := d.Store.DeleteSubscriber(r.Context(), supi); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
