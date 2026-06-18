package api

import (
	"net/http"

	"github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/store"
)

func (d Deps) handleListSessions(w http.ResponseWriter, r *http.Request) {
	if d.Store == nil {
		writeJSON(w, http.StatusOK, []store.PDUSession{})
		return
	}
	sessions, err := d.Store.ListSessions(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if sessions == nil {
		sessions = []store.PDUSession{}
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (d Deps) handleListUEContexts(w http.ResponseWriter, r *http.Request) {
	if d.Store == nil {
		writeJSON(w, http.StatusOK, []store.UEContext{})
		return
	}
	ctxs, err := d.Store.ListUEContexts(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ctxs == nil {
		ctxs = []store.UEContext{}
	}
	writeJSON(w, http.StatusOK, ctxs)
}
