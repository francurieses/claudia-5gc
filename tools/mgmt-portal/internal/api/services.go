package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	dockerclient "github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/docker"
)

func (d Deps) handleListServices(w http.ResponseWriter, r *http.Request) {
	if d.Docker == nil {
		writeJSON(w, http.StatusOK, []dockerclient.Service{})
		return
	}
	svcs, err := d.Docker.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if svcs == nil {
		svcs = []dockerclient.Service{}
	}
	writeJSON(w, http.StatusOK, svcs)
}

func (d Deps) handleServiceStart(w http.ResponseWriter, r *http.Request) {
	if d.Docker == nil {
		writeError(w, http.StatusServiceUnavailable, "docker unavailable")
		return
	}
	name := chi.URLParam(r, "name")
	if err := d.Docker.Start(r.Context(), name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "started"})
}

func (d Deps) handleServiceStop(w http.ResponseWriter, r *http.Request) {
	if d.Docker == nil {
		writeError(w, http.StatusServiceUnavailable, "docker unavailable")
		return
	}
	name := chi.URLParam(r, "name")
	if err := d.Docker.Stop(r.Context(), name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopped"})
}

func (d Deps) handleServiceRestart(w http.ResponseWriter, r *http.Request) {
	if d.Docker == nil {
		writeError(w, http.StatusServiceUnavailable, "docker unavailable")
		return
	}
	name := chi.URLParam(r, "name")
	if err := d.Docker.Restart(r.Context(), name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "restarting"})
}
