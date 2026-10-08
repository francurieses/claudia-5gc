package api

import (
	"context"
	"log/slog"
	"net/http"

	dockerclient "github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/docker"
	"github.com/go-chi/chi/v5"
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
	status, body, err := startOrRestart(r.Context(), d.Docker, name, false)
	if err != nil {
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, status, body)
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
	status, body, err := startOrRestart(r.Context(), d.Docker, name, true)
	if err != nil {
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, status, body)
}

// serviceLifecycle is the subset of the Docker client used by the start and
// restart handlers. *dockerclient.Client satisfies it; tests fake it.
type serviceLifecycle interface {
	Start(ctx context.Context, name string) error
	Restart(ctx context.Context, name string) error
	RestartNetnsSidecars(ctx context.Context, name string) ([]string, map[string]error)
}

// serviceActionResponse is the JSON body of a successful start/restart.
// Status keeps its historical values ("started" / "restarting"); Sidecars
// lists the netns sidecars (e.g. "amf-pcap") restarted so they re-join the
// container's new network namespace; SidecarErrors holds best-effort failures.
type serviceActionResponse struct {
	Status        string            `json:"status"`
	Sidecars      []string          `json:"sidecars,omitempty"`
	SidecarErrors map[string]string `json:"sidecar_errors,omitempty"`
}

// startOrRestart starts (restart=false) or restarts container name, then
// restarts any PCAP sidecar sharing its network namespace. A container
// restart/start gets a fresh netns, leaving a "network_mode: service:<nf>"
// sidecar attached to the dead one (capture silently stops). Sidecar recovery
// is best-effort: failures are logged and reported but never fail the request.
func startOrRestart(ctx context.Context, dc serviceLifecycle, name string, restart bool) (int, serviceActionResponse, error) {
	op, status := "start", "started"
	act := dc.Start
	if restart {
		op, status, act = "restart", "restarting", dc.Restart
	}
	if err := act(ctx, name); err != nil {
		return http.StatusInternalServerError, serviceActionResponse{}, err
	}
	resp := serviceActionResponse{Status: status}
	sidecars, errs := dc.RestartNetnsSidecars(ctx, name)
	resp.Sidecars = sidecars
	for sc, err := range errs {
		slog.Warn("services: netns sidecar restart failed",
			"op", op, "container", name, "sidecar", sc, "error", err)
		if resp.SidecarErrors == nil {
			resp.SidecarErrors = make(map[string]string, len(errs))
		}
		resp.SidecarErrors[sc] = err.Error()
	}
	for _, sc := range sidecars {
		slog.Info("services: netns sidecar restarted", "op", op, "container", name, "sidecar", sc)
	}
	return http.StatusOK, resp, nil
}
