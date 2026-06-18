package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	dockerclient "github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/docker"
)

// packetrusherScenarios defines the two scenarios in display order.
// Both containers share the same static IPs on n2-net/n3-net, so they are
// mutually exclusive: only one can run at a time.
var packetrusherScenarios = []struct{ slug, container string }{
	{"xn", "packetrusher"},
	{"n2", "packetrusher-n2"},
}

// packetrusherContainerName maps a scenario slug to its Docker container name.
func packetrusherContainerName(scenario string) (string, bool) {
	for _, s := range packetrusherScenarios {
		if s.slug == scenario {
			return s.container, true
		}
	}
	return "", false
}

// packetrusherPeer returns the container name of the OTHER scenario.
func packetrusherPeer(ctr string) string {
	if ctr == "packetrusher" {
		return "packetrusher-n2"
	}
	return "packetrusher"
}

// PacketRusherScenarioState is the state of one PacketRusher scenario container.
type PacketRusherScenarioState struct {
	Scenario  string `json:"scenario"`
	Container string `json:"container"`
	// State mirrors Docker container state plus two portal-specific values:
	//   "running" | "paused" | "exited" | "created" | "not_found" | "unknown"
	// "created" means the container exists but has never run successfully
	// (typically because the peer held the shared IPs when start was attempted).
	State  string `json:"state"`
	Status string `json:"status"` // human-readable Docker status
	Uptime string `json:"uptime,omitempty"`
}

// PacketRusherStatusResponse is returned by GET /api/v1/packetrusher/status.
type PacketRusherStatusResponse struct {
	Scenarios []PacketRusherScenarioState `json:"scenarios"`
}

// handlePacketRusherStatus returns the state of both PacketRusher scenario containers.
func (d Deps) handlePacketRusherStatus(w http.ResponseWriter, r *http.Request) {
	resp := PacketRusherStatusResponse{Scenarios: make([]PacketRusherScenarioState, 0, 2)}

	if d.Docker == nil {
		for _, s := range packetrusherScenarios {
			resp.Scenarios = append(resp.Scenarios, PacketRusherScenarioState{
				Scenario:  s.slug,
				Container: s.container,
				State:     "unknown",
			})
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	svcs, err := d.Docker.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	byName := make(map[string]dockerclient.Service, len(svcs))
	for _, s := range svcs {
		byName[s.Name] = s
	}

	for _, sc := range packetrusherScenarios {
		st := PacketRusherScenarioState{
			Scenario:  sc.slug,
			Container: sc.container,
			State:     "not_found",
		}
		if svc, ok := byName[sc.container]; ok {
			st.State  = svc.State
			st.Status = svc.Status
			st.Uptime = svc.Uptime
		}
		resp.Scenarios = append(resp.Scenarios, st)
	}

	writeJSON(w, http.StatusOK, resp)
}

// startResponse is the JSON body returned by the start endpoint.
type startResponse struct {
	Status      string `json:"status"`
	Container   string `json:"container"`
	StoppedPeer string `json:"stopped_peer,omitempty"`
}

// handlePacketRusherStart starts (or re-starts) a scenario container.
//
// Both PacketRusher scenarios bind the same static IPs on n2-net and n3-net,
// so they cannot run simultaneously. This handler automatically stops the peer
// container before starting the requested one, making switching transparent.
func (d Deps) handlePacketRusherStart(w http.ResponseWriter, r *http.Request) {
	ctr, ok := d.resolvePacketRusherContainer(w, r)
	if !ok {
		return
	}

	var stoppedPeer string

	// Stop the peer if it currently holds the shared network addresses.
	peer := packetrusherPeer(ctr)
	svcs, err := d.Docker.List(r.Context())
	if err == nil {
		for _, s := range svcs {
			if s.Name == peer && (s.State == "running" || s.State == "paused") {
				if stopErr := d.Docker.Stop(r.Context(), peer); stopErr == nil {
					stoppedPeer = peer
				}
				break
			}
		}
	}

	if err := d.Docker.Start(r.Context(), ctr); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, startResponse{
		Status:      "started",
		Container:   ctr,
		StoppedPeer: stoppedPeer,
	})
}

// handlePacketRusherStop stops a running scenario container.
func (d Deps) handlePacketRusherStop(w http.ResponseWriter, r *http.Request) {
	ctr, ok := d.resolvePacketRusherContainer(w, r)
	if !ok {
		return
	}
	if err := d.Docker.Stop(r.Context(), ctr); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopped", "container": ctr})
}

// handlePacketRusherPause pauses a running scenario container (SIGSTOP).
func (d Deps) handlePacketRusherPause(w http.ResponseWriter, r *http.Request) {
	ctr, ok := d.resolvePacketRusherContainer(w, r)
	if !ok {
		return
	}
	if err := d.Docker.Pause(r.Context(), ctr); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "paused", "container": ctr})
}

// handlePacketRusherResume unpauses a paused scenario container.
func (d Deps) handlePacketRusherResume(w http.ResponseWriter, r *http.Request) {
	ctr, ok := d.resolvePacketRusherContainer(w, r)
	if !ok {
		return
	}
	if err := d.Docker.Unpause(r.Context(), ctr); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "running", "container": ctr})
}

// resolvePacketRusherContainer extracts and validates the scenario URL param,
// checks Docker availability, and returns the container name.
func (d Deps) resolvePacketRusherContainer(w http.ResponseWriter, r *http.Request) (string, bool) {
	scenario := chi.URLParam(r, "scenario")
	ctr, ok := packetrusherContainerName(scenario)
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown scenario: use 'xn' or 'n2'")
		return "", false
	}
	if d.Docker == nil {
		writeError(w, http.StatusServiceUnavailable, "docker unavailable")
		return "", false
	}
	return ctr, true
}
