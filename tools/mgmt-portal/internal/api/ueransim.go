package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/store"
)

// ueContainer carries container state plus its UERANSIM role.
type ueContainer struct {
	Name    string `json:"name"`
	State   string `json:"state"`
	Status  string `json:"status"`
	Uptime  string `json:"uptime"`
	Role    string `json:"role"` // "gnb" | "ue"
}

// ueEntry combines an AMF UE context with its PDU sessions and a hint about
// which Docker container most likely runs the corresponding nr-ue process.
type ueEntry struct {
	store.UEContext
	Sessions  []store.PDUSession `json:"sessions"`
	Container string             `json:"container,omitempty"`
}

// UERANSIMStatusResponse is returned by GET /api/v1/ueransim/status.
type UERANSIMStatusResponse struct {
	Containers []ueContainer `json:"containers"`
	UEs        []ueEntry     `json:"ues"`
}

// handleUERANSIMStatus returns the combined UERANSIM runtime state:
// container list + registered UE contexts merged with their PDU sessions.
func (d Deps) handleUERANSIMStatus(w http.ResponseWriter, r *http.Request) {
	resp := UERANSIMStatusResponse{
		Containers: []ueContainer{},
		UEs:        []ueEntry{},
	}

	// 1. UERANSIM containers
	runningUEContainers := []string{}
	if d.Docker != nil {
		svcs, err := d.Docker.List(r.Context())
		if err == nil {
			for _, svc := range svcs {
				if !strings.HasPrefix(svc.Name, "ueransim-") {
					continue
				}
				role := "ue"
				if strings.Contains(svc.Name, "gnb") {
					role = "gnb"
				}
				resp.Containers = append(resp.Containers, ueContainer{
					Name:   svc.Name,
					State:  svc.State,
					Status: svc.Status,
					Uptime: svc.Uptime,
					Role:   role,
				})
				if role == "ue" && svc.State == "running" {
					runningUEContainers = append(runningUEContainers, svc.Name)
				}
			}
		}
	}

	// 2. UE contexts + sessions from PostgreSQL
	if d.Store != nil {
		ctxs, err := d.Store.ListUEContexts(r.Context())
		if err != nil {
			ctxs = []store.UEContext{}
		}
		sessions, err := d.Store.ListSessions(r.Context())
		if err != nil {
			sessions = []store.PDUSession{}
		}

		// Index sessions by SUPI for fast lookup
		sessionsBySUPI := make(map[string][]store.PDUSession, len(sessions))
		for _, s := range sessions {
			sessionsBySUPI[s.SUPI] = append(sessionsBySUPI[s.SUPI], s)
		}

		for _, uc := range ctxs {
			entry := ueEntry{
				UEContext: uc,
				Sessions:  sessionsBySUPI[uc.SUPI],
				Container: guessUEContainer(uc.SUPI, runningUEContainers),
			}
			if entry.Sessions == nil {
				entry.Sessions = []store.PDUSession{}
			}
			resp.UEs = append(resp.UEs, entry)
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// nrCLIRequest is the body for POST /api/v1/ueransim/nr-cli.
type nrCLIRequest struct {
	Container string `json:"container"`
	SUPI      string `json:"supi"`
	Command   string `json:"command"`
}

// handleNRCLI executes an nr-cli command inside a UERANSIM UE container.
// nr-cli talks to the nr-ue process socket, so both must live in the same container.
// A 20 s timeout prevents hanging when the nr-ue process is not yet ready.
func (d Deps) handleNRCLI(w http.ResponseWriter, r *http.Request) {
	var req nrCLIRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Container == "" || req.SUPI == "" || req.Command == "" {
		writeError(w, http.StatusBadRequest, "container, supi, and command are required")
		return
	}
	if !strings.HasPrefix(req.Container, "ueransim-ue") {
		writeError(w, http.StatusBadRequest, "container must be a ueransim-ue* container")
		return
	}
	if d.Docker == nil {
		writeError(w, http.StatusServiceUnavailable, "docker not available")
		return
	}

	execCtx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	result, err := d.Docker.Exec(execCtx, req.Container, []string{
		"nr-cli", req.SUPI, "-e", req.Command,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// pingRequest is the body for POST /api/v1/ueransim/ping.
type pingRequest struct {
	Container string `json:"container"`
	UEIP      string `json:"ue_ip"` // source address passed to ping -I
	Target    string `json:"target"`
	Count     int    `json:"count"` // number of ICMP packets; clamped to [1, 20]
}

// handleUERANSIMPing runs ping inside a UERANSIM UE container, using the UE's
// assigned IP as the source interface so traffic is routed through the TUN.
func (d Deps) handleUERANSIMPing(w http.ResponseWriter, r *http.Request) {
	var req pingRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Container == "" || req.UEIP == "" || req.Target == "" {
		writeError(w, http.StatusBadRequest, "container, ue_ip, and target are required")
		return
	}
	if !strings.HasPrefix(req.Container, "ueransim-ue") {
		writeError(w, http.StatusBadRequest, "container must be a ueransim-ue* container")
		return
	}
	if net.ParseIP(req.UEIP) == nil {
		writeError(w, http.StatusBadRequest, "ue_ip must be a valid IP address")
		return
	}
	if req.Count <= 0 || req.Count > 20 {
		req.Count = 4
	}
	if d.Docker == nil {
		writeError(w, http.StatusServiceUnavailable, "docker not available")
		return
	}

	// Allow each packet its 2 s wait plus a 10 s margin for command startup/teardown.
	pingTimeout := time.Duration(req.Count*2+10) * time.Second
	execCtx, cancel := context.WithTimeout(r.Context(), pingTimeout)
	defer cancel()

	result, err := d.Docker.Exec(execCtx, req.Container, []string{
		"ping", "-c", strconv.Itoa(req.Count), "-W", "2", "-I", req.UEIP, req.Target,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// ---- Scenario management -----------------------------------------------

// scenarioDef describes one UERANSIM test scenario.
type scenarioDef struct {
	name          string
	label         string
	hint          string   // CLI make target to create the containers if not_found
	containers    []string // start order; first should be the gNB
	keyContainers []string // UE-specific containers that determine active state (excludes shared gNB)
	conflicts     []string // containers from other scenarios that must stop first
}

// ueransimScenarios lists the three supported scenarios.
// "standard" and "profile-a" share ueransim-gnb (172.30.3.3).
// "slices" uses ueransim-gnb-ms (172.30.3.4) but BOTH gnbs share the
// ueransim-gnb alias on n2-net, so only one can run at a time.
//
// keyContainers excludes ueransim-gnb for standard/profile-a because the
// shared gNB being up must not make both scenarios appear active simultaneously.
var ueransimScenarios = []scenarioDef{
	{
		name:          "standard",
		label:         "Standard (1 UE)",
		hint:          "make ueransim-only",
		containers:    []string{"ueransim-gnb", "ueransim-ue"},
		keyContainers: []string{"ueransim-ue"},
		conflicts:     []string{"ueransim-ue-profile-a", "ueransim-gnb-ms", "ueransim-ue-internet", "ueransim-ue-gold", "ueransim-ue-silver", "ueransim-ue-bronze"},
	},
	{
		name:          "slices",
		label:         "Multi-Slice (4 UEs)",
		hint:          "make ueransim-slices",
		containers:    []string{"ueransim-gnb-ms", "ueransim-ue-internet", "ueransim-ue-gold", "ueransim-ue-silver", "ueransim-ue-bronze"},
		keyContainers: []string{"ueransim-gnb-ms", "ueransim-ue-internet", "ueransim-ue-gold", "ueransim-ue-silver", "ueransim-ue-bronze"},
		conflicts:     []string{"ueransim-gnb", "ueransim-ue", "ueransim-ue-profile-a"},
	},
	{
		name:          "profile-a",
		label:         "SUCI Profile A (X25519)",
		hint:          "make ueransim-profile-a",
		containers:    []string{"ueransim-gnb", "ueransim-ue-profile-a"},
		keyContainers: []string{"ueransim-ue-profile-a"},
		conflicts:     []string{"ueransim-ue", "ueransim-gnb-ms", "ueransim-ue-internet", "ueransim-ue-gold", "ueransim-ue-silver", "ueransim-ue-bronze"},
	},
}

// ScenarioContainerState holds the Docker state of one container.
type ScenarioContainerState struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

// UERANSIMScenarioState is the combined state of one scenario.
// State values: "running" | "partial" | "stopped" | "not_found"
type UERANSIMScenarioState struct {
	Name       string                   `json:"name"`
	Label      string                   `json:"label"`
	Hint       string                   `json:"hint"`
	Containers []ScenarioContainerState `json:"containers"`
	State      string                   `json:"state"`
}

// UERANSIMScenariosResponse is returned by GET /api/v1/ueransim/scenarios.
type UERANSIMScenariosResponse struct {
	Scenarios []UERANSIMScenarioState `json:"scenarios"`
}

func (d Deps) handleUERANSIMScenarios(w http.ResponseWriter, r *http.Request) {
	resp := UERANSIMScenariosResponse{
		Scenarios: make([]UERANSIMScenarioState, 0, len(ueransimScenarios)),
	}

	var byName map[string]string
	if d.Docker != nil {
		if svcs, err := d.Docker.List(r.Context()); err == nil {
			byName = make(map[string]string, len(svcs))
			for _, s := range svcs {
				byName[s.Name] = s.State
			}
		}
	}

	for _, sc := range ueransimScenarios {
		st := UERANSIMScenarioState{
			Name:       sc.name,
			Label:      sc.label,
			Hint:       sc.hint,
			Containers: make([]ScenarioContainerState, 0, len(sc.containers)),
		}

		// Populate display state for all containers (including shared gNB).
		for _, ctr := range sc.containers {
			state := "not_found"
			if byName != nil {
				if s, ok := byName[ctr]; ok {
					state = s
				}
			}
			st.Containers = append(st.Containers, ScenarioContainerState{Name: ctr, State: state})
		}

		// Determine scenario active state from keyContainers only — this prevents
		// the shared ueransim-gnb from making both standard and profile-a appear
		// active at the same time.
		keyRunning, keyFound := 0, 0
		for _, ctr := range sc.keyContainers {
			if byName != nil {
				if s, ok := byName[ctr]; ok {
					keyFound++
					if s == "running" {
						keyRunning++
					}
				}
			}
		}
		switch {
		case keyFound == 0:
			st.State = "not_found"
		case keyRunning == len(sc.keyContainers):
			st.State = "running"
		case keyRunning > 0:
			st.State = "partial"
		default:
			st.State = "stopped"
		}
		resp.Scenarios = append(resp.Scenarios, st)
	}

	writeJSON(w, http.StatusOK, resp)
}

func (d Deps) handleUERANSIMScenarioStart(w http.ResponseWriter, r *http.Request) {
	sc := resolveScenario(chi.URLParam(r, "scenario"))
	if sc == nil {
		writeError(w, http.StatusBadRequest, "unknown scenario: use 'standard', 'slices', or 'profile-a'")
		return
	}
	if d.Docker == nil {
		writeError(w, http.StatusServiceUnavailable, "docker unavailable")
		return
	}

	// Stop conflicting containers.
	if svcs, err := d.Docker.List(r.Context()); err == nil {
		active := make(map[string]bool, len(svcs))
		for _, s := range svcs {
			if s.State == "running" || s.State == "paused" {
				active[s.Name] = true
			}
		}
		for _, ctr := range sc.conflicts {
			if active[ctr] {
				_ = d.Docker.Stop(r.Context(), ctr)
			}
		}
	}

	// Start scenario containers in order.
	for _, ctr := range sc.containers {
		if err := d.Docker.Start(r.Context(), ctr); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("start %s: %s", ctr, err))
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "started", "scenario": sc.name})
}

func (d Deps) handleUERANSIMScenarioStop(w http.ResponseWriter, r *http.Request) {
	sc := resolveScenario(chi.URLParam(r, "scenario"))
	if sc == nil {
		writeError(w, http.StatusBadRequest, "unknown scenario")
		return
	}
	if d.Docker == nil {
		writeError(w, http.StatusServiceUnavailable, "docker unavailable")
		return
	}

	for i := len(sc.containers) - 1; i >= 0; i-- {
		_ = d.Docker.Stop(r.Context(), sc.containers[i])
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "stopped", "scenario": sc.name})
}

func resolveScenario(name string) *scenarioDef {
	for i := range ueransimScenarios {
		if ueransimScenarios[i].name == name {
			return &ueransimScenarios[i]
		}
	}
	return nil
}

// guessUEContainer returns the most likely Docker container for a given SUPI
// based on known UERANSIM compose naming conventions.
//
// Priority:
//  1. Named multi-slice containers (ueransim-ue-internet/gold/silver/bronze)
//  2. Generic ueransim-ue (standard single-UE / multi-UE mode)
//  3. ueransim-ue-profile-a (SUCI Profile A / X25519 scenario)
//  4. First running UE container (catch-all for future scenarios)
func guessUEContainer(supi string, running []string) string {
	imsi := strings.TrimPrefix(supi, "imsi-")

	// Index running containers for O(1) lookup.
	runningSet := make(map[string]bool, len(running))
	for _, r := range running {
		runningSet[r] = true
	}

	// Multi-slice fixed mapping (docker-compose.yml multi-slice profile)
	named := map[string]string{
		"001010000000001": "ueransim-ue-internet",
		"001010000000002": "ueransim-ue-gold",
		"001010000000003": "ueransim-ue-silver",
		"001010000000004": "ueransim-ue-bronze",
	}
	if ctr, ok := named[imsi]; ok && runningSet[ctr] {
		return ctr
	}

	// Standard single-UE / multi-UE mode.
	if runningSet["ueransim-ue"] {
		return "ueransim-ue"
	}

	// SUCI Profile A (X25519) scenario — explicit check before catch-all so
	// IMSI 001 is not routed to a wrong container when only profile-a is running.
	if runningSet["ueransim-ue-profile-a"] {
		return "ueransim-ue-profile-a"
	}

	// Catch-all for future scenarios (e.g. additional named compose services).
	if len(running) > 0 {
		return running[0]
	}
	return ""
}
