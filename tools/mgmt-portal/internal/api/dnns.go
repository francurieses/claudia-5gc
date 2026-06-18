package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/config"
)

type dnnListResponse struct {
	DNNs          []config.DNNInfo `json:"dnns"`
	NextUEPool    string           `json:"next_ue_pool"`
	NextN6Network string           `json:"next_n6_network"`
	NextTunIndex  int              `json:"next_tun_index"`
}

type addDNNRequest struct {
	config.DNNInfo
	Restart bool `json:"restart"`
}

type updateDNNRequest struct {
	Description string `json:"description"`
}

func (d Deps) handleListDNNs(w http.ResponseWriter, r *http.Request) {
	dnns, err := d.Config.GetAllDNNs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if dnns == nil {
		dnns = []config.DNNInfo{}
	}

	uePool, n6Net, tunIdx, err := d.Config.SuggestNextDNN()
	if err != nil {
		// Non-fatal — return empty suggestions
		uePool, n6Net, tunIdx = "", "", len(dnns)
	}

	writeJSON(w, http.StatusOK, dnnListResponse{
		DNNs:          dnns,
		NextUEPool:    uePool,
		NextN6Network: n6Net,
		NextTunIndex:  tunIdx,
	})
}

func (d Deps) handleAddDNN(w http.ResponseWriter, r *http.Request) {
	var req addDNNRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.UEIPPool == "" {
		writeError(w, http.StatusBadRequest, "ue_ip_pool is required")
		return
	}
	if req.N6Network == "" {
		writeError(w, http.StatusBadRequest, "n6_network is required")
		return
	}

	// Verify DNN doesn't already exist.
	existing, err := d.Config.GetAllDNNs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, e := range existing {
		if e.Name == req.Name {
			writeError(w, http.StatusConflict, fmt.Sprintf("DNN %q already exists", req.Name))
			return
		}
	}
	tunIdx := len(existing)

	// Write config files.
	if err := d.Config.AddDNN(req.DNNInfo, tunIdx); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("write config: %s", err))
		return
	}

	// Create Docker network and connect UPF.
	dockerNetName := "5gc-n6-" + req.Name
	if req.Name == "internet" {
		dockerNetName = "5gc-n6"
	}
	restarted := []string{}
	dockerErrors := []string{}

	if d.Docker != nil {
		if err := d.Docker.CreateNetwork(r.Context(), dockerNetName, req.N6Network); err != nil {
			dockerErrors = append(dockerErrors, fmt.Sprintf("create network: %s", err))
		} else {
			// Connect UPF to the new network immediately (before restart).
			if err := d.Docker.ConnectToNetwork(r.Context(), "upf", dockerNetName); err != nil {
				dockerErrors = append(dockerErrors, fmt.Sprintf("connect upf: %s", err))
			}
		}
	}

	// Restart SMF and UPF so they pick up the new DNN config.
	if req.Restart && d.Docker != nil {
		for _, nf := range []string{"upf", "smf"} {
			if err := d.Docker.Restart(r.Context(), nf); err != nil {
				dockerErrors = append(dockerErrors, fmt.Sprintf("restart %s: %s", nf, err))
			} else {
				restarted = append(restarted, nf)
			}
		}

		// After UPF restart, Docker drops dynamically-added network connections.
		// Re-attach UPF to the new network once it is back up.
		if d.Docker != nil {
			time.Sleep(3 * time.Second)
			if err := d.Docker.ConnectToNetwork(r.Context(), "upf", dockerNetName); err != nil {
				// May fail if already connected or container still starting; non-fatal.
				_ = err
			}
		}
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"dnn":          req.DNNInfo,
		"docker_net":   dockerNetName,
		"restarted":    restarted,
		"docker_errors": dockerErrors,
	})
}

func (d Deps) handleUpdateDNN(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	var req updateDNNRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := d.Config.UpdateDNNDescription(name, req.Description); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": name})
}

func (d Deps) handleDeleteDNN(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	restart := r.URL.Query().Get("restart") == "true"

	// Fetch docker network name before deleting config.
	existing, err := d.Config.GetAllDNNs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	dockerNetName := ""
	found := false
	for _, e := range existing {
		if e.Name == name {
			dockerNetName = e.DockerNet
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, fmt.Sprintf("DNN %q not found", name))
		return
	}

	// Remove from all config files.
	if err := d.Config.DeleteDNN(name); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("delete config: %s", err))
		return
	}

	restarted := []string{}
	dockerErrors := []string{}

	if d.Docker != nil {
		// Detach UPF from the network before removing it.
		if err := d.Docker.DisconnectFromNetwork(r.Context(), "upf", dockerNetName); err != nil {
			dockerErrors = append(dockerErrors, fmt.Sprintf("disconnect upf: %s", err))
		}
		// Remove the Docker network.
		if err := d.Docker.RemoveNetwork(r.Context(), dockerNetName); err != nil {
			dockerErrors = append(dockerErrors, fmt.Sprintf("remove network %s: %s", dockerNetName, err))
		}
	}

	if restart && d.Docker != nil {
		for _, nf := range []string{"smf", "upf"} {
			if err := d.Docker.Restart(r.Context(), nf); err != nil {
				dockerErrors = append(dockerErrors, fmt.Sprintf("restart %s: %s", nf, err))
			} else {
				restarted = append(restarted, nf)
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name":          name,
		"restarted":     restarted,
		"docker_errors": dockerErrors,
	})
}
