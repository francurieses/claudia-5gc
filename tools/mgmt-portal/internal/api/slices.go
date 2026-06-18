package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/config"
)

type addSliceRequest struct {
	config.SNSSAI
	Restart bool `json:"restart"`
}

func (d Deps) handleListSlices(w http.ResponseWriter, r *http.Request) {
	slices, err := d.Config.GetAllSlices()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if slices == nil {
		slices = []config.SNSSAI{}
	}
	writeJSON(w, http.StatusOK, slices)
}

func (d Deps) handleAddSlice(w http.ResponseWriter, r *http.Request) {
	var req addSliceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.SST == 0 {
		writeError(w, http.StatusBadRequest, "sst is required")
		return
	}

	for _, nf := range []string{"amf", "smf", "nssf"} {
		existing, err := d.Config.ReadSlices(nf)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("read %s config: %s", nf, err))
			return
		}
		isDuplicate := false
		for _, s := range existing {
			if s.SST == req.SST && s.SD == req.SD {
				isDuplicate = true
				break
			}
		}
		if isDuplicate {
			continue
		}
		updated := append(existing, req.SNSSAI)
		if err := d.Config.WriteSlices(nf, updated); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("write %s config: %s", nf, err))
			return
		}
	}

	restarted := []string{}
	if req.Restart && d.Docker != nil {
		for _, nf := range []string{"amf", "smf", "nssf"} {
			if err := d.Docker.Restart(r.Context(), nf); err != nil {
				// Log but don't fail — config was saved successfully
				_ = err
			} else {
				restarted = append(restarted, nf)
			}
		}
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"slice":     req.SNSSAI,
		"restarted": restarted,
	})
}

func (d Deps) handleDeleteSlice(w http.ResponseWriter, r *http.Request) {
	sstStr := chi.URLParam(r, "sst")
	sd := chi.URLParam(r, "sd")
	sst, err := strconv.Atoi(sstStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid sst")
		return
	}
	restart := r.URL.Query().Get("restart") == "true"

	for _, nf := range []string{"amf", "smf", "nssf"} {
		existing, err := d.Config.ReadSlices(nf)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("read %s config: %s", nf, err))
			return
		}
		updated := make([]config.SNSSAI, 0, len(existing))
		for _, s := range existing {
			if s.SST != sst || s.SD != sd {
				updated = append(updated, s)
			}
		}
		if err := d.Config.WriteSlices(nf, updated); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("write %s config: %s", nf, err))
			return
		}
	}

	restarted := []string{}
	if restart && d.Docker != nil {
		for _, nf := range []string{"amf", "smf", "nssf"} {
			if err := d.Docker.Restart(r.Context(), nf); err != nil {
				_ = err
			} else {
				restarted = append(restarted, nf)
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"restarted": restarted,
	})
}
