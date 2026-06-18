package api

import "net/http"

func (d Deps) handleMetricsSummary(w http.ResponseWriter, r *http.Request) {
	summary := d.Prometheus.Summary(r.Context())
	writeJSON(w, http.StatusOK, summary)
}
