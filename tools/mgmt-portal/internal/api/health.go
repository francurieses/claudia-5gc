package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// healthPingTimeout bounds the store liveness ping done by /api/v1/health.
const healthPingTimeout = time.Second

// healthResponse is the body of GET /api/v1/health.
type healthResponse struct {
	Status string `json:"status"`
	Store  string `json:"store"`
}

// storeState returns "up" when the store is wired and answers a ping within
// healthPingTimeout, otherwise "down".
func (d Deps) storeState(ctx context.Context) string {
	if d.Store == nil {
		return "down"
	}
	ctx, cancel := context.WithTimeout(ctx, healthPingTimeout)
	defer cancel()
	if err := d.Store.Ping(ctx); err != nil {
		return "down"
	}
	return "up"
}

// handleHealth is a liveness probe: always 200, store state is a field.
func (d Deps) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(healthResponse{Status: "ok", Store: d.storeState(r.Context())}); err != nil {
		slog.Warn("health response write failed", "err", err)
	}
}
