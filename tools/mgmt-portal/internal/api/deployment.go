package api

// deployment.go — deployment mode awareness (standalone core vs. RAN simulators).
//
// GET /api/v1/deployment reports which RAN simulators (UERANSIM, PacketRusher)
// are deployed next to the core. Mutating simulator endpoints answer 409
// RAN_TOOL_NOT_DEPLOYED when their tool is absent; status GETs stay available.

import (
	"net/http"
	"time"

	"github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/deployment"
)

// codeRANToolNotDeployed is the machine-readable code of the 409 response.
const codeRANToolNotDeployed = "RAN_TOOL_NOT_DEPLOYED"

// handleDeployment serves GET /api/v1/deployment.
func (d Deps) handleDeployment(w http.ResponseWriter, r *http.Request) {
	if d.Deployment == nil {
		// No detector wired (tests, or a portal started without Docker).
		c := deployment.Detect(nil, "", time.Now())
		c.Source = deployment.SourceUnavailable
		writeJSON(w, http.StatusOK, c)
		return
	}
	writeJSON(w, http.StatusOK, d.Deployment.Get(r.Context()))
}

// requireRANTool returns middleware that rejects the request with 409 when the
// given tool ("ueransim" | "packetrusher") is not deployed. Without a detector
// it lets the request through (fail-open: a portal fault must not disable tools).
func (d Deps) requireRANTool(tool string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if d.Deployment != nil && !d.Deployment.Get(r.Context()).Has(tool) {
				writeJSON(w, http.StatusConflict, map[string]string{
					"error": tool + " is not deployed in the current mode",
					"code":  codeRANToolNotDeployed,
					"tool":  tool,
					"hint":  "make up RAN=" + tool,
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
