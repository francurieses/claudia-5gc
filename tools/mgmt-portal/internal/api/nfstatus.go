package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// knownNFs lists all NFs with their SBI URL and metrics port.
var knownNFs = []struct {
	Name    string
	SBIURL  string
	MetPort string
}{
	{"nrf", "https://nrf:8000", "9100"},
	{"amf", "http://amf:9002", "9101"},
	{"ausf", "https://ausf:8002", "9102"},
	{"udm", "https://udm:8003", "9103"},
	{"smf", "https://smf:8004", "9105"},
	{"udr", "https://udr:8005", "9104"},
	{"pcf", "https://pcf:8006", "9106"},
	{"upf", "", "9107"},
	{"nssf", "https://nssf:8007", "9109"},
	{"smsf", "https://smsf:8009", "9110"},
	{"bsf", "https://bsf:8010", "9111"},
	{"nef", "https://nef:8011", "9112"},
	{"lmf", "https://lmf:8012", "9113"},
}

// NFStatus holds the health status for a single NF.
type NFStatus struct {
	Name         string `json:"name"`
	Registered   bool   `json:"registered"`
	HealthzOK    bool   `json:"healthz_ok"`
	MetricsOK    bool   `json:"metrics_ok"`
}

func (d Deps) handleNFStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()

	// Get NRF-registered instances
	instances, err := d.NRF.ListNFInstances(ctx)
	if err != nil {
		slog.Warn("nf-status: NRF list failed — registered flags will be false", "err", err)
	}
	registeredMap := map[string]bool{}
	for _, inst := range instances {
		registeredMap[inst.NfType] = true
	}

	probeClient := d.MTLSClient

	statuses := make([]NFStatus, 0, len(knownNFs))
	for _, nf := range knownNFs {
		st := NFStatus{
			Name:       nf.Name,
			Registered: registeredMap[toNFType(nf.Name)],
		}

		// Check /healthz via SBI endpoint
		if nf.SBIURL != "" {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, nf.SBIURL+"/healthz", nil)
			if err == nil {
				resp, err := probeClient.Do(req)
				if err == nil {
					resp.Body.Close()
					st.HealthzOK = resp.StatusCode == http.StatusOK
				}
			}
		}

		// Check metrics endpoint (plain HTTP)
		if nf.MetPort != "" {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet,
				"http://"+nf.Name+":"+nf.MetPort+"/metrics", nil)
			if err == nil {
				resp, err := probeClient.Do(req)
				if err == nil {
					resp.Body.Close()
					st.MetricsOK = resp.StatusCode == http.StatusOK
				}
			}
		}

		// NRF is the registry itself — it never self-registers. Mark it as
		// registered whenever it is reachable (healthz or metrics up).
		if nf.Name == "nrf" && !st.Registered {
			st.Registered = st.HealthzOK || st.MetricsOK
		}

		statuses = append(statuses, st)
	}

	writeJSON(w, http.StatusOK, statuses)
}

func toNFType(name string) string {
	switch name {
	case "nrf":
		return "NRF"
	case "amf":
		return "AMF"
	case "ausf":
		return "AUSF"
	case "udm":
		return "UDM"
	case "smf":
		return "SMF"
	case "udr":
		return "UDR"
	case "pcf":
		return "PCF"
	case "upf":
		return "UPF"
	case "nssf":
		return "NSSF"
	case "smsf":
		return "SMSF"
	case "bsf":
		return "BSF"
	case "nef":
		return "NEF"
	case "lmf":
		return "LMF"
	default:
		return name
	}
}
