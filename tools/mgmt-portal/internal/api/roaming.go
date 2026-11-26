package api

// roaming.go — roaming (N32) visibility and control for the portal (PORTAL-UI-22).
//
//	GET  /api/v1/roaming/status                                aggregated roaming view
//	POST /api/v1/roaming/{start|stop|restart}                  lifecycle of the test-peer containers
//	POST /api/v1/roaming/sepp/{sepp}/n32/{plmn}/{handshake|teardown}
//	                                                           proxy to the SEPP admin route (metrics port)
//
// Topology: SEPP (local core, compose profile core) <-> N32 <-> hSEPP + hNRF
// (roaming test peer, compose profile roaming). The portal reaches every one of them on
// obs-net, so no compose change is needed: health from the Docker healthcheck
// and /healthz, N32 state from GET /admin/v1/n32/contexts on the SEPP metrics
// port (never the N32 or SBI listener), N32-f rates from Prometheus.
// Ref: TS 23.501 §6.2.17, TS 29.573 §5.2.2 / §5.3.3.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	dockerclient "github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/docker"
	"github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/nrf"
)

// PLMN sides of a roaming deployment.
const (
	sideLocal   = "local"
	sidePartner = "partner"
)

// Aggregate N32 link states.
const (
	linkUp          = "UP"
	linkDegraded    = "DEGRADED"
	linkDown        = "DOWN"
	linkNotDeployed = "NOT_DEPLOYED"
)

const (
	// roamingProbeBudget bounds one GET /roaming/status.
	roamingProbeBudget = 4 * time.Second
	// roamingActionBudget bounds a proxied handshake/teardown (the SEPP bounds it at 15 s).
	roamingActionBudget = 20 * time.Second
	// roamingErrorLines is the number of recent warn/error lines returned.
	roamingErrorLines = 30
	// roamingLogTail is how many log lines per container are scanned for errors.
	roamingLogTail = "400"
	// roamingUpCommand is shown when the test-peer containers were never created.
	roamingUpCommand = "docker compose --profile core --profile roaming up -d hnrf hsepp hsepp-pcap"
)

// roamingNF is one NF of the roaming topology.
type roamingNF struct {
	Name     string // container name (also the obs-net DNS name)
	Role     string // display role: local SEPP, hSEPP, hNRF
	Side     string // local | partner
	SBIURL   string // /healthz over mTLS
	MetPort  string // metrics / admin port
	IsSEPP   bool
	Sidecars []string
}

// roamingTopology lists the roaming NFs; the local-core NFs are the rest of knownNFs.
var roamingTopology = []roamingNF{
	{Name: "sepp", Role: "SEPP", Side: sideLocal, SBIURL: "https://sepp:8014", MetPort: "9115", IsSEPP: true},
	{Name: "hsepp", Role: "hSEPP", Side: sidePartner, SBIURL: "https://hsepp:8014", MetPort: "9115", IsSEPP: true},
	{Name: "hnrf", Role: "hNRF", Side: sidePartner, SBIURL: "https://hnrf:8000", MetPort: "9100"},
}

// homeLifecycleOrder: hNRF first so the hSEPP registers on start.
var homeLifecycleOrder = []string{"hnrf", "hsepp"}

// sideOf returns the PLMN side of a container (partner for the roaming-profile NFs).
func sideOf(name string) string {
	for _, n := range roamingTopology {
		if n.Name == name {
			return n.Side
		}
	}
	return sideLocal
}

func roamingNFByName(name string) (roamingNF, bool) {
	for _, n := range roamingTopology {
		if n.Name == name {
			return n, true
		}
	}
	return roamingNF{}, false
}

// ---- SEPP admin view (mirror of nf/sepp/internal/admin, decoded loosely) ----

// N32Attempt is the last exchange-capability outcome for a partner.
type N32Attempt struct {
	At     time.Time `json:"at"`
	Role   string    `json:"role"`
	Result string    `json:"result"`
	Cause  string    `json:"cause,omitempty"`
}

// N32Partner is one roaming partner as seen by a SEPP.
type N32Partner struct {
	PLMN                string      `json:"plmn"`
	State               string      `json:"state"`
	Initiator           bool        `json:"initiator"`
	PeerFQDN            string      `json:"peer_fqdn,omitempty"`
	PeerAddress         string      `json:"peer_address,omitempty"`
	Security            string      `json:"security,omitempty"`
	TargetAPIRootHeader bool        `json:"target_api_root_header"`
	NFTLST              bool        `json:"nftlst"`
	NegotiatedFeatures  string      `json:"negotiated_features,omitempty"`
	EstablishedAt       *time.Time  `json:"established_at,omitempty"`
	LastAttempt         *N32Attempt `json:"last_attempt,omitempty"`
}

// N32View is GET /admin/v1/n32/contexts of one SEPP.
type N32View struct {
	NF             string       `json:"nf"`
	LocalPLMN      string       `json:"local_plmn"`
	LocalFQDN      string       `json:"local_fqdn"`
	ReleaseProfile string       `json:"release_profile"`
	SecurityMode   string       `json:"security_mode"`
	TopologyHiding bool         `json:"topology_hiding"`
	Established    int          `json:"established"`
	Partners       []N32Partner `json:"partners"`
}

// ---- response types -------------------------------------------------------

// RoamingNFStatus is the health of one roaming NF.
type RoamingNFStatus struct {
	Name      string `json:"name"`
	Role      string `json:"role"`
	Side      string `json:"side"`
	PLMN      string `json:"plmn,omitempty"`
	Deployed  bool   `json:"deployed"`
	State     string `json:"state,omitempty"`  // Docker state: running, exited, ...
	Health    string `json:"health,omitempty"` // Docker healthcheck
	Uptime    string `json:"uptime,omitempty"`
	HealthzOK bool   `json:"healthz_ok"`
	MetricsOK bool   `json:"metrics_ok"`
}

// RoamingSEPP is the N32 view of one SEPP (N32 nil when unreachable).
type RoamingSEPP struct {
	Name  string   `json:"name"`
	Role  string   `json:"role"`
	Side  string   `json:"side"`
	N32   *N32View `json:"n32,omitempty"`
	Error string   `json:"error,omitempty"`
}

// RoamingLink is the aggregate local SEPP <-> hSEPP N32 state.
type RoamingLink struct {
	State       string `json:"state"`
	Reason      string `json:"reason"`
	LocalPLMN   string `json:"local_plmn,omitempty"`
	PartnerPLMN string `json:"partner_plmn,omitempty"`
}

// RoamingTraffic holds N32-f rates over [5m] (nil = no data / Prometheus down).
type RoamingTraffic struct {
	Available   bool     `json:"available"`
	OutPerSec   *float64 `json:"out_per_sec"`
	InPerSec    *float64 `json:"in_per_sec"`
	ErrorPerSec *float64 `json:"error_per_sec"`
	P95Ms       *float64 `json:"p95_ms"`
	Handshakes  *float64 `json:"handshakes_ok_15m"`
	Error       string   `json:"error,omitempty"`
}

// RoamingHomeNRF lists the NFs registered in the test-peer NRF.
type RoamingHomeNRF struct {
	Reachable bool            `json:"reachable"`
	Error     string          `json:"error,omitempty"`
	Instances []nrf.NFProfile `json:"instances"`
}

// RoamingLogLine is a recent warn/error line of a roaming NF.
type RoamingLogLine struct {
	Container string `json:"container"`
	Time      string `json:"time,omitempty"`
	Level     string `json:"level"`
	Msg       string `json:"msg"`
	Procedure string `json:"procedure,omitempty"`
	Cause     string `json:"cause,omitempty"`
}

// RoamingStatus is the GET /api/v1/roaming/status response.
type RoamingStatus struct {
	Deployed     bool              `json:"deployed"`
	DeployHint   string            `json:"deploy_hint,omitempty"`
	Link         RoamingLink       `json:"link"`
	NFs          []RoamingNFStatus `json:"nfs"`
	SEPPs        []RoamingSEPP     `json:"sepps"`
	Traffic      RoamingTraffic    `json:"traffic"`
	HomeNRF      RoamingHomeNRF    `json:"partner_nrf"`
	RecentErrors []RoamingLogLine  `json:"recent_errors"`
	GeneratedAt  time.Time         `json:"generated_at"`
}

// ---- GET /roaming/status --------------------------------------------------

func (d Deps) handleRoamingStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), roamingProbeBudget)
	defer cancel()

	containers := map[string]dockerclient.Service{}
	if d.Docker != nil {
		if svcs, err := d.Docker.List(ctx); err == nil {
			for _, s := range svcs {
				containers[s.Name] = s
			}
		}
	}

	st := RoamingStatus{NFs: []RoamingNFStatus{}, SEPPs: []RoamingSEPP{}, RecentErrors: []RoamingLogLine{},
		HomeNRF: RoamingHomeNRF{Instances: []nrf.NFProfile{}}, GeneratedAt: time.Now().UTC()}

	var mu sync.Mutex
	var wg sync.WaitGroup
	st.NFs = make([]RoamingNFStatus, len(roamingTopology))
	for i, n := range roamingTopology {
		ctr, deployed := containers[n.Name]
		st.NFs[i] = RoamingNFStatus{Name: n.Name, Role: n.Role, Side: n.Side, Deployed: deployed,
			State: ctr.State, Health: ctr.Health, Uptime: ctr.Uptime}
		if n.Side == sidePartner && deployed {
			st.Deployed = true
		}
		if !deployed || ctr.State != "running" {
			continue
		}
		wg.Add(1)
		go func(i int, n roamingNF) {
			defer wg.Done()
			hz := d.probe(ctx, n.SBIURL+"/healthz")
			mt := d.probe(ctx, "http://"+n.Name+":"+n.MetPort+"/metrics")
			mu.Lock()
			st.NFs[i].HealthzOK, st.NFs[i].MetricsOK = hz, mt
			mu.Unlock()
		}(i, n)
	}
	for _, n := range roamingTopology {
		if !n.IsSEPP {
			continue
		}
		sp := RoamingSEPP{Name: n.Name, Role: n.Role, Side: n.Side}
		if ctr, ok := containers[n.Name]; !ok || ctr.State != "running" {
			sp.Error = "container not running"
			st.SEPPs = append(st.SEPPs, sp)
			continue
		}
		idx := len(st.SEPPs)
		st.SEPPs = append(st.SEPPs, sp)
		wg.Add(1)
		go func(idx int, n roamingNF) {
			defer wg.Done()
			v, err := d.fetchN32View(ctx, n)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				st.SEPPs[idx].Error = err.Error()
				return
			}
			st.SEPPs[idx].N32 = v
		}(idx, n)
	}
	if hn, ok := containers["hnrf"]; ok && hn.State == "running" && d.HomeNRF != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			inst, err := d.HomeNRF.ListNFInstances(ctx)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				st.HomeNRF.Error = err.Error()
				return
			}
			st.HomeNRF.Reachable = true
			if inst != nil {
				sort.Slice(inst, func(a, b int) bool { return inst[a].NfType < inst[b].NfType })
				st.HomeNRF.Instances = inst
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		tr := d.roamingTraffic(ctx)
		mu.Lock()
		st.Traffic = tr
		mu.Unlock()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		lines := d.roamingErrors(ctx, containers)
		mu.Lock()
		st.RecentErrors = lines
		mu.Unlock()
	}()
	wg.Wait()

	for i := range st.NFs { // PLMN of each NF from its SEPP view (hNRF shares hSEPP's)
		for _, sp := range st.SEPPs {
			if sp.N32 != nil && sp.Side == st.NFs[i].Side {
				st.NFs[i].PLMN = sp.N32.LocalPLMN
			}
		}
	}
	st.Link = linkState(st.Deployed, st.SEPPs)
	if !st.Deployed {
		st.DeployHint = roamingUpCommand
	}
	writeJSON(w, http.StatusOK, st)
}

// probe reports whether GET url answers 200 (mTLS client; plain HTTP works too).
func (d Deps) probe(ctx context.Context, url string) bool {
	if d.MTLSClient == nil {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := d.MTLSClient.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (d Deps) seppAdminURL(n roamingNF) string {
	return "http://" + n.Name + ":" + n.MetPort + "/admin/v1/n32/contexts"
}

// seppAdminClient talks to the SEPP admin routes (plain HTTP on the metrics
// port). Its timeout covers one operator-triggered exchange-capability.
var seppAdminClient = &http.Client{Timeout: roamingActionBudget}

func (d Deps) httpClient() *http.Client { return seppAdminClient }

func (d Deps) fetchN32View(ctx context.Context, n roamingNF) (*N32View, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.seppAdminURL(n), nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("n32 admin unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("n32 admin answered %d (SEPP image older than PORTAL-UI-22?)", resp.StatusCode)
	}
	var v N32View
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&v); err != nil {
		return nil, fmt.Errorf("n32 admin body: %w", err)
	}
	return &v, nil
}

// linkState derives the local SEPP <-> hSEPP state: UP when each SEPP holds an
// ESTABLISHED context for the other's PLMN, DEGRADED when only one does.
func linkState(deployed bool, sepps []RoamingSEPP) RoamingLink {
	var v, h *N32View
	for _, s := range sepps {
		switch {
		case s.Side == sideLocal && s.N32 != nil:
			v = s.N32
		case s.Side == sidePartner && s.N32 != nil:
			h = s.N32
		}
	}
	l := RoamingLink{}
	if v != nil {
		l.LocalPLMN = v.LocalPLMN
	}
	if h != nil {
		l.PartnerPLMN = h.LocalPLMN
	}
	if !deployed {
		l.State, l.Reason = linkNotDeployed, "test peer (hSEPP/hNRF) not deployed — compose profile `roaming`"
		return l
	}
	if v == nil || h == nil {
		l.State, l.Reason = linkDown, "a SEPP is not running or its N32 admin view is unreachable"
		return l
	}
	vh := established(v, h.LocalPLMN)
	hv := established(h, v.LocalPLMN)
	switch {
	case vh && hv:
		l.State, l.Reason = linkUp, "N32 context established on both SEPPs (TLS)"
	case vh || hv:
		l.State, l.Reason = linkDegraded, "N32 context established on one SEPP only"
	default:
		l.State, l.Reason = linkDown, "no N32 context between local SEPP and hSEPP"
	}
	return l
}

func established(v *N32View, plmn string) bool {
	for _, p := range v.Partners {
		if p.PLMN == plmn && p.State == "ESTABLISHED" {
			return true
		}
	}
	return false
}

// roamingQueries are the fixed PromQL expressions of the traffic card.
var roamingQueries = map[string]string{
	"out":  `sum(rate(fivegc_sepp_n32f_messages_total{direction="OUT"}[5m]))`,
	"in":   `sum(rate(fivegc_sepp_n32f_messages_total{direction="IN"}[5m]))`,
	"err":  `sum(rate(fivegc_sepp_n32f_messages_total{result!="OK"}[5m]))`,
	"p95":  `1000 * histogram_quantile(0.95, sum by (le) (rate(fivegc_sepp_n32f_duration_seconds_bucket[5m])))`,
	"hs15": `sum(increase(fivegc_sepp_n32c_handshake_total{result="OK"}[15m]))`,
}

func (d Deps) roamingTraffic(ctx context.Context) RoamingTraffic {
	t := RoamingTraffic{}
	if d.Prometheus == nil {
		t.Error = "Prometheus not configured"
		return t
	}
	vals := map[string]*float64{}
	for k, q := range roamingQueries {
		samples, err := d.Prometheus.Query(ctx, q)
		if err != nil {
			t.Error = err.Error()
			return t
		}
		if len(samples) > 0 {
			if f, ok := samples[0].Float(); ok && !math.IsNaN(f) && !math.IsInf(f, 0) {
				v := f
				vals[k] = &v
			}
		}
	}
	t.Available = true
	t.OutPerSec, t.InPerSec, t.ErrorPerSec, t.P95Ms, t.Handshakes = vals["out"], vals["in"], vals["err"], vals["p95"], vals["hs15"]
	return t
}

// roamingErrors returns the latest warn/error lines of the running roaming NFs.
func (d Deps) roamingErrors(ctx context.Context, containers map[string]dockerclient.Service) []RoamingLogLine {
	out := []RoamingLogLine{}
	if d.Docker == nil {
		return out
	}
	for _, n := range roamingTopology {
		if c, ok := containers[n.Name]; !ok || c.State != "running" {
			continue
		}
		text, err := d.Docker.TailLogs(ctx, n.Name, roamingLogTail)
		if err != nil {
			continue
		}
		out = append(out, parseErrorLines(n.Name, text)...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time > out[j].Time })
	if len(out) > roamingErrorLines {
		out = out[:roamingErrorLines]
	}
	return out
}

// parseErrorLines keeps the JSON log lines at WARN or ERROR.
func parseErrorLines(container, text string) []RoamingLogLine {
	var out []RoamingLogLine
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(ln, "{") {
			continue
		}
		var rec struct {
			Time      string `json:"time"`
			Level     string `json:"level"`
			Msg       string `json:"msg"`
			Procedure string `json:"procedure"`
			Cause     string `json:"cause"`
		}
		if json.Unmarshal([]byte(ln), &rec) != nil {
			continue
		}
		lvl := strings.ToLower(rec.Level)
		if lvl != "warn" && lvl != "warning" && lvl != "error" {
			continue
		}
		out = append(out, RoamingLogLine{Container: container, Time: rec.Time, Level: lvl,
			Msg: rec.Msg, Procedure: rec.Procedure, Cause: rec.Cause})
	}
	return out
}

// ---- POST /roaming/{action} -------------------------------------------------

func (d Deps) handleRoamingLifecycle(w http.ResponseWriter, r *http.Request) {
	action := chi.URLParam(r, "action")
	if action != "start" && action != "stop" && action != "restart" {
		writeError(w, http.StatusBadRequest, "action must be start, stop or restart")
		return
	}
	if d.Docker == nil {
		writeError(w, http.StatusServiceUnavailable, "docker unavailable")
		return
	}
	svcs, err := d.Docker.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	present := map[string]bool{}
	for _, s := range svcs {
		present[s.Name] = true
	}
	for _, n := range homeLifecycleOrder {
		if !present[n] {
			writeJSON(w, http.StatusConflict, map[string]string{
				"code":  "ROAMING_NOT_DEPLOYED",
				"error": "test-peer containers were never created; run: " + roamingUpCommand,
			})
			return
		}
	}
	results := map[string]string{}
	order := homeLifecycleOrder
	if action == "stop" { // stop the dependant first
		order = []string{"hsepp", "hnrf"}
	}
	for _, n := range order {
		var aerr error
		switch action {
		case "stop":
			aerr = d.Docker.Stop(r.Context(), n)
		default:
			_, _, aerr = startOrRestart(r.Context(), d.Docker, n, action == "restart")
		}
		if aerr != nil {
			results[n] = "error: " + aerr.Error()
			continue
		}
		results[n] = "ok"
	}
	slog.Info("roaming lifecycle", "action", action, "results", results)
	writeJSON(w, http.StatusOK, map[string]any{"action": action, "results": results})
}

// ---- POST /roaming/sepp/{sepp}/n32/{plmn}/{action} ----------------------------

var plmnParam = regexp.MustCompile(`^[0-9]{3}-[0-9]{2,3}$`)

func (d Deps) handleRoamingN32Action(w http.ResponseWriter, r *http.Request) {
	name, plmn, action := chi.URLParam(r, "sepp"), chi.URLParam(r, "plmn"), chi.URLParam(r, "action")
	n, ok := roamingNFByName(name)
	if !ok || !n.IsSEPP {
		writeError(w, http.StatusBadRequest, "sepp must be sepp or hsepp")
		return
	}
	if !plmnParam.MatchString(plmn) {
		writeError(w, http.StatusBadRequest, "plmn must be mcc-mnc, e.g. 001-02")
		return
	}
	if action != "handshake" && action != "teardown" {
		writeError(w, http.StatusBadRequest, "action must be handshake or teardown")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), roamingActionBudget)
	defer cancel()
	url := d.seppAdminURL(n) + "/" + plmn + "/" + action
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp, err := d.httpClient().Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "SEPP admin unreachable: "+err.Error())
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	slog.Info("roaming n32 action", "sepp", name, "plmn", plmn, "action", action, "status", resp.StatusCode)
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}
