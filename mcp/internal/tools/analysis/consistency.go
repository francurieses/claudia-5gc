package analysis

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/ue"
)

// maxFindingsPerCheck bounds how many findings one check emits, so a badly
// diverged core cannot overflow the result cap.
const maxFindingsPerCheck = 20

// Finding severities.
const (
	sevError   = "error"
	sevWarning = "warning"
	sevInfo    = "info"
)

// consistencyTool reconciles the AMF, SMF, UPF, BSF and NRF views of the core.
// It only reports a mismatch when both sides were read; an upstream that failed
// becomes a "<source>_unreachable" warning and the checks that need it are skipped.
type consistencyTool struct{ d Deps }

func (consistencyTool) Name() string        { return "core_consistency_check" }
func (consistencyTool) Risk() registry.Risk { return registry.ReadOnly }
func (consistencyTool) Description() string {
	return "Cross-check the core's state holders and report mismatches as findings (severity error|warning|info): " +
		"each AMF UE PDU session id has an SMF session (amf_psi_without_smf_session), each SMF session has an AMF UE " +
		"(smf_session_without_amf_ue), SMF session count equals the UPF PFCP session gauge (smf_upf_session_count), " +
		"BSF bindings cover the SMF sessions (bsf_binding_count), every scrape-target NF is registered in the NRF " +
		"(nrf_registration_missing; the UPF and NRF itself do not register) and no scrape target is down " +
		"(scrape_target_down). A source that cannot be read gives a <source>_unreachable warning and the dependent " +
		"checks are skipped; a missing count is null. Refs: TS 23.502 §4.3.2 (PDU session state), TS 29.244 §5.2, " +
		"TS 29.521, TS 29.510 §5.2.2."
}
func (consistencyTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{}}`)
}
func (consistencyTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"counts":{"type":"object"},"findings":{"type":"array"}}}`)
}

// Finding is one consistency finding.
type finding struct {
	Severity string `json:"severity"`
	Check    string `json:"check"`
	Detail   string `json:"detail"`
	SpecRef  string `json:"spec_ref"`
}

type smfSession struct {
	SUPI  string `json:"supi"`
	PSI   int    `json:"pduSessionId"`
	State string `json:"sessionState"`
}

// smfStateActive is the SMF sessionState of an established, usable session.
const smfStateActive = "ACTIVE"

type amfUE struct {
	SUPI     string
	GMMState string
	PSIs     []int
	// HasPSIs is true when the AMF reply carried a pdu_session_ids field.
	HasPSIs bool
}

// readAMF returns the UE list.
func readAMF(ctx context.Context, amf *clients.AMF) ([]amfUE, error) {
	raw, err := amf.ListContexts(ctx)
	if err != nil {
		return nil, err
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("decode AMF list: %w", err)
	}
	out := make([]amfUE, 0, len(items))
	for _, it := range items {
		var u amfUE
		_ = json.Unmarshal(it["supi"], &u.SUPI)
		_ = json.Unmarshal(it["gmm_state"], &u.GMMState)
		if v, ok := it["pdu_session_ids"]; ok {
			u.HasPSIs = true
			u.PSIs, _ = ue.ParsePSIs(v)
		}
		out = append(out, u)
	}
	return out, nil
}

// readSMF returns the session list. The SMF answers {"count":n,"sessions":[...]}.
func readSMF(ctx context.Context, smf *clients.SMF) ([]smfSession, error) {
	raw, err := smf.ListSessions(ctx)
	if err != nil {
		return nil, err
	}
	var wrapped struct {
		Sessions []smfSession `json:"sessions"`
	}
	if err := json.Unmarshal(raw, &wrapped); err == nil {
		return wrapped.Sessions, nil
	}
	var bare []smfSession
	if err := json.Unmarshal(raw, &bare); err != nil {
		return nil, fmt.Errorf("decode SMF sessions: %w", err)
	}
	return bare, nil
}

// gaugeFor returns the value of the sample whose nf label is nf (or has no nf
// label, as after an aggregation). ok is false when no such sample exists.
func gaugeFor(res *promclient.QueryResult, nf string) (float64, bool) {
	for _, s := range res.Data.Result {
		if got, has := s.Metric["nf"]; has && got != nf {
			continue
		}
		return s.Float64(), true
	}
	return 0, false
}

func (t consistencyTool) Invoke(ctx context.Context, _ json.RawMessage) (any, error) {
	start := time.Now()
	targets := t.d.Targets
	if targets == nil {
		targets = clients.NewTargets(t.d.Prom, "")
	}

	var (
		wg                     sync.WaitGroup
		ues                    []amfUE
		amfErr                 error
		sessions               []smfSession
		smfErr                 error
		upfRes, bsfRes, nrfRes *promclient.QueryResult
		upfErr, bsfErr, nrfErr error
		scrape                 []clients.Target
		scrapeErr              error
		activeN                int
	)
	bounded := func(f func(context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
			defer cancel()
			f(cctx)
		}()
	}
	bounded(func(c context.Context) { ues, amfErr = readAMF(c, t.d.AMF) })
	bounded(func(c context.Context) { sessions, smfErr = readSMF(c, t.d.SMF) })
	bounded(func(c context.Context) {
		upfRes, upfErr = t.d.Prom.Query(c, `sum(fivegc_upf_pfcp_sessions_active{nf="UPF"})`, time.Time{})
	})
	bounded(func(c context.Context) {
		bsfRes, bsfErr = t.d.Prom.Query(c, `fivegc_bsf_bindings_active{nf="BSF"}`, time.Time{})
	})
	bounded(func(c context.Context) {
		nrfRes, nrfErr = t.d.Prom.Query(c, `sum by (nf_type) (fivegc_nf_instances_registered{nf="NRF"})`, time.Time{})
	})
	bounded(func(c context.Context) { scrape, scrapeErr = targets.List(c) })
	wg.Wait()

	counts := map[string]any{
		"amf_ues": nil, "amf_psis": nil, "smf_sessions": nil, "smf_sessions_active": nil, "upf_pfcp_sessions": nil,
		"bsf_bindings": nil, "nrf_instances": nil, "scrape_targets": nil,
	}
	var fs []finding
	add := func(sev, check, detail, ref string) { fs = append(fs, finding{sev, check, detail, ref}) }
	unreachable := func(source string, err error) {
		add(sevWarning, source+"_unreachable", fmt.Sprintf("%s could not be read, dependent checks skipped: %v", source, err),
			"TS 23.502 §4.3.2")
	}

	// AMF and SMF views.
	amfOK, smfOK := amfErr == nil, smfErr == nil
	if !amfOK {
		unreachable("amf", amfErr)
	} else {
		psis := 0
		for _, u := range ues {
			psis += len(u.PSIs)
		}
		counts["amf_ues"], counts["amf_psis"] = len(ues), psis
	}
	if !smfOK {
		unreachable("smf", smfErr)
	} else {
		counts["smf_sessions"] = len(sessions)
		for _, s := range sessions {
			if strings.EqualFold(s.State, smfStateActive) {
				activeN++
			}
		}
		counts["smf_sessions_active"] = activeN
	}
	if amfOK && smfOK {
		fs = append(fs, crossCheck(ues, sessions)...)
	}

	// UPF PFCP session gauge against the SMF session count.
	var upfN float64
	upfOK := false
	switch {
	case upfErr != nil:
		unreachable("upf_metrics", upfErr)
	default:
		if v, ok := gaugeFor(upfRes, "UPF"); ok {
			upfN, upfOK = v, true
			counts["upf_pfcp_sessions"] = int(v)
		} else {
			add(sevWarning, "upf_metrics_no_data", "Prometheus has no fivegc_upf_pfcp_sessions_active{nf=\"UPF\"} series",
				"TS 29.244 §5.2")
		}
	}
	if smfOK && upfOK && activeN != int(upfN) {
		sev, detail := sevError, fmt.Sprintf("SMF holds %d ACTIVE sessions but the UPF reports %d PFCP sessions", activeN, int(upfN))
		if inTransition := len(sessions) - activeN; inTransition > 0 {
			sev = sevWarning
			detail = fmt.Sprintf("SMF holds %d ACTIVE sessions (%d more in transition) but the UPF reports %d PFCP sessions; sessions are in transition",
				activeN, inTransition, int(upfN))
		}
		add(sev, "smf_upf_session_count", detail, "TS 29.244 §6.3.2; TS 23.502 §4.3.2")
	}

	// BSF bindings cover the SMF sessions.
	switch {
	case bsfErr != nil:
		unreachable("bsf_metrics", bsfErr)
	default:
		if v, ok := gaugeFor(bsfRes, "BSF"); ok {
			counts["bsf_bindings"] = int(v)
			if smfOK && int(v) < len(sessions) {
				add(sevWarning, "bsf_binding_count",
					fmt.Sprintf("BSF holds %d PCF bindings for %d SMF sessions", int(v), len(sessions)),
					"TS 29.521 §5.2.2.2")
			}
		} else {
			add(sevWarning, "bsf_metrics_no_data", "Prometheus has no fivegc_bsf_bindings_active{nf=\"BSF\"} series",
				"TS 29.521 §5.2.2.2")
		}
	}

	// NRF registrations against the scrape targets.
	registered := map[string]bool{}
	nrfOK := false
	switch {
	case nrfErr != nil:
		unreachable("nrf_metrics", nrfErr)
	case len(nrfRes.Data.Result) == 0:
		add(sevWarning, "nrf_metrics_no_data", "Prometheus has no fivegc_nf_instances_registered{nf=\"NRF\"} series",
			"TS 29.510 §5.2.2.2")
	default:
		nrfOK = true
		total := 0.0
		for _, s := range nrfRes.Data.Result {
			if nf, has := s.Metric["nf"]; has && nf != "NRF" {
				continue
			}
			total += s.Float64()
			if s.Float64() > 0 {
				registered[strings.ToUpper(s.Metric["nf_type"])] = true
			}
		}
		counts["nrf_instances"] = int(total)
	}
	if scrapeErr != nil {
		unreachable("scrape_targets", scrapeErr)
	} else {
		counts["scrape_targets"] = len(scrape)
		fs = append(fs, scrapeChecks(scrape, registered, nrfOK)...)
	}

	sort.SliceStable(fs, func(i, j int) bool { return severityRank(fs[i].Severity) < severityRank(fs[j].Severity) })
	if fs == nil {
		fs = []finding{}
	}
	slog.InfoContext(ctx, "core consistency checked", "nf", "MCP", "procedure", "McpStatusAnalysisWave2",
		"tool_name", "core_consistency_check", "interface", "Namf/Nsmf/Prometheus", "direction", "OUT",
		"spec_ref", "TS 23.502 §4.3.2", "findings", len(fs), "latency_ms", time.Since(start).Milliseconds())
	return map[string]any{"counts": counts, "findings": fs}, nil
}

// crossCheck compares the AMF PDU session ids with the SMF session store in both
// directions. A deregistered UE is skipped on the AMF side: it holds no sessions.
func crossCheck(ues []amfUE, sessions []smfSession) []finding {
	bySession := map[string]bool{}
	smfSUPIs := map[string]bool{}
	for _, s := range sessions {
		bySession[fmt.Sprintf("%s/%d", s.SUPI, s.PSI)] = true
	}
	amfSUPIs := map[string]bool{}
	amfPSIs := map[string]map[int]bool{} // only UEs that report pdu_session_ids
	for _, u := range ues {
		amfSUPIs[u.SUPI] = true
		if u.HasPSIs {
			set := amfPSIs[u.SUPI]
			if set == nil {
				set = map[int]bool{}
				amfPSIs[u.SUPI] = set
			}
			for _, p := range u.PSIs {
				set[p] = true
			}
		}
	}
	var out []finding
	n := 0
	for _, u := range ues {
		if strings.Contains(strings.ToUpper(u.GMMState), "DEREGISTERED") {
			continue
		}
		for _, p := range u.PSIs {
			if bySession[fmt.Sprintf("%s/%d", u.SUPI, p)] {
				continue
			}
			if n++; n > maxFindingsPerCheck {
				break
			}
			out = append(out, finding{sevError, "amf_psi_without_smf_session",
				fmt.Sprintf("AMF UE %s lists PDU session id %d but the SMF has no such session", u.SUPI, p),
				"TS 23.502 §4.3.2"})
		}
	}
	n, m := 0, 0
	for _, s := range sessions {
		smfSUPIs[s.SUPI] = true
		if amfSUPIs[s.SUPI] {
			set, known := amfPSIs[s.SUPI]
			if !known || set[s.PSI] {
				continue
			}
			if m++; m > maxFindingsPerCheck {
				continue
			}
			out = append(out, finding{sevError, "smf_session_without_amf_psi",
				fmt.Sprintf("SMF holds PDU session %d for %s but the AMF UE context does not list that PDU session id", s.PSI, s.SUPI),
				"TS 23.502 §4.3.2.2.1"})
			continue
		}
		if n++; n > maxFindingsPerCheck {
			continue
		}
		out = append(out, finding{sevError, "smf_session_without_amf_ue",
			fmt.Sprintf("SMF holds PDU session %d for %s but the AMF has no UE context for it", s.PSI, s.SUPI),
			"TS 23.502 §4.3.2"})
	}
	return out
}

// scrapeChecks reports scrape targets that are down and NF types with a scrape
// target but no NRF registration. The UPF (PFCP only) and the NRF itself do not
// register in the NRF in this core, so they are exempt. The registration check is
// skipped when the NRF gauge could not be read.
func scrapeChecks(targets []clients.Target, registered map[string]bool, nrfOK bool) []finding {
	var out []finding
	seen := map[string]bool{}
	for _, tg := range targets {
		nf := strings.ToUpper(tg.NF)
		if !tg.Up {
			out = append(out, finding{sevWarning, "scrape_target_down",
				fmt.Sprintf("Prometheus target for %s (%s) is down", nf, tg.Raw), "n/a (operational)"})
		}
		if !nrfOK || nf == "UPF" || nf == "NRF" || seen[nf] {
			continue
		}
		seen[nf] = true
		if !registered[nf] {
			out = append(out, finding{sevWarning, "nrf_registration_missing",
				fmt.Sprintf("%s has a scrape target but no NRF registration (fivegc_nf_instances_registered{nf_type=%q})", nf, nf),
				"TS 29.510 §5.2.2.2"})
		}
	}
	return out
}
