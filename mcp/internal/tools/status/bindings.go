package status

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/toolutil"
)

// bindingParallel bounds the concurrent BSF lookups of an unfiltered listing.
const bindingParallel = 5

// maxBindingErrors bounds the error messages kept in the result.
const maxBindingErrors = 5

type smfSessionRow struct {
	SUPI         string `json:"supi"`
	PSI          int    `json:"pduSessionId"`
	DNN          string `json:"dnn"`
	UEIP         string `json:"ueIp"`
	SessionState string `json:"sessionState"`
	SNssai       struct {
		SST int    `json:"sst"`
		SD  string `json:"sd"`
	} `json:"sNssai"`
}

// readSMFSessions reads the SMF session store ({"sessions":[...]} or a bare array).
func readSMFSessions(ctx context.Context, smf *clients.SMF) ([]smfSessionRow, error) {
	if smf == nil {
		return nil, fmt.Errorf("smf not configured")
	}
	raw, err := smf.ListSessions(ctx)
	if err != nil {
		return nil, err
	}
	var wrapped struct {
		Sessions []smfSessionRow `json:"sessions"`
	}
	if err := json.Unmarshal(raw, &wrapped); err == nil {
		return wrapped.Sessions, nil
	}
	var bare []smfSessionRow
	if err := json.Unmarshal(raw, &bare); err != nil {
		return nil, fmt.Errorf("decode SMF sessions: %w", err)
	}
	return bare, nil
}

// pcfBindingListTool lists the PCF bindings the BSF holds. The BSF answers one
// binding per lookup, so an unfiltered call looks up each SMF session's UE IP.
// Ref: TS 29.521 §5.2.2.4 (Nbsf_Management_Discovery).
type pcfBindingListTool struct{ d Deps }

func (pcfBindingListTool) Name() string        { return "pcf_binding_list" }
func (pcfBindingListTool) Risk() registry.Risk { return registry.ReadOnly }
func (pcfBindingListTool) Description() string {
	return "PCF bindings held by the BSF (which PCF serves which UE IP / SUPI / DNN): bindingId, supi, ipv4Addr, " +
		"dnn, snssai, pcfFqdn, pcfId. With supi, ue_ip or dnn the BSF is asked once and returns at most one " +
		"binding; with no filter the SMF sessions are listed and the BSF is asked once per session UE IP. " +
		"bindings_active is the BSF gauge fivegc_bsf_bindings_active; queried is the number of BSF lookups. " +
		"A BSF 404 is an empty list. Ref: TS 29.521 §5.2.2.4."
}
func (pcfBindingListTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"supi":{"type":"string","description":"e.g. imsi-001010000000001"},
"ue_ip":{"type":"string","description":"UE IPv4 address, e.g. 10.60.0.1"},
"dnn":{"type":"string","description":"e.g. internet"}}}`)
}
func (pcfBindingListTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"bindings":{"type":"array"},"bindings_active":{},"queried":{"type":"integer"}}}`)
}

func (t pcfBindingListTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		SUPI string `json:"supi"`
		UEIP string `json:"ue_ip"`
		DNN  string `json:"dnn"`
	}
	if len(in) > 0 {
		if err := json.Unmarshal(in, &a); err != nil {
			return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "pcf_binding_list args: %v", err)
		}
	}
	if a.SUPI != "" {
		if perr := toolutil.ValidSUPI(a.SUPI); perr != nil {
			return nil, perr
		}
	}
	if a.UEIP != "" {
		ip, err := netip.ParseAddr(a.UEIP)
		if err != nil || !ip.Is4() {
			return nil, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"ue_ip": a.UEIP},
				"ue_ip must be an IPv4 address, got %q", a.UEIP)
		}
	}
	if a.DNN != "" {
		if perr := toolutil.ValidDNN(a.DNN); perr != nil {
			return nil, perr
		}
	}
	if t.d.BSF == nil {
		return nil, mcperr.New(mcperr.CodeToolError, "pcf_binding_list: BSF client is not configured (bsf_addr)", nil)
	}

	var queries []url.Values
	if a.SUPI != "" || a.UEIP != "" || a.DNN != "" {
		q := url.Values{}
		if a.SUPI != "" {
			q.Set("supi", a.SUPI)
		}
		if a.UEIP != "" {
			q.Set("ipv4Addr", a.UEIP)
		}
		if a.DNN != "" {
			q.Set("dnn", a.DNN)
		}
		queries = append(queries, q)
	} else {
		sessions, err := readSMFSessions(ctx, t.d.SMF)
		if err != nil {
			return nil, mcperr.ToolError(fmt.Errorf("pcf_binding_list: list SMF sessions: %w", err), nil)
		}
		seen := map[string]bool{}
		for _, s := range sessions {
			if s.UEIP == "" || seen[s.UEIP] {
				continue
			}
			seen[s.UEIP] = true
			queries = append(queries, url.Values{"ipv4Addr": {s.UEIP}})
		}
	}

	type result struct {
		raw json.RawMessage
		err error
	}
	results := make([]result, len(queries))
	sem := make(chan struct{}, bindingParallel)
	var wg sync.WaitGroup
	for i, q := range queries {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, q url.Values) {
			defer wg.Done()
			defer func() { <-sem }()
			c, cancel := context.WithTimeout(ctx, sourceTimeout)
			defer cancel()
			results[i].raw, results[i].err = t.d.BSF.Discover(c, q)
		}(i, q)
	}
	wg.Wait()

	bindings := []json.RawMessage{}
	seenID := map[string]bool{}
	var errs []string
	failed := 0
	for _, r := range results {
		if r.err != nil {
			failed++
			if len(errs) < maxBindingErrors {
				errs = append(errs, r.err.Error())
			}
			continue
		}
		if r.raw == nil {
			continue
		}
		var id struct {
			BindingID string `json:"bindingId"`
		}
		_ = json.Unmarshal(r.raw, &id)
		if id.BindingID != "" {
			if seenID[id.BindingID] {
				continue
			}
			seenID[id.BindingID] = true
		}
		bindings = append(bindings, r.raw)
	}
	if len(queries) > 0 && failed == len(queries) {
		return nil, mcperr.ToolError(fmt.Errorf("pcf_binding_list: BSF lookup failed: %s", errs[0]), nil)
	}

	out := map[string]any{"bindings": bindings, "bindings_active": nil, "queried": len(queries)}
	unavailable := map[string]string{}
	if t.d.Prom == nil {
		unavailable["bindings_active"] = "prometheus not configured"
	} else if res, err := t.d.Prom.Query(ctx, `fivegc_bsf_bindings_active{nf="BSF"}`, time.Time{}); err != nil {
		unavailable["bindings_active"] = "prometheus query failed: " + err.Error()
	} else {
		found := false
		for _, s := range res.Data.Result {
			if nf, has := s.Metric["nf"]; has && nf != "BSF" {
				continue
			}
			out["bindings_active"] = int(s.Float64())
			found = true
			break
		}
		if !found {
			unavailable["bindings_active"] = "no fivegc_bsf_bindings_active{nf=\"BSF\"} series"
		}
	}
	if len(unavailable) > 0 {
		out["unavailable"] = unavailable
	}
	if len(errs) > 0 {
		out["lookup_errors"] = errs
	}
	slog.InfoContext(ctx, "pcf bindings listed", "nf", "MCP", "procedure", "McpStatusAnalysisWave2",
		"tool_name", "pcf_binding_list", "interface", "Nbsf", "direction", "OUT",
		"spec_ref", "TS 29.521 §5.2.2.4", "queried", len(queries), "bindings", len(bindings),
		"latency_ms", time.Since(start).Milliseconds())
	return out, nil
}
