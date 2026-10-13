package status

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// sourceTimeout bounds each upstream read in slice_status.
const sourceTimeout = 3 * time.Second

var sdRe = regexp.MustCompile(`^[0-9A-Fa-f]{6}$`)

// sliceStatusTool joins, per S-NSSAI, the registered UEs (Prometheus), the active
// sessions per DNN (SMF), the Session-AMBR configuration (portal) and the gNBs
// that support the slice (AMF). Ref: TS 23.501 §5.15 (network slicing).
type sliceStatusTool struct{ d Deps }

func (sliceStatusTool) Name() string        { return "slice_status" }
func (sliceStatusTool) Risk() registry.Risk { return registry.ReadOnly }
func (sliceStatusTool) Description() string {
	return "Per network slice (S-NSSAI): registered_ues (Prometheus fivegc_ue_registered_by_slice{nf=\"AMF\"}), " +
		"active_sessions_by_dnn (SMF session store), session_ambr_config (portal slice QoS: Session-AMBR per DNN) " +
		"and gnbs_supporting (AMF gNBs whose supported TAs list the slice). The slice set is every slice seen in " +
		"those sources. A source that fails gives null for its field and a reason under \"unavailable\". " +
		"Filter with sst and/or sd. Ref: TS 23.501 §5.15."
}
func (sliceStatusTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"sst":{"type":"integer","description":"Slice/Service Type 0-255, e.g. 1 (eMBB)"},
"sd":{"type":"string","description":"Slice Differentiator, exactly 6 hex digits, e.g. 000001"}}}`)
}
func (sliceStatusTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"array","items":{"type":"object"}}`)
}

type sliceKey struct {
	SST int
	SD  string
}

type sliceEntry struct {
	Snssai       map[string]any    `json:"snssai"`
	RegisteredUE any               `json:"registered_ues"`
	Sessions     any               `json:"active_sessions_by_dnn"`
	AMBR         any               `json:"session_ambr_config"`
	GNBs         any               `json:"gnbs_supporting"`
	Unavailable  map[string]string `json:"unavailable,omitempty"`
}

func (t sliceStatusTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		SST *int   `json:"sst"`
		SD  string `json:"sd"`
	}
	if len(in) > 0 {
		if err := json.Unmarshal(in, &a); err != nil {
			return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "slice_status args: %v", err)
		}
	}
	if a.SST != nil && (*a.SST < 0 || *a.SST > 255) {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"sst": *a.SST}, "sst must be 0-255, got %d", *a.SST)
	}
	if a.SD != "" && !sdRe.MatchString(a.SD) {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"sd": a.SD}, "sd must be exactly 6 hex digits, got %q", a.SD)
	}
	sd := strings.ToLower(a.SD)
	match := func(k sliceKey) bool {
		return (a.SST == nil || *a.SST == k.SST) && (sd == "" || sd == k.SD)
	}

	var (
		wg                              sync.WaitGroup
		ues                             map[sliceKey]float64
		uesErr, smfErr, ambrErr, gnbErr error
		sessions                        map[sliceKey]map[string]int
		ambr                            map[sliceKey][]map[string]any
		gnbs                            map[sliceKey]int
	)
	bounded := func(f func(context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, sourceTimeout)
			defer cancel()
			f(c)
		}()
	}
	bounded(func(c context.Context) { ues, uesErr = t.readUEs(c) })
	bounded(func(c context.Context) { sessions, smfErr = t.readSessions(c) })
	bounded(func(c context.Context) { ambr, ambrErr = t.readAMBR(c) })
	bounded(func(c context.Context) { gnbs, gnbErr = t.readGNBs(c) })
	wg.Wait()

	if uesErr != nil && smfErr != nil && ambrErr != nil && gnbErr != nil {
		return nil, mcperr.ToolError(fmt.Errorf("slice_status: every source failed: prometheus: %v; smf: %v", uesErr, smfErr), nil)
	}

	keys := map[sliceKey]bool{}
	for k := range ues {
		keys[k] = true
	}
	for k := range sessions {
		keys[k] = true
	}
	for k := range ambr {
		keys[k] = true
	}
	for k := range gnbs {
		keys[k] = true
	}
	ordered := make([]sliceKey, 0, len(keys))
	for k := range keys {
		if match(k) {
			ordered = append(ordered, k)
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].SST != ordered[j].SST {
			return ordered[i].SST < ordered[j].SST
		}
		return ordered[i].SD < ordered[j].SD
	})

	out := make([]sliceEntry, 0, len(ordered))
	for _, k := range ordered {
		e := sliceEntry{Snssai: map[string]any{"sst": k.SST, "sd": k.SD}, Unavailable: map[string]string{}}
		switch {
		case uesErr != nil:
			e.Unavailable["registered_ues"] = "prometheus query failed: " + uesErr.Error()
		default:
			if v, ok := ues[k]; ok {
				e.RegisteredUE = int(v)
			} else {
				e.Unavailable["registered_ues"] = "no fivegc_ue_registered_by_slice series for this slice"
			}
		}
		if smfErr != nil {
			e.Unavailable["active_sessions_by_dnn"] = "SMF session list failed: " + smfErr.Error()
		} else if m := sessions[k]; m != nil {
			e.Sessions = m
		} else {
			e.Sessions = map[string]int{}
		}
		if ambrErr != nil {
			e.Unavailable["session_ambr_config"] = "portal slice QoS failed: " + ambrErr.Error()
		} else if l := ambr[k]; l != nil {
			e.AMBR = l
		} else {
			e.AMBR = []map[string]any{}
		}
		if gnbErr != nil {
			e.Unavailable["gnbs_supporting"] = "AMF gNB list failed: " + gnbErr.Error()
		} else {
			e.GNBs = gnbs[k]
		}
		if len(e.Unavailable) == 0 {
			e.Unavailable = nil
		}
		out = append(out, e)
	}
	slog.InfoContext(ctx, "slice status read", "nf", "MCP", "procedure", "McpStatusAnalysisWave2",
		"tool_name", "slice_status", "interface", "Namf/Nsmf/Prometheus", "direction", "OUT",
		"spec_ref", "TS 23.501 §5.15", "slices", len(out), "latency_ms", time.Since(start).Milliseconds())
	return out, nil
}

func sliceFrom(sst, sd string) (sliceKey, bool) {
	n, err := strconv.Atoi(sst)
	if err != nil {
		return sliceKey{}, false
	}
	return sliceKey{SST: n, SD: strings.ToLower(sd)}, true
}

func (t sliceStatusTool) readUEs(ctx context.Context) (map[sliceKey]float64, error) {
	if t.d.Prom == nil {
		return nil, fmt.Errorf("prometheus not configured")
	}
	res, err := t.d.Prom.Query(ctx, `sum by (sst, sd) (fivegc_ue_registered_by_slice{nf="AMF"})`, time.Time{})
	if err != nil {
		return nil, err
	}
	out := map[sliceKey]float64{}
	for _, s := range res.Data.Result {
		if nf, has := s.Metric["nf"]; has && nf != "AMF" {
			continue
		}
		if k, ok := sliceFrom(s.Metric["sst"], s.Metric["sd"]); ok {
			out[k] += s.Float64()
		}
	}
	return out, nil
}

func (t sliceStatusTool) readSessions(ctx context.Context) (map[sliceKey]map[string]int, error) {
	sessions, err := readSMFSessions(ctx, t.d.SMF)
	if err != nil {
		return nil, err
	}
	out := map[sliceKey]map[string]int{}
	for _, s := range sessions {
		k := sliceKey{SST: s.SNssai.SST, SD: strings.ToLower(s.SNssai.SD)}
		if out[k] == nil {
			out[k] = map[string]int{}
		}
		if s.SessionState != "" && !strings.EqualFold(s.SessionState, "ACTIVE") {
			continue
		}
		out[k][s.DNN]++
	}
	return out, nil
}

func (t sliceStatusTool) readAMBR(ctx context.Context) (map[sliceKey][]map[string]any, error) {
	if t.d.Portal == nil {
		return nil, fmt.Errorf("portal not configured")
	}
	raw, err := t.d.Portal.Get(ctx, "/slices/qos", nil)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decode slice qos: %w", err)
	}
	out := map[sliceKey][]map[string]any{}
	for _, it := range doc.Items {
		sn, _ := it["snssai"].(map[string]any)
		sst, ok := sn["sst"].(float64)
		if !ok {
			continue
		}
		sd, _ := sn["sd"].(string)
		k := sliceKey{SST: int(sst), SD: strings.ToLower(sd)}
		entry := map[string]any{}
		for f, v := range it {
			if f != "snssai" {
				entry[f] = v
			}
		}
		out[k] = append(out[k], entry)
	}
	return out, nil
}

func (t sliceStatusTool) readGNBs(ctx context.Context) (map[sliceKey]int, error) {
	if t.d.AMF == nil {
		return nil, fmt.Errorf("amf not configured")
	}
	raw, err := t.d.AMF.ListGNBs(ctx)
	if err != nil {
		return nil, err
	}
	var doc struct {
		GNBs []struct {
			State        string `json:"state"`
			SupportedTAs []struct {
				BroadcastPLMNs []struct {
					Slices []struct {
						SST int    `json:"sst"`
						SD  string `json:"sd"`
					} `json:"slices"`
				} `json:"broadcast_plmns"`
			} `json:"supported_tas"`
		} `json:"gnbs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decode gNB list: %w", err)
	}
	out := map[sliceKey]int{}
	for _, g := range doc.GNBs {
		if strings.EqualFold(g.State, "DISCONNECTED") {
			continue
		}
		seen := map[sliceKey]bool{}
		for _, ta := range g.SupportedTAs {
			for _, p := range ta.BroadcastPLMNs {
				for _, s := range p.Slices {
					k := sliceKey{SST: s.SST, SD: strings.ToLower(s.SD)}
					if !seen[k] {
						seen[k] = true
						out[k]++
					}
				}
			}
		}
	}
	return out, nil
}
