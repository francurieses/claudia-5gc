// Package status implements the read-only status tools: core health, deployment
// and subscriber state, configuration and PWS state. Subscriber
// secrets never leave this package: the portal client redacts them.
//
// 3GPP references: NF health TS 29.510 §5.2.2.6 (NF profile status); the other
// tools report operator state and carry no procedure of their own.
package status

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/guard"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/toolutil"
)

// Deps are the upstreams the status tools read from. HTTP reaches the NF metrics
// ports for /healthz; it is plain HTTP, like the metrics endpoints.
type Deps struct {
	NRF    *clients.NRF
	Portal *clients.Portal
	Prom   *promclient.Client
	HTTP   *http.Client
	// Targets resolves NF metrics addresses (with the metrics_host_override applied).
	Targets *clients.Targets
	// Probes are the cheap reachability checks core_health reports under
	// dependencies (Loki, Jaeger, ...). The portal and Prometheus are checked through
	// their own clients.
	Probes []Probe

	// The fields below serve mcp_info, slice_status and pcf_binding_list.
	AMF *clients.AMF
	SMF *clients.SMF
	BSF *clients.BSF
	// SBI is the mTLS client used to probe the SBI upstreams in mcp_info.
	SBI *http.Client
	// Registry and Guard let mcp_info read the tool counts and the access mode at call time.
	Registry *registry.Registry
	Guard    *guard.Guard
	// Version and BuildCommit identify this build (BuildCommit is set with -ldflags).
	Version, BuildCommit string
	// Upstreams are what mcp_info probes.
	Upstreams []Upstream
}

// Probe is one dependency core_health checks with a GET.
type Probe struct {
	Name string
	URL  string
}

// dependencyTimeout bounds each dependency probe in core_health.
const dependencyTimeout = 2 * time.Second

// targets returns the scrape-target resolver.
func (d Deps) targets() *clients.Targets {
	if d.Targets != nil {
		return d.Targets
	}
	return clients.NewTargets(d.Prom, "")
}

// All returns the status tools.
func All(d Deps) []registry.Tool {
	return []registry.Tool{
		coreHealthTool{d}, deploymentTool{d}, subscriberListTool{d}, subscriberGetTool{d},
		configViewTool{d}, pwsListTool{d},
		mcpInfoTool{d}, sliceStatusTool{d}, pcfBindingListTool{d},
	}
}

func schema(s string) json.RawMessage { return json.RawMessage(s) }

// ---- core_health ------------------------------------------------------------

type coreHealthTool struct{ d Deps }

func (coreHealthTool) Name() string        { return "core_health" }
func (coreHealthTool) Risk() registry.Risk { return registry.ReadOnly }
func (coreHealthTool) Description() string {
	return "Health of every NF: the NRF registration state, the Prometheus scrape target of each NF, and a " +
		"live GET /healthz on its metrics port. An NF without /healthz (the NRF) is judged by its scrape state. " +
		"One NF failing does not hide the others."
}
func (coreHealthTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{}}`)
}
func (coreHealthTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"nfs":{"type":"array"},"summary":{"type":"object"}}}`)
}

// nfProfile is the subset of an NRF NFProfile this tool reads. The NRF does not
// publish endpoint addresses in its profiles, so only the identity and status are used.
type nfProfile struct {
	NFInstanceID string `json:"nfInstanceId"`
	NFType       string `json:"nfType"`
	NFStatus     string `json:"nfStatus"`
}

func (t coreHealthTool) Invoke(ctx context.Context, _ json.RawMessage) (any, error) {
	raw, err := t.d.NRF.List(ctx, true)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("core_health: NRF list: %w", err), nil)
	}
	var list struct {
		NFInstances []nfProfile `json:"nfInstances"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("core_health: decode NRF list: %w", err), nil)
	}
	targets, err := t.d.targets().List(ctx)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("core_health: scrape targets: %w", err), nil)
	}

	// One row per NF, from the NRF registration and the scrape target of the same name.
	byNF := map[string]*nfRow{}
	order := []string{}
	add := func(nf string) *nfRow {
		key := strings.ToUpper(nf)
		if r, ok := byNF[key]; ok {
			return r
		}
		r := &nfRow{NF: key}
		byNF[key] = r
		order = append(order, key)
		return r
	}
	for _, p := range list.NFInstances {
		r := add(p.NFType)
		r.NRFStatus = p.NFStatus
		r.InstanceID = p.NFInstanceID
	}
	for _, tg := range targets {
		r := add(tg.NF)
		r.Instance = tg.Instance
		up := tg.Up
		r.Up = &up
		if tg.Instance == "" {
			r.Err = "invalid Prometheus instance label: " + tg.Raw
		}
	}

	var wg sync.WaitGroup
	for _, key := range order {
		r := byNF[key]
		if r.Instance == "" {
			continue
		}
		wg.Add(1)
		go func(r *nfRow) {
			defer wg.Done()
			t.probe(ctx, r)
		}(r)
	}
	wg.Wait()

	rows := make([]map[string]any, 0, len(order))
	healthy, unhealthy := 0, 0
	for _, key := range order {
		r := byNF[key]
		row := r.toMap()
		rows = append(rows, row)
		switch r.Healthy {
		case healthTrue:
			healthy++
		case healthFalse:
			unhealthy++
		}
	}
	return map[string]any{
		"dependencies": t.dependencies(ctx),
		"nfs":          rows,
		"summary": map[string]any{
			"registered": len(rows), "healthy": healthy, "unhealthy": unhealthy,
			"unknown": len(rows) - healthy - unhealthy,
		},
	}, nil
}

type health int

const (
	healthUnknown health = iota
	healthTrue
	healthFalse
)

// nfRow is what core_health knows about one NF.
type nfRow struct {
	NF, NRFStatus, InstanceID, Instance string
	Up                                  *bool
	Healthy                             health
	HTTPStatus                          int
	Note, Err                           string
}

func (r *nfRow) toMap() map[string]any {
	m := map[string]any{"nf_type": r.NF, "nrf_status": r.NRFStatus, "instance_id": r.InstanceID}
	switch r.Healthy {
	case healthTrue:
		m["healthy"] = true
	case healthFalse:
		m["healthy"] = false
	default:
		m["healthy"] = nil
	}
	if r.Instance != "" {
		m["address"] = r.Instance
	}
	if r.Up != nil {
		m["scrape_up"] = *r.Up
	}
	if r.HTTPStatus != 0 {
		m["http_status"] = r.HTTPStatus
	}
	if r.Note != "" {
		m["note"] = r.Note
	}
	if r.Err != "" {
		m["error"] = r.Err
	}
	return m
}

// probe sets the health of one NF. /healthz is the answer when the NF serves it.
// Otherwise the Prometheus scrape state is the answer.
func (t coreHealthTool) probe(ctx context.Context, r *nfRow) {
	hctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(hctx, http.MethodGet, "http://"+r.Instance+"/healthz", nil)
	if err != nil {
		r.Healthy, r.Err = healthFalse, err.Error()
		return
	}
	resp, err := t.d.HTTP.Do(req)
	if err != nil {
		r.Healthy, r.Err = healthFalse, err.Error()
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	r.HTTPStatus = resp.StatusCode
	switch {
	case resp.StatusCode == http.StatusOK:
		r.Healthy = healthTrue
	case resp.StatusCode == http.StatusNotFound && r.Up != nil:
		r.Note = "no /healthz on the metrics port: judged by its scrape state"
		if *r.Up {
			r.Healthy = healthTrue
		} else {
			r.Healthy = healthFalse
		}
	default:
		r.Healthy = healthFalse
	}
}

// dependencies reports the reachability of what the MCP tools themselves depend on:
// the portal (and its store), Loki, Jaeger and Prometheus. Prometheus answered the
// scrape-target query before this runs, so it is reported reachable.
func (t coreHealthTool) dependencies(ctx context.Context) map[string]any {
	out := map[string]any{"prometheus": map[string]any{"reachable": true}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	set := func(name string, v map[string]any) {
		mu.Lock()
		out[name] = v
		mu.Unlock()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		pctx, cancel := context.WithTimeout(ctx, dependencyTimeout)
		defer cancel()
		reachable, store := t.d.Portal.Health(pctx)
		set("portal", map[string]any{"reachable": reachable, "store": string(store)})
	}()
	for _, p := range t.d.Probes {
		wg.Add(1)
		go func(p Probe) {
			defer wg.Done()
			set(p.Name, map[string]any{"reachable": t.reachable(ctx, p.URL)})
		}(p)
	}
	wg.Wait()
	return out
}

// reachable reports whether a GET to url gets any HTTP answer within dependencyTimeout.
func (t coreHealthTool) reachable(ctx context.Context, url string) bool {
	hctx, cancel := context.WithTimeout(ctx, dependencyTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(hctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := t.d.HTTP.Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	_ = resp.Body.Close()
	return true
}

// ---- deployment_status ------------------------------------------------------

type deploymentTool struct{ d Deps }

func (deploymentTool) Name() string        { return "deployment_status" }
func (deploymentTool) Risk() registry.Risk { return registry.ReadOnly }
func (deploymentTool) Description() string {
	return "The deployment the portal runs: mode (standalone core, UERANSIM, PacketRusher), enabled " +
		"RAN tools and the services it reports. Read-only."
}
func (deploymentTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{}}`)
}
func (deploymentTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object"}`)
}
func (t deploymentTool) Invoke(ctx context.Context, _ json.RawMessage) (any, error) {
	raw, err := t.d.Portal.Get(ctx, "/deployment", nil)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("deployment_status: %w", err), nil)
	}
	return raw, nil
}

// ---- subscriber_list / subscriber_get --------------------------------------

// storeToolError maps a portal error on a store-backed route: a 503 is the portal
// saying its store is unavailable (PORTAL_STORE_UNAVAILABLE); anything else is wrapped.
func storeToolError(tool string, err error) *mcperr.Error {
	if mapped := clients.StoreErr(err); mapped != err {
		if me, ok := mapped.(*mcperr.Error); ok {
			return me
		}
	}
	return mcperr.ToolError(fmt.Errorf("%s: %w", tool, err), nil)
}

type subscriberListTool struct{ d Deps }

func (subscriberListTool) Name() string        { return "subscriber_list" }
func (subscriberListTool) Risk() registry.Risk { return registry.ReadOnly }
func (subscriberListTool) Description() string {
	return "List the subscribers in the UDR as the portal shows them. Long-term keys K, OPc, OP and SQN " +
		"are always redacted. Spec: TS 29.505 (subscription data model)."
}
func (subscriberListTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{}}`)
}
func (subscriberListTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object"}`)
}
func (t subscriberListTool) Invoke(ctx context.Context, _ json.RawMessage) (any, error) {
	// A portal without its store answers 200 [] here: refuse instead of reporting no subscribers.
	if perr := t.d.Portal.RequireStore(ctx); perr != nil {
		return nil, perr
	}
	raw, err := t.d.Portal.Get(ctx, "/subscribers", nil)
	if err != nil {
		return nil, storeToolError("subscriber_list", err)
	}
	return raw, nil
}

type subscriberGetTool struct{ d Deps }

func (subscriberGetTool) Name() string        { return "subscriber_get" }
func (subscriberGetTool) Risk() registry.Risk { return registry.ReadOnly }
func (subscriberGetTool) Description() string {
	return "One subscriber's record and its RFSP index override, if any. K, OPc, OP and SQN are redacted. " +
		"Spec: TS 29.505, TS 38.413 §9.3.1.27 (RFSP)."
}
func (subscriberGetTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"supi":{"type":"string","description":"e.g. imsi-001010000000001"}},"required":["supi"]}`)
}
func (subscriberGetTool) OutputSchema() json.RawMessage { return schema(`{"type":"object"}`) }
func (t subscriberGetTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	var a struct {
		SUPI string `json:"supi"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "subscriber_get args: %v", err)
	}
	if perr := toolutil.ValidSUPI(a.SUPI); perr != nil {
		return nil, perr
	}
	if perr := t.d.Portal.RequireStore(ctx); perr != nil {
		return nil, perr
	}
	sub, err := t.d.Portal.Get(ctx, "/subscribers/"+url.PathEscape(a.SUPI), nil)
	if err != nil {
		return nil, storeToolError("subscriber_get", err)
	}
	rfsp, err := t.d.Portal.Get(ctx, "/subscribers/"+url.PathEscape(a.SUPI)+"/rfsp", nil)
	out := map[string]any{"subscriber": sub, "rfsp_override": json.RawMessage("null")}
	if err == nil {
		out["rfsp_override"] = rfsp
	}
	return out, nil
}

// ---- config_view ------------------------------------------------------------

type configViewTool struct{ d Deps }

func (configViewTool) Name() string        { return "config_view" }
func (configViewTool) Risk() registry.Risk { return registry.ReadOnly }
func (configViewTool) Description() string {
	return "The operator configuration the core runs with: slices, DNNs, per-slice QoS and policy templates. " +
		"Each section is tagged change:runtime (applies live through the matching MCP tool) or " +
		"change:restart_required (read at NF start; a restart applies a change). Read-only."
}
func (configViewTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{}}`)
}
func (configViewTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"sections":{"type":"object"}}}`)
}

// configSections maps each portal section to how it changes. The table is the
// contract the runtime tools depend on: slice QoS and policy templates change live,
// slices and DNNs are read when the NFs start.
var configSections = []struct {
	key, path, change, via string
	// store marks the sections the portal serves from its Postgres store. The others
	// are proxied to the UDR/NFs and do not depend on it.
	store bool
}{
	{"slices", "/slices", "restart_required", "", false},
	{"dnns", "/dnns", "restart_required", "", false},
	{"slice_qos", "/slices/qos", "runtime", "slice_session_ambr_set", false},
	{"policy_templates", "/policy-templates", "runtime", "ursp_template_apply", true},
}

func (t configViewTool) Invoke(ctx context.Context, _ json.RawMessage) (any, error) {
	sections := map[string]any{}
	storeDown := t.d.Portal.StoreStatus(ctx) == clients.StoreDown
	for _, s := range configSections {
		entry := map[string]any{"change": s.change}
		if s.via != "" {
			entry["apply_via"] = s.via
		}
		// The store-backed section is reported as PORTAL_STORE_UNAVAILABLE, never as an
		// empty list. The proxied sections stay readable while the store is down.
		if s.store && storeDown {
			entry["error"] = clients.StoreUnavailableMessage
			entry["data"] = clients.StoreUnavailableError().Data
			sections[s.key] = entry
			continue
		}
		raw, err := t.d.Portal.Get(ctx, s.path, nil)
		if s.store && err != nil {
			if mapped, ok := clients.StoreErr(err).(*mcperr.Error); ok {
				entry["error"] = mapped.Message
				entry["data"] = mapped.Data
				sections[s.key] = entry
				continue
			}
		}
		if err != nil {
			entry["error"] = err.Error()
		} else {
			entry["value"] = raw
		}
		sections[s.key] = entry
	}
	return map[string]any{"sections": sections}, nil
}

// ---- pws_list ---------------------------------------------------------------

type pwsListTool struct{ d Deps }

func (pwsListTool) Name() string        { return "pws_list" }
func (pwsListTool) Risk() registry.Risk { return registry.ReadOnly }
func (pwsListTool) Description() string {
	return "Public Warning System broadcasts the portal's CBC store holds: message id, serial number, state " +
		"and content summary. Spec: TS 38.413 §8.9 (Write-Replace Warning)."
}
func (pwsListTool) InputSchema() json.RawMessage { return schema(`{"type":"object","properties":{}}`) }
func (pwsListTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object"}`)
}
func (t pwsListTool) Invoke(ctx context.Context, _ json.RawMessage) (any, error) {
	raw, err := t.d.Portal.Get(ctx, "/pws/broadcast", nil)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("pws_list: %w", err), nil)
	}
	return raw, nil
}
