package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/mcp/internal/config"
	"github.com/francurieses/claudia-5gc/mcp/internal/guard"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// wantRisk is the risk level of every tool the server registers. A change to a
// tool's risk, or a tool added or removed, fails this test until it is reviewed.
var wantRisk = map[string]registry.Risk{
	// A: codecs (pure)
	"nas_decode": registry.ReadOnly, "nas_encode": registry.ReadOnly,
	"ie_validate": registry.ReadOnly, "tlv_inspect": registry.ReadOnly,
	"ngap_decode": registry.ReadOnly, "pfcp_decode": registry.ReadOnly,
	// B: NRF discovery
	"nf_discover": registry.ReadOnly, "nf_list": registry.ReadOnly, "nf_status": registry.ReadOnly,
	// C: UE contexts (gmm_state_get is a deprecated alias of ue_context_get)
	"ue_list": registry.ReadOnly, "ue_context_get": registry.ReadOnly,
	"ran_gnb_list": registry.ReadOnly, "gmm_state_get": registry.ReadOnly,
	// D: traces
	"trace_query": registry.ReadOnly,
	// E: 5G-AKA (pure)
	"milenage_run": registry.ReadOnly, "suci_derive": registry.ReadOnly,
	"xres_star_compute": registry.ReadOnly, "res_star_verify": registry.ReadOnly,
	"kdf_compute": registry.ReadOnly, "aka_full_run": registry.ReadOnly,
	// F: metrics
	"metric_query": registry.ReadOnly, "kpi_snapshot": registry.ReadOnly, "alert_list": registry.ReadOnly,
	// H: PCF QoS overrides
	"qos_policy_set": registry.Mutating, "qos_policy_get": registry.ReadOnly,
	"qos_policy_delete": registry.Mutating,
	// I: PDU sessions (pdu_session_qos_modify is a deprecated alias of pdu_session_qos_set)
	"pdu_session_list": registry.ReadOnly, "pdu_session_qos_get": registry.ReadOnly,
	"pdu_session_qos_set": registry.Disruptive, "pdu_session_qos_modify": registry.Disruptive,
	"subscription_qos_get": registry.ReadOnly,
	// J: status
	"core_health": registry.ReadOnly, "deployment_status": registry.ReadOnly,
	"subscriber_list": registry.ReadOnly, "subscriber_get": registry.ReadOnly,
	"config_view": registry.ReadOnly, "pws_list": registry.ReadOnly,
	// K: analysis and PCAP (procedure_summary is a deprecated alias of procedure_stats)
	"log_query": registry.ReadOnly, "procedure_timeline": registry.ReadOnly,
	"ue_diagnose": registry.ReadOnly, "procedure_stats": registry.ReadOnly,
	"procedure_summary": registry.ReadOnly, "pcap_list": registry.ReadOnly,
	"pcap_control": registry.Mutating,
	// L: core-side control
	"ue_deregister_nw": registry.Disruptive, "pdu_session_release_nw": registry.Disruptive,
	"ue_policy_push": registry.Disruptive, "ue_page": registry.Disruptive,
	"nssaa_trigger": registry.Disruptive, "pws_broadcast": registry.Disruptive,
	"pws_cancel": registry.Disruptive,
	// M: runtime config, audit log
	"slice_session_ambr_set": registry.Disruptive, "rfsp_override_set": registry.Disruptive,
	"ursp_template_apply": registry.Disruptive, "nf_service_control": registry.Admin,
	"mcp_audit_log": registry.ReadOnly, "nf_log_level": registry.Mutating,
	// MCP-009 wave 2: read-only status and analysis (no NF change)
	"upf_stats": registry.ReadOnly, "core_consistency_check": registry.ReadOnly,
	"error_summary": registry.ReadOnly, "mcp_info": registry.ReadOnly,
	"slice_status": registry.ReadOnly, "subscription_am_get": registry.ReadOnly,
	"pcf_binding_list": registry.ReadOnly,
	// MCP-010: AN release, location, AF QoS (NEF), PWS resend, MT-SMS
	"ue_an_release_nw": registry.Disruptive, "ue_location_get": registry.Disruptive,
	"af_qos_session_create": registry.Disruptive, "af_qos_session_get": registry.ReadOnly,
	"af_qos_session_delete": registry.Disruptive, "pws_resend": registry.Disruptive,
	"sms_send_mt": registry.Disruptive,
	// MCP-011: AMF timers, PCF override list, subscriber provisioning
	"amf_timer_config": registry.Mutating, "qos_policy_list": registry.ReadOnly, "n4_session_get": registry.ReadOnly,
	"subscriber_profile_update": registry.Disruptive,
	"subscriber_provision":      registry.Admin, "subscriber_delete": registry.Admin,
}

// TestRiskGolden registers every tool group exactly as main does and checks the
// name and risk level of each tool against wantRisk.
func TestRiskGolden(t *testing.T) {
	cfg := loadTestConfig(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	g := guard.New(guard.Options{Mode: guard.ModeLab}, logger)
	reg := registry.New()
	if err := registerTools(reg, cfg, g, logger); err != nil {
		t.Fatalf("registerTools: %v", err)
	}
	got := map[string]registry.Risk{}
	for _, tl := range reg.List() {
		got[tl.Name()] = tl.Risk()
	}
	for name, want := range wantRisk {
		r, ok := got[name]
		if !ok {
			t.Errorf("tool %s is not registered", name)
			continue
		}
		if r != want {
			t.Errorf("tool %s: risk %s, want %s", name, r, want)
		}
	}
	for name := range got {
		if _, ok := wantRisk[name]; !ok {
			t.Errorf("tool %s is registered but has no reviewed risk level", name)
		}
	}
	if len(got) != 77 {
		t.Errorf("tool count: got %d, want 77", len(got))
	}
}

// TestNoUERANSIMTools guards the 2026-10-09 decisions: no UE or RAN simulator
// control or status runs through MCP. The UERANSIM and PacketRusher tools were
// removed and must not come back by accident.
func TestNoUERANSIMTools(t *testing.T) {
	cfg := loadTestConfig(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	g := guard.New(guard.Options{Mode: guard.ModeLab}, logger)
	reg := registry.New()
	if err := registerTools(reg, cfg, g, logger); err != nil {
		t.Fatalf("registerTools: %v", err)
	}
	for _, tl := range reg.List() {
		if strings.HasPrefix(tl.Name(), "ueransim_") || strings.HasPrefix(tl.Name(), "packetrusher_") {
			t.Errorf("RAN simulator tool %s must not be registered", tl.Name())
		}
	}
}

// loadTestConfig loads a minimal config through the real loader, so defaults apply.
func loadTestConfig(t *testing.T) *config.Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("transport: sse\naccess_mode: lab\nallow_service_control: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}
