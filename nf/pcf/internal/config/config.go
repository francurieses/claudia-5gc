package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	operatorcfg "github.com/francurieses/claudia-5gc/shared/config"
)

// SMPolicyDefaults holds operator-configurable defaults for SM Policy responses.
// All values come from config YAML — no hardcoding in handler code.
// Ref: TS 29.512 §5.2.2.2 (SmPolicyControl_Create response)
type SMPolicyDefaults struct {
	SessionAMBRUplink   string `yaml:"session_ambr_uplink"`
	SessionAMBRDownlink string `yaml:"session_ambr_downlink"`
	FiveQI              int    `yaml:"5qi"`
	ARPPriorityLevel    int    `yaml:"arp_priority_level"`
	ARPPreemptCap       string `yaml:"arp_preempt_cap"`
	ARPPreemptVuln      string `yaml:"arp_preempt_vuln"`
	FlowDescription     string `yaml:"flow_description"`
	FlowPrecedence      int    `yaml:"flow_precedence"`
	// Authorized5QI is the set of 5QI values the PCF permits on an SM Policy
	// Association Update (TS 29.512 §5.2.2.3). Empty ⇒ any standardised/operator
	// 5QI is allowed. Ref: TS 23.501 Table 5.7.4-1.
	Authorized5QI []int `yaml:"authorized_5qi"`
	// MaxSessionAMBRMbps caps the Session-AMBR (UL or DL, in Mbps) a modification
	// may request. 0 ⇒ no ceiling. Ref: TS 29.512 §5.2.2.3.
	MaxSessionAMBRMbps int `yaml:"max_session_ambr_mbps"`
}

// URSPRouteDescriptorConfig is a single Route Selection Descriptor within a default URSP rule.
type URSPRouteDescriptorConfig struct {
	Precedence uint8  `yaml:"precedence"`
	SSCMode    *uint8 `yaml:"ssc_mode,omitempty"`
	SNSSAI     *struct {
		SST uint8  `yaml:"sst"`
		SD  string `yaml:"sd"`
	} `yaml:"snssai,omitempty"`
	DNN            *string `yaml:"dnn,omitempty"`
	PDUSessionType *uint8  `yaml:"pdu_session_type,omitempty"`
}

// URSPRuleConfig is a single URSP rule in the PCF default policy config.
type URSPRuleConfig struct {
	Precedence        uint8 `yaml:"precedence"`
	TrafficDescriptor struct {
		MatchAll    bool     `yaml:"match_all,omitempty"`
		DNNs        []string `yaml:"dnns,omitempty"`
		FQDNs       []string `yaml:"fqdns,omitempty"`
		IPv4Addrs   []string `yaml:"ipv4_addrs,omitempty"`
		ProtocolIDs []uint8  `yaml:"protocol_ids,omitempty"`
	} `yaml:"traffic_descriptor"`
	RouteDescriptors []URSPRouteDescriptorConfig `yaml:"route_descriptors"`
}

type Config struct {
	NFInstanceID string `yaml:"nf_instance_id"`
	PLMN         struct {
		MCC string `yaml:"mcc"`
		MNC string `yaml:"mnc"`
	} `yaml:"plmn"`
	SBI struct {
		Address string `yaml:"address"`
		TLS     struct {
			CertFile string `yaml:"cert_file"`
			KeyFile  string `yaml:"key_file"`
			CAFile   string `yaml:"ca_file"`
		} `yaml:"tls"`
	} `yaml:"sbi"`
	Peers struct {
		NRF string `yaml:"nrf"`
		UDR string `yaml:"udr"`
	} `yaml:"peers"`
	Metrics struct {
		Address string `yaml:"address"`
	} `yaml:"metrics"`
	DefaultSMPolicy SMPolicyDefaults `yaml:"default_sm_policy"`
	DefaultURSP     struct {
		Rules []URSPRuleConfig `yaml:"rules"`
	} `yaml:"default_ursp"`
}

func Load() (*Config, error) {
	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = "/etc/5gc/config.yaml"
	}

	cfg := &Config{
		NFInstanceID: "00000000-0000-4006-8000-000000000001",
	}
	cfg.PLMN.MCC = "001"
	cfg.PLMN.MNC = "01"
	cfg.SBI.Address = "0.0.0.0:8006"
	cfg.Metrics.Address = "0.0.0.0:9106"
	cfg.SBI.TLS.CAFile = "/etc/5gc/pki/ca.crt"
	cfg.SBI.TLS.CertFile = "/etc/5gc/pki/pcf.crt"
	cfg.SBI.TLS.KeyFile = "/etc/5gc/pki/pcf.key"
	cfg.Peers.NRF = "nrf:8000"
	cfg.Peers.UDR = "udr:8005"

	// Layer operator PLMN between Go defaults and per-NF YAML.
	if op, err := operatorcfg.LoadOperator(""); err != nil {
		return nil, fmt.Errorf("config: operator config: %w", err)
	} else if op != nil {
		op.ApplyToPLMN(&cfg.PLMN.MCC, &cfg.PLMN.MNC)
	}

	cfg.DefaultSMPolicy = SMPolicyDefaults{
		SessionAMBRUplink:   "100 Mbps",
		SessionAMBRDownlink: "100 Mbps",
		FiveQI:              9,
		ARPPriorityLevel:    8,
		ARPPreemptCap:       "NOT_PREEMPT",
		ARPPreemptVuln:      "NOT_PREEMPTABLE",
		FlowDescription:     "permit out ip from any to assigned",
		FlowPrecedence:      100,
	}

	data, err := os.ReadFile(cfgPath)
	if err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("config: parse YAML: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("config: read file: %w", err)
	}

	return cfg, nil
}
