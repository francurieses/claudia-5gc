package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	operatorcfg "github.com/francurieses/claudia-5gc/shared/config"
)

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
		PCF string `yaml:"pcf"`
		UDM string `yaml:"udm"`
		UPF string `yaml:"upf"`
		// AMFMgmt is the AMF management API (plain HTTP) used to trigger
		// NW-initiated PDU session procedures towards the UE (N1/N2 delivery).
		AMFMgmt string `yaml:"amf_mgmt"`
		// AMF is the AMF SBI (namf-comm, mTLS HTTP/2) endpoint used for
		// Namf_Communication_N1N2MessageTransfer (CN paging of CM-IDLE UEs).
		// Ref: TS 29.518 §5.2.2.3, TS 23.502 §4.2.3.3.
		AMF string `yaml:"amf"`
	} `yaml:"peers"`
	Metrics struct {
		Address string `yaml:"address"`
	} `yaml:"metrics"`
	// UEIPPool is the legacy single-DNN pool (used when DNNs is empty).
	// Superseded by DNNs when per-DNN subnet isolation is configured.
	UEIPPool  string `yaml:"ue_ip_pool"`
	UPFN3Addr string `yaml:"upf_n3_addr"`
	// SNSSAIs is the list of slices this SMF instance handles.
	// Ref: TS 29.510 §5.2.2.2.2
	SNSSAIs []struct {
		SST int    `yaml:"sst"`
		SD  string `yaml:"sd"`
	} `yaml:"snssais"`
	// DNNs defines per-DNN UE IP pools served by this SMF instance.
	// Ref: TS 23.501 §5.6.5, TS 29.244 §6.3.3.14 (Network Instance IE)
	// Adding a new DNN: append an entry and add matching entry in operator.yaml.
	DNNs []DNNConfig `yaml:"dnns"`
	// N4 configures the SMF's PFCP behaviour on N4 beyond the client sends
	// (establishment/modification/deletion): the persistent Session Report
	// receiver and the Usage Reporting Rule installed at establishment.
	// Ref: TS 29.244 §5.2.2.4, §7.5.2.4, §7.5.5.
	N4 N4Config `yaml:"n4"`
}

// N4Config holds PFCP (N4) usage-reporting configuration.
// Ref: TS 29.244 §5.2.2.4 (URR handling), §7.5.5 (Session Report Request).
type N4Config struct {
	// ReportListen is the address the SMF's persistent PFCP receiver binds
	// to for node-initiated messages (Session Report Request). This is the
	// well-known N4 UDP port; every SMF instance must have one bound inside
	// its own container. Ref: TS 29.244 §6.2.1.
	ReportListen string `yaml:"report_listen"`
	// VolumeThresholdBytes is the total-volume threshold (TOVOL) installed
	// in the Create URR's Volume Threshold IE at PDU Session Establishment.
	// Crossing it triggers a VOLTH Usage Report. Ref: TS 29.244 §8.2.13.
	VolumeThresholdBytes uint64 `yaml:"volume_threshold_bytes"`
	// MeasurementPeriodSeconds is the periodic reporting cadence installed
	// in the Create URR's Measurement Period IE. Ref: TS 29.244 §8.2.42.
	MeasurementPeriodSeconds int `yaml:"measurement_period_seconds"`
}

// DNNConfig holds the per-DNN IP pool configuration for the SMF.
// Ref: TS 23.501 §5.6.5, §5.8.2.2
type DNNConfig struct {
	Name     string `yaml:"name"`
	UEIPPool string `yaml:"ue_ip_pool"`
	// UEIPv6Prefix is the base IPv6 prefix (e.g. "2001:db8:61::/56") from which
	// per-session /64 prefixes are delegated for IPv6 / IPv4v6 PDU sessions.
	// Empty = the DNN is IPv4-only (IPv6 requests are downgraded to IPv4).
	// Ref: TS 23.501 §5.8.2.2.
	UEIPv6Prefix string `yaml:"ue_ipv6_prefix"`
	// SecondaryAuth marks the DNN as requiring DN-specific secondary
	// authentication/authorization with an external DN-AAA server during PDU
	// Session Establishment. Default false — a DNN not listed here (or listed
	// without this flag) establishes exactly as before (no EAP round).
	// Ref: TS 23.501 §5.6.6, TS 23.502 §4.3.2.3.
	SecondaryAuth bool `yaml:"secondary_auth"`
	// DNAAAUnreachable is a dev/test knob that simulates an unreachable/
	// timing-out DN-AAA for this DNN (TS 24.501 §9.11.4.2 unreachable/timeout
	// error case). Only meaningful when SecondaryAuth is true.
	DNAAAUnreachable bool `yaml:"dn_aaa_unreachable"`
	// DNS is the list of IPv4 DNS resolver addresses advertised to the UE in
	// the (Extended) Protocol Configuration Options of the PDU Session
	// Establishment Accept (TS 24.008 §10.5.6.3, container ID 0x000D "DNS
	// Server IPv4 Address"). Defaulted in Load() when empty — Android (and
	// most UEs) treat an empty PCO DNS list as "no internet" even when the
	// user-plane IP path itself works, since connectivity validation needs a
	// resolver to reach the captive-portal check host.
	DNS []string `yaml:"dns"`
}

// DefaultDNSServers matches Open5GS's smf.yaml default PCO DNS list.
var DefaultDNSServers = []string{"8.8.8.8", "8.8.4.4"}

func Load() (*Config, error) {
	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = "/etc/5gc/config.yaml"
	}

	cfg := &Config{
		NFInstanceID: "00000000-0000-4005-8000-000000000001",
		UEIPPool:     "10.60.0.0/16",
		UPFN3Addr:    "172.30.3.100",
	}
	cfg.PLMN.MCC, cfg.PLMN.MNC = "001", "01"
	cfg.SBI.Address = "0.0.0.0:8004"
	cfg.Metrics.Address = "0.0.0.0:9105"
	cfg.Peers.PCF, cfg.Peers.UDM, cfg.Peers.UPF = "pcf:8006", "udm:8003", "upf:8805"
	cfg.Peers.AMFMgmt = "amf:9002"
	cfg.Peers.AMF = "amf:8001"
	cfg.SBI.TLS.CAFile = "/etc/5gc/pki/ca.crt"
	cfg.SBI.TLS.CertFile, cfg.SBI.TLS.KeyFile = "/etc/5gc/pki/smf.crt", "/etc/5gc/pki/smf.key"
	cfg.Peers.NRF = "nrf:8000"
	cfg.N4.ReportListen = "0.0.0.0:8805"
	cfg.N4.VolumeThresholdBytes = 1000000 // 1 MB, TS 29.244 §8.2.13
	cfg.N4.MeasurementPeriodSeconds = 60  // TS 29.244 §8.2.42

	// Layer operator config (PLMN + slices + DNNs) between Go defaults and per-NF YAML.
	if op, err := operatorcfg.LoadOperator(""); err != nil {
		return nil, fmt.Errorf("config: operator config: %w", err)
	} else if op != nil {
		op.ApplyToPLMN(&cfg.PLMN.MCC, &cfg.PLMN.MNC)
		if slices := op.Slices(); len(slices) > 0 {
			cfg.SNSSAIs = cfg.SNSSAIs[:0]
			for _, s := range slices {
				cfg.SNSSAIs = append(cfg.SNSSAIs, struct {
					SST int    `yaml:"sst"`
					SD  string `yaml:"sd"`
				}{SST: s.SST, SD: s.SD})
			}
		}
		// Populate per-DNN config from operator registry (can be overridden by per-NF YAML).
		if dnnList := op.DNNList(); len(dnnList) > 0 && len(cfg.DNNs) == 0 {
			for _, d := range dnnList {
				cfg.DNNs = append(cfg.DNNs, DNNConfig{Name: d.Name, UEIPPool: d.UEIPPool})
			}
		}
	}

	data, err := os.ReadFile(cfgPath)
	if err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("config: parse YAML: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("config: read file: %w", err)
	}

	// Fall back to legacy single-pool config when DNNs is still empty.
	if len(cfg.DNNs) == 0 {
		cfg.DNNs = []DNNConfig{{Name: "internet", UEIPPool: cfg.UEIPPool}}
	}

	// Default DNS per DNN when the operator/per-NF YAML did not set one, so a
	// UE always gets resolvers in the PCO instead of silently going without.
	for i := range cfg.DNNs {
		if len(cfg.DNNs[i].DNS) == 0 {
			cfg.DNNs[i].DNS = append([]string(nil), DefaultDNSServers...)
		}
	}

	return cfg, nil
}
