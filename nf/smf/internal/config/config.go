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
}

// DNNConfig holds the per-DNN IP pool configuration for the SMF.
// Ref: TS 23.501 §5.6.5
type DNNConfig struct {
	Name     string `yaml:"name"`
	UEIPPool string `yaml:"ue_ip_pool"`
}

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
	cfg.SBI.TLS.CAFile = "/etc/5gc/pki/ca.crt"
	cfg.SBI.TLS.CertFile, cfg.SBI.TLS.KeyFile = "/etc/5gc/pki/smf.crt", "/etc/5gc/pki/smf.key"
	cfg.Peers.NRF = "nrf:8000"

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

	return cfg, nil
}
