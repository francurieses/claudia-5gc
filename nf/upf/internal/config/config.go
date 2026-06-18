// Package config loads UPF configuration from YAML.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	operatorcfg "github.com/francurieses/claudia-5gc/shared/config"
)

// DNNConfig holds the per-DNN N6 TUN configuration for the UPF.
// Each DNN gets an isolated TUN interface so UE subnets never overlap.
// Ref: TS 23.501 §5.6.5, TS 29.244 §6.3.3.14 (Network Instance)
type DNNConfig struct {
	Name      string `yaml:"name"`
	UEIPPool  string `yaml:"ue_ip_pool"`  // CIDR for UE addresses (e.g., "10.60.0.0/24")
	TunName   string `yaml:"tun_name"`    // TUN device name (e.g., "upfgtp0")
	TunAddr   string `yaml:"tun_addr"`    // CIDR assigned to TUN (e.g., "10.60.0.254/24")
	GatewayIP string `yaml:"gateway_ip"`  // N6 bridge gateway for internet egress
}

// Config holds UPF runtime configuration.
type Config struct {
	NFInstanceID string `yaml:"nf_instance_id"`
	PLMN         struct {
		MCC string `yaml:"mcc"`
		MNC string `yaml:"mnc"`
	} `yaml:"plmn"`
	N3 struct {
		Address string `yaml:"address"` // GTP-U listener address (e.g., 0.0.0.0:2152)
		IP      string `yaml:"ip"`      // UPF IP for N3 transport layer (e.g., 172.30.3.100)
	} `yaml:"n3"`
	N4 struct {
		Address string `yaml:"address"` // PFCP listener address (e.g., 0.0.0.0:8805)
	} `yaml:"n4"`
	Metrics struct {
		Address string `yaml:"address"` // Prometheus metrics listener (e.g., 0.0.0.0:9107)
	} `yaml:"metrics"`
	// DNNs defines per-DNN TUN interfaces for N6 forwarding.
	// Adding a new DNN: append here and add the matching n6-<name>-net in docker-compose.yml.
	DNNs []DNNConfig `yaml:"dnns"`
	// UEIPPool and N6 are legacy single-DNN fields kept for backward compatibility.
	// They are superseded by DNNs when DNNs is non-empty.
	UEIPPool string `yaml:"ue_ip_pool"`
	N6       struct {
		GatewayIP string `yaml:"gateway_ip"`
		TunName   string `yaml:"tun_name"`
		TunAddr   string `yaml:"tun_addr"`
	} `yaml:"n6"`
}

// Load reads configuration from file or environment.
func Load() (*Config, error) {
	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = "/etc/5gc/config.yaml"
	}

	cfg := &Config{
		NFInstanceID: "00000000-0000-4007-8000-000000000001",
		UEIPPool:     "10.60.0.0/24",
	}

	// Set defaults
	cfg.N3.Address = "0.0.0.0:2152"
	cfg.N3.IP = "172.30.3.100"
	cfg.N4.Address = "0.0.0.0:8805"
	cfg.Metrics.Address = "0.0.0.0:9107"
	cfg.PLMN.MCC = "001"
	cfg.PLMN.MNC = "01"
	cfg.N6.GatewayIP = "172.30.6.1"
	cfg.N6.TunName = "upfgtp0"
	cfg.N6.TunAddr = "10.60.0.254/24"

	// Layer operator PLMN + DNN registry between Go defaults and per-NF YAML.
	if op, err := operatorcfg.LoadOperator(""); err != nil {
		return nil, fmt.Errorf("config: operator config: %w", err)
	} else if op != nil {
		op.ApplyToPLMN(&cfg.PLMN.MCC, &cfg.PLMN.MNC)
		// Operator DNNs pre-populate the UPF DNN list; per-NF YAML can override.
		// The N6 TUN fields (tun_name/tun_addr/gateway_ip) must still be set in
		// the per-NF YAML since they are deployment-specific.
		if dnnList := op.DNNList(); len(dnnList) > 0 && len(cfg.DNNs) == 0 {
			for i, d := range dnnList {
				cfg.DNNs = append(cfg.DNNs, DNNConfig{
					Name:     d.Name,
					UEIPPool: d.UEIPPool,
					// Derive sensible TUN defaults: upfgtpN, last-octet .254
					TunName: fmt.Sprintf("upfgtp%d", i),
				})
			}
		}
	}

	data, err := os.ReadFile(cfgPath)
	if err == nil {
		// File exists, parse it
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("config: parse YAML: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("config: read file: %w", err)
	}

	// Fall back to legacy single-DNN config when DNNs is still empty after YAML.
	if len(cfg.DNNs) == 0 {
		cfg.DNNs = []DNNConfig{{
			Name:      "internet",
			UEIPPool:  cfg.UEIPPool,
			TunName:   cfg.N6.TunName,
			TunAddr:   cfg.N6.TunAddr,
			GatewayIP: cfg.N6.GatewayIP,
		}}
	}

	return cfg, nil
}
