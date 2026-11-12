// Package config loads the SEPP configuration from a YAML file.
//
// Config path: CONFIG_PATH env var → /etc/5gc/config.yaml (default).
// Ref: TS 23.501 §6.2.17 (SEPP), TS 29.573 (N32).
package config

import (
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

// PLMN is an MCC/MNC pair (MNC 2 or 3 digits).
type PLMN struct {
	MCC string `yaml:"mcc"`
	MNC string `yaml:"mnc"`
}

// N32Peer is a remote SEPP this SEPP initiates the N32-c exchange-capability
// towards at startup (TS 29.573 §5.2.2 step 1).
type N32Peer struct {
	// PLMN is the peer's PLMN (the targetPlmnId of the exchange).
	PLMN PLMN `yaml:"plmn"`
	// FQDN is the peer SEPP FQDN (telescopic form, TS 23.003 §28.5.2).
	FQDN string `yaml:"fqdn"`
	// Address is the peer N32 listener host:port that is dialled.
	Address string `yaml:"address"`
}

// Config holds all SEPP configuration.
type Config struct {
	// NFInstanceID is the unique SEPP NF instance UUID. Ref: TS 29.510 §6.1.6.2.2.
	NFInstanceID string `yaml:"nf_instance_id"`

	PLMN struct {
		MCC string `yaml:"mcc"`
		MNC string `yaml:"mnc"`
	} `yaml:"plmn"`

	SBI struct {
		// Address is the listen address of the intra-PLMN SBI server (host:port).
		Address string `yaml:"address"`
		// FQDN is the SEPP FQDN advertised in the NRF profile.
		FQDN string `yaml:"fqdn"`
		TLS  struct {
			CertFile string `yaml:"cert_file"`
			KeyFile  string `yaml:"key_file"`
			CAFile   string `yaml:"ca_file"`
		} `yaml:"tls"`
	} `yaml:"sbi"`

	// N32 holds the inter-PLMN listener (N32-c and N32-f) used from REL19-9.4.
	N32 struct {
		Address string `yaml:"address"`
		// RoamingPartners lists the remote PLMNs accepted on N32-c
		// (TS 29.573 §5.2.2; TS 33.501 §13.1.2). Empty means none.
		RoamingPartners []PLMN `yaml:"roaming_partners"`
		// Peers lists the remote SEPPs to run the N32-c initiator towards.
		Peers []N32Peer `yaml:"peers"`
		// TargetAPIRootSupported: local support of the 3gpp-Sbi-Target-apiRoot
		// header (TS 29.500 §6.1.4.3.4). Default true.
		TargetAPIRootSupported bool `yaml:"target_api_root_supported"`
		// TopologyHiding is the operator policy for topology hiding on N32-f
		// (TS 33.501 §13.1). Omitted means enabled; see TopologyHidingEnabled.
		TopologyHiding *bool `yaml:"topology_hiding"`
		// TLS is the N32 trust material; empty fields fall back to sbi.tls
		// (see N32TLS). A separate CA keeps the roaming-partner trust anchors
		// apart from the intra-PLMN SBI CA. Ref: TS 33.210 §6.2.
		TLS struct {
			CertFile string `yaml:"cert_file"`
			KeyFile  string `yaml:"key_file"`
			CAFile   string `yaml:"ca_file"`
		} `yaml:"tls"`
	} `yaml:"n32"`

	Peers struct {
		// NRF is the NRF address (host:port). Ref: TS 29.510 §5.2.2.
		NRF string `yaml:"nrf"`
	} `yaml:"peers"`

	Metrics struct {
		// Address is the Prometheus metrics listen address (host:port).
		Address string `yaml:"address"`
	} `yaml:"metrics"`

	// Release selects the release profile (rel17 default, rel19); NF_RELEASE_PROFILE overrides.
	Release capability.ReleaseConfig `yaml:"release"`
}

// Load reads the SEPP configuration from CONFIG_PATH (or /etc/5gc/config.yaml).
// A missing file is tolerated and defaults are used.
func Load() (*Config, error) {
	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = "/etc/5gc/config.yaml"
	}
	cfg := defaults()
	data, err := os.ReadFile(cfgPath)
	if err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("sepp: config: parse YAML: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("sepp: config: read file: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// TLSFiles is a certificate, key and CA bundle path triple.
type TLSFiles struct{ CertFile, KeyFile, CAFile string }

// N32TLS returns the N32 listener TLS files: n32.tls.* with each empty field
// falling back to sbi.tls.*.
func (c *Config) N32TLS() TLSFiles {
	f := TLSFiles{c.N32.TLS.CertFile, c.N32.TLS.KeyFile, c.N32.TLS.CAFile}
	if f.CertFile == "" {
		f.CertFile = c.SBI.TLS.CertFile
	}
	if f.KeyFile == "" {
		f.KeyFile = c.SBI.TLS.KeyFile
	}
	if f.CAFile == "" {
		f.CAFile = c.SBI.TLS.CAFile
	}
	return f
}

// TopologyHidingEnabled reports the topology-hiding policy: true unless
// n32.topology_hiding is explicitly false. Ref: TS 33.501 §13.1.
func (c *Config) TopologyHidingEnabled() bool {
	return c.N32.TopologyHiding == nil || *c.N32.TopologyHiding
}

// HasRoamingConfig reports whether any roaming configuration (n32.peers or
// n32.roaming_partners) is present, i.e. the N32-f forwarder is required.
func (c *Config) HasRoamingConfig() bool {
	return len(c.N32.Peers) > 0 || len(c.N32.RoamingPartners) > 0
}

// Validate checks the roaming-partner list and the local PLMN: mcc is three
// digits and mnc two or three digits (TS 29.571 §5.4.4.2).
func (c *Config) Validate() error {
	if !validPLMN(c.PLMN.MCC, c.PLMN.MNC) {
		return fmt.Errorf("sepp: config: invalid plmn %q/%q", c.PLMN.MCC, c.PLMN.MNC)
	}
	for i, p := range c.N32.RoamingPartners {
		if !validPLMN(p.MCC, p.MNC) {
			return fmt.Errorf("sepp: config: n32.roaming_partners[%d]: invalid plmn %q/%q", i, p.MCC, p.MNC)
		}
	}
	for i, p := range c.N32.Peers {
		if !validPLMN(p.PLMN.MCC, p.PLMN.MNC) {
			return fmt.Errorf("sepp: config: n32.peers[%d]: invalid plmn %q/%q", i, p.PLMN.MCC, p.PLMN.MNC)
		}
		if p.FQDN == "" {
			return fmt.Errorf("sepp: config: n32.peers[%d]: fqdn is required", i)
		}
		host, port, err := net.SplitHostPort(p.Address)
		if err != nil || host == "" || port == "" {
			return fmt.Errorf("sepp: config: n32.peers[%d]: address %q must be host:port", i, p.Address)
		}
	}
	return nil
}

func validPLMN(mcc, mnc string) bool {
	digits := func(s string, min, max int) bool {
		if len(s) < min || len(s) > max {
			return false
		}
		for _, r := range s {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
	}
	return digits(mcc, 3, 3) && digits(mnc, 2, 3)
}

func defaults() *Config {
	cfg := &Config{}
	cfg.NFInstanceID = "00000000-0000-4014-8000-000000000001"
	cfg.PLMN.MCC = "001"
	cfg.PLMN.MNC = "01"
	cfg.SBI.Address = "0.0.0.0:8014"
	cfg.SBI.FQDN = "sepp.5gc.mnc001.mcc001.3gppnetwork.org"
	cfg.SBI.TLS.CAFile = "/etc/5gc/pki/ca.crt"
	cfg.SBI.TLS.CertFile = "/etc/5gc/pki/sepp.crt"
	cfg.SBI.TLS.KeyFile = "/etc/5gc/pki/sepp.key"
	cfg.N32.Address = "0.0.0.0:8443"
	cfg.N32.TargetAPIRootSupported = true
	cfg.Peers.NRF = "nrf:8000"
	cfg.Metrics.Address = "0.0.0.0:9115"
	return cfg
}
