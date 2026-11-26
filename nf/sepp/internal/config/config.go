// Package config loads the SEPP configuration from a YAML file.
//
// Config path: CONFIG_PATH env var → /etc/5gc/config.yaml (default).
// Ref: TS 23.501 §6.2.17 (SEPP), TS 29.573 (N32).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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

// Key is the canonical "mcc-mnc3" form of the PLMN: the MNC is zero-padded to
// three digits, as in the 3gppnetwork.org FQDNs (TS 23.003 §28.5.2), so the
// partners, the certificate SAN PLMNs and the file keys compare equal.
func (p PLMN) Key() string { return p.MCC + "-" + padMNC(p.MNC) }

// String is the "mcc-mnc" form used by the admin view.
func (p PLMN) String() string { return p.MCC + "-" + p.MNC }

func padMNC(mnc string) string {
	for len(mnc) < 3 {
		mnc = "0" + mnc
	}
	return mnc
}

// DeriveSEPPFQDN returns the telescopic-root SEPP FQDN of a PLMN,
// sepp.5gc.mnc<MNC3>.mcc<MCC>.3gppnetwork.org (TS 23.003 §28.5.2).
func DeriveSEPPFQDN(p PLMN) string {
	return "sepp.5gc.mnc" + padMNC(p.MNC) + ".mcc" + p.MCC + ".3gppnetwork.org"
}

// Partner is one roaming partner (inline `n32.partners` and the shared
// partners file use the same schema). Ref: docs/procedures/N32InteropReadiness.md §4.1.
type Partner struct {
	// PLMN is the partner PLMN; key of its trust anchor.
	PLMN PLMN `yaml:"plmn"`
	// N32 is the SEPP-side part: trust anchor, FQDN, N32-c initiator target.
	N32 PartnerN32 `yaml:"n32"`
	// HomeNFs is read by the AMF only; the SEPP ignores it.
	HomeNFs HomeNFs `yaml:"home_nfs"`
	// Source is "file" or "config" (set at load, not read from YAML).
	Source string `yaml:"-"`
}

// PartnerN32 is the SEPP part of a Partner.
type PartnerN32 struct {
	// CAFile is the trust anchor bundle of this partner PLMN only (required
	// for a SEPP partner). Never the SBI CA. Ref: TS 33.501 §13.1.2.
	CAFile string `yaml:"ca_file"`
	// SEPPFQDN is the partner SEPP FQDN; default derived from the PLMN.
	SEPPFQDN string `yaml:"sepp_fqdn"`
	// Address is the partner N32 listener host:port; present means the N32-c
	// initiator targets it at startup (TS 29.573 §5.2.2 step 1).
	Address string `yaml:"address"`
}

// HomeNFs are the home-network apiRoots used by the AMF (ignored by the SEPP).
type HomeNFs struct {
	AUSFAPIRoot string `yaml:"ausf_api_root"`
	UDMAPIRoot  string `yaml:"udm_api_root"`
	SMFAPIRoot  string `yaml:"smf_api_root"` // H-SMF apiRoot (AMF-only; accepted so the shared partners file loads)
}

// FQDN is the partner SEPP FQDN (explicit or derived from the PLMN).
func (p Partner) FQDN() string {
	if p.N32.SEPPFQDN != "" {
		return p.N32.SEPPFQDN
	}
	return DeriveSEPPFQDN(p.PLMN)
}

const (
	// PartnersFileEnv overrides n32.partners_file (shared with the AMF).
	PartnersFileEnv = "ROAMING_PARTNERS_FILE"
	// DefaultPartnersFile is the partners file used when neither the env nor
	// n32.partners_file is set. A missing file means no partners.
	DefaultPartnersFile = "/etc/5gc/roaming/partners.yaml"
	// DefaultN32CertFile and DefaultN32KeyFile are the local N32 certificate
	// (never the SBI one). Ref: TS 33.501 §13.1.
	DefaultN32CertFile = "/etc/5gc/pki/n32/local/sepp.crt"
	DefaultN32KeyFile  = "/etc/5gc/pki/n32/local/sepp.key"
	// SourceFile and SourceConfig tag where an effective partner came from.
	SourceFile   = "file"
	SourceConfig = "config"
)

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

	// N32 holds the inter-PLMN listener (N32-c and N32-f).
	N32 struct {
		Address string `yaml:"address"`
		// Partners are the inline roaming partners; the partners file overrides
		// entries with the same PLMN. After Load it holds the effective list.
		Partners []Partner `yaml:"partners"`
		// PartnersFile is the shared partners file (env ROAMING_PARTNERS_FILE wins).
		PartnersFile string `yaml:"partners_file"`
		// TargetAPIRootSupported: local support of the 3gpp-Sbi-Target-apiRoot
		// header (TS 29.500 §6.1.4.3.4). Default true.
		TargetAPIRootSupported bool `yaml:"target_api_root_supported"`
		// TopologyHiding is the operator policy for topology hiding on N32-f
		// (TS 33.501 §13.1). Omitted means enabled; see TopologyHidingEnabled.
		TopologyHiding *bool `yaml:"topology_hiding"`
		// TLS is the local N32 certificate. There is no fallback to sbi.tls and
		// no CA here: trust anchors are per partner PLMN. Ref: TS 33.210 §6.2.
		TLS struct {
			CertFile string `yaml:"cert_file"`
			KeyFile  string `yaml:"key_file"`
		} `yaml:"tls"`
	} `yaml:"n32"`

	// PartnersFilePath is the partners file consulted at load; PartnersFileLoaded
	// reports whether it existed (a missing file is not an error). Not YAML.
	PartnersFilePath   string `yaml:"-"`
	PartnersFileLoaded bool   `yaml:"-"`

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

// Load reads the SEPP configuration from CONFIG_PATH (or /etc/5gc/config.yaml),
// then the partners file (ROAMING_PARTNERS_FILE, n32.partners_file, default
// DefaultPartnersFile). A missing config or partners file is tolerated; an
// invalid partners file or a legacy key is an error (fail closed).
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
		if err := rejectLegacy(data); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("sepp: config: read file: %w", err)
	}
	if cfg.SBI.FQDN == "" {
		cfg.SBI.FQDN = DeriveSEPPFQDN(PLMN{MCC: cfg.PLMN.MCC, MNC: cfg.PLMN.MNC})
	}
	if err := cfg.loadPartners(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// rejectLegacy refuses the pre-SEPP-005 keys with an error naming the replacement.
func rejectLegacy(data []byte) error {
	var probe struct {
		N32 struct {
			RoamingPartners yaml.Node `yaml:"roaming_partners"`
			Peers           yaml.Node `yaml:"peers"`
			TLS             struct {
				CAFile yaml.Node `yaml:"ca_file"`
			} `yaml:"tls"`
		} `yaml:"n32"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return fmt.Errorf("sepp: config: parse YAML: %w", err)
	}
	switch {
	case probe.N32.RoamingPartners.Kind != 0:
		return errors.New("sepp: config: n32.roaming_partners is no longer supported: use n32.partners[] (or the partners file) with n32.ca_file")
	case probe.N32.Peers.Kind != 0:
		return errors.New("sepp: config: n32.peers is no longer supported: use n32.partners[].n32.address")
	case probe.N32.TLS.CAFile.Kind != 0:
		return errors.New("sepp: config: n32.tls.ca_file is no longer supported: use per-partner n32.partners[].n32.ca_file (N32 never trusts a shared CA)")
	}
	return nil
}

// loadPartners merges the partners file over the inline partners.
func (c *Config) loadPartners() error {
	if err := checkUnique(c.N32.Partners, "n32.partners"); err != nil {
		return err
	}
	for i := range c.N32.Partners {
		c.N32.Partners[i].Source = SourceConfig
	}
	path := os.Getenv(PartnersFileEnv)
	if path == "" {
		path = c.N32.PartnersFile
	}
	if path == "" {
		path = DefaultPartnersFile
	}
	c.PartnersFilePath = path
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("sepp: config: read partners file %q: %w", path, err)
	}
	c.PartnersFileLoaded = true
	var f struct {
		Partners []Partner `yaml:"partners"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("sepp: config: partners file %q invalid: %w", path, err)
	}
	if err := checkUnique(f.Partners, "partners file "+path); err != nil {
		return err
	}
	for _, fp := range f.Partners {
		fp.Source = SourceFile
		replaced := false
		for i, ip := range c.N32.Partners {
			if ip.PLMN.Key() == fp.PLMN.Key() {
				c.N32.Partners[i], replaced = fp, true
				break
			}
		}
		if !replaced {
			c.N32.Partners = append(c.N32.Partners, fp)
		}
	}
	return nil
}

func checkUnique(ps []Partner, label string) error {
	seen := map[string]bool{}
	for i, p := range ps {
		if !validPLMN(p.PLMN.MCC, p.PLMN.MNC) {
			return fmt.Errorf("sepp: config: %s[%d]: invalid plmn %q/%q", label, i, p.PLMN.MCC, p.PLMN.MNC)
		}
		if seen[p.PLMN.Key()] {
			return fmt.Errorf("sepp: config: %s: duplicate partner plmn %s", label, p.PLMN)
		}
		seen[p.PLMN.Key()] = true
	}
	return nil
}

// TLSFiles is a certificate, key and CA bundle path triple (SBI listener).
type TLSFiles struct{ CertFile, KeyFile, CAFile string }

// TopologyHidingEnabled reports the topology-hiding policy: true unless
// n32.topology_hiding is explicitly false. Ref: TS 33.501 §13.1.
func (c *Config) TopologyHidingEnabled() bool {
	return c.N32.TopologyHiding == nil || *c.N32.TopologyHiding
}

// N32Partners returns the effective partners that carry an N32 trust anchor
// (n32.ca_file); partners with only home_nfs belong to the AMF.
func (c *Config) N32Partners() []Partner {
	var out []Partner
	for _, p := range c.N32.Partners {
		if p.N32.CAFile != "" {
			out = append(out, p)
		}
	}
	return out
}

// Initiators returns the N32 partners with an address: the N32-c initiator targets.
func (c *Config) Initiators() []Partner {
	var out []Partner
	for _, p := range c.N32Partners() {
		if p.N32.Address != "" {
			out = append(out, p)
		}
	}
	return out
}

// HasRoamingConfig reports whether any N32 partner exists, i.e. the N32-f
// forwarder and the local N32 certificate are required.
func (c *Config) HasRoamingConfig() bool { return len(c.N32Partners()) > 0 }

// Validate checks the local PLMN and the effective partners: mcc is three
// digits and mnc two or three digits (TS 29.571 §5.4.4.2); an N32 block needs
// ca_file; address is host:port.
func (c *Config) Validate() error {
	if !validPLMN(c.PLMN.MCC, c.PLMN.MNC) {
		return fmt.Errorf("sepp: config: invalid plmn %q/%q", c.PLMN.MCC, c.PLMN.MNC)
	}
	if err := checkUnique(c.N32.Partners, "n32.partners"); err != nil {
		return err
	}
	for i, p := range c.N32.Partners {
		if p.N32.CAFile == "" && (p.N32.Address != "" || p.N32.SEPPFQDN != "") {
			return fmt.Errorf("sepp: config: n32.partners[%d] (%s): n32.ca_file is required", i, p.PLMN)
		}
		if p.N32.Address != "" {
			host, port, err := net.SplitHostPort(p.N32.Address)
			if err != nil || host == "" || port == "" {
				return fmt.Errorf("sepp: config: n32.partners[%d] (%s): address %q must be host:port", i, p.PLMN, p.N32.Address)
			}
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
	cfg.SBI.TLS.CAFile = "/etc/5gc/pki/ca.crt"
	cfg.SBI.TLS.CertFile = "/etc/5gc/pki/sepp.crt"
	cfg.SBI.TLS.KeyFile = "/etc/5gc/pki/sepp.key"
	cfg.N32.Address = "0.0.0.0:8443"
	cfg.N32.TLS.CertFile = DefaultN32CertFile
	cfg.N32.TLS.KeyFile = DefaultN32KeyFile
	cfg.N32.TargetAPIRootSupported = true
	cfg.Peers.NRF = "nrf:8000"
	cfg.Metrics.Address = "0.0.0.0:9115"
	return cfg
}
